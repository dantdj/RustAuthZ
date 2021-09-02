use async_trait::async_trait;
use headers::{Header, HeaderMap};
use reqwest::header::CACHE_CONTROL;
use std::any::Any;
use std::error::Error;
use std::fmt;
use std::time::Instant;

const GOOGLE_CERT_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// This is based on purely what the Google JWKs contain - will need extending
/// when supporting new providers
#[derive(serde::Deserialize, Clone)]
pub struct Jwk {
    #[serde(rename = "use")]
    pub public_key_use: String,

    #[serde(rename = "alg")]
    pub algorithm: String,

    #[serde(rename = "n")]
    pub modulus: String,

    #[serde(rename = "e")]
    pub exponent: String,

    #[serde(rename = "kty")]
    pub key_type: String,

    #[serde(rename = "kid")]
    pub key_id: String,
}

impl Jwk {
    pub fn get_id(&self) -> String {
        self.key_id.clone()
    }
}

#[derive(serde::Deserialize, Clone)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn get_key(&self, id: &str) -> Option<Jwk> {
        self.keys.iter().find(|key| key.key_id == id).cloned()
    }
}

#[derive(Debug, Clone)]
pub struct KeyNotFoundError {
    pub details: String,
}

impl KeyNotFoundError {
    fn new(message: &str) -> KeyNotFoundError {
        KeyNotFoundError {
            details: message.to_string(),
        }
    }
}

impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "couldn't find key matching provided key id")
    }
}

impl Error for KeyNotFoundError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[async_trait]
pub trait AsyncKeyProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Jwk, KeyNotFoundError>;
    fn as_any(&self) -> &dyn Any;
}

#[derive(Clone)]
pub struct GoogleKeyProvider {
    cached: Option<JwkSet>,
    expiration_time: Instant,
}

impl Default for GoogleKeyProvider {
    fn default() -> Self {
        Self {
            cached: None,
            expiration_time: Instant::now(),
        }
    }
}

impl GoogleKeyProvider {
    fn process_response(
        &mut self,
        headers: &HeaderMap,
        text: &str,
    ) -> Result<&JwkSet, KeyNotFoundError> {
        let mut expiration_time = None;
        let x = headers.get_all(CACHE_CONTROL);
        if let Ok(cache_header) = headers::CacheControl::decode(&mut x.iter()) {
            if let Some(max_age) = cache_header.max_age() {
                expiration_time = Some(Instant::now() + max_age);
            }
        }
        let key_set = serde_json::from_str(&text)
            .map_err(|_| KeyNotFoundError::new("failed to parse keyset"))?;
        if let Some(expiration_time) = expiration_time {
            self.cached = Some(key_set);
            self.expiration_time = expiration_time;
        }
        Ok(self.cached.as_ref().unwrap())
    }
    async fn download_keys_async(&mut self) -> Result<&JwkSet, KeyNotFoundError> {
        let result = reqwest::get(GOOGLE_CERT_URL)
            .await
            .map_err(|_| KeyNotFoundError::new("failed to request keys from Google"))?;
        self.process_response(
            &result.headers().clone(),
            &result
                .text()
                .await
                .map_err(|_| KeyNotFoundError::new("failed to extract text from result"))?,
        )
    }
}

#[async_trait]
impl AsyncKeyProvider for GoogleKeyProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Jwk, KeyNotFoundError> {
        if let Some(ref cached_keys) = self.cached {
            if self.expiration_time > Instant::now() {
                tracing::info!("Returning key from cache...");
                match cached_keys.get_key(key_id) {
                    Some(key) => return Ok(key),
                    None => return Err(KeyNotFoundError::new("not found")),
                }
            }
        }
        tracing::info!("Getting new keys...");
        
        match self.download_keys_async().await?.get_key(key_id) {
            Some(key) => Ok(key),
            None => return Err(KeyNotFoundError::new("couldn't get key"))
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
