use std::time::Instant;
use reqwest::{header::CACHE_CONTROL};
use async_trait::async_trait;
use headers::{Header, HeaderMap};
use std::any::Any;

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

pub trait KeyProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<Jwk>, ()>;
}

#[async_trait]
pub trait AsyncKeyProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Option<Jwk>, ()>;
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
    fn process_response(&mut self, headers: &HeaderMap, text: &str) -> Result<&JwkSet, ()> {
        let mut expiration_time = None;
        let x = headers.get_all(CACHE_CONTROL);
        if let Ok(cache_header) = headers::CacheControl::decode(&mut x.iter()) {
            if let Some(max_age) = cache_header.max_age() {
                expiration_time = Some(Instant::now() + max_age);
            }
        }
        let key_set = serde_json::from_str(&text).map_err(|_| ())?;
        if let Some(expiration_time) = expiration_time {
            self.cached = Some(key_set);
            self.expiration_time = expiration_time;
        }
        Ok(self.cached.as_ref().unwrap())
    }
    pub fn download_keys(&mut self) -> Result<&JwkSet, ()> {
        let result = reqwest::blocking::get(GOOGLE_CERT_URL).map_err(|_| ())?;
        self.process_response(&result.headers().clone(), &result.text().map_err(|_| ())?)
    }
    async fn download_keys_async(&mut self) -> Result<&JwkSet, ()> {
        let result = reqwest::get(GOOGLE_CERT_URL).await.map_err(|_| ())?;
        self.process_response(
            &result.headers().clone(),
            &result.text().await.map_err(|_| ())?,
        )
    }
}

impl KeyProvider for GoogleKeyProvider {
    fn get_key(&mut self, key_id: &str) -> Result<Option<Jwk>, ()> {
        if let Some(ref cached_keys) = self.cached {
            if self.expiration_time > Instant::now() {
                return Ok(cached_keys.get_key(key_id));
            }
        }
        Ok(self.download_keys()?.get_key(key_id))
    }
}

#[async_trait]
impl AsyncKeyProvider for GoogleKeyProvider {
    async fn get_key_async(&mut self, key_id: &str) -> Result<Option<Jwk>, ()> {
        if let Some(ref cached_keys) = self.cached {
            if self.expiration_time > Instant::now() {
                tracing::info!("Returning key from cache...");
                return Ok(cached_keys.get_key(key_id));
            }
        }
        tracing::info!("Getting new keys...");
        Ok(self.download_keys_async().await?.get_key(key_id))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}