use std::time::Instant;
use reqwest::get;

const GOOGLE_CERT_URL = "https://www.googleapis.com/oauth2/v3/certs";

/// This is based on purely what the Google JWKs contain - will need extending 
/// when supporting new providers
#[derive(serde::Deserialize, serde::Serialize)]
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

pub struct JwkSet {
    keys: Vec<Jwk>,
}

pub trait AsyncKeyProvider {
    async fn get_key_async(&mut self, kid: &str) -> Result<Option<Jwk>>
}

pub struct GoogleKeyProvider {
    cachedKeys: Option<JwkSet>,
    expires: Instant,
}

impl Default for GoogleKeyProvider {
    fn default() -> Self {
        Self {
            cachedKeys: None,
            expires: Instant::now(),
        }
    }
}

impl GoogleKeyProvider {
    pub fn download_keys(&mut self) -> Result<&JwkSet, ()> {
        let result = reqwest::get(GOOGLE_CERT_URL).await?;
        
    }
}
