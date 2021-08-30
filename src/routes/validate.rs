use actix_web::{web, HttpResponse, Responder};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::{error::Error, fmt};
use uuid::Uuid;
use crate::key_providers::{ AsyncKeyProvider, GoogleKeyProvider};
use crate::state::AppState;

#[derive(serde::Deserialize)]
pub struct JwtBody {
    jwt: String,
}

#[derive(serde::Serialize)]
pub struct ValidateResponse {
    valid: bool,
}

pub async fn validate(jwt_body: web::Json<JwtBody>, data: web::Data<AppState>) -> impl Responder {
    let request_id = Uuid::new_v4();
    let request_span = tracing::info_span!(
        "Validating JWT",
        %request_id
    );

    let _request_span_guard = request_span.enter();
    match validate_jwt(&jwt_body.jwt, data.provider).await {
        Ok(valid_token) => {
            tracing::info!("Token validated successfully");
            HttpResponse::Ok().json(ValidateResponse { valid: valid_token })
        }
        Err(e) => {
            tracing::error!("Failed to validate JWT: {:?}", e);
            HttpResponse::Unauthorized().finish()
        }
    }
}

#[derive(serde::Deserialize)]
struct Claims {
    exp: usize,
    name: String,
    email: String,
}

async fn validate_jwt(jwt: &String, provider: GoogleKeyProvider) -> Result<bool, Box<dyn std::error::Error>> {
    let keys = get_google_signing_keys().await?;
    
    let header = decode_header(&jwt)?;

    let mut provider = GoogleKeyProvider::default();
    let key_to_use = provider.get_key_async(&header.clone().kid.unwrap()).await.unwrap().unwrap();
    //let key_to_use = get_key_to_use(&keys.keys, header.kid.unwrap())?;

    let token = decode::<Claims>(
        &jwt,
        &DecodingKey::from_rsa_components(&key_to_use.modulus, &key_to_use.exponent),
        &Validation::new(Algorithm::RS256),
    )?;

    Ok(true)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct GoogleSigningKeysResponse {
    keys: Vec<GoogleSigningKey>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct GoogleSigningKey {
    alg: String,
    n: String,
    e: String,
    kty: String,
    kid: String,
}

async fn get_google_signing_keys() -> Result<GoogleSigningKeysResponse, Box<dyn std::error::Error>>
{
    let response_body = reqwest::get("https://www.googleapis.com/oauth2/v3/certs")
        .await?
        .text()
        .await?;
    let signing_keys: GoogleSigningKeysResponse = serde_json::from_str(&response_body)?;
    Ok(signing_keys)
}

#[derive(Debug)]
struct KeyNotFound(String);

impl fmt::Display for KeyNotFound {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error finding key: {}", self.0)
    }
}

impl Error for KeyNotFound {}

fn get_key_to_use(
    keys: &Vec<GoogleSigningKey>,
    kid: String,
) -> Result<&GoogleSigningKey, Box<dyn std::error::Error>> {
    for key in keys.iter() {
        if key.kid == kid {
            return Ok(key);
        }
    }

    Err(Box::new(KeyNotFound(
        "No key could be found in `keys` that matched the provided `kid`".into(),
    )))
}
