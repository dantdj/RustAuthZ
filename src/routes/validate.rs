use crate::key_providers::{AsyncKeyProvider, GoogleKeyProvider};
use actix_web::{web, HttpResponse, Responder};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::boxed::Box;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct JwtBody {
    jwt: String,
}

#[derive(serde::Serialize)]
pub struct ValidateResponse {
    valid: bool,
}

pub async fn validate(
    jwt_body: web::Json<JwtBody>,
    provider: web::Data<Mutex<GoogleKeyProvider>>,
) -> impl Responder {
    let before = Instant::now();
    let request_id = Uuid::new_v4();
    let request_span = tracing::info_span!(
        "Validating JWT",
        %request_id
    );

    let _request_span_guard = request_span.enter();

    match validate_jwt(&jwt_body.jwt, provider.into_inner()).await {
        Ok(valid_token) => {
            tracing::info!("Token validated successfully in {:?}", before.elapsed());
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
    /// The expiry time of the token
    exp: usize,
    /// The name of the individual the token was issued to
    name: String,
    /// The email of the individual the token was issued to
    email: String,
}

async fn validate_jwt(
    jwt: &String,
    provider: Arc<Mutex<GoogleKeyProvider>>,
) -> Result<bool, InvalidKeyError> {
    let header = match decode_header(&jwt) {
        Ok(header) => header,
        Err(e) => return Err(InvalidKeyError::new(&e.to_string())),
    };
    let mut guard = provider.lock().unwrap();

    let key_to_use = match guard.get_key_async(&header.clone().kid.unwrap()).await {
        Ok(key) => key,
        Err(e) => return Err(InvalidKeyError::new(&e.details)),
    };
    drop(guard);

    let token = decode::<Claims>(
        &jwt,
        &DecodingKey::from_rsa_components(&key_to_use.modulus, &key_to_use.exponent),
        &Validation::new(Algorithm::RS256),
    );

    Ok(true)
}

#[derive(Debug, Clone)]
pub struct InvalidKeyError {
    pub details: String,
}

impl InvalidKeyError {
    fn new(message: &str) -> InvalidKeyError {
        InvalidKeyError {
            details: message.to_string(),
        }
    }
}

impl fmt::Display for InvalidKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "provided key failed validation")
    }
}

impl Error for InvalidKeyError {
    fn description(&self) -> &str {
        &self.details
    }
}
