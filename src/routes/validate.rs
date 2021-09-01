use crate::key_providers::{AsyncKeyProvider, GoogleKeyProvider};
use actix_web::{web, HttpResponse, Responder};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::boxed::Box;
use std::sync::{Arc, Mutex};
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
    let request_id = Uuid::new_v4();
    let request_span = tracing::info_span!(
        "Validating JWT",
        %request_id
    );

    let _request_span_guard = request_span.enter();

    match validate_jwt(&jwt_body.jwt, provider.into_inner()).await {
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

async fn validate_jwt(
    jwt: &String,
    provider: Arc<Mutex<GoogleKeyProvider>>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let header = decode_header(&jwt)?;
    let mut guard = provider.lock().unwrap();
    let key_to_use = match guard.get_key_async(&"hi".to_string()).await {
        Ok(key) => key.unwrap(),
        Err(_) => panic!("TODO: Handle"),
    };
    drop(guard);

    let token = decode::<Claims>(
        &jwt,
        &DecodingKey::from_rsa_components(&key_to_use.modulus, &key_to_use.exponent),
        &Validation::new(Algorithm::RS256),
    )?;

    Ok(true)
}
