use crate::validator::{Validator, Claims};
use actix_web::{web, HttpResponse, Responder};
use std::sync::Mutex;
use std::time::Instant;
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct JwtBody {
    jwt: String,
}

#[derive(serde::Serialize)]
pub struct ValidateResponse {
    valid: bool,
    claims: Claims,
}

pub async fn validate(
    jwt_body: web::Json<JwtBody>,
    validator: web::Data<Mutex<Validator>>,
) -> impl Responder {
    let before = Instant::now();
    let request_id = Uuid::new_v4();
    let request_span = tracing::info_span!(
        "Validating JWT",
        %request_id
    );

    let _request_span_guard = request_span.enter();

    let mut guard = validator.lock().unwrap();

    match guard.validate_jwt(&jwt_body.jwt).await {
        Ok(valid_token) => {
            tracing::info!("Token validated successfully in {:?}", before.elapsed());
            drop(guard);
            HttpResponse::Ok().json(ValidateResponse { valid: valid_token.valid, claims: valid_token.token_data.claims })
        }
        Err(e) => {
            tracing::error!("Failed to validate JWT: {:?}", e);
            drop(guard);
            HttpResponse::Unauthorized().finish()
        }
    }
}