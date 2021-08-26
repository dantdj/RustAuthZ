use uuid::Uuid;
use std::io;
use actix_web::{web, HttpResponse, Responder};

#[derive(serde::Deserialize)]
pub struct JwtBody {
    jwt: String,
}

pub async fn validate(jwt_body: web::Json<JwtBody>) -> impl Responder {
    let request_id = Uuid::new_v4();
    let request_span = tracing::info_span!(
        "Validating JWT",
        %request_id
    );

    let _request_span_guard = request_span.enter();
    match validate_jwt(&jwt_body.jwt) {
        Ok(_) => {
            tracing::info!("Token validated successfully");
            HttpResponse::Ok().finish()
        }, 
        Err(e) => {
            tracing::error!("Failed to validate JWT: {:?}", e);
            HttpResponse::Unauthorized().finish()
        }
    }
}

fn validate_jwt(jwt: &String) -> Result<bool, io::Error> {
    Ok(true)
}