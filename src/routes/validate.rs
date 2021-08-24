use actix_web::{web, HttpResponse, Responder};

#[derive(serde::Deserialize)]
pub struct JwtBody {
    jwt: String,
}

pub async fn validate(jwt_body: web::Json<JwtBody>) -> impl Responder {
    let is_valid = false;
    println!("{}", &jwt_body.jwt);
    if is_valid {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}
