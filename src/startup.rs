use crate::validator::Validator;
use crate::routes::{health_check, validate};
use actix_web::{dev::Server, middleware::Logger, web, App, HttpServer};
use std::net::TcpListener;
use std::sync::Mutex;

pub fn run(listener: TcpListener, audience: String, issuer: String) -> Result<Server, std::io::Error> {
    let validator = web::Data::new(Mutex::new(Validator::new(audience, issuer)));
    let server = HttpServer::new(move || {
        App::new()
            .app_data(validator.clone())
            .wrap(Logger::default())
            .route("/ping", web::get().to(health_check))
            .route("/validate", web::post().to(validate))
    })
    .listen(listener)?
    .run();
    Ok(server)
}
