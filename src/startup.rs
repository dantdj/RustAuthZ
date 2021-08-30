use crate::routes::{health_check, validate};
use crate::key_providers::{ AsyncKeyProvider, GoogleKeyProvider};
use crate::jsonwebtokens::JwtBody;
use actix_web::{dev::Server, middleware::Logger, web, App, HttpServer};
use std::net::TcpListener;
use crate::state::AppState;

pub fn run(listener: TcpListener) -> Result<Server, std::io::Error> {
    let mut key_provider = GoogleKeyProvider::default();

    let server = HttpServer::new(|| {
        App::new()
            .app_data(AppState {
                provider: key_provider,
            })
            .wrap(Logger::default())
            .route("/ping", web::get().to(health_check))
            .route("/validate", web::post().to(validate))
    })
    .listen(listener)?
    .run();
    Ok(server)
}
