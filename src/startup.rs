use crate::routes::{health_check, validate};
use crate::key_providers::{GoogleKeyProvider};
use actix_web::{dev::Server, middleware::Logger, web, App, HttpServer};
use std::net::TcpListener;
use std::sync::Arc;

pub fn run(listener: TcpListener) -> Result<Server, std::io::Error> {
    let key_provider = web::Data::from(Arc::new(GoogleKeyProvider::default()));

    let server = HttpServer::new(move || {
        App::new()
            .app_data(key_provider.clone())
            .wrap(Logger::default())
            .route("/ping", web::get().to(health_check))
            .route("/validate", web::post().to(validate))
    })
    .listen(listener)?
    .run();
    Ok(server)
}
