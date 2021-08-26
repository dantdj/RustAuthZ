use actix_web::middleware::Logger;
use crate::routes::{health_check, validate};
use actix_web::{dev::Server, web, App, HttpServer};
use std::net::TcpListener;

pub fn run(listener: TcpListener) -> Result<Server, std::io::Error> {
    let server = HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .route("/ping", web::get().to(health_check))
            .route("/validate", web::post().to(validate))
    })
    .listen(listener)?
    .run();
    Ok(server)
}
