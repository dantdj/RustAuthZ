use rust_authz::run;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    run().await?.await
}
