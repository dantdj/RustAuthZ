#[actix_rt::test]
async fn health_check_works() {
    // Arrange
    spawn_app();

    let client = reqwest::Client::new();

    // Act
    let response = client
        .get("http://127.0.0.1:8080/ping")
        .send()
        .await
        .expect("Failed to execute request");

    // Assert
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}

fn spawn_app() -> std::io::Result<()> {
    let server = rust_authz::run().expect("Failed to bind address");
    let _ = tokio::spawn(server) ; 
}
