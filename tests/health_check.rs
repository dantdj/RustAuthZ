#[actix_rt::test]
async fn health_check_works() {
    // Arrange
    let address = spawn_app();
    let client = reqwest::Client::new();

    // Act
    let response = client
        .get(format!("{}/ping", &address))
        .send()
        .await
        .expect("Failed to execute request");

    // Assert
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}

use std::net::TcpListener;

/// Creates an instance of the application server, and returns the formatted IP
/// and port combo to access the instance in a test.
fn spawn_app() -> String {
    // Setting port number to 0 means it uses a random available port
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind random port");
    // Extract port number for use in tests
    let port = listener.local_addr().unwrap().port();

    let server = rust_authz::startup::run(listener).expect("Failed to bind address");
    let _ = tokio::spawn(server);

    format!("http://127.0.0.1:{}", port)
}
