use base64::prelude::{BASE64_STANDARD, Engine as _};
use integration_tests::TestServer;
use serde_json::json;

#[tokio::test]
async fn register_user_persists_to_test_database() {
    let test_server = TestServer::spawn().await;
    let client = reqwest::Client::new();

    // register user
    let response = client
        .post(test_server.url("/api/v1/user"))
        .json(&json!({
            "user_email": "integration@test.com",
            "user_password_hash": BASE64_STANDARD.encode(b"password"),
            "key": BASE64_STANDARD.encode([1u8, 2u8, 3u8]),
        }))
        .send()
        .await
        .expect("request to test server failed");

    assert!(response.status().is_success());

    // ensure the user is in the database
    let db = test_server.open_db();
    let persisted_email: String = db
        .query_row("SELECT email FROM users WHERE id = 1", [], |row| row.get(0))
        .expect("expected registered user in test database");

    assert_eq!(persisted_email, "integration@test.com");
}
