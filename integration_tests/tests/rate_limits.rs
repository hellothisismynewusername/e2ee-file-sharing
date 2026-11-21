use base64::prelude::{BASE64_URL_SAFE, Engine as _};
use integration_tests::TestServer;
use server::constants::GENERAL_RATE_LIMIT_EMAIL_BURST_SIZE;

#[tokio::test]
async fn general_api_email_limit_returns_429_after_burst() {
    let test_server = TestServer::builder().development_mode(true).spawn().await;
    let client = reqwest::Client::new();
    let email = "ratelimit@test.com";
    let password = b"super-secret";
    let encoded_password = BASE64_URL_SAFE.encode(password);

    test_server.seed_user(email, password);

    // try sending just within the burst size
    for _ in 0..GENERAL_RATE_LIMIT_EMAIL_BURST_SIZE {
        let response = client
            .get(test_server.url(&format!(
                "/api/v1/list-files?user_email={email}&user_password_hash={encoded_password}"
            )))
            .send()
            .await
            .expect("rate-limit warmup request failed");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    // sending one more request should trip the limit
    let response = client
        .get(test_server.url(&format!(
            "/api/v1/list-files?user_email={email}&user_password_hash={encoded_password}"
        )))
        .send()
        .await
        .expect("rate-limit trigger request failed");

    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
}
