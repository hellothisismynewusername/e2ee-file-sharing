#[tokio::main]
async fn main() {
    server::run_from_env().await.unwrap();
}
