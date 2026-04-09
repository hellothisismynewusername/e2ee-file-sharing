use std::path::{Path, PathBuf};

use reqwest::Url;
use rusqlite::{Connection, params};
use server::ServerConfig;
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle};

pub struct TestServerBuilder {
    development_mode: bool,
}

impl Default for TestServerBuilder {
    fn default() -> Self {
        Self {
            development_mode: true,
        }
    }
}

impl TestServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn development_mode(mut self, development_mode: bool) -> Self {
        self.development_mode = development_mode;
        self
    }

    pub async fn spawn(self) -> TestServer {
        let temp_dir = tempfile::tempdir().expect("failed to create tempdir");
        let db_path = temp_dir.path().join("test.sqlite3");
        let upload_directory = temp_dir.path().join("uploads");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test listener");
        let address = listener
            .local_addr()
            .expect("failed to get test listener address");
        let config = ServerConfig {
            db_filename: db_path.to_string_lossy().into_owned(),
            upload_directory: upload_directory.to_string_lossy().into_owned(),
            bind_addr: address.to_string(),
            development_mode: self.development_mode,
        };
        let app = server::build_app(&config)
            .await
            .expect("failed to build server app");

        let task = tokio::spawn(async move {
            server::serve(listener, app)
                .await
                .expect("test server crashed unexpectedly");
        });

        TestServer {
            _temp_dir: temp_dir,
            db_path,
            base_url: Url::parse(&format!("http://{address}")).expect("invalid test server url"),
            task,
        }
    }
}

pub struct TestServer {
    _temp_dir: TempDir,
    db_path: PathBuf,
    base_url: Url,
    task: JoinHandle<()>,
}

impl TestServer {
    pub async fn spawn() -> Self {
        TestServerBuilder::new().spawn().await
    }

    pub fn builder() -> TestServerBuilder {
        TestServerBuilder::new()
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn open_db(&self) -> Connection {
        Connection::open(&self.db_path).expect("failed to open test database")
    }

    pub fn seed_user(&self, email: &str, raw_password: &[u8]) {
        let db = self.open_db();
        let salt = corelib::server::make_salt();
        let password_hash = corelib::server::salt_password(raw_password, &salt);

        db.execute(
            "INSERT INTO users (email, password_hash, salt, pk_pub) VALUES (?, ?, ?, X'00')",
            params![email, password_hash, salt],
        )
        .expect("failed to seed test user");
    }

    pub fn url(&self, path: &str) -> Url {
        self.base_url
            .join(path)
            .expect("failed to join test server url")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
