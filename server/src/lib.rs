mod api;
pub mod constants;
mod db;

use api::{HandlerState, connection_task};
use axum::{Router, middleware};
use std::{env, error::Error, net::SocketAddr, sync::Arc};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::trace::TraceLayer;
use tracing::Level;
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::db::Database;

type DynError = Box<dyn Error + Send + Sync>;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub db_filename: String,
    pub upload_directory: String,
    pub bind_addr: String,
    pub development_mode: bool,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        Self {
            db_filename: env::var("DATABASE").unwrap_or("e2ee-file-sharing.db".to_string()),
            upload_directory: env::var("UPLOAD_DIRECTORY").unwrap_or("/tmp/e2ee-fs".to_string()),
            bind_addr: env::var("EFS_SERVER_LISTEN").unwrap_or("127.0.0.1:8091".to_string()),
            development_mode: constants::development_mode_from_env(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(info(
    title = "E2EE File Sharing API",
    description = "API for E2EE file sharing",
    version = "0.1.0",
))]
struct ApiDoc;

pub async fn build_app(config: &ServerConfig) -> Result<Router, DynError> {
    let mut db = Database::open(&config.db_filename)?;
    db::init_db(&mut db)?;

    tokio::fs::create_dir_all(&config.upload_directory).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let db_filename = config.db_filename.clone();
    let state = HandlerState {
        tx,
        upload_directory: config.upload_directory.clone(),
        new_db: Arc::new(Box::new(move || {
            Database::open(&db_filename).expect("Failed to open database")
        })),
    };
    tokio::spawn(connection_task(db, rx));

    let email_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(constants::UPLOAD_RATE_LIMIT_EMAIL_REPLENISH_TIME)
            .burst_size(constants::UPLOAD_RATE_LIMIT_EMAIL_BURST_SIZE)
            .key_extractor(api::UserEmailExtractor)
            .finish()
            .unwrap(),
    );

    let ip_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(constants::UPLOAD_RATE_LIMIT_IP_REPLENISH_TIME)
            .burst_size(constants::UPLOAD_RATE_LIMIT_IP_BURST_SIZE)
            .finish()
            .unwrap(),
    );

    let (ws_app, ws_openapi) = OpenApiRouter::new()
        .routes(routes!(api::ws_file_upload))
        .with_state(state.clone())
        .split_for_parts();

    let ws_app = ws_app.layer(GovernorLayer::new(email_config));
    let ws_app = if !config.development_mode {
        ws_app.layer(GovernorLayer::new(ip_config))
    } else {
        ws_app
    };

    let general_email_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(constants::GENERAL_RATE_LIMIT_EMAIL_REPLENISH_TIME)
            .burst_size(constants::GENERAL_RATE_LIMIT_EMAIL_BURST_SIZE)
            .key_extractor(api::UserEmailExtractor)
            .finish()
            .unwrap(),
    );

    let general_ip_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(constants::GENERAL_RATE_LIMIT_IP_REPLENISH_TIME)
            .burst_size(constants::GENERAL_RATE_LIMIT_IP_BURST_SIZE)
            .finish()
            .unwrap(),
    );

    let (general_app, general_openapi) = OpenApiRouter::new()
        .routes(routes!(api::list_files))
        .routes(routes!(api::get_file))
        .routes(routes!(api::get_file_info))
        .routes(routes!(api::list_groups))
        .with_state(state.clone())
        .split_for_parts();

    let general_app = general_app.layer(GovernorLayer::new(general_email_config));
    let general_app = if !config.development_mode {
        general_app.layer(GovernorLayer::new(general_ip_config))
    } else {
        general_app
    };

    let (others_app, others_openapi) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(api::get_user_info))
        .routes(routes!(api::get_user_key))
        .routes(routes!(api::get_group_by_id))
        .routes(routes!(api::get_group_key_by_id))
        .routes(routes!(api::get_group_by_members))
        .routes(routes!(api::create_group))
        .with_state(state.clone())
        .split_for_parts();

    let others_app = others_app.merge(general_app);
    let others_openapi = others_openapi.merge_from(general_openapi);

    let auth_app = others_app.merge(ws_app);
    let auth_openapi = others_openapi.merge_from(ws_openapi);
    let auth_app = auth_app.route_layer(middleware::from_fn_with_state(
        state.clone(),
        api::user_auth,
    ));

    let (unauth_app, unauth_openapi) = OpenApiRouter::new()
        .routes(routes!(api::register_user))
        .with_state(state)
        .split_for_parts();

    let app = auth_app.merge(unauth_app);
    let openapi = auth_openapi.merge_from(unauth_openapi);
    let app = app.merge(
        utoipa_swagger_ui::SwaggerUi::new("/swagger-ui").url("/api/v1/openapi.json", openapi),
    );

    Ok(app.layer(
        TraceLayer::new_for_http()
            .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO))
            .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::INFO)),
    ))
}

pub async fn serve(listener: tokio::net::TcpListener, app: Router) -> Result<(), DynError> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

pub async fn run(config: ServerConfig) -> Result<(), DynError> {
    let _ = tracing_subscriber::fmt().try_init();

    let app = build_app(&config).await?;
    println!("server starting on port {}", config.bind_addr);
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    serve(listener, app).await
}

pub async fn run_from_env() -> Result<(), DynError> {
    run(ServerConfig::from_env()).await
}
