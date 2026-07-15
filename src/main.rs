mod admin;
mod auth;
mod config;
mod database;
mod discovery;
mod error;
mod hub;
mod protocol;
mod proxy;
mod qr;
mod registry;
mod routes;
mod secure;
mod sync_info;
mod tunnel;

use crate::config::Config;
use crate::database::Database;
use crate::registry::Registry;
use crate::routes::build_router;
use crate::tunnel::AppState;
use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let config = Config::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log))
        .with_target(false)
        .compact()
        .init();

    let config = Arc::new(config);
    let database = Database::open(&config.data_dir)?;
    let registry = Registry::new(config.clone());
    let _discovery_handle = discovery::start_mdns(config.clone())?;
    let hub = hub::Hub::load_or_create(&config.data_dir, database.clone())?;
    let state = AppState {
        registry: registry.clone(),
        config: config.clone(),
        hub,
        database,
    };

    // Background GC
    let gc_registry = registry.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            gc_registry.gc_rooms();
            gc_registry.gc_stale_devices();
        }
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    info!(
        listen = %config.listen,
        auth = config.auth_required(),
        version = env!("CARGO_PKG_VERSION"),
        "crosspaste-server started (central hub)"
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}
