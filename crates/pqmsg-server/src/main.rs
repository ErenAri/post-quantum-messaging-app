use anyhow::Context;
use pqmsg_server::{build_router, init_db, AppState, RateLimiter};
use sqlx::sqlite::SqlitePoolOptions;
use std::env;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "pqmsg_server=info".to_string()))
        .init();

    let bind_addr = env::var("PQMSG_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let database_url =
        env::var("PQMSG_DATABASE_URL").unwrap_or_else(|_| "sqlite://pqmsg-server.db".to_string());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .with_context(|| format!("failed to connect to {database_url}"))?;
    init_db(&pool).await?;

    let state = AppState::new(pool, Arc::new(RateLimiter::new(60.0, 1.0)));
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("pqmsg-server listening on {bind_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
