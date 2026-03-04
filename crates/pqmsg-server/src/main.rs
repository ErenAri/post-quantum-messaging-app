use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use pqmsg_core::alg::SecurityProfile;
use pqmsg_server::{build_router, init_db, AppState, RateLimiter};
use sqlx::sqlite::SqlitePoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "pqmsg_server=info".to_string()))
        .init();

    let bind_addr = env::var("PQMSG_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let database_url =
        env::var("PQMSG_DATABASE_URL").unwrap_or_else(|_| "sqlite://pqmsg-server.db".to_string());
    let profile_raw = env::var("PQMSG_SECURITY_PROFILE").unwrap_or_else(|_| "research".to_string());
    let security_profile = SecurityProfile::parse(&profile_raw)
        .with_context(|| format!("invalid PQMSG_SECURITY_PROFILE '{profile_raw}'"))?;
    let tls_cert_path = env::var("PQMSG_TLS_CERT_PATH").ok();
    let tls_key_path = env::var("PQMSG_TLS_KEY_PATH").ok();

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .with_context(|| format!("failed to connect to {database_url}"))?;
    init_db(&pool).await?;

    let state = AppState::with_security_profile(
        pool,
        Arc::new(RateLimiter::new(
            60.0,
            1.0,
            20_000,
            StdDuration::from_secs(600),
        )),
        security_profile,
    );
    let app = build_router(state);

    match (tls_cert_path, tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            let tls_config = RustlsConfig::from_pem_file(cert_path.clone(), key_path.clone())
                .await
                .with_context(|| {
                    format!(
                        "failed to load TLS certificate/key from cert='{cert_path}' key='{key_path}'"
                    )
                })?;
            info!(
                "pqmsg-server listening with TLS on {bind_addr} profile={}",
                security_profile.as_str()
            );
            axum_server::bind_rustls(bind_addr.parse()?, tls_config)
                .serve(app.into_make_service())
                .await?;
        }
        (None, None) => {
            if security_profile.requires_tls() {
                anyhow::bail!(
                    "profile '{}' requires TLS; set PQMSG_TLS_CERT_PATH and PQMSG_TLS_KEY_PATH",
                    security_profile.as_str()
                );
            }
            let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
            info!(
                "pqmsg-server listening without TLS on {bind_addr} profile={}",
                security_profile.as_str()
            );
            axum::serve(listener, app).await?;
        }
        _ => {
            anyhow::bail!("set both PQMSG_TLS_CERT_PATH and PQMSG_TLS_KEY_PATH, or neither");
        }
    }
    Ok(())
}
