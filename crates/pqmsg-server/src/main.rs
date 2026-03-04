use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use pqmsg_core::alg::SecurityProfile;
use pqmsg_server::{build_router, init_db, parse_db_backend, AppState, PushNotifier, RateLimiter};
use sqlx::any::AnyPoolOptions;
use std::env;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tracing::info;

fn parse_env_u32(name: &str, default: u32) -> anyhow::Result<u32> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .with_context(|| format!("invalid {name}='{value}': expected integer")),
        Err(_) => Ok(default),
    }
}

fn parse_env_u64(name: &str, default: u64) -> anyhow::Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("invalid {name}='{value}': expected integer")),
        Err(_) => Ok(default),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "pqmsg_server=info".to_string()))
        .init();

    let bind_addr = env::var("PQMSG_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let database_url =
        env::var("PQMSG_DATABASE_URL").unwrap_or_else(|_| "sqlite://pqmsg-server.db".to_string());
    let profile_raw =
        env::var("PQMSG_SECURITY_PROFILE").unwrap_or_else(|_| "high_assurance".to_string());
    let security_profile = SecurityProfile::parse(&profile_raw)
        .with_context(|| format!("invalid PQMSG_SECURITY_PROFILE '{profile_raw}'"))?;
    let db_backend = parse_db_backend(&database_url)
        .map_err(|message| anyhow::anyhow!("{message} (got '{database_url}')"))?;
    let db_max_connections = parse_env_u32("PQMSG_DB_MAX_CONNECTIONS", 20)?;
    let db_min_connections = parse_env_u32("PQMSG_DB_MIN_CONNECTIONS", 1)?;
    if db_min_connections > db_max_connections {
        anyhow::bail!("PQMSG_DB_MIN_CONNECTIONS cannot exceed PQMSG_DB_MAX_CONNECTIONS");
    }
    let db_acquire_timeout_secs = parse_env_u64("PQMSG_DB_ACQUIRE_TIMEOUT_SECS", 5)?;
    let db_idle_timeout_secs = parse_env_u64("PQMSG_DB_IDLE_TIMEOUT_SECS", 300)?;
    let fcm_server_key = env::var("PQMSG_FCM_SERVER_KEY").ok();
    let fcm_endpoint = env::var("PQMSG_FCM_ENDPOINT")
        .unwrap_or_else(|_| "https://fcm.googleapis.com/fcm/send".to_string());
    let tls_cert_path = env::var("PQMSG_TLS_CERT_PATH").ok();
    let tls_key_path = env::var("PQMSG_TLS_KEY_PATH").ok();

    let pool = AnyPoolOptions::new()
        .max_connections(db_max_connections)
        .min_connections(db_min_connections)
        .acquire_timeout(StdDuration::from_secs(db_acquire_timeout_secs))
        .idle_timeout(Some(StdDuration::from_secs(db_idle_timeout_secs)))
        .connect(&database_url)
        .await
        .with_context(|| format!("failed to connect to {database_url}"))?;
    init_db(&pool, db_backend).await?;

    let push_notifier = Arc::new(PushNotifier::with_fcm(fcm_server_key, fcm_endpoint));
    let push_enabled = push_notifier.is_enabled();
    let state = AppState::with_security_profile(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            60.0,
            1.0,
            20_000,
            StdDuration::from_secs(600),
        )),
        security_profile,
    )
    .with_push_notifier(push_notifier);
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
                "pqmsg-server listening with TLS on {bind_addr} profile={} db_backend={} max_conn={} min_conn={} push_enabled={}",
                security_profile.as_str()
                ,
                db_backend.as_str(),
                db_max_connections,
                db_min_connections,
                push_enabled
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
                "pqmsg-server listening without TLS on {bind_addr} profile={} db_backend={} max_conn={} min_conn={} push_enabled={}",
                security_profile.as_str(),
                db_backend.as_str(),
                db_max_connections,
                db_min_connections,
                push_enabled
            );
            axum::serve(listener, app).await?;
        }
        _ => {
            anyhow::bail!("set both PQMSG_TLS_CERT_PATH and PQMSG_TLS_KEY_PATH, or neither");
        }
    }
    Ok(())
}
