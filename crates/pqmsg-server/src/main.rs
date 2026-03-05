use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use pqmsg_core::alg::SecurityProfile;
use pqmsg_server::{
    build_router, init_db, parse_db_backend, AppState, AuditLogger, DosHardeningPolicy,
    PushNotifier, RateLimiter,
};
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

fn parse_env_optional_u8(name: &str) -> anyhow::Result<Option<u8>> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u8>()
            .with_context(|| format!("invalid {name}='{value}': expected integer 0..255"))
            .map(Some),
        Err(_) => Ok(None),
    }
}

fn parse_env_optional_i64(name: &str) -> anyhow::Result<Option<i64>> {
    match env::var(name) {
        Ok(value) => value
            .parse::<i64>()
            .with_context(|| format!("invalid {name}='{value}': expected integer"))
            .map(Some),
        Err(_) => Ok(None),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    let log_filter = env::var("RUST_LOG").unwrap_or_else(|_| "pqmsg_server=info".to_string());
    let log_format = env::var("PQMSG_LOG_FORMAT").unwrap_or_else(|_| "json".to_string());
    if log_format.trim().eq_ignore_ascii_case("pretty") {
        tracing_subscriber::fmt()
            .with_env_filter(log_filter)
            .with_target(true)
            .init();
    } else {
        tracing_subscriber::fmt()
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_env_filter(log_filter)
            .init();
    }

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
    let rate_limit_capacity = parse_env_u32("PQMSG_RATE_LIMIT_CAPACITY", 60)? as f64;
    let rate_limit_refill_per_second =
        parse_env_u32("PQMSG_RATE_LIMIT_REFILL_PER_SECOND", 1)? as f64;
    let rate_limit_max_entries = parse_env_u32("PQMSG_RATE_LIMIT_MAX_ENTRIES", 20_000)? as usize;
    let rate_limit_bucket_ttl_secs = parse_env_u64("PQMSG_RATE_LIMIT_BUCKET_TTL_SECS", 600)?;
    let rate_limit_redis_url = env::var("PQMSG_RATE_LIMIT_REDIS_URL")
        .ok()
        .and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
    let rate_limit_redis_key_prefix = env::var("PQMSG_RATE_LIMIT_REDIS_KEY_PREFIX")
        .unwrap_or_else(|_| "pqmsg:ratelimit:".to_string());
    let mut dos_policy = DosHardeningPolicy::for_security_profile(security_profile);
    if let Some(bits) = parse_env_optional_u8("PQMSG_REGISTRATION_POW_BITS")? {
        dos_policy = dos_policy.with_registration_pow_bits(bits);
    }
    if let Some(interval) = parse_env_optional_i64("PQMSG_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS")? {
        dos_policy = dos_policy.with_prekey_publish_min_interval_seconds(interval);
    }
    if let Some(reserve) = parse_env_optional_i64("PQMSG_PREKEY_BUNDLE_RESERVE_COUNT")? {
        dos_policy = dos_policy.with_prekey_bundle_reserve_count(reserve);
    }
    let fcm_server_key = env::var("PQMSG_FCM_SERVER_KEY").ok();
    let fcm_endpoint = env::var("PQMSG_FCM_ENDPOINT")
        .unwrap_or_else(|_| "https://fcm.googleapis.com/fcm/send".to_string());
    let audit_log_path = env::var("PQMSG_AUDIT_LOG_PATH").ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
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

    let rate_limiter = if let Some(redis_url) = &rate_limit_redis_url {
        Arc::new(
            RateLimiter::with_redis(
                rate_limit_capacity,
                rate_limit_refill_per_second,
                rate_limit_max_entries,
                StdDuration::from_secs(rate_limit_bucket_ttl_secs),
                redis_url,
                Some(rate_limit_redis_key_prefix.clone()),
            )
            .with_context(|| {
                format!("failed to initialize redis rate limiter with url '{redis_url}'")
            })?,
        )
    } else {
        Arc::new(RateLimiter::new(
            rate_limit_capacity,
            rate_limit_refill_per_second,
            rate_limit_max_entries,
            StdDuration::from_secs(rate_limit_bucket_ttl_secs),
        ))
    };

    let push_notifier = Arc::new(PushNotifier::with_fcm(fcm_server_key, fcm_endpoint));
    let push_enabled = push_notifier.is_enabled();
    let audit_logger = if let Some(path) = &audit_log_path {
        Arc::new(
            AuditLogger::with_path(path)
                .with_context(|| format!("failed to initialize audit logger at '{path}'"))?,
        )
    } else {
        Arc::new(AuditLogger::disabled())
    };
    let audit_enabled = audit_logger.is_enabled();
    let state =
        AppState::with_security_profile(pool, db_backend, rate_limiter.clone(), security_profile)
            .with_dos_policy(dos_policy)
            .with_audit_logger(audit_logger)
            .with_push_notifier(push_notifier);
    let app = build_router(state);
    let rate_limiter_mode = if rate_limiter.is_distributed() {
        "redis"
    } else {
        "in_memory"
    };

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
                "pqmsg-server listening with TLS on {bind_addr} profile={} db_backend={} max_conn={} min_conn={} push_enabled={} audit_enabled={} limiter_mode={} registration_pow_bits={} prekey_publish_min_interval_seconds={} prekey_bundle_reserve_count={}",
                security_profile.as_str()
                ,
                db_backend.as_str(),
                db_max_connections,
                db_min_connections,
                push_enabled,
                audit_enabled,
                rate_limiter_mode,
                dos_policy.registration_pow_bits(),
                dos_policy.prekey_publish_min_interval_seconds(),
                dos_policy.prekey_bundle_reserve_count()
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
                "pqmsg-server listening without TLS on {bind_addr} profile={} db_backend={} max_conn={} min_conn={} push_enabled={} audit_enabled={} limiter_mode={} registration_pow_bits={} prekey_publish_min_interval_seconds={} prekey_bundle_reserve_count={}",
                security_profile.as_str(),
                db_backend.as_str(),
                db_max_connections,
                db_min_connections,
                push_enabled,
                audit_enabled,
                rate_limiter_mode,
                dos_policy.registration_pow_bits(),
                dos_policy.prekey_publish_min_interval_seconds(),
                dos_policy.prekey_bundle_reserve_count()
            );
            axum::serve(listener, app).await?;
        }
        _ => {
            anyhow::bail!("set both PQMSG_TLS_CERT_PATH and PQMSG_TLS_KEY_PATH, or neither");
        }
    }
    Ok(())
}
