use anyhow::Context;
use axum_server::tls_rustls::RustlsConfig;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use pqmsg_core::alg::{enforce_runtime_security_profile, RuntimeCryptoProfile, SecurityProfile};
use pqmsg_server::{
    build_router, init_db, parse_db_backend, AppState, AuditLogger, AuthReplayCache, BlobStore,
    DbBackend, DeploymentMode, DosHardeningPolicy, EphemeralStateStore, PushNotifier, RateLimiter,
    RealtimeHub,
};
use sentry::ClientOptions;
use sqlx::any::AnyPoolOptions;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tower_http::timeout::TimeoutLayer;
use tracing::info;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

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

fn parse_env_optional_f64(name: &str) -> anyhow::Result<Option<f64>> {
    match env::var(name) {
        Ok(value) => value
            .parse::<f64>()
            .with_context(|| format!("invalid {name}='{value}': expected floating-point number"))
            .map(Some),
        Err(_) => Ok(None),
    }
}

fn load_sender_certificate_signing_key(
    deployment_mode: DeploymentMode,
) -> anyhow::Result<Arc<SigningKey>> {
    match env::var("PQMSG_SENDER_CERT_SIGNING_KEY") {
        Ok(value) => {
            let key_bytes = B64.decode(value.trim()).with_context(|| {
                "invalid PQMSG_SENDER_CERT_SIGNING_KEY: expected base64-encoded 32-byte seed"
            })?;
            let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
                anyhow::anyhow!(
                    "invalid PQMSG_SENDER_CERT_SIGNING_KEY: expected base64-encoded 32-byte seed"
                )
            })?;
            Ok(Arc::new(SigningKey::from_bytes(&key_bytes)))
        }
        Err(_) if deployment_mode.requires_production_baseline() => {
            anyhow::bail!("PQMSG_SENDER_CERT_SIGNING_KEY is required outside development mode")
        }
        Err(_) => Ok(Arc::new(SigningKey::from_bytes(&[0x53; 32]))),
    }
}

struct DeploymentContract {
    deployment_mode: DeploymentMode,
    security_profile: SecurityProfile,
    runtime_crypto_profile: RuntimeCryptoProfile,
    db_backend: DbBackend,
    tls_enabled: bool,
    audit_enabled: bool,
    redis_enabled: bool,
    structured_logging: bool,
}

fn enforce_deployment_contract(contract: DeploymentContract) -> anyhow::Result<()> {
    if !contract.deployment_mode.requires_production_baseline() {
        return Ok(());
    }
    if matches!(contract.security_profile, SecurityProfile::Research) {
        anyhow::bail!(
            "PQMSG_DEPLOYMENT_MODE='{}' requires PQMSG_SECURITY_PROFILE to be 'high_assurance' or 'nss_aligned'",
            contract.deployment_mode.as_str()
        );
    }
    if contract.db_backend != DbBackend::Postgres {
        anyhow::bail!(
            "PQMSG_DEPLOYMENT_MODE='{}' requires PostgreSQL (set PQMSG_DATABASE_URL=postgres://...)",
            contract.deployment_mode.as_str()
        );
    }
    if !contract.tls_enabled {
        anyhow::bail!(
            "PQMSG_DEPLOYMENT_MODE='{}' requires TLS (set PQMSG_TLS_CERT_PATH and PQMSG_TLS_KEY_PATH)",
            contract.deployment_mode.as_str()
        );
    }
    if !contract.audit_enabled {
        anyhow::bail!(
            "PQMSG_DEPLOYMENT_MODE='{}' requires audit logging (set PQMSG_AUDIT_LOG_PATH)",
            contract.deployment_mode.as_str()
        );
    }
    if !contract.redis_enabled {
        anyhow::bail!(
            "PQMSG_DEPLOYMENT_MODE='{}' requires Redis-backed distributed rate limiting, replay protection, and realtime fanout (set PQMSG_RATE_LIMIT_REDIS_URL)",
            contract.deployment_mode.as_str()
        );
    }
    if !contract.structured_logging {
        anyhow::bail!(
            "PQMSG_DEPLOYMENT_MODE='{}' requires structured JSON logs (set PQMSG_LOG_FORMAT=json)",
            contract.deployment_mode.as_str()
        );
    }
    if !contract.runtime_crypto_profile.pq_oqs_enabled {
        anyhow::bail!(
            "PQMSG_DEPLOYMENT_MODE='{}' requires a PQ-enabled runtime (build with pqmsg-core/pq-oqs support)",
            contract.deployment_mode.as_str()
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    let profile_raw =
        env::var("PQMSG_SECURITY_PROFILE").unwrap_or_else(|_| "high_assurance".to_string());
    let security_profile = SecurityProfile::parse(&profile_raw)
        .with_context(|| format!("invalid PQMSG_SECURITY_PROFILE '{profile_raw}'"))?;
    let deployment_mode_raw =
        env::var("PQMSG_DEPLOYMENT_MODE").unwrap_or_else(|_| "development".to_string());
    let deployment_mode = DeploymentMode::parse(&deployment_mode_raw)
        .map_err(|_| anyhow::anyhow!("invalid PQMSG_DEPLOYMENT_MODE '{deployment_mode_raw}'"))?;
    let runtime_crypto_profile = enforce_runtime_security_profile(security_profile, None)
        .with_context(|| {
            format!(
                "compiled runtime crypto backend is incompatible with security profile '{}'",
                security_profile.as_str()
            )
        })?;
    let sentry_dsn = env::var("PQMSG_SENTRY_DSN").ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let sentry_traces_sample_rate = parse_env_optional_f64("PQMSG_SENTRY_TRACES_SAMPLE_RATE")?
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    let sentry_guard = sentry_dsn.as_deref().map(|dsn| {
        sentry::init((
            dsn,
            ClientOptions {
                release: sentry::release_name!(),
                environment: Some(security_profile.as_str().to_string().into()),
                traces_sample_rate: sentry_traces_sample_rate as f32,
                attach_stacktrace: true,
                ..Default::default()
            },
        ))
    });
    let sentry_enabled = sentry_guard.is_some();
    let log_filter = env::var("RUST_LOG").unwrap_or_else(|_| "pqmsg_server=info".to_string());
    let log_format = env::var("PQMSG_LOG_FORMAT").unwrap_or_else(|_| "json".to_string());

    // Optional OpenTelemetry OTLP exporter
    let otlp_endpoint = env::var("PQMSG_OTLP_ENDPOINT").ok().and_then(|v| {
        let trimmed = v.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });
    let otel_provider = if let Some(endpoint) = &otlp_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .with_context(|| format!("failed to create OTLP exporter for '{endpoint}'"))?;
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_service_name("pqmsg-server")
                    .build(),
            )
            .build();
        Some(provider)
    } else {
        None
    };

    let pretty = log_format.trim().eq_ignore_ascii_case("pretty");
    let structured_logging = !pretty;

    if pretty {
        let reg = tracing_subscriber::registry()
            .with(EnvFilter::new(log_filter))
            .with(tracing_subscriber::fmt::layer().with_target(true));
        if sentry_enabled {
            if let Some(ref provider) = otel_provider {
                reg.with(sentry_tracing::layer())
                    .with(
                        tracing_opentelemetry::layer().with_tracer(provider.tracer("pqmsg-server")),
                    )
                    .init();
            } else {
                reg.with(sentry_tracing::layer()).init();
            }
        } else if let Some(ref provider) = otel_provider {
            reg.with(tracing_opentelemetry::layer().with_tracer(provider.tracer("pqmsg-server")))
                .init();
        } else {
            reg.init();
        }
    } else {
        let reg = tracing_subscriber::registry()
            .with(EnvFilter::new(log_filter))
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_span_list(false),
            );
        if sentry_enabled {
            if let Some(ref provider) = otel_provider {
                reg.with(sentry_tracing::layer())
                    .with(
                        tracing_opentelemetry::layer().with_tracer(provider.tracer("pqmsg-server")),
                    )
                    .init();
            } else {
                reg.with(sentry_tracing::layer()).init();
            }
        } else if let Some(ref provider) = otel_provider {
            reg.with(tracing_opentelemetry::layer().with_tracer(provider.tracer("pqmsg-server")))
                .init();
        } else {
            reg.init();
        }
    }

    let bind_addr = env::var("PQMSG_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let database_url =
        env::var("PQMSG_DATABASE_URL").unwrap_or_else(|_| "sqlite://pqmsg-server.db".to_string());
    let blob_store_dir =
        env::var("PQMSG_BLOB_STORE_DIR").unwrap_or_else(|_| "./pqmsg-blob-store".to_string());
    let db_backend = parse_db_backend(&database_url)
        .map_err(|message| anyhow::anyhow!("{message} (check PQMSG_DATABASE_URL)"))?;
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
    let ephemeral_redis_key_prefix = env::var("PQMSG_EPHEMERAL_REDIS_KEY_PREFIX")
        .unwrap_or_else(|_| "pqmsg:ephemeral:".to_string());
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
    if let Some(interval) = parse_env_optional_i64("PQMSG_PQ_RATCHET_INTERVAL")? {
        let interval = u32::try_from(interval).with_context(|| {
            format!("invalid PQMSG_PQ_RATCHET_INTERVAL '{interval}': must be 0..4294967295")
        })?;
        dos_policy = dos_policy.with_pq_ratchet_interval(interval);
    }
    let fcm_server_key = env::var("PQMSG_FCM_SERVER_KEY").ok();
    let fcm_endpoint = env::var("PQMSG_FCM_ENDPOINT")
        .unwrap_or_else(|_| "https://fcm.googleapis.com/fcm/send".to_string());
    let apns_bearer_token = env::var("PQMSG_APNS_BEARER_TOKEN").ok();
    let apns_topic = env::var("PQMSG_APNS_TOPIC").ok();
    let apns_endpoint = env::var("PQMSG_APNS_ENDPOINT")
        .unwrap_or_else(|_| "https://api.push.apple.com".to_string());
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
    let tls_enabled = tls_cert_path.is_some() && tls_key_path.is_some();

    let pool = AnyPoolOptions::new()
        .max_connections(db_max_connections)
        .min_connections(db_min_connections)
        .acquire_timeout(StdDuration::from_secs(db_acquire_timeout_secs))
        .idle_timeout(Some(StdDuration::from_secs(db_idle_timeout_secs)))
        .connect(&database_url)
        .await
        .with_context(|| "failed to connect to database (check PQMSG_DATABASE_URL)")?;
    let skip_auto_migrate = env::var("PQMSG_SKIP_AUTO_MIGRATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if skip_auto_migrate {
        info!("auto-migration skipped (PQMSG_SKIP_AUTO_MIGRATE=true)");
    } else {
        init_db(&pool, db_backend).await?;
        info!("database migrations applied successfully");
    }

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

    let push_notifier = Arc::new(PushNotifier::with_providers(
        fcm_server_key,
        fcm_endpoint,
        apns_bearer_token,
        apns_topic,
        apns_endpoint,
    ));
    let push_enabled = push_notifier.is_enabled();
    let push_providers = push_notifier.enabled_providers();
    let audit_logger = if let Some(path) = &audit_log_path {
        let max_bytes = parse_env_u64("PQMSG_AUDIT_LOG_MAX_BYTES", 50 * 1024 * 1024)?;
        let max_files = parse_env_u32("PQMSG_AUDIT_LOG_MAX_FILES", 5)?;
        Arc::new(
            AuditLogger::with_path_and_rotation(path, max_bytes, max_files)
                .with_context(|| format!("failed to initialize audit logger at '{path}'"))?,
        )
    } else {
        Arc::new(AuditLogger::disabled())
    };
    let audit_enabled = audit_logger.is_enabled();
    if security_profile.requires_tls() && !audit_enabled {
        anyhow::bail!(
            "PQMSG_AUDIT_LOG_PATH is required for {} profile. \
             Set the environment variable to enable mandatory audit logging.",
            security_profile.as_str()
        );
    }
    let auth_replay = if let Some(redis_url) = &rate_limit_redis_url {
        Arc::new(
            AuthReplayCache::with_redis(
                100_000,
                StdDuration::from_secs(600),
                redis_url,
                rate_limit_redis_key_prefix.clone(),
            )
            .with_context(|| {
                format!("failed to initialize redis replay cache with url '{redis_url}'")
            })?,
        )
    } else {
        Arc::new(AuthReplayCache::new(100_000, StdDuration::from_secs(600)))
    };
    let cors_allowed_origins: Vec<String> = env::var("PQMSG_CORS_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let trusted_proxies: Vec<std::net::IpAddr> =
        env::var("PQMSG_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.parse::<std::net::IpAddr>().with_context(|| {
                        format!("invalid IP in PQMSG_TRUSTED_PROXIES: '{trimmed}'")
                    }))
                }
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
    let runtime_suite_id = runtime_crypto_profile.suite_id;
    let runtime_pq_enabled = runtime_crypto_profile.pq_oqs_enabled;
    enforce_deployment_contract(DeploymentContract {
        deployment_mode,
        security_profile,
        runtime_crypto_profile: runtime_crypto_profile.clone(),
        db_backend,
        tls_enabled,
        audit_enabled,
        redis_enabled: rate_limit_redis_url.is_some(),
        structured_logging,
    })?;
    let realtime_hub = if let Some(redis_url) = &rate_limit_redis_url {
        let client = redis::Client::open(redis_url.as_str()).with_context(|| {
            format!("failed to create redis client for realtime hub: '{redis_url}'")
        })?;
        let hub = RealtimeHub::with_redis(client);
        hub.spawn_redis_subscriber();
        hub
    } else {
        RealtimeHub::new()
    };
    let blob_store = Arc::new(
        BlobStore::local_fs(&blob_store_dir)
            .with_context(|| format!("failed to initialize blob store at '{blob_store_dir}'"))?,
    );
    let ephemeral_state = Arc::new(if let Some(redis_url) = &rate_limit_redis_url {
        EphemeralStateStore::with_redis(redis_url, ephemeral_redis_key_prefix.clone())
            .with_context(|| {
                format!("failed to initialize redis ephemeral state with url '{redis_url}'")
            })?
    } else {
        EphemeralStateStore::disabled()
    });
    let sender_certificate_signing_key = load_sender_certificate_signing_key(deployment_mode)?;
    let state =
        AppState::with_security_profile(pool, db_backend, rate_limiter.clone(), security_profile)
            .with_deployment_mode(deployment_mode)
            .with_runtime_crypto_profile(runtime_crypto_profile)
            .with_transport_security(tls_enabled)
            .with_structured_logging(structured_logging)
            .with_dos_policy(dos_policy)
            .with_audit_logger(audit_logger)
            .with_push_notifier(push_notifier)
            .with_auth_replay(auth_replay)
            .with_cors_allowed_origins(cors_allowed_origins)
            .with_trusted_proxies(trusted_proxies)
            .with_realtime_hub(realtime_hub)
            .with_blob_store(blob_store)
            .with_ephemeral_state(ephemeral_state)
            .with_sender_certificate_signing_key(sender_certificate_signing_key);

    // Spawn the ephemeral message expiry reaper
    tokio::spawn(pqmsg_server::run_message_expiry_reaper(state.clone()));

    let app = build_router(state).layer(TimeoutLayer::with_status_code(
        axum::http::StatusCode::REQUEST_TIMEOUT,
        StdDuration::from_secs(30),
    ));
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
                "pqmsg-server listening with TLS on {bind_addr} deployment_mode={} profile={} db_backend={} runtime_suite_id={} pq_enabled={} max_conn={} min_conn={} push_enabled={} audit_enabled={} limiter_mode={} registration_pow_bits={} prekey_publish_min_interval_seconds={} prekey_bundle_reserve_count={} pq_ratchet_interval={} sentry_enabled={}",
                deployment_mode.as_str(),
                security_profile.as_str(),
                db_backend.as_str(),
                runtime_suite_id,
                runtime_pq_enabled,
                db_max_connections,
                db_min_connections,
                push_enabled,
                audit_enabled,
                rate_limiter_mode,
                dos_policy.registration_pow_bits(),
                dos_policy.prekey_publish_min_interval_seconds(),
                dos_policy.prekey_bundle_reserve_count(),
                dos_policy.pq_ratchet_interval(),
                sentry_enabled
            );
            info!("enabled_push_providers={}", push_providers.join(","));
            let handle = axum_server::Handle::new();
            let shutdown_handle = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                info!("graceful shutdown initiated, draining connections...");
                shutdown_handle.graceful_shutdown(Some(StdDuration::from_secs(30)));
            });
            axum_server::bind_rustls(bind_addr.parse()?, tls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
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
                "pqmsg-server listening without TLS on {bind_addr} deployment_mode={} profile={} db_backend={} runtime_suite_id={} pq_enabled={} max_conn={} min_conn={} push_enabled={} audit_enabled={} limiter_mode={} registration_pow_bits={} prekey_publish_min_interval_seconds={} prekey_bundle_reserve_count={} pq_ratchet_interval={} sentry_enabled={}",
                deployment_mode.as_str(),
                security_profile.as_str(),
                db_backend.as_str(),
                runtime_suite_id,
                runtime_pq_enabled,
                db_max_connections,
                db_min_connections,
                push_enabled,
                audit_enabled,
                rate_limiter_mode,
                dos_policy.registration_pow_bits(),
                dos_policy.prekey_publish_min_interval_seconds(),
                dos_policy.prekey_bundle_reserve_count(),
                dos_policy.pq_ratchet_interval(),
                sentry_enabled
            );
            info!("enabled_push_providers={}", push_providers.join(","));
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        }
        _ => {
            anyhow::bail!("set both PQMSG_TLS_CERT_PATH and PQMSG_TLS_KEY_PATH, or neither");
        }
    }
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
            .expect("failed to install SIGTERM handler")
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

#[cfg(test)]
mod tests {
    use super::{enforce_deployment_contract, DeploymentContract};
    use pqmsg_core::alg::runtime_crypto_profile;
    use pqmsg_core::alg::SecurityProfile;
    use pqmsg_server::{DbBackend, DeploymentMode};

    #[test]
    fn development_mode_allows_local_defaults() {
        let runtime = runtime_crypto_profile().expect("runtime profile");
        enforce_deployment_contract(DeploymentContract {
            deployment_mode: DeploymentMode::Development,
            security_profile: SecurityProfile::Research,
            runtime_crypto_profile: runtime,
            db_backend: DbBackend::Sqlite,
            tls_enabled: false,
            audit_enabled: false,
            redis_enabled: false,
            structured_logging: false,
        })
        .expect("development should remain permissive");
    }

    #[test]
    fn pilot_requires_hardened_profile() {
        let runtime = runtime_crypto_profile().expect("runtime profile");
        let error = enforce_deployment_contract(DeploymentContract {
            deployment_mode: DeploymentMode::Pilot,
            security_profile: SecurityProfile::Research,
            runtime_crypto_profile: runtime,
            db_backend: DbBackend::Postgres,
            tls_enabled: true,
            audit_enabled: true,
            redis_enabled: true,
            structured_logging: true,
        })
        .expect_err("pilot should reject research profile");
        assert!(error
            .to_string()
            .contains("requires PQMSG_SECURITY_PROFILE to be 'high_assurance' or 'nss_aligned'"));
    }

    #[test]
    fn pilot_requires_postgres() {
        let runtime = runtime_crypto_profile().expect("runtime profile");
        let error = enforce_deployment_contract(DeploymentContract {
            deployment_mode: DeploymentMode::Pilot,
            security_profile: SecurityProfile::HighAssurance,
            runtime_crypto_profile: runtime,
            db_backend: DbBackend::Sqlite,
            tls_enabled: true,
            audit_enabled: true,
            redis_enabled: true,
            structured_logging: true,
        })
        .expect_err("pilot should reject sqlite");
        assert!(error.to_string().contains("requires PostgreSQL"));
    }

    #[test]
    fn production_requires_redis() {
        let runtime = runtime_crypto_profile().expect("runtime profile");
        let error = enforce_deployment_contract(DeploymentContract {
            deployment_mode: DeploymentMode::Production,
            security_profile: SecurityProfile::HighAssurance,
            runtime_crypto_profile: runtime,
            db_backend: DbBackend::Postgres,
            tls_enabled: true,
            audit_enabled: true,
            redis_enabled: false,
            structured_logging: true,
        })
        .expect_err("production should reject local redis-free mode");
        assert!(error
            .to_string()
            .contains("requires Redis-backed distributed"));
    }

    #[test]
    fn production_accepts_hardened_stack() {
        let runtime = runtime_crypto_profile().expect("runtime profile");
        if runtime.pq_oqs_enabled {
            enforce_deployment_contract(DeploymentContract {
                deployment_mode: DeploymentMode::Production,
                security_profile: SecurityProfile::HighAssurance,
                runtime_crypto_profile: runtime,
                db_backend: DbBackend::Postgres,
                tls_enabled: true,
                audit_enabled: true,
                redis_enabled: true,
                structured_logging: true,
            })
            .expect("production baseline should accept hardened stack");
        }
    }
}
