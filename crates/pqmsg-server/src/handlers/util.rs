use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{AnyPool, Row};
use tracing::warn;

use crate::error::AppError;
use crate::types::*;
use crate::{AppState, PushProvider, MAX_POW_NONCE_LEN, RELAY_DEDUP_TTL_SECONDS};

pub(crate) fn record_security_event(
    state: &AppState,
    event: &str,
    outcome: &str,
    request_id: Option<&str>,
    user_id: Option<&str>,
    device_id: Option<&str>,
    detail: Option<String>,
) {
    state.metrics().record_security_event(event);
    state.audit_logger().log_security_event(
        event,
        outcome,
        request_id,
        user_id,
        device_id,
        detail.as_deref(),
    );
}

/// Extract the originating client IP.
///
/// Proxy headers (`X-Forwarded-For`, `X-Real-IP`) are only trusted when the
/// request arrives from a known proxy address listed in `trusted_proxies`.
/// Otherwise the peer (socket) address is returned directly.
pub(crate) fn extract_client_ip(
    headers: &axum::http::HeaderMap,
    peer_addr: Option<std::net::IpAddr>,
    trusted_proxies: &[std::net::IpAddr],
) -> Option<String> {
    let peer_is_trusted = peer_addr
        .map(|addr| trusted_proxies.contains(&addr))
        .unwrap_or(false);

    if peer_is_trusted {
        if let Some(val) = headers.get("x-forwarded-for") {
            if let Ok(s) = val.to_str() {
                if let Some(first) = s.split(',').next() {
                    let ip = first.trim();
                    if !ip.is_empty() {
                        return Some(ip.to_owned());
                    }
                }
            }
        }
        if let Some(val) = headers.get("x-real-ip") {
            if let Ok(s) = val.to_str() {
                let ip = s.trim();
                if !ip.is_empty() {
                    return Some(ip.to_owned());
                }
            }
        }
    }

    peer_addr.map(|a| a.to_string())
}

pub(crate) fn check_rate_limit(state: &AppState, key: &str) -> Result<(), AppError> {
    if state.rate_limiter.allow(key) {
        Ok(())
    } else {
        record_security_event(
            state,
            "rate_limit_rejected",
            "reject",
            None,
            None,
            None,
            Some(format!("bucket={key}")),
        );
        Err(AppError::rate_limited("rate limit exceeded"))
    }
}

pub(crate) fn enforce_registration_pow(
    state: &AppState,
    request: &RegisterUserRequest,
) -> Result<(), AppError> {
    let bits = state.dos_policy().registration_pow_bits();
    if bits == 0 {
        return Ok(());
    }
    if bits > 32 {
        return Err(AppError::internal(
            "registration_pow_bits must be <= 32 for SHA-256 proof checks",
        ));
    }
    let nonce = request
        .pow_nonce
        .as_deref()
        .ok_or_else(|| AppError::bad_request("pow_nonce is required for registration"))?;
    validate_pow_nonce(nonce)?;
    let message = registration_pow_message(request, nonce);
    let digest = Sha256::digest(message);
    if !has_leading_zero_bits(&digest, bits) {
        return Err(AppError::bad_request("invalid registration proof-of-work"));
    }
    Ok(())
}

pub(crate) async fn enforce_prekey_publish_interval(
    state: &AppState,
    user_id: &str,
    device_id: &str,
) -> Result<(), AppError> {
    let min_interval = state.dos_policy().prekey_publish_min_interval_seconds();
    if min_interval <= 0 {
        return Ok(());
    }
    let last_updated = sqlx::query_scalar::<_, String>(
        "SELECT updated_at
         FROM prekeys
         WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(state.pool())
    .await?;
    let Some(last_updated) = last_updated else {
        return Ok(());
    };
    let parsed = DateTime::parse_from_rfc3339(&last_updated)
        .map_err(|_| AppError::internal("invalid prekeys.updated_at timestamp"))?
        .with_timezone(&Utc);
    let elapsed = Utc::now().signed_duration_since(parsed).num_seconds();
    if elapsed < min_interval {
        return Err(AppError::rate_limited(
            "prekey upload interval has not elapsed",
        ));
    }
    Ok(())
}

pub(crate) fn registration_pow_message(request: &RegisterUserRequest, nonce: &str) -> Vec<u8> {
    [
        b"register".as_slice(),
        request.user_id.as_bytes(),
        request.device_id.as_bytes(),
        request.identity_x25519_pub.as_bytes(),
        request.identity_sig_pub.as_bytes(),
        nonce.as_bytes(),
    ]
    .join(&[0u8][..])
}

pub(crate) fn validate_pow_nonce(value: &str) -> Result<(), AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_POW_NONCE_LEN {
        return Err(AppError::bad_request(format!(
            "pow_nonce must be 1..={MAX_POW_NONCE_LEN} characters"
        )));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AppError::bad_request(
            "pow_nonce must contain only [A-Za-z0-9_-]",
        ));
    }
    Ok(())
}

pub(crate) fn has_leading_zero_bits(bytes: &[u8], bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let full_bytes = usize::from(bits / 8);
    let remaining_bits = bits % 8;
    if bytes.len() < full_bytes {
        return false;
    }
    if bytes.iter().take(full_bytes).any(|byte| *byte != 0) {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    if bytes.len() <= full_bytes {
        return false;
    }
    let mask = 0xFFu8 << (8 - remaining_bits);
    bytes[full_bytes] & mask == 0
}

pub(crate) async fn observe_relay_dedup(
    state: &AppState,
    dedup_key: &str,
) -> Result<bool, AppError> {
    let now = Utc::now();
    let now_unix = now.timestamp();
    let now_rfc3339 = now.to_rfc3339();
    let expires_at_unix = now_unix + RELAY_DEDUP_TTL_SECONDS;
    sqlx::query("DELETE FROM relay_dedup WHERE expires_at_unix <= $1")
        .bind(now_unix)
        .execute(state.pool())
        .await?;
    let result = sqlx::query(
        "INSERT INTO relay_dedup (dedup_key, expires_at_unix, updated_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (dedup_key) DO UPDATE
         SET expires_at_unix = EXCLUDED.expires_at_unix,
             updated_at = EXCLUDED.updated_at
         WHERE relay_dedup.expires_at_unix <= $4",
    )
    .bind(dedup_key)
    .bind(expires_at_unix)
    .bind(now_rfc3339)
    .bind(now_unix)
    .execute(state.pool())
    .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn dispatch_push_wake_signals(
    state: &AppState,
    recipient_user_id: &str,
    excluded_device_id: &str,
) -> Result<(), String> {
    if !state.push_notifier().is_enabled() {
        return Ok(());
    }
    let rows = sqlx::query(
        "SELECT pt.provider, pt.token
         FROM push_tokens pt
         JOIN user_devices ud
           ON ud.user_id = pt.user_id
          AND ud.device_id = pt.device_id
         WHERE pt.user_id = $1
           AND ud.active = 1
           AND pt.device_id <> $2",
    )
    .bind(recipient_user_id)
    .bind(excluded_device_id)
    .fetch_all(state.pool())
    .await
    .map_err(|error| error.to_string())?;

    for row in rows {
        let provider_raw: String = row.try_get("provider").map_err(|error| error.to_string())?;
        let token: String = row.try_get("token").map_err(|error| error.to_string())?;
        let Some(provider) = PushProvider::parse(&provider_raw) else {
            warn!(
                "skipping unsupported push provider '{}' for user '{}'",
                provider_raw, recipient_user_id
            );
            continue;
        };
        let result = state
            .push_notifier()
            .send_wake_signal(provider, &token)
            .await;
        if let Err(ref e) = result {
            if e.contains("circuit breaker open") {
                let event = format!("{}_circuit_open", provider.as_str());
                record_security_event(
                    state,
                    &event,
                    "fail",
                    None,
                    Some(recipient_user_id),
                    None,
                    Some(e.clone()),
                );
            }
            return Err(result.unwrap_err());
        }
    }
    Ok(())
}

pub(crate) async fn select_one_time_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    table: &str,
    user_id: &str,
    device_id: &str,
) -> Result<Option<Vec<u8>>, AppError> {
    let query = format!(
        "SELECT id, prekey FROM {table}
         WHERE user_id = $1 AND device_id = $2 AND consumed = 0
         ORDER BY id ASC
         LIMIT 1"
    );
    let row = sqlx::query(&query)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let id: i64 = row.try_get("id")?;
    let key: Vec<u8> = row.try_get("prekey")?;
    let update = format!("UPDATE {table} SET consumed = 1 WHERE id = $1");
    sqlx::query(&update).bind(id).execute(&mut **tx).await?;
    Ok(Some(key))
}

pub(crate) async fn count_available_one_time_keys(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    table: &str,
    user_id: &str,
    device_id: &str,
) -> Result<i64, AppError> {
    let query = format!(
        "SELECT COUNT(*) AS count
         FROM {table}
         WHERE user_id = $1 AND device_id = $2 AND consumed = 0"
    );
    let count = sqlx::query_scalar::<_, i64>(&query)
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(count)
}

pub(crate) async fn load_remaining_one_time_counts(
    pool: &AnyPool,
    user_id: &str,
    device_id: &str,
) -> Result<(i64, i64), AppError> {
    let remaining_x = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) AS count
         FROM one_time_prekeys_x25519
         WHERE user_id = $1 AND device_id = $2 AND consumed = 0",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await?;
    let remaining_pq = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) AS count
         FROM one_time_prekeys_mlkem768
         WHERE user_id = $1 AND device_id = $2 AND consumed = 0",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(pool)
    .await?;
    Ok((remaining_x, remaining_pq))
}
