use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{AppState, MAX_MESSAGE_BYTES};

const MAX_TTL_SECONDS: u64 = 7 * 24 * 3600; // 1 week

pub(crate) async fn relay_ephemeral_message(
    State(state): State<AppState>,
    Path(recipient_user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RelayEphemeralRequest>,
) -> Result<Json<RelayResponse>, AppError> {
    check_rate_limit(&state, &format!("ephemeral-relay:{recipient_user_id}"))?;
    validate_id("recipient_user_id", &recipient_user_id)?;
    validate_id("sender_user_id", &request.sender_user_id)?;
    validate_id("device_id", &request.device_id)?;

    if request.ttl_seconds == 0 || request.ttl_seconds > MAX_TTL_SECONDS {
        return Err(AppError::bad_request(format!(
            "ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
        )));
    }

    let blob = decode_base64_range(
        "message_bytes_base64",
        &request.message_bytes_base64,
        1,
        MAX_MESSAGE_BYTES,
    )?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.sender_user_id {
        return Err(AppError::bad_request(
            "auth user_id must match sender_user_id",
        ));
    }
    if auth.device_id != request.device_id {
        return Err(AppError::bad_request(
            "auth device_id must match request device_id",
        ));
    }
    let auth_message = format!(
        "ephemeral-relay:{}:{}:{}:{}",
        auth.user_id, auth.device_id, recipient_user_id, request.ttl_seconds
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Dedup
    let mut dedup_hasher = Sha256::new();
    dedup_hasher.update(b"ephemeral:");
    dedup_hasher.update(request.sender_user_id.as_bytes());
    dedup_hasher.update(b":");
    dedup_hasher.update(recipient_user_id.as_bytes());
    dedup_hasher.update(b":");
    dedup_hasher.update(&blob);
    let dedup_key = hex::encode(dedup_hasher.finalize());
    if !observe_relay_dedup(&state, &dedup_key).await? {
        return Err(AppError::conflict("duplicate ephemeral message detected"));
    }

    ensure_user_exists(&state.pool, &recipient_user_id).await?;
    ensure_user_exists(&state.pool, &request.sender_user_id).await?;
    let recipient_devices = load_active_device_ids(state.pool(), &recipient_user_id).await?;
    if recipient_devices.is_empty() {
        return Err(AppError::not_found(
            "recipient has no active linked devices",
        ));
    }

    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let expires_at = (now + Duration::seconds(request.ttl_seconds as i64)).to_rfc3339();

    let mut tx = state.pool.begin().await?;
    let mut first_message_id: Option<i64> = None;
    let mut device_count = 0usize;
    for recipient_device_id in &recipient_devices {
        let message_id: i64 = sqlx::query_scalar(
            "INSERT INTO relay_messages (
                recipient_user_id,
                recipient_device_id,
                sender_user_id,
                device_id,
                message_blob,
                received_at
             ) VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING message_id",
        )
        .bind(&recipient_user_id)
        .bind(recipient_device_id)
        .bind(&request.sender_user_id)
        .bind(&request.device_id)
        .bind(&blob)
        .bind(&now_str)
        .fetch_one(&mut *tx)
        .await?;

        // Record expiry metadata
        sqlx::query(
            "INSERT INTO message_expiry_meta (message_id, recipient_device_id, expires_at)
             VALUES ($1, $2, $3)",
        )
        .bind(message_id)
        .bind(recipient_device_id)
        .bind(&expires_at)
        .execute(&mut *tx)
        .await?;

        if first_message_id.is_none() {
            first_message_id = Some(message_id);
        }
        device_count += 1;
    }
    tx.commit().await?;

    // Push wake
    let push_state = state.clone();
    let push_recipient = recipient_user_id.clone();
    let push_excluded = if request.sender_user_id == recipient_user_id {
        request.device_id.clone()
    } else {
        String::new()
    };
    tokio::spawn(async move {
        if let Err(e) =
            dispatch_push_wake_signals(&push_state, &push_recipient, &push_excluded).await
        {
            tracing::warn!("ephemeral push wake dispatch failed reason={}", e);
        }
    });

    Ok(Json(RelayResponse {
        message_id: first_message_id.unwrap_or(0),
        delivered_device_count: device_count,
        received_at: now_str,
    }))
}

/// Background task to delete expired ephemeral messages and stale data.
/// Should be spawned once at startup.
pub async fn run_message_expiry_reaper(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Err(e) = reap_expired_messages(&state).await {
            tracing::warn!("message expiry reaper error: {e:?}");
        }
        if let Err(e) = reap_stale_data(&state).await {
            tracing::warn!("stale data reaper error: {e:?}");
        }
    }
}

async fn reap_expired_messages(state: &AppState) -> Result<(), crate::error::AppError> {
    let now = Utc::now().to_rfc3339();
    // Delete expired messages in batch
    let result = sqlx::query(
        "DELETE FROM relay_messages WHERE message_id IN (
            SELECT message_id FROM message_expiry_meta WHERE expires_at <= $1
        )",
    )
    .bind(&now)
    .execute(state.pool())
    .await?;

    let deleted = result.rows_affected();
    if deleted > 0 {
        // Clean up expiry metadata
        sqlx::query("DELETE FROM message_expiry_meta WHERE expires_at <= $1")
            .bind(&now)
            .execute(state.pool())
            .await?;
        tracing::info!("message expiry reaper deleted {deleted} expired messages");
    }
    Ok(())
}

/// Clean up stale data: expired dedup entries, consumed one-time prekeys,
/// expired identity rotation challenges, and old delivered relay messages.
async fn reap_stale_data(state: &AppState) -> Result<(), crate::error::AppError> {
    let now_unix = Utc::now().timestamp();

    // 1. Expired relay_dedup entries
    let dedup_deleted = sqlx::query("DELETE FROM relay_dedup WHERE expires_at_unix <= $1")
        .bind(now_unix)
        .execute(state.pool())
        .await?
        .rows_affected();

    // 2. Consumed one-time prekeys from the live post-migration tables.
    let otk_x_deleted = sqlx::query("DELETE FROM one_time_prekeys_x25519 WHERE consumed = 1")
        .execute(state.pool())
        .await?
        .rows_affected();

    let otk_pq_deleted = sqlx::query("DELETE FROM one_time_prekeys_mlkem768 WHERE consumed = 1")
        .execute(state.pool())
        .await?
        .rows_affected();

    // 3. Expired identity rotation challenges (older than 10 minutes)
    let challenge_cutoff = (Utc::now() - Duration::seconds(600)).to_rfc3339();
    let challenge_deleted =
        sqlx::query("DELETE FROM identity_rotation_challenges WHERE created_at < $1")
            .bind(&challenge_cutoff)
            .execute(state.pool())
            .await?
            .rows_affected();

    let total = dedup_deleted + otk_x_deleted + otk_pq_deleted + challenge_deleted;
    if total > 0 {
        tracing::info!(
            dedup = dedup_deleted,
            consumed_otk_x25519 = otk_x_deleted,
            consumed_otk_mlkem = otk_pq_deleted,
            expired_challenges = challenge_deleted,
            "stale data reaper cleanup"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::reap_stale_data;
    use crate::db::{init_db, parse_db_backend};
    use crate::{AppState, RateLimiter};
    use sqlx::any::AnyPoolOptions;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    #[tokio::test]
    async fn stale_data_reaper_targets_live_one_time_prekey_tables() {
        sqlx::any::install_default_drivers();
        let database_url = "sqlite::memory:";
        let db_backend = parse_db_backend(database_url).expect("sqlite backend");
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await
            .expect("connect sqlite memory");
        init_db(&pool, db_backend).await.expect("migrate");

        let rate_limiter = Arc::new(RateLimiter::new(8.0, 1.0, 64, StdDuration::from_secs(60)));
        let state = AppState::new(pool.clone(), db_backend, rate_limiter);

        sqlx::query(
            "INSERT INTO users (
                user_id,
                identity_x25519_pub,
                identity_sig_pub,
                device_id,
                created_at,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind("alice")
        .bind(vec![1_u8; 32])
        .bind(vec![2_u8; 32])
        .bind("alice-dev-1")
        .bind("2026-01-01T00:00:00Z")
        .bind("2026-01-01T00:00:00Z")
        .execute(&pool)
        .await
        .expect("insert user");

        sqlx::query(
            "INSERT INTO one_time_prekeys_x25519 (
                user_id,
                device_id,
                prekey,
                consumed,
                created_at
            ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind("alice")
        .bind("alice-dev-1")
        .bind(vec![3_u8; 32])
        .bind(1_i64)
        .bind("2026-01-01T00:00:00Z")
        .execute(&pool)
        .await
        .expect("insert consumed x25519 otk");

        sqlx::query(
            "INSERT INTO one_time_prekeys_mlkem768 (
                user_id,
                device_id,
                prekey,
                consumed,
                created_at
            ) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind("alice")
        .bind("alice-dev-1")
        .bind(vec![4_u8; 32])
        .bind(1_i64)
        .bind("2026-01-01T00:00:00Z")
        .execute(&pool)
        .await
        .expect("insert consumed mlkem otk");

        reap_stale_data(&state).await.expect("reap stale data");

        let remaining_x25519: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys_x25519")
                .fetch_one(&pool)
                .await
                .expect("count x25519 otks");
        let remaining_mlkem: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys_mlkem768")
                .fetch_one(&pool)
                .await
                .expect("count mlkem otks");

        assert_eq!(remaining_x25519, 0);
        assert_eq!(remaining_mlkem, 0);
    }
}
