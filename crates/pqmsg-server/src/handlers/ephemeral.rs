use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{AppState, MAX_MESSAGE_BYTES};
use super::util::*;

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
        return Err(AppError::bad_request("auth user_id must match sender_user_id"));
    }
    if auth.device_id != request.device_id {
        return Err(AppError::bad_request("auth device_id must match request device_id"));
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
        return Err(AppError::not_found("recipient has no active linked devices"));
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
        if let Err(e) = dispatch_push_wake_signals(&push_state, &push_recipient, &push_excluded).await {
            tracing::warn!("ephemeral push wake dispatch failed reason={}", e);
        }
    });

    Ok(Json(RelayResponse {
        message_id: first_message_id.unwrap_or(0),
        delivered_device_count: device_count,
        received_at: now_str,
    }))
}

/// Background task to delete expired ephemeral messages.
/// Should be spawned once at startup.
pub async fn run_message_expiry_reaper(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Err(e) = reap_expired_messages(&state).await {
            tracing::warn!("message expiry reaper error: {e:?}");
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
