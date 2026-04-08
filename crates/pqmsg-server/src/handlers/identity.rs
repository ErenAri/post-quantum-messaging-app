use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use pqmsg_core::alg::SecurityProfile;
use sqlx::{Any, Row};

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{AppState, DeploymentMode, PQ_SIG_PUB_KEY_LEN, SIG_PUB_KEY_LEN, X25519_KEY_LEN};

async fn delete_user_owned_state(
    tx: &mut sqlx::Transaction<'_, Any>,
    user_id: &str,
) -> Result<(), AppError> {
    for query in [
        "DELETE FROM ws_inbox_tickets WHERE user_id = $1",
        "DELETE FROM inbox_cursors WHERE user_id = $1",
        "DELETE FROM sealed_inbox_cursors WHERE user_id = $1",
        "DELETE FROM message_expiry_meta
         WHERE message_id IN (
            SELECT message_id
            FROM relay_messages
            WHERE recipient_user_id = $1 OR sender_user_id = $1
         )",
        "DELETE FROM message_receipts
         WHERE recipient_user_id = $1
            OR message_id IN (
                SELECT message_id
                FROM relay_messages
                WHERE recipient_user_id = $1 OR sender_user_id = $1
            )",
        "DELETE FROM sealed_relay_messages WHERE sender_user_id = $1",
        "DELETE FROM call_signals
         WHERE from_user_id = $1
            OR call_id IN (
                SELECT call_id
                FROM call_sessions
                WHERE caller_user_id = $1 OR callee_user_id = $1
            )",
        "DELETE FROM call_sessions WHERE caller_user_id = $1 OR callee_user_id = $1",
        "DELETE FROM story_views
         WHERE viewer_user_id = $1
            OR story_id IN (
                SELECT story_id
                FROM stories
                WHERE author_user_id = $1
            )",
        "DELETE FROM stories WHERE author_user_id = $1",
        "DELETE FROM channel_subscribers
         WHERE user_id = $1
            OR channel_id IN (
                SELECT channel_id
                FROM channels
                WHERE owner_user_id = $1
            )",
        "DELETE FROM channel_messages
         WHERE channel_id IN (
            SELECT channel_id
            FROM channels
            WHERE owner_user_id = $1
         )",
        "DELETE FROM channels WHERE owner_user_id = $1",
    ] {
        sqlx::query(query).bind(user_id).execute(&mut **tx).await?;
    }

    sqlx::query("DELETE FROM users WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;

    Ok(())
}

pub(crate) async fn register_user(
    State(state): State<AppState>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>, AppError> {
    check_rate_limit(&state, &format!("register:{}", request.user_id))?;
    validate_id("user_id", &request.user_id)?;
    validate_id("device_id", &request.device_id)?;
    enforce_registration_pow(&state, &request)?;

    let identity_x25519 = decode_base64_exact(
        "identity_x25519_pub",
        &request.identity_x25519_pub,
        X25519_KEY_LEN,
    )?;
    let identity_sig = decode_base64_range(
        "identity_sig_pub",
        &request.identity_sig_pub,
        SIG_PUB_KEY_LEN,
        SIG_PUB_KEY_LEN,
    )?;
    validate_ed25519_public_key(&identity_sig)?;
    let identity_pq_sig = decode_base64_exact(
        "identity_pq_sig_pub",
        &request.identity_pq_sig_pub,
        PQ_SIG_PUB_KEY_LEN,
    )?;
    validate_ml_dsa_public_key(&identity_pq_sig)?;

    let now = Utc::now().to_rfc3339();
    let sealed_delivery_token = generate_sealed_delivery_token();
    let insert_result = sqlx::query(
        "INSERT INTO users (
            user_id, identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id, sealed_delivery_token, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7)",
    )
    .bind(&request.user_id)
    .bind(&identity_x25519)
    .bind(&identity_sig)
    .bind(&identity_pq_sig)
    .bind(&request.device_id)
    .bind(&sealed_delivery_token)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_error)) if db_error.is_unique_violation() => {
            let existing = sqlx::query(
                "SELECT identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id, sealed_delivery_token, created_at
                 FROM users
                 WHERE user_id = $1",
            )
            .bind(&request.user_id)
            .fetch_optional(&state.pool)
            .await?;
            let Some(existing) = existing else {
                return Err(AppError::internal(
                    "unique constraint raced with missing user row",
                ));
            };

            let existing_identity_x25519: Vec<u8> = existing.try_get("identity_x25519_pub")?;
            let existing_identity_sig: Vec<u8> = existing.try_get("identity_sig_pub")?;
            let existing_identity_pq_sig: Option<Vec<u8>> =
                existing.try_get("identity_pq_sig_pub")?;
            let existing_device_id: String = existing.try_get("device_id")?;
            let existing_delivery_token: Option<Vec<u8>> =
                existing.try_get("sealed_delivery_token")?;
            let existing_created_at: String = existing.try_get("created_at")?;

            if existing_identity_x25519 != identity_x25519
                || existing_identity_sig != identity_sig
                || existing_device_id != request.device_id
                || existing_identity_pq_sig
                    .as_ref()
                    .is_some_and(|existing_key| existing_key != &identity_pq_sig)
            {
                return Err(AppError::conflict(
                    "user_id is already registered with an immutable identity",
                ));
            }

            if existing_identity_pq_sig.is_none() {
                sqlx::query(
                    "UPDATE users
                     SET identity_pq_sig_pub = $1, sealed_delivery_token = COALESCE(sealed_delivery_token, $2), updated_at = $3
                     WHERE user_id = $4 AND identity_pq_sig_pub IS NULL",
                )
                .bind(&identity_pq_sig)
                .bind(&sealed_delivery_token)
                .bind(&now)
                .bind(&request.user_id)
                .execute(&state.pool)
                .await?;
            } else if existing_delivery_token.is_none() {
                sqlx::query(
                    "UPDATE users
                     SET sealed_delivery_token = $1, updated_at = $2
                     WHERE user_id = $3 AND sealed_delivery_token IS NULL",
                )
                .bind(&sealed_delivery_token)
                .bind(&now)
                .bind(&request.user_id)
                .execute(&state.pool)
                .await?;
            }

            sqlx::query(
                "INSERT INTO user_devices (user_id, device_id, active, linked_at, revoked_at)
                 VALUES ($1, $2, 1, $3, NULL)
                 ON CONFLICT (user_id, device_id) DO UPDATE SET
                    active = 1,
                    revoked_at = NULL",
            )
            .bind(&request.user_id)
            .bind(&existing_device_id)
            .bind(&existing_created_at)
            .execute(&state.pool)
            .await?;

            return Ok(Json(RegisterUserResponse {
                user_id: request.user_id,
                device_id: existing_device_id,
                registered_at: existing_created_at,
            }));
        }
        Err(error) => return Err(error.into()),
    }

    sqlx::query(
        "INSERT INTO user_devices (user_id, device_id, active, linked_at, revoked_at)
         VALUES ($1, $2, 1, $3, NULL)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            active = 1,
            revoked_at = NULL",
    )
    .bind(&request.user_id)
    .bind(&request.device_id)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    sqlx::query(
        "INSERT INTO identity_events (
            user_id, version, identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id, event_type, changed_at
         ) VALUES ($1, 1, $2, $3, $4, $5, 'initial', $6)
         ON CONFLICT (user_id, version) DO NOTHING",
    )
    .bind(&request.user_id)
    .bind(&identity_x25519)
    .bind(&identity_sig)
    .bind(&identity_pq_sig)
    .bind(&request.device_id)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    record_security_event(
        &state,
        "user_registered",
        "success",
        None,
        Some(&request.user_id),
        Some(&request.device_id),
        None,
    );
    Ok(Json(RegisterUserResponse {
        user_id: request.user_id,
        device_id: request.device_id,
        registered_at: now,
    }))
}

pub(crate) async fn reset_dev_user_identity(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, AppError> {
    check_rate_limit(&state, &format!("dev-reset:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    if !matches!(state.deployment_mode(), DeploymentMode::Development)
        || !matches!(state.security_profile(), SecurityProfile::Research)
    {
        return Err(AppError::forbidden(
            "development-only user reset is disabled outside research development mode",
        ));
    }

    let mut tx = state.pool.begin().await?;
    delete_user_owned_state(&mut tx, &user_id).await?;

    tx.commit().await?;

    let _ = state.ephemeral_state().clear_presence(&user_id);

    record_security_event(
        &state,
        "dev_user_identity_reset",
        "success",
        None,
        Some(&user_id),
        None,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn delete_account(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DeleteAccountResponse>, AppError> {
    check_rate_limit(&state, &format!("account-delete:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = delete_account_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let deleted_at = Utc::now().to_rfc3339();
    let deleted_device_id = auth.device_id.clone();
    let mut tx = state.pool.begin().await?;
    delete_user_owned_state(&mut tx, &user_id).await?;
    tx.commit().await?;

    let _ = state.ephemeral_state().clear_presence(&user_id);

    record_security_event(
        &state,
        "account_deleted",
        "success",
        None,
        Some(&user_id),
        Some(&deleted_device_id),
        None,
    );

    Ok(Json(DeleteAccountResponse {
        user_id,
        deleted_device_id,
        deleted_at,
    }))
}

pub(crate) async fn list_devices(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DeviceListResponse>, AppError> {
    check_rate_limit(&state, &format!("devices-list:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = list_devices_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let rows = sqlx::query(
        "SELECT device_id, active, linked_at, revoked_at
         FROM user_devices
         WHERE user_id = $1
         ORDER BY linked_at ASC, device_id ASC",
    )
    .bind(&user_id)
    .fetch_all(state.pool())
    .await?;
    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let active: i64 = row.try_get("active")?;
        devices.push(DeviceRecord {
            device_id: row.try_get("device_id")?,
            active: active != 0,
            linked_at: row.try_get("linked_at")?,
            revoked_at: row.try_get("revoked_at")?,
        });
    }

    Ok(Json(DeviceListResponse { user_id, devices }))
}

pub(crate) async fn link_device(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<LinkDeviceRequest>,
) -> Result<Json<LinkDeviceResponse>, AppError> {
    check_rate_limit(&state, &format!("devices-link:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("new_device_id", &request.new_device_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    if auth.device_id == request.new_device_id {
        return Err(AppError::bad_request(
            "new_device_id must differ from authenticated device_id",
        ));
    }
    let auth_message = link_device_auth_message(&auth, &user_id, &request.new_device_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO user_devices (user_id, device_id, active, linked_at, revoked_at)
         VALUES ($1, $2, 1, $3, NULL)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            active = 1,
            revoked_at = NULL",
    )
    .bind(&user_id)
    .bind(&request.new_device_id)
    .bind(&now)
    .execute(state.pool())
    .await?;

    let linked_at: String = sqlx::query_scalar(
        "SELECT linked_at
         FROM user_devices
         WHERE user_id = $1 AND device_id = $2",
    )
    .bind(&user_id)
    .bind(&request.new_device_id)
    .fetch_one(state.pool())
    .await?;

    record_security_event(
        &state,
        "device_linked",
        "success",
        None,
        Some(&user_id),
        Some(&request.new_device_id),
        Some(format!("by_device={}", auth.device_id)),
    );
    Ok(Json(LinkDeviceResponse {
        user_id,
        linked_device_id: request.new_device_id,
        linked_at,
    }))
}

pub(crate) async fn revoke_device(
    State(state): State<AppState>,
    Path((user_id, target_device_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<RevokeDeviceResponse>, AppError> {
    check_rate_limit(&state, &format!("devices-revoke:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("target_device_id", &target_device_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    if auth.device_id == target_device_id {
        return Err(AppError::bad_request(
            "cannot revoke currently authenticated device",
        ));
    }
    let auth_message = revoke_device_auth_message(&auth, &user_id, &target_device_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let target_row = sqlx::query(
        "SELECT active
         FROM user_devices
         WHERE user_id = $1 AND device_id = $2",
    )
    .bind(&user_id)
    .bind(&target_device_id)
    .fetch_optional(state.pool())
    .await?;
    let Some(target_row) = target_row else {
        return Err(AppError::not_found("target device not found"));
    };
    let target_active: i64 = target_row.try_get("active")?;
    if target_active == 0 {
        return Err(AppError::conflict("target device is already revoked"));
    }

    let revoked_at = Utc::now().to_rfc3339();
    let mut tx = state.pool.begin().await?;
    let updated = retire_device_row(&mut tx, &user_id, &target_device_id, &revoked_at).await?;
    if updated.rows_affected() != 1 {
        return Err(AppError::conflict("target device is already revoked"));
    }

    update_user_primary_device_after_retire(&mut tx, &user_id, &target_device_id, &revoked_at)
        .await?;
    cleanup_retired_device_state(&mut tx, &user_id, &target_device_id).await?;

    tx.commit().await?;

    record_security_event(
        &state,
        "device_revoked",
        "success",
        None,
        Some(&user_id),
        Some(&target_device_id),
        Some(format!("by_device={}", auth.device_id)),
    );
    Ok(Json(RevokeDeviceResponse {
        user_id,
        revoked_device_id: target_device_id,
        revoked_at,
    }))
}

pub(crate) async fn retire_current_device(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RetireCurrentDeviceResponse>, AppError> {
    check_rate_limit(&state, &format!("devices-retire:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = retire_current_device_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let retired_at = Utc::now().to_rfc3339();
    let mut tx = state.pool.begin().await?;
    let updated = retire_device_row(&mut tx, &user_id, &auth.device_id, &retired_at).await?;
    if updated.rows_affected() != 1 {
        return Err(AppError::conflict("current device is already revoked"));
    }

    let remaining_active_devices =
        update_user_primary_device_after_retire(&mut tx, &user_id, &auth.device_id, &retired_at)
            .await?;
    cleanup_retired_device_state(&mut tx, &user_id, &auth.device_id).await?;
    tx.commit().await?;

    record_security_event(
        &state,
        "device_self_retired",
        "success",
        None,
        Some(&user_id),
        Some(&auth.device_id),
        None,
    );
    Ok(Json(RetireCurrentDeviceResponse {
        user_id,
        retired_device_id: auth.device_id,
        retired_at,
        remaining_active_devices,
    }))
}

async fn retire_device_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    user_id: &str,
    device_id: &str,
    retired_at: &str,
) -> Result<sqlx::any::AnyQueryResult, AppError> {
    sqlx::query(
        "UPDATE user_devices
         SET active = 0, revoked_at = $3
         WHERE user_id = $1 AND device_id = $2 AND active = 1",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(retired_at)
    .execute(&mut **tx)
    .await
    .map_err(Into::into)
}

async fn update_user_primary_device_after_retire(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    user_id: &str,
    retired_device_id: &str,
    retired_at: &str,
) -> Result<usize, AppError> {
    let remaining_device_rows = sqlx::query(
        "SELECT device_id
         FROM user_devices
         WHERE user_id = $1 AND active = 1
         ORDER BY linked_at ASC, device_id ASC",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await?;
    let remaining_active_devices = remaining_device_rows.len();

    sqlx::query(
        "UPDATE users
         SET updated_at = $1
         WHERE user_id = $2",
    )
    .bind(retired_at)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    if let Some(primary_row) = remaining_device_rows.first() {
        let replacement_device_id: String = primary_row.try_get("device_id")?;
        sqlx::query(
            "UPDATE users
             SET device_id = $1
             WHERE user_id = $2 AND device_id = $3",
        )
        .bind(&replacement_device_id)
        .bind(user_id)
        .bind(retired_device_id)
        .execute(&mut **tx)
        .await?;
    }

    Ok(remaining_active_devices)
}

async fn cleanup_retired_device_state(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    user_id: &str,
    device_id: &str,
) -> Result<(), AppError> {
    for statement in [
        "DELETE FROM prekeys WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM one_time_prekeys_x25519 WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM one_time_prekeys_mlkem768 WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM message_expiry_meta WHERE message_id IN (
            SELECT message_id
            FROM relay_messages
            WHERE recipient_user_id = $1 AND recipient_device_id = $2
         )",
        "DELETE FROM message_expiry_meta WHERE message_id IN (
            SELECT message_id
            FROM sealed_relay_messages
            WHERE recipient_user_id = $1 AND recipient_device_id = $2
         )",
        "DELETE FROM relay_messages WHERE recipient_user_id = $1 AND recipient_device_id = $2",
        "DELETE FROM sealed_relay_messages WHERE recipient_user_id = $1 AND recipient_device_id = $2",
        "DELETE FROM push_tokens WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM inbox_cursors WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM sealed_inbox_cursors WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM message_receipts WHERE recipient_user_id = $1 AND recipient_device_id = $2",
        "DELETE FROM presence_state WHERE user_id = $1 AND device_id = $2",
        "DELETE FROM typing_state WHERE sender_user_id = $1 AND sender_device_id = $2",
    ] {
        sqlx::query(statement)
            .bind(user_id)
            .bind(device_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}
