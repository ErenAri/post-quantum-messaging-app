use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use sqlx::Row;

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{AppState, SIG_PUB_KEY_LEN, X25519_KEY_LEN};

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

    let now = Utc::now().to_rfc3339();
    let insert_result = sqlx::query(
        "INSERT INTO users (user_id, identity_x25519_pub, identity_sig_pub, device_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $5)",
    )
    .bind(&request.user_id)
    .bind(&identity_x25519)
    .bind(&identity_sig)
    .bind(&request.device_id)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_error)) if db_error.is_unique_violation() => {
            let existing = sqlx::query(
                "SELECT identity_x25519_pub, identity_sig_pub, device_id, created_at
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
            let existing_device_id: String = existing.try_get("device_id")?;
            let existing_created_at: String = existing.try_get("created_at")?;

            if existing_identity_x25519 != identity_x25519
                || existing_identity_sig != identity_sig
                || existing_device_id != request.device_id
            {
                return Err(AppError::conflict(
                    "user_id is already registered with an immutable identity",
                ));
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
            user_id, version, identity_x25519_pub, identity_sig_pub, device_id, event_type, changed_at
         ) VALUES ($1, 1, $2, $3, $4, 'initial', $5)
         ON CONFLICT (user_id, version) DO NOTHING",
    )
    .bind(&request.user_id)
    .bind(&identity_x25519)
    .bind(&identity_sig)
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
    let updated = sqlx::query(
        "UPDATE user_devices
         SET active = 0, revoked_at = $3
         WHERE user_id = $1 AND device_id = $2 AND active = 1",
    )
    .bind(&user_id)
    .bind(&target_device_id)
    .bind(&revoked_at)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(AppError::conflict("target device is already revoked"));
    }

    sqlx::query(
        "UPDATE users
         SET device_id = $1, updated_at = $2
         WHERE user_id = $3 AND device_id = $4",
    )
    .bind(&auth.device_id)
    .bind(&revoked_at)
    .bind(&user_id)
    .bind(&target_device_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM prekeys WHERE user_id = $1 AND device_id = $2")
        .bind(&user_id)
        .bind(&target_device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM one_time_prekeys_x25519 WHERE user_id = $1 AND device_id = $2")
        .bind(&user_id)
        .bind(&target_device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM one_time_prekeys_mlkem768 WHERE user_id = $1 AND device_id = $2")
        .bind(&user_id)
        .bind(&target_device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM push_tokens WHERE user_id = $1 AND device_id = $2")
        .bind(&user_id)
        .bind(&target_device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM inbox_cursors WHERE user_id = $1 AND device_id = $2")
        .bind(&user_id)
        .bind(&target_device_id)
        .execute(&mut *tx)
        .await?;

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
