use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{AppState, MAX_BACKUP_BLOB_BYTES};

pub(crate) async fn upload_backup(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<BackupUploadRequest>,
) -> Result<Json<BackupUploadResponse>, AppError> {
    check_rate_limit(&state, &format!("backup-upload:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("device_id", &request.device_id)?;
    if request.backup_version <= 0 {
        return Err(AppError::bad_request("backup_version must be positive"));
    }
    let backup_blob = decode_base64_range(
        "encrypted_backup_bytes_base64",
        &request.encrypted_backup_bytes_base64,
        1,
        MAX_BACKUP_BLOB_BYTES,
    )?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    if auth.device_id != request.device_id {
        return Err(AppError::bad_request(
            "auth device_id must match request device_id",
        ));
    }
    let blob_hash = hex::encode(Sha256::digest(&backup_blob));
    let auth_message = format!(
        "backups-upload:{}:{}:{}:{}:{}:{}",
        auth.user_id, auth.device_id, auth.timestamp, auth.nonce, request.backup_version, blob_hash
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let now = Utc::now().to_rfc3339();
    let backup_id = Uuid::new_v4().simple().to_string();
    let object_key = format!("backups/{user_id}/{backup_id}.bin");
    let byte_len = i64::try_from(backup_blob.len())
        .map_err(|_| AppError::internal("backup byte_len overflow"))?;
    state
        .blob_store()
        .put(&object_key, &backup_blob)
        .map_err(|_| AppError::internal("persist encrypted backup blob"))?;

    let previous = sqlx::query(
        "SELECT backup_id, blob_object_key
         FROM encrypted_backups
         WHERE user_id = $1",
    )
    .bind(&user_id)
    .fetch_optional(state.pool())
    .await?;

    sqlx::query(
        "INSERT INTO encrypted_backups (
            backup_id,
            user_id,
            device_id,
            backup_version,
            blob_object_key,
            byte_len,
            recovery_hint,
            created_at,
            updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (user_id) DO UPDATE SET
            backup_id = EXCLUDED.backup_id,
            device_id = EXCLUDED.device_id,
            backup_version = EXCLUDED.backup_version,
            blob_object_key = EXCLUDED.blob_object_key,
            byte_len = EXCLUDED.byte_len,
            recovery_hint = EXCLUDED.recovery_hint,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(&backup_id)
    .bind(&user_id)
    .bind(&request.device_id)
    .bind(request.backup_version)
    .bind(&object_key)
    .bind(byte_len)
    .bind(request.recovery_hint.as_deref())
    .bind(&now)
    .bind(&now)
    .execute(state.pool())
    .await?;

    if let Some(previous) = previous {
        let previous_key: String = previous.try_get("blob_object_key")?;
        let previous_backup_id: String = previous.try_get("backup_id")?;
        if previous_key != object_key || previous_backup_id != backup_id {
            let _ = state.blob_store().delete(&previous_key);
        }
    }

    Ok(Json(BackupUploadResponse {
        backup_id,
        user_id,
        device_id: request.device_id,
        backup_version: request.backup_version,
        byte_len: usize::try_from(byte_len)
            .map_err(|_| AppError::internal("backup byte_len conversion overflow"))?,
        uploaded_at: now,
    }))
}

pub(crate) async fn download_latest_backup(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<BackupDownloadResponse>, AppError> {
    check_rate_limit(&state, &format!("backup-download:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = format!(
        "backups-download:{}:{}:{}:{}:{}",
        auth.user_id, auth.device_id, auth.timestamp, auth.nonce, user_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    Ok(Json(load_backup_response(&state, &user_id).await?))
}

pub(crate) async fn download_recovery_backup(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<BackupDownloadResponse>, AppError> {
    check_rate_limit(&state, &format!("backup-recovery:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(state.pool(), &user_id).await?;

    Ok(Json(load_backup_response(&state, &user_id).await?))
}

async fn load_backup_response(
    state: &AppState,
    user_id: &str,
) -> Result<BackupDownloadResponse, AppError> {
    let row = sqlx::query(
        "SELECT
            backup_id,
            device_id,
            backup_version,
            blob_object_key,
            recovery_hint,
            updated_at
         FROM encrypted_backups
         WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(state.pool())
    .await?;
    let Some(row) = row else {
        return Err(AppError::not_found("backup not found"));
    };

    let object_key: String = row.try_get("blob_object_key")?;
    let blob = state
        .blob_store()
        .get(&object_key)
        .map_err(|_| AppError::internal("read encrypted backup blob"))?
        .ok_or_else(|| AppError::not_found("backup not found"))?;

    Ok(BackupDownloadResponse {
        backup_id: row.try_get("backup_id")?,
        user_id: user_id.to_string(),
        device_id: row.try_get("device_id")?,
        backup_version: row.try_get("backup_version")?,
        recovery_hint: row.try_get("recovery_hint")?,
        encrypted_backup_bytes_base64: B64.encode(blob),
        uploaded_at: row.try_get("updated_at")?,
    })
}
