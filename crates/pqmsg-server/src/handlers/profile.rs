use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{Duration, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::ephemeral_state::PresenceRecord;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{
    AppState, MAX_AVATAR_BLOB_BYTES, MAX_FILE_BLOB_BYTES, MAX_TYPING_EVENTS, PRESENCE_TTL_SECONDS,
    TYPING_TTL_SECONDS,
};

pub(crate) async fn register_push_token(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RegisterPushTokenRequest>,
) -> Result<Json<RegisterPushTokenResponse>, AppError> {
    check_rate_limit(&state, &format!("push-token:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("device_id", &request.device_id)?;
    let (provider, token) = resolve_push_token_payload(&request)?;
    let token = validate_push_token(provider, &token)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    if auth.device_id != request.device_id {
        return Err(AppError::bad_request(
            "auth device_id must match request device_id",
        ));
    }
    let auth_message = push_token_auth_message(&auth, &request.device_id, &token)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO push_tokens (
            user_id,
            device_id,
            provider,
            token,
            updated_at
         ) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, device_id, provider) DO UPDATE SET
            token = EXCLUDED.token,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(&user_id)
    .bind(&request.device_id)
    .bind(provider.as_str())
    .bind(&token)
    .bind(&now)
    .execute(state.pool())
    .await?;

    Ok(Json(RegisterPushTokenResponse {
        user_id,
        device_id: request.device_id,
        provider: provider.as_str().to_string(),
        registered_at: now,
    }))
}

pub(crate) async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FileUploadRequest>,
) -> Result<Json<FileUploadResponse>, AppError> {
    check_rate_limit(
        &state,
        &format!("files-upload:{}", request.recipient_user_id),
    )?;
    validate_id("recipient_user_id", &request.recipient_user_id)?;
    validate_id("device_id", &request.device_id)?;
    let mime_type = validate_mime_type("mime_type", &request.mime_type)?;
    let file_blob = decode_base64_range(
        "file_bytes_base64",
        &request.file_bytes_base64,
        1,
        MAX_FILE_BLOB_BYTES,
    )?;

    let auth = parse_request_auth(&headers)?;
    if auth.device_id != request.device_id {
        return Err(AppError::bad_request(
            "auth device_id must match request device_id",
        ));
    }
    let auth_message =
        file_upload_auth_message(&auth, &request.recipient_user_id, &file_blob, &mime_type)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &auth.user_id).await?;
    ensure_user_exists(state.pool(), &request.recipient_user_id).await?;

    let now = Utc::now().to_rfc3339();
    let file_id = Uuid::new_v4().simple().to_string();
    let object_key = format!("files/{file_id}");
    let byte_len =
        i64::try_from(file_blob.len()).map_err(|_| AppError::internal("file byte_len overflow"))?;
    state
        .blob_store()
        .put(&object_key, &file_blob)
        .map_err(|_| AppError::internal("persist encrypted file blob"))?;
    sqlx::query(
        "INSERT INTO encrypted_files (
            file_id,
            owner_user_id,
            owner_device_id,
            recipient_user_id,
            mime_type,
            object_key,
            file_blob,
            byte_len,
            created_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&file_id)
    .bind(&auth.user_id)
    .bind(&request.device_id)
    .bind(&request.recipient_user_id)
    .bind(&mime_type)
    .bind(&object_key)
    .bind(Vec::<u8>::new())
    .bind(byte_len)
    .bind(&now)
    .execute(state.pool())
    .await?;

    Ok(Json(FileUploadResponse {
        file_id,
        owner_user_id: auth.user_id,
        recipient_user_id: request.recipient_user_id,
        mime_type,
        byte_len: usize::try_from(byte_len)
            .map_err(|_| AppError::internal("file byte_len conversion overflow"))?,
        uploaded_at: now,
    }))
}

pub(crate) async fn download_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<FileDownloadResponse>, AppError> {
    check_rate_limit(&state, &format!("files-download:{file_id}"))?;
    validate_file_id(&file_id)?;

    let auth = parse_request_auth(&headers)?;
    let auth_message = file_download_auth_message(&auth, &file_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &auth.user_id).await?;

    let row = sqlx::query(
        "SELECT
            file_id,
            owner_user_id,
            recipient_user_id,
            mime_type,
            object_key,
            file_blob,
            created_at
         FROM encrypted_files
         WHERE file_id = $1",
    )
    .bind(&file_id)
    .fetch_optional(state.pool())
    .await?;
    let Some(row) = row else {
        return Err(AppError::not_found("file not found"));
    };

    let owner_user_id: String = row.try_get("owner_user_id")?;
    let recipient_user_id: String = row.try_get("recipient_user_id")?;
    if auth.user_id != owner_user_id && auth.user_id != recipient_user_id {
        return Err(AppError::not_found("file not found"));
    }

    let object_key: Option<String> = row.try_get("object_key")?;
    let file_blob = if let Some(object_key) = object_key {
        state
            .blob_store()
            .get(&object_key)
            .map_err(|_| AppError::internal("read encrypted file blob"))?
            .ok_or_else(|| AppError::not_found("file not found"))?
    } else {
        row.try_get("file_blob")?
    };
    Ok(Json(FileDownloadResponse {
        file_id: row.try_get("file_id")?,
        owner_user_id,
        recipient_user_id,
        mime_type: row.try_get("mime_type")?,
        file_bytes_base64: B64.encode(file_blob),
        uploaded_at: row.try_get("created_at")?,
    }))
}

pub(crate) async fn upsert_user_profile(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpsertProfileRequest>,
) -> Result<Json<UserProfileResponse>, AppError> {
    check_rate_limit(&state, &format!("profile-upsert:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    let display_name = validate_optional_profile_display_name(request.display_name.as_deref())?;
    let avatar_mime = validate_optional_mime_type("avatar_mime", request.avatar_mime.as_deref())?;
    let avatar_blob = match request.avatar_bytes_base64.as_deref() {
        Some(value) => Some(decode_base64_range(
            "avatar_bytes_base64",
            value,
            1,
            MAX_AVATAR_BLOB_BYTES,
        )?),
        None => None,
    };
    if avatar_blob.is_some() && avatar_mime.is_none() {
        return Err(AppError::bad_request(
            "avatar_mime is required when avatar_bytes_base64 is present",
        ));
    }
    if avatar_blob.is_none() && avatar_mime.is_some() {
        return Err(AppError::bad_request(
            "avatar_bytes_base64 is required when avatar_mime is present",
        ));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = profile_upsert_auth_message(
        &auth,
        &user_id,
        display_name.as_deref(),
        avatar_mime.as_deref(),
        avatar_blob.as_deref(),
    )?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let now = Utc::now().to_rfc3339();
    let avatar_object_key = if let Some(blob) = avatar_blob.as_ref() {
        let object_key = format!("avatars/{user_id}/{}", Uuid::new_v4().simple());
        state
            .blob_store()
            .put(&object_key, blob)
            .map_err(|_| AppError::internal("persist avatar blob"))?;
        Some(object_key)
    } else {
        None
    };
    let previous_avatar_object_key: Option<String> =
        sqlx::query_scalar("SELECT avatar_object_key FROM user_profiles WHERE user_id = $1")
            .bind(&user_id)
            .fetch_optional(state.pool())
            .await?
            .flatten();
    sqlx::query(
        "INSERT INTO user_profiles (
            user_id,
            display_name,
            avatar_mime,
            avatar_blob,
            avatar_object_key,
            updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            avatar_mime = EXCLUDED.avatar_mime,
            avatar_blob = EXCLUDED.avatar_blob,
            avatar_object_key = EXCLUDED.avatar_object_key,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(&user_id)
    .bind(&display_name)
    .bind(&avatar_mime)
    .bind(Option::<Vec<u8>>::None)
    .bind(&avatar_object_key)
    .bind(&now)
    .execute(state.pool())
    .await?;

    if let Some(previous_key) = previous_avatar_object_key {
        if avatar_object_key.as_deref() != Some(previous_key.as_str()) {
            let _ = state.blob_store().delete(&previous_key);
        }
    }

    let avatar_bytes_base64 = avatar_blob.as_ref().map(|value| B64.encode(value));
    Ok(Json(UserProfileResponse {
        user_id,
        display_name,
        avatar_mime,
        avatar_bytes_base64,
        updated_at: Some(now),
    }))
}

pub(crate) async fn get_user_profile(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<UserProfileResponse>, AppError> {
    check_rate_limit(&state, &format!("profile-get:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    let auth_message = profile_get_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &auth.user_id).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let row = sqlx::query(
        "SELECT display_name, avatar_mime, avatar_blob, avatar_object_key, updated_at
         FROM user_profiles
         WHERE user_id = $1",
    )
    .bind(&user_id)
    .fetch_optional(state.pool())
    .await?;

    let Some(row) = row else {
        return Ok(Json(UserProfileResponse {
            user_id,
            display_name: None,
            avatar_mime: None,
            avatar_bytes_base64: None,
            updated_at: None,
        }));
    };

    let avatar_object_key: Option<String> = row.try_get("avatar_object_key")?;
    let avatar_blob: Option<Vec<u8>> = if let Some(object_key) = avatar_object_key {
        Some(
            state
                .blob_store()
                .get(&object_key)
                .map_err(|_| AppError::internal("read avatar blob"))?
                .ok_or_else(|| AppError::not_found("profile avatar not found"))?,
        )
    } else {
        row.try_get("avatar_blob")?
    };
    Ok(Json(UserProfileResponse {
        user_id,
        display_name: row.try_get("display_name")?,
        avatar_mime: row.try_get("avatar_mime")?,
        avatar_bytes_base64: avatar_blob.map(|value| B64.encode(value)),
        updated_at: row.try_get("updated_at")?,
    }))
}

pub(crate) async fn update_presence(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PresenceUpdateRequest>,
) -> Result<Json<PresenceResponse>, AppError> {
    check_rate_limit(&state, &format!("presence-update:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    let status = validate_presence_status(&request.status)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = presence_update_auth_message(&auth, &user_id, &status)?;
    let inbox_compat_auth_message = inbox_auth_message(&auth, &user_id, 0)?;
    verify_request_auth_any(&state, &auth, &[&auth_message, &inbox_compat_auth_message]).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let now = Utc::now().to_rfc3339();
    let expires_at = if status == "offline" {
        now.clone()
    } else {
        (Utc::now() + Duration::seconds(PRESENCE_TTL_SECONDS)).to_rfc3339()
    };
    if state.ephemeral_state().is_distributed() {
        if status == "offline" {
            state.ephemeral_state().clear_presence(&user_id)?;
        } else {
            state.ephemeral_state().set_presence(
                &PresenceRecord {
                    user_id: user_id.clone(),
                    device_id: auth.device_id.clone(),
                    status: status.clone(),
                    updated_at: now.clone(),
                    expires_at: expires_at.clone(),
                },
                PRESENCE_TTL_SECONDS as usize,
            )?;
        }
        return Ok(Json(PresenceResponse {
            user_id,
            status: status.clone(),
            active: status != "offline",
            updated_at: Some(now),
            expires_at: Some(expires_at),
        }));
    }
    sqlx::query(
        "INSERT INTO presence_state (
            user_id,
            device_id,
            status,
            updated_at,
            expires_at
         ) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id) DO UPDATE SET
            device_id = EXCLUDED.device_id,
            status = EXCLUDED.status,
            updated_at = EXCLUDED.updated_at,
            expires_at = EXCLUDED.expires_at",
    )
    .bind(&user_id)
    .bind(&auth.device_id)
    .bind(&status)
    .bind(&now)
    .bind(&expires_at)
    .execute(state.pool())
    .await?;

    Ok(Json(PresenceResponse {
        user_id,
        status: status.clone(),
        active: status != "offline",
        updated_at: Some(now),
        expires_at: Some(expires_at),
    }))
}

pub(crate) async fn get_presence(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PresenceResponse>, AppError> {
    check_rate_limit(&state, &format!("presence-get:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    let auth_message = presence_get_auth_message(&auth, &user_id)?;
    let inbox_compat_auth_message = inbox_auth_message(&auth, &auth.user_id, 0)?;
    verify_request_auth_any(&state, &auth, &[&auth_message, &inbox_compat_auth_message]).await?;
    ensure_user_exists(state.pool(), &auth.user_id).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    if state.ephemeral_state().is_distributed() {
        if let Some(record) = state.ephemeral_state().get_presence(&user_id)? {
            let now = Utc::now().to_rfc3339();
            let active = record.expires_at > now;
            return Ok(Json(PresenceResponse {
                user_id,
                status: if active {
                    record.status
                } else {
                    "offline".to_string()
                },
                active,
                updated_at: Some(record.updated_at),
                expires_at: Some(record.expires_at),
            }));
        }
        return Ok(Json(PresenceResponse {
            user_id,
            status: "offline".to_string(),
            active: false,
            updated_at: None,
            expires_at: None,
        }));
    }

    let row = sqlx::query(
        "SELECT status, updated_at, expires_at
         FROM presence_state
         WHERE user_id = $1",
    )
    .bind(&user_id)
    .fetch_optional(state.pool())
    .await?;

    let Some(row) = row else {
        return Ok(Json(PresenceResponse {
            user_id,
            status: "offline".to_string(),
            active: false,
            updated_at: None,
            expires_at: None,
        }));
    };

    let now = Utc::now().to_rfc3339();
    let raw_status: String = row.try_get("status")?;
    let updated_at: String = row.try_get("updated_at")?;
    let expires_at: String = row.try_get("expires_at")?;
    let active = raw_status != "offline" && expires_at > now;
    let status = if active {
        raw_status
    } else {
        "offline".to_string()
    };

    Ok(Json(PresenceResponse {
        user_id,
        status,
        active,
        updated_at: Some(updated_at),
        expires_at: Some(expires_at),
    }))
}

pub(crate) async fn update_typing(
    State(state): State<AppState>,
    Path(peer_user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TypingUpdateRequest>,
) -> Result<Json<TypingUpdateResponse>, AppError> {
    check_rate_limit(&state, &format!("typing-update:{peer_user_id}"))?;
    validate_id("peer_user_id", &peer_user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id == peer_user_id {
        return Err(AppError::bad_request(
            "peer_user_id must differ from authenticated user_id",
        ));
    }
    let auth_message = typing_update_auth_message(&auth, &peer_user_id, request.is_typing)?;
    let inbox_compat_auth_message = inbox_auth_message(&auth, &auth.user_id, 0)?;
    verify_request_auth_any(&state, &auth, &[&auth_message, &inbox_compat_auth_message]).await?;
    ensure_user_exists(state.pool(), &auth.user_id).await?;
    ensure_user_exists(state.pool(), &peer_user_id).await?;

    let now = Utc::now().to_rfc3339();
    if state.ephemeral_state().is_distributed() {
        if request.is_typing {
            let expires_at = (Utc::now() + Duration::seconds(TYPING_TTL_SECONDS)).to_rfc3339();
            let indicator = TypingIndicator {
                sender_user_id: auth.user_id.clone(),
                sender_device_id: auth.device_id.clone(),
                updated_at: now.clone(),
                expires_at: expires_at.clone(),
            };
            state.ephemeral_state().set_typing(
                &peer_user_id,
                &indicator,
                TYPING_TTL_SECONDS as usize,
            )?;
            return Ok(Json(TypingUpdateResponse {
                recipient_user_id: peer_user_id,
                sender_user_id: auth.user_id,
                sender_device_id: auth.device_id,
                is_typing: true,
                updated_at: now,
                expires_at: Some(expires_at),
            }));
        }
        state
            .ephemeral_state()
            .clear_typing(&peer_user_id, &auth.user_id, &auth.device_id)?;
        return Ok(Json(TypingUpdateResponse {
            recipient_user_id: peer_user_id,
            sender_user_id: auth.user_id,
            sender_device_id: auth.device_id,
            is_typing: false,
            updated_at: now,
            expires_at: None,
        }));
    }
    if request.is_typing {
        let expires_at = (Utc::now() + Duration::seconds(TYPING_TTL_SECONDS)).to_rfc3339();
        sqlx::query(
            "INSERT INTO typing_state (
                recipient_user_id,
                sender_user_id,
                sender_device_id,
                is_typing,
                updated_at,
                expires_at
             ) VALUES ($1, $2, $3, 1, $4, $5)
             ON CONFLICT (recipient_user_id, sender_user_id, sender_device_id) DO UPDATE SET
                is_typing = EXCLUDED.is_typing,
                updated_at = EXCLUDED.updated_at,
                expires_at = EXCLUDED.expires_at",
        )
        .bind(&peer_user_id)
        .bind(&auth.user_id)
        .bind(&auth.device_id)
        .bind(&now)
        .bind(&expires_at)
        .execute(state.pool())
        .await?;
        return Ok(Json(TypingUpdateResponse {
            recipient_user_id: peer_user_id,
            sender_user_id: auth.user_id,
            sender_device_id: auth.device_id,
            is_typing: true,
            updated_at: now,
            expires_at: Some(expires_at),
        }));
    }

    sqlx::query(
        "DELETE FROM typing_state
         WHERE recipient_user_id = $1
           AND sender_user_id = $2
           AND sender_device_id = $3",
    )
    .bind(&peer_user_id)
    .bind(&auth.user_id)
    .bind(&auth.device_id)
    .execute(state.pool())
    .await?;
    Ok(Json(TypingUpdateResponse {
        recipient_user_id: peer_user_id,
        sender_user_id: auth.user_id,
        sender_device_id: auth.device_id,
        is_typing: false,
        updated_at: now,
        expires_at: None,
    }))
}

pub(crate) async fn get_typing(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<TypingInboxResponse>, AppError> {
    check_rate_limit(&state, &format!("typing-get:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = typing_get_auth_message(&auth, &user_id)?;
    let inbox_compat_auth_message = inbox_auth_message(&auth, &user_id, 0)?;
    verify_request_auth_any(&state, &auth, &[&auth_message, &inbox_compat_auth_message]).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    if state.ephemeral_state().is_distributed() {
        let typing = state
            .ephemeral_state()
            .list_typing(&user_id, MAX_TYPING_EVENTS as usize)?
            .unwrap_or_default();
        return Ok(Json(TypingInboxResponse {
            user_id,
            typing,
            checked_at: Utc::now().to_rfc3339(),
        }));
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "DELETE FROM typing_state
         WHERE recipient_user_id = $1
           AND (is_typing = 0 OR expires_at <= $2)",
    )
    .bind(&user_id)
    .bind(&now)
    .execute(state.pool())
    .await?;

    let rows = sqlx::query(
        "SELECT sender_user_id, sender_device_id, updated_at, expires_at
         FROM typing_state
         WHERE recipient_user_id = $1 AND is_typing = 1 AND expires_at > $2
         ORDER BY updated_at DESC
         LIMIT $3",
    )
    .bind(&user_id)
    .bind(&now)
    .bind(MAX_TYPING_EVENTS)
    .fetch_all(state.pool())
    .await?;
    let mut typing = Vec::with_capacity(rows.len());
    for row in rows {
        typing.push(TypingIndicator {
            sender_user_id: row.try_get("sender_user_id")?,
            sender_device_id: row.try_get("sender_device_id")?,
            updated_at: row.try_get("updated_at")?,
            expires_at: row.try_get("expires_at")?,
        });
    }
    Ok(Json(TypingInboxResponse {
        user_id,
        typing,
        checked_at: now,
    }))
}
