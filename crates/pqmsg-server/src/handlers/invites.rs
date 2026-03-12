use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{Duration, Utc};
use sqlx::Row;
use uuid::Uuid;

use super::prekeys::load_bundle_response;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::handlers::util::check_rate_limit;
use crate::types::*;
use crate::validation::*;
use crate::AppState;

const CONTACT_INVITE_TTL_DAYS: i64 = 14;

struct ContactInviteRecord {
    user_id: String,
    expires_at: String,
}

fn validate_contact_invite_token(invite_token: &str) -> Result<String, AppError> {
    let trimmed = invite_token.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AppError::bad_request(
            "invite token must be 1..=128 characters",
        ));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AppError::bad_request(
            "invite token contains invalid characters",
        ));
    }
    Ok(trimmed.to_string())
}

async fn purge_expired_contact_invites(state: &AppState) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    sqlx::query("DELETE FROM contact_invites WHERE expires_at <= $1")
        .bind(&now)
        .execute(state.pool())
        .await?;
    Ok(())
}

async fn load_contact_invite_record(
    state: &AppState,
    invite_token: &str,
) -> Result<ContactInviteRecord, AppError> {
    let now = Utc::now().to_rfc3339();
    let row = sqlx::query(
        "SELECT user_id, expires_at
         FROM contact_invites
         WHERE invite_token = $1
           AND expires_at > $2",
    )
    .bind(invite_token)
    .bind(&now)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| AppError::not_found("contact invite not found or expired"))?;

    let user_id: String = row.try_get("user_id")?;
    let expires_at: String = row.try_get("expires_at")?;
    ensure_user_exists(state.pool(), &user_id).await?;
    Ok(ContactInviteRecord {
        user_id,
        expires_at,
    })
}

pub(crate) async fn create_contact_invite(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ContactInviteCreateResponse>, AppError> {
    check_rate_limit(&state, &format!("contact-invite-create:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = contact_invite_create_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    purge_expired_contact_invites(&state).await?;

    let now = Utc::now();
    let expires_at = (now + Duration::days(CONTACT_INVITE_TTL_DAYS)).to_rfc3339();
    let issued_at = now.to_rfc3339();
    let invite_token = Uuid::new_v4().simple().to_string();

    // Keep only the newest active invite token per user to reduce stale-link exposure.
    sqlx::query("DELETE FROM contact_invites WHERE user_id = $1")
        .bind(&user_id)
        .execute(state.pool())
        .await?;

    sqlx::query(
        "INSERT INTO contact_invites (invite_token, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&invite_token)
    .bind(&user_id)
    .bind(&issued_at)
    .bind(&expires_at)
    .execute(state.pool())
    .await?;

    Ok(Json(ContactInviteCreateResponse {
        user_id,
        invite_token,
        expires_at,
    }))
}

pub(crate) async fn resolve_contact_invite(
    State(state): State<AppState>,
    Path(invite_token): Path<String>,
) -> Result<Json<ContactInviteResolveResponse>, AppError> {
    check_rate_limit(&state, "contact-invite-resolve")?;
    purge_expired_contact_invites(&state).await?;
    let invite_token = validate_contact_invite_token(&invite_token)?;
    let invite = load_contact_invite_record(&state, &invite_token).await?;

    Ok(Json(ContactInviteResolveResponse {
        invite_token,
        user_id: invite.user_id,
        expires_at: invite.expires_at,
    }))
}

pub(crate) async fn get_contact_invite_bundle(
    State(state): State<AppState>,
    Path(invite_token): Path<String>,
) -> Result<Json<BundleResponse>, AppError> {
    check_rate_limit(&state, "contact-invite-bundle")?;
    purge_expired_contact_invites(&state).await?;
    let invite_token = validate_contact_invite_token(&invite_token)?;
    let invite = load_contact_invite_record(&state, &invite_token).await?;
    let bundle =
        load_bundle_response(&state, &invite.user_id, &BundleQuery { device_id: None }).await?;
    Ok(Json(bundle))
}
