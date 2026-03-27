use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{Duration, Utc};
use ed25519_dalek::Signer;
use serde::Serialize;
use sqlx::Row;

use super::invites::{ensure_contact_invite_for_purpose, ContactInvitePurpose};
use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::AppState;

#[derive(Clone, Copy)]
enum ContactDiscoveryTicketPurpose {
    Upload,
    Match,
}

impl ContactDiscoveryTicketPurpose {
    fn parse(raw: &str) -> Result<Self, AppError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "upload" => Ok(Self::Upload),
            "match" => Ok(Self::Match),
            _ => Err(AppError::bad_request(
                "contact discovery ticket purpose must be 'upload' or 'match'",
            )),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Match => "match",
        }
    }

    const fn max_uses(self) -> u8 {
        match self {
            Self::Upload => 3,
            Self::Match => 2,
        }
    }
}

fn ensure_contact_discovery_supported(_state: &AppState) -> Result<(), AppError> {
    Err(AppError::forbidden(
        "raw-hash contact discovery on the app server is disabled; use the configured private discovery service ticket flow",
    ))
}

fn ensure_contact_discovery_ticket_supported(state: &AppState) -> Result<String, AppError> {
    state.contact_discovery_service_origin().ok_or_else(|| {
        AppError::forbidden(
            "private contact discovery service is not configured; use manual contacts or invite links",
        )
    })
}

#[derive(Serialize)]
struct ContactDiscoveryTicketPayload {
    v: u8,
    user_id: String,
    device_id: String,
    purpose: String,
    manifest_contract_sha256: String,
    contact_invite_token: String,
    contact_invite_expires_at: String,
    issued_at: String,
    expires_at: String,
    max_uses: u8,
    nonce: String,
}

pub(crate) async fn create_contact_discovery_ticket(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ContactDiscoveryTicketRequest>,
) -> Result<Json<ContactDiscoveryTicketResponse>, AppError> {
    let service_origin = ensure_contact_discovery_ticket_supported(&state)?;
    check_rate_limit(&state, &format!("contact-discovery-ticket:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(state.pool(), &user_id).await?;
    let purpose = ContactDiscoveryTicketPurpose::parse(&request.purpose)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = contact_discovery_ticket_auth_message(&auth, &user_id, purpose.as_str())?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let bootstrap_invite = ensure_contact_invite_for_purpose(
        &state,
        &user_id,
        ContactInvitePurpose::DiscoveryBootstrap,
        false,
    )
    .await?;
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::minutes(5);
    let manifest_contract_sha256 = state
        .contact_discovery_expected_manifest_contract_sha256()
        .ok_or_else(|| {
            AppError::forbidden(
                "private contact discovery manifest contract hash is not configured; use manual contacts or invite links",
            )
        })?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let payload = ContactDiscoveryTicketPayload {
        v: 1,
        user_id: user_id.clone(),
        device_id: auth.device_id.clone(),
        purpose: purpose.as_str().to_string(),
        manifest_contract_sha256,
        contact_invite_token: bootstrap_invite.invite_token,
        contact_invite_expires_at: bootstrap_invite.expires_at,
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        max_uses: purpose.max_uses(),
        nonce: nonce.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload)
        .map_err(|_| AppError::internal("serialize contact discovery ticket"))?;
    let signature = state
        .sender_certificate_signing_key()
        .sign(&payload_bytes)
        .to_bytes();
    let ticket = format!("{}.{}", B64.encode(payload_bytes), B64.encode(signature));

    Ok(Json(ContactDiscoveryTicketResponse {
        user_id,
        device_id: auth.device_id,
        service_origin,
        ticket,
        ticket_nonce: nonce,
        expires_at: expires_at.to_rfc3339(),
    }))
}

pub(crate) async fn upload_discovery_handles(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DiscoveryHandlesUploadRequest>,
) -> Result<Json<DiscoveryHandlesUploadResponse>, AppError> {
    ensure_contact_discovery_supported(&state)?;
    check_rate_limit(&state, &format!("discovery-handles:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    let phone_hashes =
        normalize_sha256_hashes("phone_hashes_sha256", &request.phone_hashes_sha256)?;
    let email_hashes =
        normalize_sha256_hashes("email_hashes_sha256", &request.email_hashes_sha256)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message =
        discovery_handles_auth_message(&auth, &user_id, &phone_hashes, &email_hashes)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let now = Utc::now().to_rfc3339();
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM discovery_handles WHERE user_id = $1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    for hash in &phone_hashes {
        sqlx::query(
            "INSERT INTO discovery_handles (
                user_id,
                handle_hash_sha256,
                handle_kind,
                created_at,
                updated_at
             ) VALUES ($1, $2, 'phone', $3, $3)",
        )
        .bind(&user_id)
        .bind(hash)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }
    for hash in &email_hashes {
        sqlx::query(
            "INSERT INTO discovery_handles (
                user_id,
                handle_hash_sha256,
                handle_kind,
                created_at,
                updated_at
             ) VALUES ($1, $2, 'email', $3, $3)",
        )
        .bind(&user_id)
        .bind(hash)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    Ok(Json(DiscoveryHandlesUploadResponse {
        user_id,
        device_id: auth.device_id,
        uploaded_phone_hashes: phone_hashes.len(),
        uploaded_email_hashes: email_hashes.len(),
        updated_at: now,
    }))
}

pub(crate) async fn match_discovery_hashes(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DiscoveryMatchRequest>,
) -> Result<Json<DiscoveryMatchResponse>, AppError> {
    ensure_contact_discovery_supported(&state)?;
    check_rate_limit(&state, &format!("discovery-match:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    let query_hashes = normalize_sha256_hashes("hashes_sha256", &request.hashes_sha256)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = discovery_match_auth_message(&auth, &user_id, &query_hashes)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let mut matches = Vec::new();
    for hash in &query_hashes {
        let rows = sqlx::query(
            "SELECT handle_hash_sha256, user_id, handle_kind
             FROM discovery_handles
             WHERE handle_hash_sha256 = $1 AND user_id <> $2
             ORDER BY user_id ASC
             LIMIT 128",
        )
        .bind(hash)
        .bind(&user_id)
        .fetch_all(state.pool())
        .await?;
        for row in rows {
            matches.push(DiscoveryMatchItem {
                hash_sha256: row.try_get("handle_hash_sha256")?,
                matched_user_id: row.try_get("user_id")?,
                handle_kind: row.try_get("handle_kind")?,
            });
        }
    }

    Ok(Json(DiscoveryMatchResponse {
        user_id,
        matches,
        checked_at: Utc::now().to_rfc3339(),
    }))
}

pub(crate) async fn list_contacts(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ContactListResponse>, AppError> {
    check_rate_limit(&state, &format!("contacts-list:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = contacts_list_auth_message(&auth, &user_id)?;
    let inbox_compat_auth_message = inbox_auth_message(&auth, &user_id, 0)?;
    verify_request_auth_any(&state, &auth, &[&auth_message, &inbox_compat_auth_message]).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let rows = sqlx::query(
        "SELECT
            contacts.contact_user_id,
            user_profiles.username,
            contacts.alias,
            contacts.verified_by_qr,
            contacts.verified_fingerprint_sha256,
            contacts.created_at,
            contacts.updated_at
         FROM contacts
         LEFT JOIN user_profiles
           ON user_profiles.user_id = contacts.contact_user_id
         WHERE contacts.user_id = $1
         ORDER BY contacts.updated_at DESC, contacts.contact_user_id ASC",
    )
    .bind(&user_id)
    .fetch_all(state.pool())
    .await?;
    let mut contacts = Vec::with_capacity(rows.len());
    for row in rows {
        let verified_by_qr: i64 = row.try_get("verified_by_qr")?;
        contacts.push(ContactListItem {
            contact_user_id: row.try_get("contact_user_id")?,
            username: row.try_get("username")?,
            alias: row.try_get("alias")?,
            verified_by_qr: verified_by_qr != 0,
            verified_fingerprint_sha256: row.try_get("verified_fingerprint_sha256")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        });
    }

    Ok(Json(ContactListResponse { user_id, contacts }))
}

pub(crate) async fn upsert_contact(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpsertContactRequest>,
) -> Result<Json<UpsertContactResponse>, AppError> {
    check_rate_limit(&state, &format!("contacts-upsert:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("contact_user_id", &request.contact_user_id)?;
    if user_id == request.contact_user_id {
        return Err(AppError::bad_request("cannot add self as contact"));
    }
    let alias = validate_optional_contact_alias(request.alias.as_deref())?;
    let verified_by_qr = request.verified_by_qr.unwrap_or(false);
    let verified_fingerprint_sha256 =
        validate_optional_fingerprint_sha256(request.verified_fingerprint_sha256.as_deref())?;
    if verified_by_qr && verified_fingerprint_sha256.is_none() {
        return Err(AppError::bad_request(
            "verified_fingerprint_sha256 is required when verified_by_qr is true",
        ));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = contacts_upsert_auth_message(
        &auth,
        &user_id,
        &request.contact_user_id,
        alias.as_deref(),
        verified_by_qr,
        verified_fingerprint_sha256.as_deref(),
    )?;
    let inbox_compat_auth_message = inbox_auth_message(&auth, &user_id, 0)?;
    verify_request_auth_any(&state, &auth, &[&auth_message, &inbox_compat_auth_message]).await?;
    ensure_user_exists(state.pool(), &user_id).await?;
    ensure_user_exists(state.pool(), &request.contact_user_id).await?;

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO contacts (
            user_id,
            contact_user_id,
            alias,
            verified_by_qr,
            verified_fingerprint_sha256,
            created_at,
            updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $6)
         ON CONFLICT (user_id, contact_user_id) DO UPDATE SET
            alias = EXCLUDED.alias,
            verified_by_qr = EXCLUDED.verified_by_qr,
            verified_fingerprint_sha256 = EXCLUDED.verified_fingerprint_sha256,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(&user_id)
    .bind(&request.contact_user_id)
    .bind(alias.clone())
    .bind(if verified_by_qr { 1 } else { 0 })
    .bind(verified_fingerprint_sha256.clone())
    .bind(&now)
    .execute(state.pool())
    .await?;

    Ok(Json(UpsertContactResponse {
        user_id,
        contact_user_id: request.contact_user_id,
        alias,
        verified_by_qr,
        verified_fingerprint_sha256,
        updated_at: now,
    }))
}

pub(crate) async fn remove_contact(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RemoveContactRequest>,
) -> Result<Json<RemoveContactResponse>, AppError> {
    check_rate_limit(&state, &format!("contacts-remove:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("contact_user_id", &request.contact_user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = contacts_remove_auth_message(&auth, &user_id, &request.contact_user_id)?;
    let inbox_compat_auth_message = inbox_auth_message(&auth, &user_id, 0)?;
    verify_request_auth_any(&state, &auth, &[&auth_message, &inbox_compat_auth_message]).await?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let removed_at = Utc::now().to_rfc3339();
    let deleted = sqlx::query(
        "DELETE FROM contacts
         WHERE user_id = $1 AND contact_user_id = $2",
    )
    .bind(&user_id)
    .bind(&request.contact_user_id)
    .execute(state.pool())
    .await?
    .rows_affected()
        > 0;

    Ok(Json(RemoveContactResponse {
        user_id,
        removed_contact_user_id: request.contact_user_id,
        removed: deleted,
        removed_at,
    }))
}
