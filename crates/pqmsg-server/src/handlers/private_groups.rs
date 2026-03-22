use axum::extract::{Path, State};
use axum::Json;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use super::util::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::AppState;

const PRIVATE_GROUP_CIPHERTEXT_NONCE_LEN: usize = 12;
const PRIVATE_GROUP_AUTH_KEY_LEN: usize = 32;
const PRIVATE_GROUP_MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
const PRIVATE_GROUP_MAX_AAD_BYTES: usize = 4096;
const PRIVATE_GROUP_INVITE_DEFAULT_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const PRIVATE_GROUP_INVITE_MAX_TTL_SECS: i64 = 30 * 24 * 60 * 60;

struct PrivateGroupInviteRecord {
    group_id: String,
    epoch: i64,
    invite_commitment_sha256: String,
    invite_ciphertext_nonce_base64: String,
    invite_ciphertext_base64: String,
    invite_ciphertext_aad_base64: String,
    created_at: String,
    expires_at: String,
}

pub(crate) async fn publish_private_group_state(
    State(state): State<AppState>,
    Json(request): Json<PublishPrivateGroupStateRequest>,
) -> Result<Json<PublishPrivateGroupStateResponse>, AppError> {
    check_rate_limit(
        &state,
        &format!("private-groups-publish:{}", request.group_id.trim()),
    )?;

    validate_id("group_id", &request.group_id)?;
    let epoch = validate_private_group_epoch(request.epoch)?;
    let state_commitment_sha256 =
        validate_sha256_hex("state_commitment_sha256", &request.state_commitment_sha256)?;
    let authorizing_membership_handle_sha256 = validate_sha256_hex(
        "authorizing_membership_handle_sha256",
        &request.authorizing_membership_handle_sha256,
    )?;
    decode_base64_exact(
        "ciphertext_nonce_base64",
        &request.ciphertext_nonce_base64,
        PRIVATE_GROUP_CIPHERTEXT_NONCE_LEN,
    )?;
    decode_base64_max(
        "ciphertext_base64",
        &request.ciphertext_base64,
        PRIVATE_GROUP_MAX_CIPHERTEXT_BYTES,
    )?;
    decode_base64_max(
        "ciphertext_aad_base64",
        &request.ciphertext_aad_base64,
        PRIVATE_GROUP_MAX_AAD_BYTES,
    )?;
    let authorizing_publish_key = decode_base64_exact(
        "authorizing_publish_key_base64",
        &request.authorizing_publish_key_base64,
        PRIVATE_GROUP_AUTH_KEY_LEN,
    )?;
    let authorizing_publish_key_sha256 = hex::encode(Sha256::digest(&authorizing_publish_key));

    let members = normalize_private_group_members(&request.members)?;
    let now = Utc::now().to_rfc3339();

    let latest_epoch_row = sqlx::query(
        "SELECT MAX(epoch) AS latest_epoch
         FROM private_group_states
         WHERE group_id = $1",
    )
    .bind(request.group_id.trim())
    .fetch_one(state.pool())
    .await?;
    let latest_epoch: Option<i64> = latest_epoch_row.try_get("latest_epoch")?;

    match latest_epoch {
        None => {
            if epoch != 1 {
                return Err(AppError::bad_request(
                    "private group bootstrap publish must start at epoch 1",
                ));
            }
            let bootstrap_record = members
                .iter()
                .find(|member| {
                    member.membership_handle_sha256 == authorizing_membership_handle_sha256
                })
                .ok_or_else(|| {
                    AppError::forbidden(
                        "bootstrap private group publish requires the authorizing membership handle in the member set",
                    )
                })?;
            if bootstrap_record.publish_key_sha256.as_deref()
                != Some(authorizing_publish_key_sha256.as_str())
            {
                return Err(AppError::forbidden(
                    "bootstrap private group publish key does not match the authorizing member credential",
                ));
            }
        }
        Some(latest_epoch) => {
            if epoch != latest_epoch + 1 {
                return Err(AppError::bad_request(
                    "private group epoch must advance exactly by one",
                ));
            }
            let row = sqlx::query(
                "SELECT publish_key_sha256
                 FROM private_group_member_credentials
                 WHERE membership_handle_sha256 = $1
                   AND group_id = $2
                   AND epoch = $3
                   AND revoked_at IS NULL",
            )
            .bind(&authorizing_membership_handle_sha256)
            .bind(request.group_id.trim())
            .bind(latest_epoch)
            .fetch_optional(state.pool())
            .await?;
            let Some(row) = row else {
                return Err(AppError::forbidden(
                    "authorizing private group membership handle is not active for the latest epoch",
                ));
            };
            let stored_publish_key_sha256: Option<String> = row.try_get("publish_key_sha256")?;
            if stored_publish_key_sha256.as_deref() != Some(authorizing_publish_key_sha256.as_str())
            {
                return Err(AppError::forbidden(
                    "authorizing private group publish key is invalid",
                ));
            }
        }
    }

    let mut tx = state.pool().begin().await?;

    if let Some(latest_epoch) = latest_epoch {
        sqlx::query(
            "UPDATE private_group_member_credentials
             SET revoked_at = $1
             WHERE group_id = $2 AND epoch = $3 AND revoked_at IS NULL",
        )
        .bind(&now)
        .bind(request.group_id.trim())
        .bind(latest_epoch)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        "INSERT INTO private_group_states (
            group_id,
            epoch,
            state_commitment_sha256,
            ciphertext_nonce_base64,
            ciphertext_base64,
            ciphertext_aad_base64,
            published_by_membership_handle_sha256,
            published_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(request.group_id.trim())
    .bind(epoch)
    .bind(&state_commitment_sha256)
    .bind(request.ciphertext_nonce_base64.trim())
    .bind(request.ciphertext_base64.trim())
    .bind(request.ciphertext_aad_base64.trim())
    .bind(&authorizing_membership_handle_sha256)
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|error| {
        map_private_group_conflict(error, "private group state for this epoch already exists")
    })?;

    sqlx::query(
        "UPDATE private_group_invites
         SET revoked_at = $1
         WHERE group_id = $2
           AND epoch < $3
           AND revoked_at IS NULL",
    )
    .bind(&now)
    .bind(request.group_id.trim())
    .bind(epoch)
    .execute(&mut *tx)
    .await?;

    for member in &members {
        sqlx::query(
            "INSERT INTO private_group_member_credentials (
                membership_handle_sha256,
                group_id,
                epoch,
                member_commitment_sha256,
                fetch_key_sha256,
                publish_key_sha256,
                created_at,
                revoked_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)",
        )
        .bind(&member.membership_handle_sha256)
        .bind(request.group_id.trim())
        .bind(epoch)
        .bind(&member.member_commitment_sha256)
        .bind(&member.fetch_key_sha256)
        .bind(member.publish_key_sha256.as_deref())
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            map_private_group_conflict(error, "private group membership handle already exists")
        })?;
    }

    tx.commit().await?;

    Ok(Json(PublishPrivateGroupStateResponse {
        group_id: request.group_id.trim().to_string(),
        epoch: epoch as u64,
        stored_member_count: members.len(),
        published_at: now,
    }))
}

pub(crate) async fn fetch_private_group_state(
    State(state): State<AppState>,
    Json(request): Json<FetchPrivateGroupStateRequest>,
) -> Result<Json<FetchPrivateGroupStateResponse>, AppError> {
    let membership_handle_sha256 = validate_sha256_hex(
        "membership_handle_sha256",
        &request.membership_handle_sha256,
    )?;
    check_rate_limit(
        &state,
        &format!("private-groups-fetch:{membership_handle_sha256}"),
    )?;
    let fetch_key = decode_base64_exact(
        "fetch_key_base64",
        &request.fetch_key_base64,
        PRIVATE_GROUP_AUTH_KEY_LEN,
    )?;
    let fetch_key_sha256 = hex::encode(Sha256::digest(&fetch_key));

    let row = sqlx::query(
        "SELECT
            c.group_id,
            c.epoch,
            c.fetch_key_sha256,
            s.state_commitment_sha256,
            s.ciphertext_nonce_base64,
            s.ciphertext_base64,
            s.ciphertext_aad_base64,
            s.published_at
         FROM private_group_member_credentials c
         INNER JOIN private_group_states s
           ON s.group_id = c.group_id AND s.epoch = c.epoch
         WHERE c.membership_handle_sha256 = $1
           AND c.revoked_at IS NULL",
    )
    .bind(&membership_handle_sha256)
    .fetch_optional(state.pool())
    .await?;
    let Some(row) = row else {
        return Err(AppError::not_found("private group state not found"));
    };
    let stored_fetch_key_sha256: String = row.try_get("fetch_key_sha256")?;
    if stored_fetch_key_sha256 != fetch_key_sha256 {
        return Err(AppError::forbidden(
            "private group fetch credential is invalid",
        ));
    }

    let epoch: i64 = row.try_get("epoch")?;
    Ok(Json(FetchPrivateGroupStateResponse {
        group_id: row.try_get("group_id")?,
        epoch: epoch as u64,
        state_commitment_sha256: row.try_get("state_commitment_sha256")?,
        ciphertext_nonce_base64: row.try_get("ciphertext_nonce_base64")?,
        ciphertext_base64: row.try_get("ciphertext_base64")?,
        ciphertext_aad_base64: row.try_get("ciphertext_aad_base64")?,
        published_at: row.try_get("published_at")?,
    }))
}

pub(crate) async fn create_private_group_invite(
    State(state): State<AppState>,
    Json(request): Json<CreatePrivateGroupInviteRequest>,
) -> Result<Json<CreatePrivateGroupInviteResponse>, AppError> {
    check_rate_limit(
        &state,
        &format!("private-groups-invite-create:{}", request.group_id.trim()),
    )?;

    validate_id("group_id", &request.group_id)?;
    let epoch = validate_private_group_epoch(request.epoch)?;
    let invite_commitment_sha256 = validate_sha256_hex(
        "invite_commitment_sha256",
        &request.invite_commitment_sha256,
    )?;
    let authorizing_membership_handle_sha256 = validate_sha256_hex(
        "authorizing_membership_handle_sha256",
        &request.authorizing_membership_handle_sha256,
    )?;
    decode_base64_exact(
        "invite_ciphertext_nonce_base64",
        &request.invite_ciphertext_nonce_base64,
        PRIVATE_GROUP_CIPHERTEXT_NONCE_LEN,
    )?;
    decode_base64_max(
        "invite_ciphertext_base64",
        &request.invite_ciphertext_base64,
        PRIVATE_GROUP_MAX_CIPHERTEXT_BYTES,
    )?;
    decode_base64_max(
        "invite_ciphertext_aad_base64",
        &request.invite_ciphertext_aad_base64,
        PRIVATE_GROUP_MAX_AAD_BYTES,
    )?;
    let authorizing_publish_key = decode_base64_exact(
        "authorizing_publish_key_base64",
        &request.authorizing_publish_key_base64,
        PRIVATE_GROUP_AUTH_KEY_LEN,
    )?;
    let authorizing_publish_key_sha256 = hex::encode(Sha256::digest(&authorizing_publish_key));
    let expires_in_seconds = validate_private_group_invite_ttl(
        request
            .expires_in_seconds
            .unwrap_or(PRIVATE_GROUP_INVITE_DEFAULT_TTL_SECS as u32),
    )?;

    purge_expired_private_group_invites(&state).await?;
    authorize_current_private_group_publish_capability(
        &state,
        request.group_id.trim(),
        epoch,
        &authorizing_membership_handle_sha256,
        &authorizing_publish_key_sha256,
    )
    .await?;

    let created_at_dt = Utc::now();
    let created_at = created_at_dt.to_rfc3339();
    let expires_at = (created_at_dt + Duration::seconds(expires_in_seconds)).to_rfc3339();
    let invite_token = Uuid::new_v4().simple().to_string();

    sqlx::query(
        "INSERT INTO private_group_invites (
            invite_token,
            group_id,
            epoch,
            invite_commitment_sha256,
            invite_ciphertext_nonce_base64,
            invite_ciphertext_base64,
            invite_ciphertext_aad_base64,
            created_by_membership_handle_sha256,
            created_at,
            expires_at,
            revoked_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)",
    )
    .bind(&invite_token)
    .bind(request.group_id.trim())
    .bind(epoch)
    .bind(&invite_commitment_sha256)
    .bind(request.invite_ciphertext_nonce_base64.trim())
    .bind(request.invite_ciphertext_base64.trim())
    .bind(request.invite_ciphertext_aad_base64.trim())
    .bind(&authorizing_membership_handle_sha256)
    .bind(&created_at)
    .bind(&expires_at)
    .execute(state.pool())
    .await
    .map_err(|error| {
        map_private_group_conflict(error, "private group invite token already exists")
    })?;

    Ok(Json(CreatePrivateGroupInviteResponse {
        invite_token,
        group_id: request.group_id.trim().to_string(),
        epoch: epoch as u64,
        expires_at,
        created_at,
    }))
}

pub(crate) async fn resolve_private_group_invite(
    State(state): State<AppState>,
    Path(invite_token): Path<String>,
) -> Result<Json<ResolvePrivateGroupInviteResponse>, AppError> {
    check_rate_limit(&state, "private-groups-invite-resolve")?;
    purge_expired_private_group_invites(&state).await?;
    let invite_token = validate_private_group_invite_token(&invite_token)?;
    let invite = load_private_group_invite_record(&state, &invite_token).await?;
    let latest_epoch = load_latest_private_group_epoch(state.pool(), &invite.group_id).await?;
    if invite.epoch != latest_epoch {
        return Err(AppError::conflict(
            "private group invite is stale; fetch a newer invite package",
        ));
    }

    Ok(Json(ResolvePrivateGroupInviteResponse {
        invite_token,
        group_id: invite.group_id,
        epoch: invite.epoch as u64,
        invite_commitment_sha256: invite.invite_commitment_sha256,
        invite_ciphertext_nonce_base64: invite.invite_ciphertext_nonce_base64,
        invite_ciphertext_base64: invite.invite_ciphertext_base64,
        invite_ciphertext_aad_base64: invite.invite_ciphertext_aad_base64,
        created_at: invite.created_at,
        expires_at: invite.expires_at,
    }))
}

pub(crate) async fn consume_private_group_invite(
    State(state): State<AppState>,
    Path(invite_token): Path<String>,
) -> Result<Json<ConsumePrivateGroupInviteResponse>, AppError> {
    check_rate_limit(&state, "private-groups-invite-consume")?;
    purge_expired_private_group_invites(&state).await?;
    let invite_token = validate_private_group_invite_token(&invite_token)?;
    load_private_group_invite_record(&state, &invite_token).await?;
    let revoked_at = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE private_group_invites
         SET revoked_at = $1
         WHERE invite_token = $2
           AND revoked_at IS NULL",
    )
    .bind(&revoked_at)
    .bind(&invite_token)
    .execute(state.pool())
    .await?;

    Ok(Json(ConsumePrivateGroupInviteResponse {
        invite_token,
        consumed: true,
        revoked_at,
    }))
}

fn normalize_private_group_members(
    raw_members: &[PrivateGroupMemberCredentialRecord],
) -> Result<Vec<PrivateGroupMemberCredentialRecord>, AppError> {
    if raw_members.is_empty() {
        return Err(AppError::bad_request(
            "private group members cannot be empty",
        ));
    }
    if raw_members.len() > crate::MAX_GROUP_MEMBERS {
        return Err(AppError::bad_request(format!(
            "private group members cannot exceed {}",
            crate::MAX_GROUP_MEMBERS
        )));
    }
    let mut members = Vec::with_capacity(raw_members.len());
    let mut seen_handles = std::collections::BTreeSet::new();
    for member in raw_members {
        let membership_handle_sha256 = validate_sha256_hex(
            "members[].membership_handle_sha256",
            &member.membership_handle_sha256,
        )?;
        let member_commitment_sha256 = validate_sha256_hex(
            "members[].member_commitment_sha256",
            &member.member_commitment_sha256,
        )?;
        let fetch_key_sha256 =
            validate_sha256_hex("members[].fetch_key_sha256", &member.fetch_key_sha256)?;
        let publish_key_sha256 = member
            .publish_key_sha256
            .as_deref()
            .map(|value| validate_sha256_hex("members[].publish_key_sha256", value))
            .transpose()?;
        if !seen_handles.insert(membership_handle_sha256.clone()) {
            return Err(AppError::bad_request(
                "private group membership handles must be unique",
            ));
        }
        members.push(PrivateGroupMemberCredentialRecord {
            membership_handle_sha256,
            member_commitment_sha256,
            fetch_key_sha256,
            publish_key_sha256,
        });
    }
    Ok(members)
}

fn validate_private_group_epoch(epoch: u64) -> Result<i64, AppError> {
    if epoch == 0 {
        return Err(AppError::bad_request("private group epoch must be >= 1"));
    }
    i64::try_from(epoch).map_err(|_| AppError::bad_request("private group epoch is too large"))
}

fn validate_private_group_invite_ttl(expires_in_seconds: u32) -> Result<i64, AppError> {
    let expires_in_seconds = i64::from(expires_in_seconds);
    if !(60..=PRIVATE_GROUP_INVITE_MAX_TTL_SECS).contains(&expires_in_seconds) {
        return Err(AppError::bad_request(format!(
            "private group invite expiry must be between 60 and {PRIVATE_GROUP_INVITE_MAX_TTL_SECS} seconds"
        )));
    }
    Ok(expires_in_seconds)
}

fn validate_private_group_invite_token(invite_token: &str) -> Result<String, AppError> {
    let trimmed = invite_token.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(AppError::bad_request(
            "private group invite token must be 1..=128 characters",
        ));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AppError::bad_request(
            "private group invite token contains invalid characters",
        ));
    }
    Ok(trimmed.to_string())
}

async fn purge_expired_private_group_invites(state: &AppState) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "DELETE FROM private_group_invites
         WHERE expires_at <= $1 OR revoked_at IS NOT NULL",
    )
    .bind(&now)
    .execute(state.pool())
    .await?;
    Ok(())
}

async fn load_private_group_invite_record(
    state: &AppState,
    invite_token: &str,
) -> Result<PrivateGroupInviteRecord, AppError> {
    let now = Utc::now().to_rfc3339();
    let row = sqlx::query(
        "SELECT group_id, epoch, invite_commitment_sha256, invite_ciphertext_nonce_base64,
                invite_ciphertext_base64, invite_ciphertext_aad_base64, created_at, expires_at
         FROM private_group_invites
         WHERE invite_token = $1
           AND expires_at > $2
           AND revoked_at IS NULL",
    )
    .bind(invite_token)
    .bind(&now)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| AppError::not_found("private group invite not found or expired"))?;

    Ok(PrivateGroupInviteRecord {
        group_id: row.try_get("group_id")?,
        epoch: row.try_get("epoch")?,
        invite_commitment_sha256: row.try_get("invite_commitment_sha256")?,
        invite_ciphertext_nonce_base64: row.try_get("invite_ciphertext_nonce_base64")?,
        invite_ciphertext_base64: row.try_get("invite_ciphertext_base64")?,
        invite_ciphertext_aad_base64: row.try_get("invite_ciphertext_aad_base64")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

async fn load_latest_private_group_epoch(
    pool: &sqlx::AnyPool,
    group_id: &str,
) -> Result<i64, AppError> {
    let latest_epoch = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(epoch) AS latest_epoch
         FROM private_group_states
         WHERE group_id = $1",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?
    .ok_or_else(|| AppError::not_found("private group state not found"))?;
    Ok(latest_epoch)
}

async fn authorize_current_private_group_publish_capability(
    state: &AppState,
    group_id: &str,
    epoch: i64,
    membership_handle_sha256: &str,
    publish_key_sha256: &str,
) -> Result<(), AppError> {
    let latest_epoch = load_latest_private_group_epoch(state.pool(), group_id).await?;
    if epoch != latest_epoch {
        return Err(AppError::conflict(
            "private group invite epoch is stale; refresh state first",
        ));
    }

    let row = sqlx::query(
        "SELECT publish_key_sha256
         FROM private_group_member_credentials
         WHERE membership_handle_sha256 = $1
           AND group_id = $2
           AND epoch = $3
           AND revoked_at IS NULL",
    )
    .bind(membership_handle_sha256)
    .bind(group_id)
    .bind(latest_epoch)
    .fetch_optional(state.pool())
    .await?;
    let Some(row) = row else {
        return Err(AppError::forbidden(
            "authorizing private group membership handle is not active for the latest epoch",
        ));
    };
    let stored_publish_key_sha256: Option<String> = row.try_get("publish_key_sha256")?;
    if stored_publish_key_sha256.as_deref() != Some(publish_key_sha256) {
        return Err(AppError::forbidden(
            "authorizing private group publish key is invalid",
        ));
    }
    Ok(())
}

fn map_private_group_conflict(error: sqlx::Error, detail: &'static str) -> AppError {
    match error {
        sqlx::Error::Database(database_error)
            if database_error.is_unique_violation()
                || database_error.is_foreign_key_violation() =>
        {
            AppError::conflict(detail)
        }
        other => other.into(),
    }
}
