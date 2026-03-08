use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::Row;

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{AppState, MAX_GROUP_MEMBERS, MAX_MESSAGE_BYTES};

pub(crate) async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateGroupRequest>,
) -> Result<Json<CreateGroupResponse>, AppError> {
    check_rate_limit(&state, "groups-create")?;
    validate_id("group_id", &request.group_id)?;
    let mut member_user_ids = normalize_group_members(&request.member_user_ids)?;

    let auth = parse_request_auth(&headers)?;
    let auth_message = group_create_auth_message(&auth, &request.group_id, &member_user_ids)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(state.pool(), &auth.user_id).await?;
    if !member_user_ids.iter().any(|member| member == &auth.user_id) {
        member_user_ids.push(auth.user_id.clone());
        member_user_ids.sort_unstable();
        member_user_ids.dedup();
    }
    if member_user_ids.len() > MAX_GROUP_MEMBERS {
        return Err(AppError::bad_request(format!(
            "member_user_ids cannot exceed {MAX_GROUP_MEMBERS}"
        )));
    }
    for member_user_id in &member_user_ids {
        ensure_user_exists(state.pool(), member_user_id).await?;
    }

    let existing = sqlx::query("SELECT owner_user_id FROM groups WHERE group_id = $1")
        .bind(&request.group_id)
        .fetch_optional(state.pool())
        .await?;
    if existing.is_some() {
        return Err(AppError::conflict("group_id already exists"));
    }

    let now = Utc::now().to_rfc3339();
    let mut tx = state.pool().begin().await?;
    sqlx::query(
        "INSERT INTO groups (group_id, owner_user_id, created_at, updated_at)
         VALUES ($1, $2, $3, $3)",
    )
    .bind(&request.group_id)
    .bind(&auth.user_id)
    .bind(&now)
    .execute(&mut *tx)
    .await?;
    for member_user_id in &member_user_ids {
        sqlx::query(
            "INSERT INTO group_members (
                group_id,
                user_id,
                added_by_user_id,
                joined_at,
                removed_at
             ) VALUES ($1, $2, $3, $4, NULL)",
        )
        .bind(&request.group_id)
        .bind(member_user_id)
        .bind(&auth.user_id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    Ok(Json(CreateGroupResponse {
        group_id: request.group_id,
        owner_user_id: auth.user_id,
        member_count: member_user_ids.len(),
        created_at: now,
    }))
}

pub(crate) async fn list_group_members(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<GroupMembersResponse>, AppError> {
    check_rate_limit(&state, &format!("groups-members-list:{group_id}"))?;
    validate_id("group_id", &group_id)?;

    let auth = parse_request_auth(&headers)?;
    let auth_message = group_members_list_auth_message(&auth, &group_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    if !is_active_group_member(state.pool(), &group_id, &auth.user_id).await? {
        return Err(AppError::not_found("group not found"));
    }

    let rows = sqlx::query(
        "SELECT user_id, joined_at
         FROM group_members
         WHERE group_id = $1 AND removed_at IS NULL
         ORDER BY joined_at ASC, user_id ASC",
    )
    .bind(&group_id)
    .fetch_all(state.pool())
    .await?;
    let mut members = Vec::with_capacity(rows.len());
    for row in rows {
        members.push(GroupMemberRecord {
            user_id: row.try_get("user_id")?,
            joined_at: row.try_get("joined_at")?,
        });
    }

    Ok(Json(GroupMembersResponse { group_id, members }))
}

pub(crate) async fn add_group_member(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AddGroupMemberRequest>,
) -> Result<Json<GroupMemberMutationResponse>, AppError> {
    check_rate_limit(&state, &format!("groups-members-add:{group_id}"))?;
    validate_id("group_id", &group_id)?;
    validate_id("member_user_id", &request.member_user_id)?;

    let auth = parse_request_auth(&headers)?;
    let auth_message = group_members_add_auth_message(&auth, &group_id, &request.member_user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let owner_user_id = load_group_owner_user_id(state.pool(), &group_id).await?;
    if auth.user_id != owner_user_id {
        return Err(AppError::bad_request("only group owner can add members"));
    }
    ensure_user_exists(state.pool(), &request.member_user_id).await?;

    let active_count = count_active_group_members(state.pool(), &group_id).await?;
    if active_count >= MAX_GROUP_MEMBERS as i64
        && !is_active_group_member(state.pool(), &group_id, &request.member_user_id).await?
    {
        return Err(AppError::bad_request(format!(
            "group member count cannot exceed {MAX_GROUP_MEMBERS}"
        )));
    }

    let now = Utc::now().to_rfc3339();
    let changed = sqlx::query(
        "INSERT INTO group_members (
            group_id,
            user_id,
            added_by_user_id,
            joined_at,
            removed_at
         ) VALUES ($1, $2, $3, $4, NULL)
         ON CONFLICT (group_id, user_id) DO UPDATE SET
            added_by_user_id = EXCLUDED.added_by_user_id,
            joined_at = EXCLUDED.joined_at,
            removed_at = NULL",
    )
    .bind(&group_id)
    .bind(&request.member_user_id)
    .bind(&auth.user_id)
    .bind(&now)
    .execute(state.pool())
    .await?
    .rows_affected()
        > 0;
    sqlx::query("UPDATE groups SET updated_at = $1 WHERE group_id = $2")
        .bind(&now)
        .bind(&group_id)
        .execute(state.pool())
        .await?;

    Ok(Json(GroupMemberMutationResponse {
        group_id,
        member_user_id: request.member_user_id,
        owner_user_id,
        changed,
        updated_at: now,
    }))
}

pub(crate) async fn remove_group_member(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RemoveGroupMemberRequest>,
) -> Result<Json<GroupMemberMutationResponse>, AppError> {
    check_rate_limit(&state, &format!("groups-members-remove:{group_id}"))?;
    validate_id("group_id", &group_id)?;
    validate_id("member_user_id", &request.member_user_id)?;

    let auth = parse_request_auth(&headers)?;
    let auth_message =
        group_members_remove_auth_message(&auth, &group_id, &request.member_user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let owner_user_id = load_group_owner_user_id(state.pool(), &group_id).await?;
    if auth.user_id != owner_user_id {
        return Err(AppError::bad_request("only group owner can remove members"));
    }
    if request.member_user_id == owner_user_id {
        return Err(AppError::bad_request("group owner cannot be removed"));
    }

    let now = Utc::now().to_rfc3339();
    let changed = sqlx::query(
        "UPDATE group_members
         SET removed_at = $1
         WHERE group_id = $2 AND user_id = $3 AND removed_at IS NULL",
    )
    .bind(&now)
    .bind(&group_id)
    .bind(&request.member_user_id)
    .execute(state.pool())
    .await?
    .rows_affected()
        > 0;
    sqlx::query("UPDATE groups SET updated_at = $1 WHERE group_id = $2")
        .bind(&now)
        .bind(&group_id)
        .execute(state.pool())
        .await?;

    Ok(Json(GroupMemberMutationResponse {
        group_id,
        member_user_id: request.member_user_id,
        owner_user_id,
        changed,
        updated_at: now,
    }))
}

pub(crate) async fn relay_group_message(
    State(state): State<AppState>,
    Path(group_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<GroupRelayRequest>,
) -> Result<Json<GroupRelayResponse>, AppError> {
    check_rate_limit(&state, &format!("groups-relay:{group_id}"))?;
    validate_id("group_id", &group_id)?;
    validate_id("sender_user_id", &request.sender_user_id)?;
    validate_id("device_id", &request.device_id)?;
    let blob = decode_base64_max(
        "message_bytes_base64",
        &request.message_bytes_base64,
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
    let auth_message = group_relay_auth_message(&auth, &group_id, &request.sender_user_id, &blob)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    if !is_active_group_member(state.pool(), &group_id, &request.sender_user_id).await? {
        return Err(AppError::not_found("group not found"));
    }

    let mut hasher = Sha256::new();
    hasher.update(group_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(request.sender_user_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(&blob);
    let dedup_key = format!("group:{:x}", hasher.finalize());
    if !observe_relay_dedup(&state, &dedup_key).await? {
        return Err(AppError::conflict("duplicate group relay payload"));
    }

    let all_member_devices = load_active_group_member_devices(state.pool(), &group_id).await?;
    if all_member_devices.is_empty() {
        return Err(AppError::not_found("group not found"));
    }

    let delivery_targets: Vec<&(String, String)> = all_member_devices
        .iter()
        .filter(|(user_id, device_id)| {
            !(user_id == &request.sender_user_id && device_id == &request.device_id)
        })
        .collect();

    let member_user_ids: Vec<&str> = all_member_devices
        .iter()
        .map(|(user_id, _)| user_id.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let now = Utc::now().to_rfc3339();
    let mut tx = state.pool().begin().await?;
    let delivery_count = delivery_targets.len();
    let mut deliveries: Vec<(&str, &str, i64, InboxItem)> =
        Vec::with_capacity(delivery_count);
    for (recipient_user_id, recipient_device_id) in delivery_targets {
        let message_id = sqlx::query_scalar::<_, i64>(
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
        .bind(recipient_user_id.as_str())
        .bind(recipient_device_id.as_str())
        .bind(&request.sender_user_id)
        .bind(&request.device_id)
        .bind(&blob)
        .bind(&now)
        .fetch_one(&mut *tx)
        .await?;
        deliveries.push((
            recipient_user_id.as_str(),
            recipient_device_id.as_str(),
            message_id,
            InboxItem {
                message_id,
                sender_user_id: request.sender_user_id.clone(),
                message_bytes_base64: request.message_bytes_base64.clone(),
                received_at: now.clone(),
            },
        ));
    }
    tx.commit().await?;

    for (recipient_user_id, recipient_device_id, _, item) in &deliveries {
        state
            .realtime_hub()
            .publish(recipient_user_id, recipient_device_id, item.clone());
    }

    let delivered_users = deliveries
        .iter()
        .filter(|(recipient_user_id, _, _, _)| *recipient_user_id != request.sender_user_id)
        .map(|(recipient_user_id, _, _, _)| *recipient_user_id)
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    for recipient_user_id in &member_user_ids {
        if *recipient_user_id == request.sender_user_id {
            let _ = dispatch_push_wake_signals(&state, recipient_user_id, &request.device_id).await;
            continue;
        }
        let _ = dispatch_push_wake_signals(&state, recipient_user_id, "").await;
    }

    let first_message_id = deliveries.first().map(|(_, _, message_id, _)| *message_id);

    Ok(Json(GroupRelayResponse {
        group_id,
        delivered_message_count: delivery_count,
        delivered_user_count: delivered_users,
        first_message_id,
        received_at: now,
    }))
}
