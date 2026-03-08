use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Utc;

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::AppState;

const MAX_CHANNEL_NAME_LEN: usize = 128;
const MAX_CHANNEL_DESC_LEN: usize = 1024;
const MAX_CHANNEL_MESSAGE_BYTES: usize = 256 * 1024;

/// POST /v1/channels
pub(crate) async fn create_channel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateChannelRequest>,
) -> Result<Json<CreateChannelResponse>, AppError> {
    check_rate_limit(&state, &format!("channel-create:{}", request.owner_user_id))?;
    validate_id("owner_user_id", &request.owner_user_id)?;
    validate_id("device_id", &request.device_id)?;

    if request.display_name.trim().is_empty() || request.display_name.len() > MAX_CHANNEL_NAME_LEN {
        return Err(AppError::bad_request(
            "display_name must be 1..=128 characters",
        ));
    }
    if request.description.len() > MAX_CHANNEL_DESC_LEN {
        return Err(AppError::bad_request(
            "description must be <= 1024 characters",
        ));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.owner_user_id {
        return Err(AppError::bad_request(
            "auth user_id must match owner_user_id",
        ));
    }
    let auth_message = format!("channel-create:{}:{}", auth.user_id, auth.device_id);
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;
    ensure_user_exists(state.pool(), &request.owner_user_id).await?;

    let now = Utc::now().to_rfc3339();
    let channel_id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO channels (channel_id, owner_user_id, display_name, description, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&channel_id)
    .bind(&request.owner_user_id)
    .bind(request.display_name.trim())
    .bind(request.description.trim())
    .bind(&now)
    .execute(state.pool())
    .await?;

    // Auto-subscribe the owner
    sqlx::query(
        "INSERT INTO channel_subscribers (channel_id, user_id, subscribed_at) VALUES ($1, $2, $3)",
    )
    .bind(&channel_id)
    .bind(&request.owner_user_id)
    .bind(&now)
    .execute(state.pool())
    .await?;

    Ok(Json(CreateChannelResponse {
        channel_id,
        created_at: now,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ChannelMessagesQuery {
    pub(crate) since: Option<i64>,
}

/// GET /v1/channels/:channel_id/messages
pub(crate) async fn get_channel_messages(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<ChannelMessagesQuery>,
) -> Result<Json<ChannelMessagesResponse>, AppError> {
    let auth = parse_request_auth(&headers)?;
    let auth_message = format!(
        "channel-messages:{}:{}:{}",
        auth.user_id, auth.device_id, channel_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify subscriber
    let subscribed: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM channel_subscribers WHERE channel_id = $1 AND user_id = $2",
    )
    .bind(&channel_id)
    .bind(&auth.user_id)
    .fetch_one(state.pool())
    .await
    .unwrap_or(false);

    if !subscribed {
        return Err(AppError::bad_request(
            "must be subscribed to read channel messages",
        ));
    }

    let since = query.since.unwrap_or(0);
    let rows = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT message_id, content_base64, created_at
         FROM channel_messages
         WHERE channel_id = $1 AND message_id > $2
         ORDER BY message_id ASC
         LIMIT 100",
    )
    .bind(&channel_id)
    .bind(since)
    .fetch_all(state.pool())
    .await?;

    let messages = rows
        .into_iter()
        .map(|(mid, content, cat)| ChannelMessageItem {
            message_id: mid,
            content_base64: content,
            created_at: cat,
        })
        .collect();

    Ok(Json(ChannelMessagesResponse {
        channel_id,
        messages,
    }))
}

/// POST /v1/channels/:channel_id/messages
pub(crate) async fn post_channel_message(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ChannelMessageRequest>,
) -> Result<Json<ChannelMessageResponse>, AppError> {
    check_rate_limit(&state, &format!("channel-msg:{channel_id}"))?;
    validate_id("owner_user_id", &request.owner_user_id)?;
    validate_id("device_id", &request.device_id)?;
    decode_base64_range(
        "content_base64",
        &request.content_base64,
        1,
        MAX_CHANNEL_MESSAGE_BYTES,
    )?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.owner_user_id {
        return Err(AppError::bad_request(
            "auth user_id must match owner_user_id",
        ));
    }
    let auth_message = format!(
        "channel-post:{}:{}:{}",
        auth.user_id, auth.device_id, channel_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify the user is the channel owner (admin-only send)
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_user_id FROM channels WHERE channel_id = $1")
            .bind(&channel_id)
            .fetch_optional(state.pool())
            .await?;

    match owner {
        None => return Err(AppError::not_found("channel not found")),
        Some(ref o) if o != &request.owner_user_id => {
            return Err(AppError::bad_request(
                "only the channel owner can post messages",
            ));
        }
        _ => {}
    }

    let now = Utc::now().to_rfc3339();
    let message_id: i64 = sqlx::query_scalar(
        "INSERT INTO channel_messages (channel_id, content_base64, created_at)
         VALUES ($1, $2, $3)
         RETURNING message_id",
    )
    .bind(&channel_id)
    .bind(&request.content_base64)
    .bind(&now)
    .fetch_one(state.pool())
    .await?;

    Ok(Json(ChannelMessageResponse {
        message_id,
        created_at: now,
    }))
}

/// POST /v1/channels/:channel_id/subscribe
pub(crate) async fn subscribe_channel(
    State(state): State<AppState>,
    Path(channel_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SubscribeChannelResponse>, AppError> {
    let auth = parse_request_auth(&headers)?;
    let auth_message = format!(
        "channel-subscribe:{}:{}:{}",
        auth.user_id, auth.device_id, channel_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify channel exists
    let exists: bool =
        sqlx::query_scalar("SELECT COUNT(*) > 0 FROM channels WHERE channel_id = $1")
            .bind(&channel_id)
            .fetch_one(state.pool())
            .await
            .unwrap_or(false);

    if !exists {
        return Err(AppError::not_found("channel not found"));
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO channel_subscribers (channel_id, user_id, subscribed_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (channel_id, user_id) DO NOTHING",
    )
    .bind(&channel_id)
    .bind(&auth.user_id)
    .bind(&now)
    .execute(state.pool())
    .await?;

    Ok(Json(SubscribeChannelResponse {
        channel_id,
        subscribed_at: now,
    }))
}

/// GET /v1/channels
pub(crate) async fn list_channels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ChannelListResponse>, AppError> {
    let auth = parse_request_auth(&headers)?;
    let auth_message = format!("channel-list:{}:{}", auth.user_id, auth.device_id);
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
        "SELECT c.channel_id, c.owner_user_id, c.display_name, c.description, c.created_at
         FROM channels c
         INNER JOIN channel_subscribers cs ON cs.channel_id = c.channel_id
         WHERE cs.user_id = $1
         ORDER BY c.created_at DESC
         LIMIT 100",
    )
    .bind(&auth.user_id)
    .fetch_all(state.pool())
    .await?;

    let mut channels = Vec::with_capacity(rows.len());
    for (cid, owner, name, desc, cat) in rows {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM channel_subscribers WHERE channel_id = $1")
                .bind(&cid)
                .fetch_one(state.pool())
                .await
                .unwrap_or(0);
        channels.push(ChannelInfo {
            channel_id: cid,
            owner_user_id: owner,
            display_name: name,
            description: desc,
            subscriber_count: count,
            created_at: cat,
        });
    }

    Ok(Json(ChannelListResponse { channels }))
}
