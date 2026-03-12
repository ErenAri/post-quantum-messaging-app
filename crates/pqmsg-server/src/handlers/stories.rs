use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{Duration, Utc};

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::AppState;

const STORY_TTL_HOURS: i64 = 24;
const MAX_STORY_CONTENT_BYTES: usize = 512 * 1024;

fn ensure_stories_supported(state: &AppState) -> Result<(), AppError> {
    if !state.stories_supported() {
        return Err(AppError::forbidden(
            "stories are disabled in the private-messaging-only profile",
        ));
    }
    Ok(())
}

/// POST /v1/stories
pub(crate) async fn create_story(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateStoryRequest>,
) -> Result<Json<CreateStoryResponse>, AppError> {
    check_rate_limit(&state, &format!("story-create:{}", request.author_user_id))?;
    ensure_stories_supported(&state)?;
    validate_id("author_user_id", &request.author_user_id)?;
    validate_id("device_id", &request.device_id)?;
    decode_base64_range(
        "content_base64",
        &request.content_base64,
        1,
        MAX_STORY_CONTENT_BYTES,
    )?;
    if !["text", "image", "video"].contains(&request.media_type.as_str()) {
        return Err(AppError::bad_request(
            "media_type must be 'text', 'image', or 'video'",
        ));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.author_user_id {
        return Err(AppError::bad_request(
            "auth user_id must match author_user_id",
        ));
    }
    let auth_message = format!("story-create:{}:{}", auth.user_id, auth.device_id);
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;
    ensure_user_exists(state.pool(), &request.author_user_id).await?;

    let now = Utc::now();
    let expires = now + Duration::hours(STORY_TTL_HOURS);
    let story_id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO stories (story_id, author_user_id, content_base64, media_type, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&story_id)
    .bind(&request.author_user_id)
    .bind(&request.content_base64)
    .bind(&request.media_type)
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(state.pool())
    .await?;

    Ok(Json(CreateStoryResponse {
        story_id,
        created_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
    }))
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct StoriesFeedQuery {
    pub(crate) user_id: Option<String>,
}

/// GET /v1/stories/feed
pub(crate) async fn get_stories_feed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<StoriesFeedQuery>,
) -> Result<Json<StoriesFeedResponse>, AppError> {
    ensure_stories_supported(&state)?;
    let auth = parse_request_auth(&headers)?;
    let auth_message = format!("story-feed:{}:{}", auth.user_id, auth.device_id);
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    let now = Utc::now().to_rfc3339();

    let stories: Vec<StoryItem> = if let Some(ref author) = query.user_id {
        validate_id("user_id", author)?;
        let rows = sqlx::query_as::<_, (String, String, String, String, String, String)>(
            "SELECT s.story_id, s.author_user_id, s.content_base64, s.media_type, s.created_at, s.expires_at
             FROM stories s
             WHERE s.author_user_id = $1 AND s.expires_at > $2
             ORDER BY s.created_at DESC
             LIMIT 50",
        )
        .bind(author)
        .bind(&now)
        .fetch_all(state.pool())
        .await?;

        let mut items = Vec::with_capacity(rows.len());
        for (sid, auid, content, mt, cat, eat) in rows {
            let vc: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM story_views WHERE story_id = $1")
                    .bind(&sid)
                    .fetch_one(state.pool())
                    .await
                    .unwrap_or(0);
            items.push(StoryItem {
                story_id: sid,
                author_user_id: auid,
                content_base64: content,
                media_type: mt,
                created_at: cat,
                expires_at: eat,
                view_count: vc,
            });
        }
        items
    } else {
        // Fetch stories from contacts or all users (for demo, all non-expired)
        let rows = sqlx::query_as::<_, (String, String, String, String, String, String)>(
            "SELECT s.story_id, s.author_user_id, s.content_base64, s.media_type, s.created_at, s.expires_at
             FROM stories s
             WHERE s.expires_at > $1
             ORDER BY s.created_at DESC
             LIMIT 100",
        )
        .bind(&now)
        .fetch_all(state.pool())
        .await?;

        let mut items = Vec::with_capacity(rows.len());
        for (sid, auid, content, mt, cat, eat) in rows {
            let vc: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM story_views WHERE story_id = $1")
                    .bind(&sid)
                    .fetch_one(state.pool())
                    .await
                    .unwrap_or(0);
            items.push(StoryItem {
                story_id: sid,
                author_user_id: auid,
                content_base64: content,
                media_type: mt,
                created_at: cat,
                expires_at: eat,
                view_count: vc,
            });
        }
        items
    };

    Ok(Json(StoriesFeedResponse { stories }))
}

/// POST /v1/stories/:story_id/view
pub(crate) async fn view_story(
    State(state): State<AppState>,
    Path(story_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ViewStoryResponse>, AppError> {
    ensure_stories_supported(&state)?;
    let auth = parse_request_auth(&headers)?;
    let auth_message = format!(
        "story-view:{}:{}:{}",
        auth.user_id, auth.device_id, story_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify story exists and is not expired
    let exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 FROM stories WHERE story_id = $1 AND expires_at > $2",
    )
    .bind(&story_id)
    .bind(Utc::now().to_rfc3339())
    .fetch_one(state.pool())
    .await
    .unwrap_or(false);

    if !exists {
        return Err(AppError::not_found("story not found or expired"));
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO story_views (story_id, viewer_user_id, viewed_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (story_id, viewer_user_id) DO NOTHING",
    )
    .bind(&story_id)
    .bind(&auth.user_id)
    .bind(&now)
    .execute(state.pool())
    .await?;

    Ok(Json(ViewStoryResponse {
        story_id,
        viewed_at: now,
    }))
}
