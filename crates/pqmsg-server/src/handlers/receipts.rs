use axum::extract::{Path, Query, State};
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
use crate::AppState;

const MAX_RECEIPTS_PAGE: i64 = 200;

pub(crate) async fn send_receipt(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SendReceiptRequest>,
) -> Result<Json<SendReceiptResponse>, AppError> {
    check_rate_limit(&state, &format!("receipt:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    if request.receipt_type != "delivered" && request.receipt_type != "read" {
        return Err(AppError::bad_request(
            "receipt_type must be 'delivered' or 'read'",
        ));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = format!(
        "receipt:{}:{}:{}:{}",
        auth.user_id, auth.device_id, request.message_id, request.receipt_type
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO message_receipts (message_id, recipient_user_id, recipient_device_id, receipt_type, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (message_id, recipient_user_id, recipient_device_id, receipt_type) DO UPDATE SET created_at = $5",
    )
    .bind(request.message_id)
    .bind(&user_id)
    .bind(&auth.device_id)
    .bind(&request.receipt_type)
    .bind(&now)
    .execute(state.pool())
    .await?;

    record_security_event(
        &state,
        "receipt_sent",
        "ok",
        None,
        Some(&user_id),
        Some(&auth.device_id),
        Some(format!(
            "message_id={} type={}",
            request.message_id, request.receipt_type
        )),
    );

    Ok(Json(SendReceiptResponse {
        message_id: request.message_id,
        receipt_type: request.receipt_type,
        created_at: now,
    }))
}

pub(crate) async fn get_receipts(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<ReceiptsQuery>,
) -> Result<Json<ReceiptsResponse>, AppError> {
    check_rate_limit(&state, &format!("get-receipts:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let since_id = query.since_id.unwrap_or(0);
    let auth_message = format!(
        "get-receipts:{}:{}:{}",
        auth.user_id, auth.device_id, since_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Fetch receipts for messages originally sent by this user
    let rows = sqlx::query(
        "SELECT r.id, r.message_id, r.recipient_user_id, r.recipient_device_id, r.receipt_type, r.created_at
         FROM message_receipts r
         INNER JOIN relay_messages m ON m.message_id = r.message_id
         WHERE m.sender_user_id = $1 AND r.id > $2
         ORDER BY r.id ASC
         LIMIT $3",
    )
    .bind(&user_id)
    .bind(since_id)
    .bind(MAX_RECEIPTS_PAGE)
    .fetch_all(state.pool())
    .await?;

    let mut receipts = Vec::with_capacity(rows.len());
    for row in rows {
        receipts.push(ReceiptItem {
            message_id: row.try_get("message_id")?,
            recipient_user_id: row.try_get("recipient_user_id")?,
            recipient_device_id: row.try_get("recipient_device_id")?,
            receipt_type: row.try_get("receipt_type")?,
            created_at: row.try_get("created_at")?,
        });
    }

    Ok(Json(ReceiptsResponse {
        sender_user_id: user_id,
        receipts,
    }))
}
