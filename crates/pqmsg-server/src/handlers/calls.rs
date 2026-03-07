use axum::extract::{Path, State};
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

/// POST /v1/calls/:callee_user_id/offer
/// Initiates a call by sending an SDP offer. Stores the signaling data for the callee to poll.
pub(crate) async fn call_offer(
    State(state): State<AppState>,
    Path(callee_user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CallOfferRequest>,
) -> Result<Json<CallOfferResponse>, AppError> {
    check_rate_limit(&state, &format!("call-offer:{callee_user_id}"))?;
    validate_id("callee_user_id", &callee_user_id)?;
    validate_id("caller_user_id", &request.caller_user_id)?;
    validate_id("device_id", &request.device_id)?;

    if !["audio", "video"].contains(&request.call_type.as_str()) {
        return Err(AppError::bad_request("call_type must be 'audio' or 'video'"));
    }
    decode_base64_range("sdp_offer_base64", &request.sdp_offer_base64, 1, 64 * 1024)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.caller_user_id {
        return Err(AppError::bad_request(
            "auth user_id must match caller_user_id",
        ));
    }
    let auth_message = format!(
        "call-offer:{}:{}:{}",
        auth.user_id, auth.device_id, callee_user_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    ensure_user_exists(state.pool(), &callee_user_id).await?;
    ensure_user_exists(state.pool(), &request.caller_user_id).await?;

    let now = Utc::now();
    let now_str = now.to_rfc3339();
    let call_id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO call_sessions (call_id, caller_user_id, callee_user_id, call_type, status, created_at)
         VALUES ($1, $2, $3, $4, 'ringing', $5)",
    )
    .bind(&call_id)
    .bind(&request.caller_user_id)
    .bind(&callee_user_id)
    .bind(&request.call_type)
    .bind(&now_str)
    .execute(state.pool())
    .await?;

    sqlx::query(
        "INSERT INTO call_signals (call_id, signal_type, from_user_id, payload_base64, created_at)
         VALUES ($1, 'offer', $2, $3, $4)",
    )
    .bind(&call_id)
    .bind(&request.caller_user_id)
    .bind(&request.sdp_offer_base64)
    .bind(&now_str)
    .execute(state.pool())
    .await?;

    Ok(Json(CallOfferResponse {
        call_id,
        created_at: now_str,
    }))
}

/// POST /v1/calls/:call_id/answer
/// Callee answers an incoming call with their SDP answer.
pub(crate) async fn call_answer(
    State(state): State<AppState>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CallAnswerRequest>,
) -> Result<Json<CallAnswerResponse>, AppError> {
    check_rate_limit(&state, &format!("call-answer:{call_id}"))?;
    validate_id("callee_user_id", &request.callee_user_id)?;
    validate_id("device_id", &request.device_id)?;
    decode_base64_range("sdp_answer_base64", &request.sdp_answer_base64, 1, 64 * 1024)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.callee_user_id {
        return Err(AppError::bad_request(
            "auth user_id must match callee_user_id",
        ));
    }
    let auth_message = format!(
        "call-answer:{}:{}:{}",
        auth.user_id, auth.device_id, call_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify the call exists and callee matches
    let callee: Option<String> = sqlx::query_scalar(
        "SELECT callee_user_id FROM call_sessions WHERE call_id = $1 AND status = 'ringing'",
    )
    .bind(&call_id)
    .fetch_optional(state.pool())
    .await?;

    match callee {
        Some(ref expected) if expected == &request.callee_user_id => {}
        Some(_) => {
            return Err(AppError::bad_request(
                "callee_user_id does not match the call session",
            ));
        }
        None => {
            return Err(AppError::not_found("call session not found or not ringing"));
        }
    }

    let now_str = Utc::now().to_rfc3339();

    sqlx::query("UPDATE call_sessions SET status = 'active', answered_at = $1 WHERE call_id = $2")
        .bind(&now_str)
        .bind(&call_id)
        .execute(state.pool())
        .await?;

    sqlx::query(
        "INSERT INTO call_signals (call_id, signal_type, from_user_id, payload_base64, created_at)
         VALUES ($1, 'answer', $2, $3, $4)",
    )
    .bind(&call_id)
    .bind(&request.callee_user_id)
    .bind(&request.sdp_answer_base64)
    .bind(&now_str)
    .execute(state.pool())
    .await?;

    Ok(Json(CallAnswerResponse {
        call_id: call_id.clone(),
        answered_at: now_str,
    }))
}

/// POST /v1/calls/:call_id/ice
/// Exchange ICE candidates for NAT traversal.
pub(crate) async fn call_ice_candidate(
    State(state): State<AppState>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<IceCandidateRequest>,
) -> Result<Json<IceCandidateResponse>, AppError> {
    check_rate_limit(&state, &format!("call-ice:{call_id}"))?;
    validate_id("sender_user_id", &request.sender_user_id)?;
    validate_id("device_id", &request.device_id)?;
    decode_base64_range("candidate_base64", &request.candidate_base64, 1, 16 * 1024)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.sender_user_id {
        return Err(AppError::bad_request(
            "auth user_id must match sender_user_id",
        ));
    }
    let auth_message = format!(
        "call-ice:{}:{}:{}",
        auth.user_id, auth.device_id, call_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify the call exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM call_sessions WHERE call_id = $1 AND status IN ('ringing', 'active'))",
    )
    .bind(&call_id)
    .fetch_one(state.pool())
    .await?;

    if !exists {
        return Err(AppError::not_found("call session not found or already ended"));
    }

    let now_str = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO call_signals (call_id, signal_type, from_user_id, payload_base64, created_at)
         VALUES ($1, 'ice-candidate', $2, $3, $4)",
    )
    .bind(&call_id)
    .bind(&request.sender_user_id)
    .bind(&request.candidate_base64)
    .bind(&now_str)
    .execute(state.pool())
    .await?;

    Ok(Json(IceCandidateResponse {
        call_id: call_id.clone(),
        queued_at: now_str,
    }))
}

/// POST /v1/calls/:call_id/hangup
/// End an active or ringing call.
pub(crate) async fn call_hangup(
    State(state): State<AppState>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CallHangupRequest>,
) -> Result<Json<CallHangupResponse>, AppError> {
    check_rate_limit(&state, &format!("call-hangup:{call_id}"))?;
    validate_id("user_id", &request.user_id)?;
    validate_id("device_id", &request.device_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != request.user_id {
        return Err(AppError::bad_request("auth user_id must match request user_id"));
    }
    let auth_message = format!(
        "call-hangup:{}:{}:{}",
        auth.user_id, auth.device_id, call_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify user is part of the call
    let participant: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM call_sessions WHERE call_id = $1 AND (caller_user_id = $2 OR callee_user_id = $2) AND status IN ('ringing', 'active'))",
    )
    .bind(&call_id)
    .bind(&request.user_id)
    .fetch_one(state.pool())
    .await?;

    if !participant {
        return Err(AppError::not_found(
            "call session not found or user is not a participant",
        ));
    }

    let now_str = Utc::now().to_rfc3339();
    let reason = request.reason.as_deref().unwrap_or("normal");

    sqlx::query(
        "UPDATE call_sessions SET status = 'ended', ended_at = $1, end_reason = $2 WHERE call_id = $3",
    )
    .bind(&now_str)
    .bind(reason)
    .bind(&call_id)
    .execute(state.pool())
    .await?;

    sqlx::query(
        "INSERT INTO call_signals (call_id, signal_type, from_user_id, payload_base64, created_at)
         VALUES ($1, 'hangup', $2, $3, $4)",
    )
    .bind(&call_id)
    .bind(&request.user_id)
    .bind(reason)
    .bind(&now_str)
    .execute(state.pool())
    .await?;

    Ok(Json(CallHangupResponse {
        call_id: call_id.clone(),
        ended_at: now_str,
    }))
}

/// GET /v1/calls/:call_id/signals?since=<signal_id>
/// Poll for new call signals (SDP offers/answers, ICE candidates, hangups).
pub(crate) async fn poll_call_signals(
    State(state): State<AppState>,
    Path(call_id): Path<String>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<CallSignalsQuery>,
) -> Result<Json<PollCallSignalsResponse>, AppError> {
    check_rate_limit(&state, &format!("call-signals:{call_id}"))?;

    let auth = parse_request_auth(&headers)?;
    let auth_message = format!(
        "call-signals:{}:{}:{}",
        auth.user_id, auth.device_id, call_id
    );
    verify_request_auth(&state, &auth, auth_message.as_bytes()).await?;

    // Verify user is part of the call
    let participant: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM call_sessions WHERE call_id = $1 AND (caller_user_id = $2 OR callee_user_id = $2))",
    )
    .bind(&call_id)
    .bind(&auth.user_id)
    .fetch_one(state.pool())
    .await?;

    if !participant {
        return Err(AppError::not_found(
            "call session not found or user is not a participant",
        ));
    }

    let since = query.since.unwrap_or(0);
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT signal_type, from_user_id, payload_base64, created_at
         FROM call_signals
         WHERE call_id = $1 AND signal_id > $2 AND from_user_id != $3
         ORDER BY signal_id ASC
         LIMIT 50",
    )
    .bind(&call_id)
    .bind(since)
    .bind(&auth.user_id)
    .fetch_all(state.pool())
    .await?;

    let signals = rows
        .into_iter()
        .map(|(signal_type, from_user_id, payload_base64, created_at)| CallSignal {
            signal_type,
            from_user_id,
            payload_base64,
            created_at,
        })
        .collect();

    Ok(Json(PollCallSignalsResponse {
        call_id: call_id.clone(),
        signals,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct CallSignalsQuery {
    pub(crate) since: Option<i64>,
}
