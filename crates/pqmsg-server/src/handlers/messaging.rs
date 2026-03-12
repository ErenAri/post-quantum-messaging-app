use std::time::Duration as StdDuration;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{Duration, Utc};
use ed25519_dalek::Signer;
use futures_util::{SinkExt, StreamExt};
use pqmsg_core::sealed::{SenderCertificate, SENDER_CERT_VALIDITY_SECS};
use sha2::{Digest, Sha256};
use sqlx::{AnyPool, Row};

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::ephemeral_state::WsInboxTicketRecord;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{
    AppState, MAX_DELETE_MESSAGE_IDS, MAX_INBOX_PAGE, MAX_MESSAGE_BYTES, SEALED_DELIVERY_TOKEN_LEN,
};

fn ensure_authenticated_direct_messaging_supported(state: &AppState) -> Result<(), AppError> {
    if state.authenticated_direct_messaging_supported() {
        Ok(())
    } else {
        Err(AppError::forbidden(
            "legacy authenticated direct messaging is disabled; use sealed relay/inbox",
        ))
    }
}

pub(crate) async fn ws_inbox(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<WsInboxQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    ensure_authenticated_direct_messaging_supported(&state)?;
    check_rate_limit(&state, &format!("ws-inbox:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let (device_id, since) =
        authenticate_ws_inbox_connection(&state, &user_id, &headers, &query).await?;

    Ok(ws.on_upgrade(move |socket| async move {
        handle_ws_inbox_socket(state, user_id, device_id, since, socket).await;
    }))
}

pub(crate) async fn create_ws_inbox_ticket(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<InboxQuery>,
) -> Result<Json<WsInboxTicketResponse>, AppError> {
    ensure_authenticated_direct_messaging_supported(&state)?;
    check_rate_limit(&state, &format!("ws-inbox-ticket:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(AppError::bad_request("since must be non-negative"));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = inbox_auth_message(&auth, &user_id, since)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    enforce_inbox_cursor_monotonic(&state, &user_id, &auth.device_id, since).await?;

    purge_expired_ws_inbox_tickets(&state).await?;
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(30);
    let ticket = uuid::Uuid::new_v4().to_string();
    if state.ephemeral_state().is_distributed() {
        state.ephemeral_state().put_ws_ticket(
            &ticket,
            &WsInboxTicketRecord {
                user_id: user_id.clone(),
                device_id: auth.device_id.clone(),
                since,
                expires_at: expires_at.to_rfc3339(),
            },
            30,
        )?;
    } else {
        sqlx::query(
            "INSERT INTO ws_inbox_tickets (ticket, user_id, device_id, since, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&ticket)
        .bind(&user_id)
        .bind(&auth.device_id)
        .bind(since)
        .bind(issued_at.to_rfc3339())
        .bind(expires_at.to_rfc3339())
        .execute(state.pool())
        .await?;
    }

    Ok(Json(WsInboxTicketResponse {
        ticket,
        expires_at: expires_at.to_rfc3339(),
    }))
}

pub(crate) async fn ws_sealed_inbox(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<WsInboxQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    check_rate_limit(&state, &format!("ws-sealed-inbox:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let (device_id, since) =
        authenticate_ws_sealed_inbox_connection(&state, &user_id, &headers, &query).await?;

    Ok(ws.on_upgrade(move |socket| async move {
        handle_ws_sealed_inbox_socket(state, user_id, device_id, since, socket).await;
    }))
}

pub(crate) async fn create_ws_sealed_inbox_ticket(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<InboxQuery>,
) -> Result<Json<WsInboxTicketResponse>, AppError> {
    check_rate_limit(&state, &format!("ws-sealed-inbox-ticket:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(AppError::bad_request("since must be non-negative"));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = sealed_inbox_auth_message(&auth, &user_id, since)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    enforce_sealed_inbox_cursor_monotonic(&state, &user_id, &auth.device_id, since).await?;

    purge_expired_ws_inbox_tickets(&state).await?;
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(30);
    let ticket = uuid::Uuid::new_v4().to_string();
    if state.ephemeral_state().is_distributed() {
        state.ephemeral_state().put_ws_ticket(
            &ticket,
            &WsInboxTicketRecord {
                user_id: user_id.clone(),
                device_id: auth.device_id.clone(),
                since,
                expires_at: expires_at.to_rfc3339(),
            },
            30,
        )?;
    } else {
        sqlx::query(
            "INSERT INTO ws_inbox_tickets (ticket, user_id, device_id, since, issued_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&ticket)
        .bind(&user_id)
        .bind(&auth.device_id)
        .bind(since)
        .bind(issued_at.to_rfc3339())
        .bind(expires_at.to_rfc3339())
        .execute(state.pool())
        .await?;
    }

    Ok(Json(WsInboxTicketResponse {
        ticket,
        expires_at: expires_at.to_rfc3339(),
    }))
}

async fn authenticate_ws_inbox_connection(
    state: &AppState,
    user_id: &str,
    headers: &HeaderMap,
    query: &WsInboxQuery,
) -> Result<(String, i64), AppError> {
    if let Some(ticket) = query.ticket.as_deref() {
        return consume_ws_inbox_ticket(state, user_id, ticket).await;
    }

    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(AppError::bad_request("since must be non-negative"));
    }

    let auth = parse_request_auth(headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = ws_inbox_auth_message(&auth, user_id, since)?;
    verify_request_auth(state, &auth, &auth_message).await?;
    enforce_inbox_cursor_monotonic(state, user_id, &auth.device_id, since).await?;

    Ok((auth.device_id, since))
}

async fn authenticate_ws_sealed_inbox_connection(
    state: &AppState,
    user_id: &str,
    headers: &HeaderMap,
    query: &WsInboxQuery,
) -> Result<(String, i64), AppError> {
    if let Some(ticket) = query.ticket.as_deref() {
        return consume_ws_sealed_inbox_ticket(state, user_id, ticket).await;
    }

    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(AppError::bad_request("since must be non-negative"));
    }

    let auth = parse_request_auth(headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = sealed_inbox_auth_message(&auth, user_id, since)?;
    verify_request_auth(state, &auth, &auth_message).await?;
    enforce_sealed_inbox_cursor_monotonic(state, user_id, &auth.device_id, since).await?;

    Ok((auth.device_id, since))
}

async fn consume_ws_inbox_ticket(
    state: &AppState,
    user_id: &str,
    ticket: &str,
) -> Result<(String, i64), AppError> {
    let (device_id, since) = consume_ws_inbox_ticket_unchecked(state, user_id, ticket).await?;
    enforce_inbox_cursor_monotonic(state, user_id, &device_id, since).await?;
    Ok((device_id, since))
}

async fn consume_ws_sealed_inbox_ticket(
    state: &AppState,
    user_id: &str,
    ticket: &str,
) -> Result<(String, i64), AppError> {
    let (device_id, since) = consume_ws_inbox_ticket_unchecked(state, user_id, ticket).await?;
    enforce_sealed_inbox_cursor_monotonic(state, user_id, &device_id, since).await?;
    Ok((device_id, since))
}

async fn consume_ws_inbox_ticket_unchecked(
    state: &AppState,
    user_id: &str,
    ticket: &str,
) -> Result<(String, i64), AppError> {
    let trimmed_ticket = ticket.trim();
    if trimmed_ticket.is_empty() || trimmed_ticket.len() > 128 {
        return Err(AppError::bad_request("ticket must be 1..=128 characters"));
    }

    purge_expired_ws_inbox_tickets(state).await?;
    let now = Utc::now().to_rfc3339();
    let (device_id, since) = if state.ephemeral_state().is_distributed() {
        let Some(record) = state.ephemeral_state().consume_ws_ticket(trimmed_ticket)? else {
            return Err(AppError::bad_request("invalid or expired websocket ticket"));
        };
        if record.user_id != user_id {
            return Err(AppError::bad_request("websocket ticket user_id mismatch"));
        }
        if record.expires_at <= now {
            return Err(AppError::bad_request("invalid or expired websocket ticket"));
        }
        (record.device_id, record.since)
    } else {
        let row = sqlx::query(
            "DELETE FROM ws_inbox_tickets
             WHERE ticket = $1
             RETURNING user_id, device_id, since, expires_at",
        )
        .bind(trimmed_ticket)
        .fetch_optional(state.pool())
        .await?;
        let Some(row) = row else {
            return Err(AppError::bad_request("invalid or expired websocket ticket"));
        };

        let ticket_user_id: String = row.try_get("user_id")?;
        if ticket_user_id != user_id {
            return Err(AppError::bad_request("websocket ticket user_id mismatch"));
        }
        let expires_at: String = row.try_get("expires_at")?;
        if expires_at <= now {
            return Err(AppError::bad_request("invalid or expired websocket ticket"));
        }

        (row.try_get("device_id")?, row.try_get("since")?)
    };
    Ok((device_id, since))
}

async fn purge_expired_ws_inbox_tickets(state: &AppState) -> Result<(), AppError> {
    if state.ephemeral_state().is_distributed() {
        return Ok(());
    }
    let now = Utc::now().to_rfc3339();
    sqlx::query("DELETE FROM ws_inbox_tickets WHERE expires_at <= $1")
        .bind(now)
        .execute(state.pool())
        .await?;
    Ok(())
}

pub(crate) async fn relay_message(
    State(state): State<AppState>,
    Path(recipient_user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RelayRequest>,
) -> Result<Json<RelayResponse>, AppError> {
    ensure_authenticated_direct_messaging_supported(&state)?;
    check_rate_limit(&state, &format!("relay:{recipient_user_id}"))?;
    validate_id("recipient_user_id", &recipient_user_id)?;
    validate_id("sender_user_id", &request.sender_user_id)?;
    validate_id("device_id", &request.device_id)?;

    let blob = decode_base64_range(
        "message_bytes_base64",
        &request.message_bytes_base64,
        1,
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
    let auth_message = relay_auth_message(&auth, &recipient_user_id, &blob)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let mut dedup_hasher = Sha256::new();
    dedup_hasher.update(request.sender_user_id.as_bytes());
    dedup_hasher.update(b":");
    dedup_hasher.update(recipient_user_id.as_bytes());
    dedup_hasher.update(b":");
    dedup_hasher.update(&blob);
    let dedup_key = hex::encode(dedup_hasher.finalize());
    if !observe_relay_dedup(&state, &dedup_key).await? {
        return Err(AppError::conflict("duplicate message detected"));
    }

    ensure_user_exists(&state.pool, &recipient_user_id).await?;
    ensure_user_exists(&state.pool, &request.sender_user_id).await?;
    let recipient_devices = load_active_device_ids(state.pool(), &recipient_user_id).await?;
    if recipient_devices.is_empty() {
        return Err(AppError::not_found(
            "recipient has no active linked devices to deliver",
        ));
    }

    let now = Utc::now().to_rfc3339();
    let encoded_blob = B64.encode(&blob);
    let mut tx = state.pool.begin().await?;
    let mut deliveries = Vec::with_capacity(recipient_devices.len());
    for recipient_device_id in &recipient_devices {
        let message_id: i64 = sqlx::query_scalar(
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
        .bind(&recipient_user_id)
        .bind(recipient_device_id)
        .bind(&request.sender_user_id)
        .bind(&request.device_id)
        .bind(&blob)
        .bind(&now)
        .fetch_one(&mut *tx)
        .await?;
        deliveries.push((
            recipient_device_id.clone(),
            InboxItem {
                message_id,
                sender_user_id: request.sender_user_id.clone(),
                message_bytes_base64: encoded_blob.clone(),
                received_at: now.clone(),
            },
        ));
    }
    tx.commit().await?;

    for (recipient_device_id, item) in &deliveries {
        state
            .realtime_hub()
            .publish(&recipient_user_id, recipient_device_id, item.clone());
    }

    let push_state = state.clone();
    let push_recipient = recipient_user_id.clone();
    let push_excluded_device = if request.sender_user_id == recipient_user_id {
        request.device_id.clone()
    } else {
        String::new()
    };
    if let Ok(permit) = state.push_spawn_semaphore().clone().try_acquire_owned() {
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                dispatch_push_wake_signals(&push_state, &push_recipient, &push_excluded_device)
                    .await
            {
                tracing::warn!("push wake dispatch failed reason={}", error);
            }
        });
    } else {
        tracing::warn!("push dispatch skipped: spawn semaphore full");
    }

    Ok(Json(RelayResponse {
        message_id: deliveries
            .first()
            .map(|(_, item)| item.message_id)
            .unwrap_or(0),
        delivered_device_count: deliveries.len(),
        received_at: now,
    }))
}

pub(crate) async fn relay_sealed_message(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Path(recipient_user_id): Path<String>,
    Json(request): Json<SealedRelayRequest>,
) -> Result<Json<SealedRelayResponse>, AppError> {
    // IP-based rate limit: sealed sender has no auth, so IP is the only abuse signal
    let peer_ip = peer.map(|ci| ci.0.ip());
    let ip = extract_client_ip(&headers, peer_ip, state.trusted_proxies());
    if let Some(ref ip) = ip {
        check_rate_limit(&state, &format!("sealed-ip:{ip}"))?;
    }
    check_rate_limit(&state, &format!("sealed-relay:{recipient_user_id}"))?;
    validate_id("recipient_user_id", &recipient_user_id)?;
    let delivery_token = decode_base64_exact(
        "delivery_token",
        &request.delivery_token,
        SEALED_DELIVERY_TOKEN_LEN,
    )?;
    let blob = decode_base64_range(
        "message_bytes_base64",
        &request.message_bytes_base64,
        1,
        MAX_MESSAGE_BYTES,
    )?;

    let mut dedup_hasher = Sha256::new();
    dedup_hasher.update(b"sealed:");
    dedup_hasher.update(recipient_user_id.as_bytes());
    dedup_hasher.update(b":");
    dedup_hasher.update(&delivery_token);
    dedup_hasher.update(b":");
    dedup_hasher.update(&blob);
    let dedup_key = hex::encode(dedup_hasher.finalize());
    if !observe_relay_dedup(&state, &dedup_key).await? {
        return Err(AppError::conflict("duplicate sealed message detected"));
    }

    ensure_user_exists(&state.pool, &recipient_user_id).await?;
    let stored_delivery_token: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT sealed_delivery_token
         FROM users
         WHERE user_id = $1",
    )
    .bind(&recipient_user_id)
    .fetch_optional(state.pool())
    .await?
    .flatten();
    let Some(stored_delivery_token) = stored_delivery_token else {
        return Err(AppError::conflict(
            "recipient is missing a sealed delivery token",
        ));
    };
    if stored_delivery_token != delivery_token {
        return Err(AppError::forbidden("invalid sealed delivery token"));
    }
    let recipient_devices = load_active_device_ids(state.pool(), &recipient_user_id).await?;
    if recipient_devices.is_empty() {
        return Err(AppError::not_found(
            "recipient has no active linked devices to deliver",
        ));
    }

    let now = Utc::now().to_rfc3339();
    let encoded_blob = B64.encode(&blob);
    let mut tx = state.pool.begin().await?;
    let mut first_message_id: Option<i64> = None;
    let mut deliveries: Vec<(String, SealedInboxItem)> =
        Vec::with_capacity(recipient_devices.len());
    for recipient_device_id in &recipient_devices {
        let message_id: i64 = sqlx::query_scalar(
            "INSERT INTO sealed_relay_messages (
                recipient_user_id,
                recipient_device_id,
                message_blob,
                received_at
            ) VALUES ($1, $2, $3, $4)
            RETURNING message_id",
        )
        .bind(&recipient_user_id)
        .bind(recipient_device_id)
        .bind(&blob)
        .bind(&now)
        .fetch_one(&mut *tx)
        .await?;
        if first_message_id.is_none() {
            first_message_id = Some(message_id);
        }
        deliveries.push((
            recipient_device_id.clone(),
            SealedInboxItem {
                message_id,
                sender_identity_x25519_pub: None,
                message_bytes_base64: encoded_blob.clone(),
                received_at: now.clone(),
            },
        ));
    }
    tx.commit().await?;

    for (recipient_device_id, item) in &deliveries {
        state
            .sealed_realtime_hub()
            .publish(&recipient_user_id, recipient_device_id, item.clone());
    }

    let push_state = state.clone();
    let push_recipient = recipient_user_id.clone();
    if let Ok(permit) = state.push_spawn_semaphore().clone().try_acquire_owned() {
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = dispatch_push_wake_signals(&push_state, &push_recipient, "").await {
                tracing::warn!("sealed push wake dispatch failed reason={}", error);
            }
        });
    } else {
        tracing::warn!("sealed push dispatch skipped: spawn semaphore full");
    }

    Ok(Json(SealedRelayResponse {
        delivered_device_count: recipient_devices.len(),
        first_message_id,
        received_at: now,
    }))
}

pub(crate) async fn issue_sender_certificate(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SenderCertificateResponse>, AppError> {
    check_rate_limit(&state, &format!("sender-certificate:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = sender_certificate_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let sender_identity_x25519_pub: Vec<u8> =
        sqlx::query_scalar("SELECT identity_x25519_pub FROM users WHERE user_id = $1")
            .bind(&user_id)
            .fetch_optional(state.pool())
            .await?
            .ok_or_else(|| AppError::not_found("user not found"))?;
    let sender_identity_pub: [u8; 32] = sender_identity_x25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| AppError::internal("stored identity_x25519_pub has invalid length"))?;

    let now = Utc::now();
    let expires_at = now + Duration::seconds(SENDER_CERT_VALIDITY_SECS as i64);
    let mut certificate = SenderCertificate {
        sender_user_id: user_id.clone(),
        sender_device_id: auth.device_id.clone(),
        sender_identity_pub,
        expires_at: expires_at.timestamp() as u64,
        server_signature: Vec::new(),
    };
    let body = certificate
        .signing_body()
        .map_err(|_| AppError::internal("failed to encode sender certificate"))?;
    certificate.server_signature = state
        .sender_certificate_signing_key()
        .sign(&body)
        .to_bytes()
        .to_vec();
    let certificate_bytes = certificate
        .encode()
        .map_err(|_| AppError::internal("failed to encode sender certificate"))?;

    Ok(Json(SenderCertificateResponse {
        user_id,
        device_id: auth.device_id,
        certificate_base64: B64.encode(certificate_bytes),
        expires_at: expires_at.to_rfc3339(),
    }))
}

pub(crate) async fn get_inbox(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<InboxQuery>,
) -> Result<Json<InboxResponse>, AppError> {
    ensure_authenticated_direct_messaging_supported(&state)?;
    check_rate_limit(&state, &format!("inbox:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(AppError::bad_request("since must be non-negative"));
    }
    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = inbox_auth_message(&auth, &user_id, since)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    let last_seen =
        enforce_inbox_cursor_monotonic(&state, &user_id, &auth.device_id, since).await?;

    let messages = load_inbox_messages(state.pool(), &user_id, &auth.device_id, since).await?;
    let delivered_max = messages
        .iter()
        .map(|item| item.message_id)
        .max()
        .unwrap_or(last_seen.max(since));
    update_inbox_cursor(&state, &user_id, &auth.device_id, delivered_max).await?;

    Ok(Json(InboxResponse { user_id, messages }))
}

pub(crate) async fn get_sealed_inbox(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<InboxQuery>,
) -> Result<Json<SealedInboxResponse>, AppError> {
    check_rate_limit(&state, &format!("sealed-inbox:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(AppError::bad_request("since must be non-negative"));
    }
    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = sealed_inbox_auth_message(&auth, &user_id, since)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    let last_seen =
        enforce_sealed_inbox_cursor_monotonic(&state, &user_id, &auth.device_id, since).await?;

    let messages =
        load_sealed_inbox_messages(state.pool(), &user_id, &auth.device_id, since).await?;
    let delivered_max = messages
        .iter()
        .map(|item| item.message_id)
        .max()
        .unwrap_or(last_seen.max(since));
    update_sealed_inbox_cursor(&state, &user_id, &auth.device_id, delivered_max).await?;

    Ok(Json(SealedInboxResponse { user_id, messages }))
}

pub(crate) async fn delete_inbox_messages(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DeleteInboxRequest>,
) -> Result<Json<DeleteInboxResponse>, AppError> {
    ensure_authenticated_direct_messaging_supported(&state)?;
    check_rate_limit(&state, &format!("inbox-delete:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    if request.message_ids.len() > MAX_DELETE_MESSAGE_IDS {
        return Err(AppError::bad_request(format!(
            "message_ids cannot exceed {MAX_DELETE_MESSAGE_IDS} entries"
        )));
    }
    if request.message_ids.is_empty() && request.delete_before_id.is_none() {
        return Err(AppError::bad_request(
            "provide message_ids or delete_before_id",
        ));
    }
    if request.message_ids.iter().any(|id| *id <= 0) {
        return Err(AppError::bad_request(
            "message_ids must be positive integers",
        ));
    }
    if request.delete_before_id.is_some_and(|value| value <= 0) {
        return Err(AppError::bad_request(
            "delete_before_id must be a positive integer",
        ));
    }

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = inbox_delete_auth_message(&auth, &user_id, &request)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let normalized_ids = normalize_message_ids(&request.message_ids);
    let mut deleted_count: u64 = 0;
    let mut tx = state.pool.begin().await?;
    for message_id in normalized_ids {
        let result = sqlx::query(
            "DELETE FROM relay_messages
             WHERE recipient_user_id = $1 AND recipient_device_id = $2 AND message_id = $3",
        )
        .bind(&user_id)
        .bind(&auth.device_id)
        .bind(message_id)
        .execute(&mut *tx)
        .await?;
        deleted_count = deleted_count.saturating_add(result.rows_affected());
    }
    if let Some(delete_before_id) = request.delete_before_id {
        let result = sqlx::query(
            "DELETE FROM relay_messages
             WHERE recipient_user_id = $1
               AND recipient_device_id = $2
               AND message_id <= $3",
        )
        .bind(&user_id)
        .bind(&auth.device_id)
        .bind(delete_before_id)
        .execute(&mut *tx)
        .await?;
        deleted_count = deleted_count.saturating_add(result.rows_affected());
    }
    tx.commit().await?;

    Ok(Json(DeleteInboxResponse {
        user_id,
        device_id: auth.device_id,
        deleted_count,
        deleted_at: Utc::now().to_rfc3339(),
    }))
}

pub(crate) async fn handle_ws_inbox_socket(
    state: AppState,
    user_id: String,
    device_id: String,
    since: i64,
    socket: WebSocket,
) {
    let (subscriber_id, mut receiver) = state.realtime_hub().subscribe(&user_id, &device_id);
    let mut last_message_id = since;
    let backlog = load_inbox_messages(state.pool(), &user_id, &device_id, since).await;
    let (mut sender, mut client_stream) = socket.split();

    let Ok(backlog_messages) = backlog else {
        state
            .realtime_hub()
            .unsubscribe(&user_id, &device_id, subscriber_id);
        let _ = sender.send(WsMessage::Close(None)).await;
        return;
    };

    if let Some(max_id) = backlog_messages.iter().map(|item| item.message_id).max() {
        last_message_id = max_id;
    }
    if !backlog_messages.is_empty() {
        let payload = WsInboxEnvelope {
            event: "sync",
            user_id: user_id.clone(),
            messages: backlog_messages,
        };
        let Ok(text) = serde_json::to_string(&payload) else {
            state
                .realtime_hub()
                .unsubscribe(&user_id, &device_id, subscriber_id);
            let _ = sender.send(WsMessage::Close(None)).await;
            return;
        };
        if sender.send(WsMessage::Text(text)).await.is_err() {
            state
                .realtime_hub()
                .unsubscribe(&user_id, &device_id, subscriber_id);
            return;
        }
    }
    if update_inbox_cursor(&state, &user_id, &device_id, last_message_id)
        .await
        .is_err()
    {
        state
            .realtime_hub()
            .unsubscribe(&user_id, &device_id, subscriber_id);
        let _ = sender.send(WsMessage::Close(None)).await;
        return;
    }

    let mut ping_interval = tokio::time::interval(StdDuration::from_secs(30));
    ping_interval.tick().await; // consume the immediate first tick
    let idle_timeout = StdDuration::from_secs(90);
    let mut last_activity = tokio::time::Instant::now();

    loop {
        tokio::select! {
            maybe_inbound = client_stream.next() => {
                match maybe_inbound {
                    Some(Ok(WsMessage::Close(_))) => {
                        state
                            .realtime_hub()
                            .unsubscribe(&user_id, &device_id, subscriber_id);
                        return;
                    }
                    Some(Ok(WsMessage::Ping(payload))) => {
                        last_activity = tokio::time::Instant::now();
                        if sender.send(WsMessage::Pong(payload)).await.is_err() {
                            state
                                .realtime_hub()
                                .unsubscribe(&user_id, &device_id, subscriber_id);
                            return;
                        }
                    }
                    Some(Ok(WsMessage::Pong(_))) => {
                        last_activity = tokio::time::Instant::now();
                    }
                    Some(Ok(_)) => {
                        last_activity = tokio::time::Instant::now();
                    }
                    Some(Err(_)) => {
                        state
                            .realtime_hub()
                            .unsubscribe(&user_id, &device_id, subscriber_id);
                        return;
                    }
                    None => {
                        state
                            .realtime_hub()
                            .unsubscribe(&user_id, &device_id, subscriber_id);
                        return;
                    }
                }
            }
            maybe_message = receiver.recv() => {
                let Some(message) = maybe_message else {
                    state
                        .realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                };
                if message.message_id <= last_message_id {
                    continue;
                }
                last_message_id = message.message_id;
                let payload = WsInboxEnvelope {
                    event: "relay",
                    user_id: user_id.clone(),
                    messages: vec![message],
                };
                let Ok(text) = serde_json::to_string(&payload) else {
                    state
                        .realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                };
                if sender.send(WsMessage::Text(text)).await.is_err() {
                    state
                        .realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
                if update_inbox_cursor(&state, &user_id, &device_id, last_message_id)
                    .await
                    .is_err()
                {
                    state
                        .realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
                last_activity = tokio::time::Instant::now();
            }
            _ = ping_interval.tick() => {
                if last_activity.elapsed() > idle_timeout {
                    let _ = sender.send(WsMessage::Close(None)).await;
                    state
                        .realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
                if sender.send(WsMessage::Ping(vec![])).await.is_err() {
                    state
                        .realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
            }
        }
    }
}

pub(crate) async fn handle_ws_sealed_inbox_socket(
    state: AppState,
    user_id: String,
    device_id: String,
    since: i64,
    socket: WebSocket,
) {
    let (subscriber_id, mut receiver) = state.sealed_realtime_hub().subscribe(&user_id, &device_id);
    let mut last_message_id = since;
    let backlog = load_sealed_inbox_messages(state.pool(), &user_id, &device_id, since).await;
    let (mut sender, mut client_stream) = socket.split();

    let Ok(backlog_messages) = backlog else {
        state
            .sealed_realtime_hub()
            .unsubscribe(&user_id, &device_id, subscriber_id);
        let _ = sender.send(WsMessage::Close(None)).await;
        return;
    };

    if let Some(max_id) = backlog_messages.iter().map(|item| item.message_id).max() {
        last_message_id = max_id;
    }
    if !backlog_messages.is_empty() {
        let payload = WsSealedInboxEnvelope {
            event: "sync",
            user_id: user_id.clone(),
            messages: backlog_messages,
        };
        let Ok(text) = serde_json::to_string(&payload) else {
            state
                .sealed_realtime_hub()
                .unsubscribe(&user_id, &device_id, subscriber_id);
            let _ = sender.send(WsMessage::Close(None)).await;
            return;
        };
        if sender.send(WsMessage::Text(text)).await.is_err() {
            state
                .sealed_realtime_hub()
                .unsubscribe(&user_id, &device_id, subscriber_id);
            return;
        }
    }
    if update_sealed_inbox_cursor(&state, &user_id, &device_id, last_message_id)
        .await
        .is_err()
    {
        state
            .sealed_realtime_hub()
            .unsubscribe(&user_id, &device_id, subscriber_id);
        let _ = sender.send(WsMessage::Close(None)).await;
        return;
    }

    let mut ping_interval = tokio::time::interval(StdDuration::from_secs(30));
    ping_interval.tick().await;
    let idle_timeout = StdDuration::from_secs(90);
    let mut last_activity = tokio::time::Instant::now();

    loop {
        tokio::select! {
            maybe_inbound = client_stream.next() => {
                match maybe_inbound {
                    Some(Ok(WsMessage::Close(_))) => {
                        state
                            .sealed_realtime_hub()
                            .unsubscribe(&user_id, &device_id, subscriber_id);
                        return;
                    }
                    Some(Ok(WsMessage::Ping(payload))) => {
                        last_activity = tokio::time::Instant::now();
                        if sender.send(WsMessage::Pong(payload)).await.is_err() {
                            state
                                .sealed_realtime_hub()
                                .unsubscribe(&user_id, &device_id, subscriber_id);
                            return;
                        }
                    }
                    Some(Ok(WsMessage::Pong(_))) => {
                        last_activity = tokio::time::Instant::now();
                    }
                    Some(Ok(_)) => {
                        last_activity = tokio::time::Instant::now();
                    }
                    Some(Err(_)) => {
                        state
                            .sealed_realtime_hub()
                            .unsubscribe(&user_id, &device_id, subscriber_id);
                        return;
                    }
                    None => {
                        state
                            .sealed_realtime_hub()
                            .unsubscribe(&user_id, &device_id, subscriber_id);
                        return;
                    }
                }
            }
            maybe_message = receiver.recv() => {
                let Some(message) = maybe_message else {
                    state
                        .sealed_realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                };
                if message.message_id <= last_message_id {
                    continue;
                }
                last_message_id = message.message_id;
                let payload = WsSealedInboxEnvelope {
                    event: "relay",
                    user_id: user_id.clone(),
                    messages: vec![message],
                };
                let Ok(text) = serde_json::to_string(&payload) else {
                    state
                        .sealed_realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                };
                if sender.send(WsMessage::Text(text)).await.is_err() {
                    state
                        .sealed_realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
                if update_sealed_inbox_cursor(&state, &user_id, &device_id, last_message_id)
                    .await
                    .is_err()
                {
                    state
                        .sealed_realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
                last_activity = tokio::time::Instant::now();
            }
            _ = ping_interval.tick() => {
                if last_activity.elapsed() > idle_timeout {
                    let _ = sender.send(WsMessage::Close(None)).await;
                    state
                        .sealed_realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
                if sender.send(WsMessage::Ping(vec![])).await.is_err() {
                    state
                        .sealed_realtime_hub()
                        .unsubscribe(&user_id, &device_id, subscriber_id);
                    return;
                }
            }
        }
    }
}

pub(crate) async fn load_inbox_messages(
    pool: &AnyPool,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Result<Vec<InboxItem>, AppError> {
    let rows = sqlx::query(
        "SELECT message_id, sender_user_id, message_blob, received_at
         FROM relay_messages
         WHERE recipient_user_id = $1 AND recipient_device_id = $2 AND message_id > $3
         ORDER BY message_id ASC
         LIMIT $4",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(since)
    .bind(MAX_INBOX_PAGE)
    .fetch_all(pool)
    .await?;

    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        messages.push(InboxItem {
            message_id: row.try_get("message_id")?,
            sender_user_id: row.try_get("sender_user_id")?,
            message_bytes_base64: B64.encode(row.try_get::<Vec<u8>, _>("message_blob")?),
            received_at: row.try_get("received_at")?,
        });
    }
    Ok(messages)
}

pub(crate) async fn load_sealed_inbox_messages(
    pool: &AnyPool,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Result<Vec<SealedInboxItem>, AppError> {
    let rows = sqlx::query(
        "SELECT message_id, sender_identity_x25519_pub, message_blob, received_at
         FROM sealed_relay_messages
         WHERE recipient_user_id = $1
           AND recipient_device_id = $2
           AND message_id > $3
         ORDER BY message_id ASC
         LIMIT $4",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(since)
    .bind(MAX_INBOX_PAGE)
    .fetch_all(pool)
    .await?;

    let mut messages = Vec::with_capacity(rows.len());
    for row in rows {
        messages.push(SealedInboxItem {
            message_id: row.try_get("message_id")?,
            sender_identity_x25519_pub: row
                .try_get::<Option<Vec<u8>>, _>("sender_identity_x25519_pub")?
                .map(|value| B64.encode(value)),
            message_bytes_base64: B64.encode(row.try_get::<Vec<u8>, _>("message_blob")?),
            received_at: row.try_get("received_at")?,
        });
    }
    Ok(messages)
}

pub(crate) async fn enforce_inbox_cursor_monotonic(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Result<i64, AppError> {
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT last_message_id
         FROM inbox_cursors
         WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(state.pool())
    .await?
    .unwrap_or(0);
    if since < existing {
        return Err(AppError::conflict(
            "inbox since cursor regressed for this authenticated session",
        ));
    }
    Ok(existing)
}

pub(crate) async fn enforce_sealed_inbox_cursor_monotonic(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Result<i64, AppError> {
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT last_message_id
         FROM sealed_inbox_cursors
         WHERE user_id = $1 AND device_id = $2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(state.pool())
    .await?
    .unwrap_or(0);
    if since < existing {
        return Err(AppError::conflict(
            "sealed inbox since cursor regressed for this authenticated session",
        ));
    }
    Ok(existing)
}

pub(crate) async fn update_inbox_cursor(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    message_id: i64,
) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO inbox_cursors (user_id, device_id, last_message_id, updated_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            last_message_id = CASE
                WHEN inbox_cursors.last_message_id > EXCLUDED.last_message_id
                    THEN inbox_cursors.last_message_id
                ELSE EXCLUDED.last_message_id
            END,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(message_id)
    .bind(now)
    .execute(state.pool())
    .await?;
    Ok(())
}

pub(crate) async fn update_sealed_inbox_cursor(
    state: &AppState,
    user_id: &str,
    device_id: &str,
    message_id: i64,
) -> Result<(), AppError> {
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO sealed_inbox_cursors (user_id, device_id, last_message_id, updated_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            last_message_id = CASE
                WHEN sealed_inbox_cursors.last_message_id > EXCLUDED.last_message_id
                    THEN sealed_inbox_cursors.last_message_id
                ELSE EXCLUDED.last_message_id
            END,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(message_id)
    .bind(now)
    .execute(state.pool())
    .await?;
    Ok(())
}
