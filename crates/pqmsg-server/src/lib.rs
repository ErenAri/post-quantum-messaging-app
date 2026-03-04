use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pqmsg_core::alg::PROTOCOL_VERSION_V1;
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MAX_BODY_BYTES: usize = 1_048_576;
const MAX_USER_ID_LEN: usize = 128;
const MAX_DEVICE_ID_LEN: usize = 128;
const X25519_KEY_LEN: usize = 32;
const SIG_PUB_KEY_LEN: usize = 32;
const SIG_LEN: usize = 64;
const MIN_PQ_KEY_LEN: usize = 32;
const MAX_PQ_KEY_LEN: usize = 4096;
const MAX_ONE_TIME_KEYS: usize = 256;
const MAX_MESSAGE_BYTES: usize = 1_000_000;
const MAX_INBOX_PAGE: i64 = 200;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct AppState {
    pool: SqlitePool,
    rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(pool: SqlitePool, rate_limiter: Arc<RateLimiter>) -> Self {
        Self { pool, rate_limiter }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_second: f64,
    inner: Arc<Mutex<HashMap<String, BucketState>>>,
}

#[derive(Clone, Copy)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(capacity: f64, refill_per_second: f64) -> Self {
        Self {
            capacity,
            refill_per_second,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        let now = Instant::now();
        let bucket = map.entry(key.to_string()).or_insert(BucketState {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_second).min(self.capacity);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct AppError {
    status: StatusCode,
    title: &'static str,
    detail: String,
}

impl AppError {
    fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            title: "Bad Request",
            detail: detail.into(),
        }
    }

    fn not_found(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            title: "Not Found",
            detail: detail.into(),
        }
    }

    fn rate_limited(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            title: "Too Many Requests",
            detail: detail.into(),
        }
    }

    fn conflict(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            title: "Conflict",
            detail: detail.into(),
        }
    }

    fn internal(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            title: "Internal Server Error",
            detail: detail.into(),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        Self::internal(value.to_string())
    }
}

#[derive(Serialize)]
struct ProblemJson<'a> {
    r#type: &'a str,
    title: &'a str,
    status: u16,
    detail: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = Json(ProblemJson {
            r#type: "about:blank",
            title: self.title,
            status: self.status.as_u16(),
            detail: self.detail,
        });
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
struct RegisterUserRequest {
    user_id: String,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    device_id: String,
}

#[derive(Debug, Serialize)]
struct RegisterUserResponse {
    user_id: String,
    device_id: String,
    registered_at: String,
}

#[derive(Debug, Deserialize)]
struct PublishPrekeysRequest {
    signed_prekey_x25519_pub: String,
    sig_over_spk: String,
    pq_signed_prekey_pub_mlkem768: String,
    sig_over_pqspk: String,
    one_time_prekeys_x25519: Vec<String>,
    one_time_prekeys_mlkem768: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PublishPrekeysResponse {
    user_id: String,
    device_id: String,
    uploaded_one_time_prekeys_x25519: usize,
    uploaded_one_time_prekeys_mlkem768: usize,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct BundleResponse {
    user_id: String,
    device_id: String,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    signed_prekey_x25519_pub: String,
    sig_over_spk: String,
    pq_signed_prekey_pub_mlkem768: String,
    sig_over_pqspk: String,
    one_time_prekey_x25519: Option<String>,
    one_time_prekey_mlkem768: Option<String>,
    bundle_generated_at: String,
}

#[derive(Debug, Deserialize)]
struct RelayRequest {
    sender_user_id: String,
    device_id: String,
    message_bytes_base64: String,
}

#[derive(Debug, Serialize)]
struct RelayResponse {
    message_id: i64,
    received_at: String,
}

#[derive(Debug, Deserialize)]
struct InboxQuery {
    since: Option<i64>,
}

#[derive(Debug, Serialize)]
struct InboxItem {
    message_id: i64,
    sender_user_id: String,
    message_bytes_base64: String,
    received_at: String,
}

#[derive(Debug, Serialize)]
struct InboxResponse {
    user_id: String,
    messages: Vec<InboxItem>,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: &'static str,
}

pub async fn init_db(pool: &SqlitePool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/users/register", post(register_user))
        .route("/v1/users/:user_id/prekeys", post(publish_prekeys))
        .route("/v1/users/:user_id/bundle", get(get_bundle))
        .route("/v1/relay/:recipient_user_id", post(relay_message))
        .route("/v1/inbox/:user_id", get(get_inbox))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn health() -> Json<StatusResponse> {
    Json(StatusResponse { status: "ok" })
}

async fn register_user(
    State(state): State<AppState>,
    Json(request): Json<RegisterUserRequest>,
) -> Result<Json<RegisterUserResponse>, AppError> {
    check_rate_limit(&state, &format!("register:{}", request.user_id))?;
    validate_id("user_id", &request.user_id)?;
    validate_id("device_id", &request.device_id)?;

    let identity_x25519 = decode_base64_exact(
        "identity_x25519_pub",
        &request.identity_x25519_pub,
        X25519_KEY_LEN,
    )?;
    let identity_sig = decode_base64_range(
        "identity_sig_pub",
        &request.identity_sig_pub,
        SIG_PUB_KEY_LEN,
        SIG_PUB_KEY_LEN,
    )?;
    validate_ed25519_public_key(&identity_sig)?;

    let now = Utc::now().to_rfc3339();
    let insert_result = sqlx::query(
        "INSERT INTO users (user_id, identity_x25519_pub, identity_sig_pub, device_id, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
    )
    .bind(&request.user_id)
    .bind(&identity_x25519)
    .bind(&identity_sig)
    .bind(&request.device_id)
    .bind(&now)
    .execute(&state.pool)
    .await;

    match insert_result {
        Ok(_) => {}
        Err(sqlx::Error::Database(db_error)) if db_error.is_unique_violation() => {
            let existing = sqlx::query(
                "SELECT identity_x25519_pub, identity_sig_pub, device_id, created_at
                 FROM users
                 WHERE user_id = ?1",
            )
            .bind(&request.user_id)
            .fetch_optional(&state.pool)
            .await?;
            let Some(existing) = existing else {
                return Err(AppError::internal(
                    "unique constraint raced with missing user row",
                ));
            };

            let existing_identity_x25519: Vec<u8> = existing.try_get("identity_x25519_pub")?;
            let existing_identity_sig: Vec<u8> = existing.try_get("identity_sig_pub")?;
            let existing_device_id: String = existing.try_get("device_id")?;
            let existing_created_at: String = existing.try_get("created_at")?;

            if existing_identity_x25519 != identity_x25519
                || existing_identity_sig != identity_sig
                || existing_device_id != request.device_id
            {
                return Err(AppError::conflict(
                    "user_id is already registered with an immutable identity",
                ));
            }

            return Ok(Json(RegisterUserResponse {
                user_id: request.user_id,
                device_id: existing_device_id,
                registered_at: existing_created_at,
            }));
        }
        Err(error) => return Err(error.into()),
    }

    Ok(Json(RegisterUserResponse {
        user_id: request.user_id,
        device_id: request.device_id,
        registered_at: now,
    }))
}

async fn publish_prekeys(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(request): Json<PublishPrekeysRequest>,
) -> Result<Json<PublishPrekeysResponse>, AppError> {
    check_rate_limit(&state, &format!("prekeys:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_one_time_count(
        "one_time_prekeys_x25519",
        request.one_time_prekeys_x25519.len(),
    )?;
    validate_one_time_count(
        "one_time_prekeys_mlkem768",
        request.one_time_prekeys_mlkem768.len(),
    )?;

    let signed_prekey_x = decode_base64_exact(
        "signed_prekey_x25519_pub",
        &request.signed_prekey_x25519_pub,
        X25519_KEY_LEN,
    )?;
    let sig_over_spk =
        decode_base64_range("sig_over_spk", &request.sig_over_spk, SIG_LEN, SIG_LEN)?;
    let pq_signed_prekey = decode_base64_range(
        "pq_signed_prekey_pub_mlkem768",
        &request.pq_signed_prekey_pub_mlkem768,
        MIN_PQ_KEY_LEN,
        MAX_PQ_KEY_LEN,
    )?;
    let sig_over_pqspk =
        decode_base64_range("sig_over_pqspk", &request.sig_over_pqspk, SIG_LEN, SIG_LEN)?;

    let mut one_time_x = Vec::with_capacity(request.one_time_prekeys_x25519.len());
    for key in &request.one_time_prekeys_x25519 {
        one_time_x.push(decode_base64_exact(
            "one_time_prekeys_x25519[]",
            key,
            X25519_KEY_LEN,
        )?);
    }

    let mut one_time_pq = Vec::with_capacity(request.one_time_prekeys_mlkem768.len());
    for key in &request.one_time_prekeys_mlkem768 {
        one_time_pq.push(decode_base64_range(
            "one_time_prekeys_mlkem768[]",
            key,
            MIN_PQ_KEY_LEN,
            MAX_PQ_KEY_LEN,
        )?);
    }

    let user_row = sqlx::query("SELECT device_id, identity_sig_pub FROM users WHERE user_id = ?1")
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await?;
    let Some(user_row) = user_row else {
        return Err(AppError::not_found("user not found"));
    };

    let identity_sig_pub: Vec<u8> = user_row.try_get("identity_sig_pub")?;
    maybe_verify_prekey_signatures(
        &identity_sig_pub,
        &signed_prekey_x,
        &sig_over_spk,
        &pq_signed_prekey,
        &sig_over_pqspk,
    )?;

    let device_id: String = user_row.try_get("device_id")?;
    let now = Utc::now().to_rfc3339();
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        "INSERT INTO prekeys (
            user_id, signed_prekey_x25519_pub, sig_over_spk,
            pq_signed_prekey_pub_mlkem768, sig_over_pqspk, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(user_id) DO UPDATE SET
            signed_prekey_x25519_pub = excluded.signed_prekey_x25519_pub,
            sig_over_spk = excluded.sig_over_spk,
            pq_signed_prekey_pub_mlkem768 = excluded.pq_signed_prekey_pub_mlkem768,
            sig_over_pqspk = excluded.sig_over_pqspk,
            updated_at = excluded.updated_at",
    )
    .bind(&user_id)
    .bind(&signed_prekey_x)
    .bind(&sig_over_spk)
    .bind(&pq_signed_prekey)
    .bind(&sig_over_pqspk)
    .bind(&now)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM one_time_prekeys_x25519 WHERE user_id = ?1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM one_time_prekeys_mlkem768 WHERE user_id = ?1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;

    for key in &one_time_x {
        sqlx::query(
            "INSERT INTO one_time_prekeys_x25519 (user_id, prekey, consumed, created_at)
             VALUES (?1, ?2, 0, ?3)",
        )
        .bind(&user_id)
        .bind(key)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }
    for key in &one_time_pq {
        sqlx::query(
            "INSERT INTO one_time_prekeys_mlkem768 (user_id, prekey, consumed, created_at)
             VALUES (?1, ?2, 0, ?3)",
        )
        .bind(&user_id)
        .bind(key)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(Json(PublishPrekeysResponse {
        user_id,
        device_id,
        uploaded_one_time_prekeys_x25519: one_time_x.len(),
        uploaded_one_time_prekeys_mlkem768: one_time_pq.len(),
        updated_at: now,
    }))
}

async fn get_bundle(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<BundleResponse>, AppError> {
    check_rate_limit(&state, &format!("bundle:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let mut tx = state.pool.begin().await?;

    let row = sqlx::query(
        "SELECT
            u.user_id,
            u.device_id,
            u.identity_x25519_pub,
            u.identity_sig_pub,
            p.signed_prekey_x25519_pub,
            p.sig_over_spk,
            p.pq_signed_prekey_pub_mlkem768,
            p.sig_over_pqspk
         FROM users u
         JOIN prekeys p ON p.user_id = u.user_id
         WHERE u.user_id = ?1",
    )
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Err(AppError::not_found("bundle not found"));
    };

    let x25519_otk = select_one_time_key(&mut tx, "one_time_prekeys_x25519", &user_id).await?;
    let mlkem_otk = select_one_time_key(&mut tx, "one_time_prekeys_mlkem768", &user_id).await?;
    tx.commit().await?;

    Ok(Json(BundleResponse {
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        identity_x25519_pub: B64.encode(row.try_get::<Vec<u8>, _>("identity_x25519_pub")?),
        identity_sig_pub: B64.encode(row.try_get::<Vec<u8>, _>("identity_sig_pub")?),
        signed_prekey_x25519_pub: B64
            .encode(row.try_get::<Vec<u8>, _>("signed_prekey_x25519_pub")?),
        sig_over_spk: B64.encode(row.try_get::<Vec<u8>, _>("sig_over_spk")?),
        pq_signed_prekey_pub_mlkem768: B64
            .encode(row.try_get::<Vec<u8>, _>("pq_signed_prekey_pub_mlkem768")?),
        sig_over_pqspk: B64.encode(row.try_get::<Vec<u8>, _>("sig_over_pqspk")?),
        one_time_prekey_x25519: x25519_otk.map(|bytes| B64.encode(bytes)),
        one_time_prekey_mlkem768: mlkem_otk.map(|bytes| B64.encode(bytes)),
        bundle_generated_at: Utc::now().to_rfc3339(),
    }))
}

async fn relay_message(
    State(state): State<AppState>,
    Path(recipient_user_id): Path<String>,
    Json(request): Json<RelayRequest>,
) -> Result<Json<RelayResponse>, AppError> {
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

    ensure_user_exists(&state.pool, &recipient_user_id).await?;
    ensure_user_exists(&state.pool, &request.sender_user_id).await?;

    let now = Utc::now().to_rfc3339();
    let result = sqlx::query(
        "INSERT INTO relay_messages (
            recipient_user_id, sender_user_id, device_id, message_blob, received_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(&recipient_user_id)
    .bind(&request.sender_user_id)
    .bind(&request.device_id)
    .bind(blob)
    .bind(&now)
    .execute(&state.pool)
    .await?;

    Ok(Json(RelayResponse {
        message_id: result.last_insert_rowid(),
        received_at: now,
    }))
}

async fn get_inbox(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Query(query): Query<InboxQuery>,
) -> Result<Json<InboxResponse>, AppError> {
    check_rate_limit(&state, &format!("inbox:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let since = query.since.unwrap_or(0);
    if since < 0 {
        return Err(AppError::bad_request("since must be non-negative"));
    }

    let rows = sqlx::query(
        "SELECT message_id, sender_user_id, message_blob, received_at
         FROM relay_messages
         WHERE recipient_user_id = ?1 AND message_id > ?2
         ORDER BY message_id ASC
         LIMIT ?3",
    )
    .bind(&user_id)
    .bind(since)
    .bind(MAX_INBOX_PAGE)
    .fetch_all(&state.pool)
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

    Ok(Json(InboxResponse { user_id, messages }))
}

async fn select_one_time_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    table: &str,
    user_id: &str,
) -> Result<Option<Vec<u8>>, AppError> {
    let query = format!(
        "SELECT id, prekey FROM {table}
         WHERE user_id = ?1 AND consumed = 0
         ORDER BY id ASC
         LIMIT 1"
    );
    let row = sqlx::query(&query)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };

    let id: i64 = row.try_get("id")?;
    let key: Vec<u8> = row.try_get("prekey")?;
    let update = format!("UPDATE {table} SET consumed = 1 WHERE id = ?1");
    sqlx::query(&update).bind(id).execute(&mut **tx).await?;
    Ok(Some(key))
}

async fn ensure_user_exists(pool: &SqlitePool, user_id: &str) -> Result<(), AppError> {
    let exists = sqlx::query("SELECT 1 FROM users WHERE user_id = ?1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    if exists.is_none() {
        return Err(AppError::not_found(format!("user '{user_id}' not found")));
    }
    Ok(())
}

fn check_rate_limit(state: &AppState, key: &str) -> Result<(), AppError> {
    if state.rate_limiter.allow(key) {
        Ok(())
    } else {
        Err(AppError::rate_limited("rate limit exceeded"))
    }
}

fn validate_id(field: &'static str, value: &str) -> Result<(), AppError> {
    let len = value.trim().len();
    if len == 0 || len > MAX_USER_ID_LEN || len > MAX_DEVICE_ID_LEN {
        return Err(AppError::bad_request(format!(
            "{field} must be 1..128 non-whitespace characters"
        )));
    }
    Ok(())
}

fn validate_one_time_count(field: &'static str, count: usize) -> Result<(), AppError> {
    if count > MAX_ONE_TIME_KEYS {
        return Err(AppError::bad_request(format!(
            "{field} cannot contain more than {MAX_ONE_TIME_KEYS} items"
        )));
    }
    Ok(())
}

fn decode_base64_exact(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<Vec<u8>, AppError> {
    let decoded = decode_base64_range(field, value, expected_len, expected_len)?;
    Ok(decoded)
}

fn decode_base64_range(
    field: &'static str,
    value: &str,
    min_len: usize,
    max_len: usize,
) -> Result<Vec<u8>, AppError> {
    if value.is_empty() {
        return Err(AppError::bad_request(format!("{field} cannot be empty")));
    }
    let max_encoded = max_len.div_ceil(3) * 4 + 8;
    if value.len() > max_encoded {
        return Err(AppError::bad_request(format!("{field} is too large")));
    }
    let decoded = B64
        .decode(value.as_bytes())
        .map_err(|_| AppError::bad_request(format!("{field} is not valid base64")))?;
    if decoded.len() < min_len || decoded.len() > max_len {
        return Err(AppError::bad_request(format!(
            "{field} decoded length must be between {min_len} and {max_len}"
        )));
    }
    Ok(decoded)
}

fn validate_ed25519_public_key(identity_sig_pub: &[u8]) -> Result<(), AppError> {
    let key_bytes: [u8; SIG_PUB_KEY_LEN] = identity_sig_pub
        .try_into()
        .map_err(|_| AppError::bad_request("identity_sig_pub must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| AppError::bad_request("identity_sig_pub is not a valid Ed25519 public key"))?;
    Ok(())
}

fn maybe_verify_prekey_signatures(
    identity_sig_pub: &[u8],
    signed_prekey_x25519_pub: &[u8],
    sig_over_spk: &[u8],
    pq_signed_prekey_pub_mlkem768: &[u8],
    sig_over_pqspk: &[u8],
) -> Result<(), AppError> {
    let identity_sig_pub: [u8; SIG_PUB_KEY_LEN] = identity_sig_pub
        .try_into()
        .map_err(|_| AppError::bad_request("identity_sig_pub must be 32 bytes"))?;
    let verifier = VerifyingKey::from_bytes(&identity_sig_pub)
        .map_err(|_| AppError::bad_request("identity_sig_pub is not a valid Ed25519 public key"))?;

    let spk_pub: [u8; X25519_KEY_LEN] = signed_prekey_x25519_pub
        .try_into()
        .map_err(|_| AppError::bad_request("signed_prekey_x25519_pub must be 32 bytes"))?;
    let spk_signature: [u8; SIG_LEN] = sig_over_spk
        .try_into()
        .map_err(|_| AppError::bad_request("sig_over_spk must be 64 bytes"))?;
    let spk_message =
        signed_prekey_signature_message(PROTOCOL_VERSION_V1, &DhPublicKey(spk_pub))
            .map_err(|_| AppError::bad_request("failed to build SPK signature transcript"))?;
    let spk_signature = Signature::from_bytes(&spk_signature);
    verifier
        .verify(&spk_message, &spk_signature)
        .map_err(|_| AppError::bad_request("sig_over_spk verification failed"))?;

    let pq_signature: [u8; SIG_LEN] = sig_over_pqspk
        .try_into()
        .map_err(|_| AppError::bad_request("sig_over_pqspk must be 64 bytes"))?;
    let pq_message =
        pq_signed_prekey_signature_message(PROTOCOL_VERSION_V1, pq_signed_prekey_pub_mlkem768)
            .map_err(|_| AppError::bad_request("failed to build PQSPK signature transcript"))?;
    let pq_signature = Signature::from_bytes(&pq_signature);
    verifier
        .verify(&pq_message, &pq_signature)
        .map_err(|_| AppError::bad_request("sig_over_pqspk verification failed"))?;

    Ok(())
}
