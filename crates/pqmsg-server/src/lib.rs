use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pqmsg_core::alg::{SecurityProfile, PROTOCOL_VERSION_V1};
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};
use uuid::Uuid;

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
const MAX_ROTATION_CHALLENGE_ID_LEN: usize = 128;
const ROTATION_CHALLENGE_BYTES: usize = 32;
const ROTATION_CHALLENGE_TTL_MINUTES: i64 = 10;
const MAX_IDENTITY_LOG_ITEMS: i64 = 128;
const ROTATE_SIG_TAG_USER_ID: u16 = critical_type(0x3101);
const ROTATE_SIG_TAG_CHALLENGE_ID: u16 = critical_type(0x3102);
const ROTATE_SIG_TAG_CHALLENGE_NONCE: u16 = critical_type(0x3103);
const ROTATE_SIG_TAG_NEW_IDENTITY_X25519: u16 = critical_type(0x3104);
const ROTATE_SIG_TAG_NEW_IDENTITY_SIG: u16 = critical_type(0x3105);
const ROTATE_SIG_TAG_NEW_DEVICE_ID: u16 = critical_type(0x3106);
const AUTH_HEADER_USER: &str = "x-pqmsg-auth-user";
const AUTH_HEADER_DEVICE: &str = "x-pqmsg-auth-device";
const AUTH_HEADER_TIMESTAMP: &str = "x-pqmsg-auth-timestamp";
const AUTH_HEADER_NONCE: &str = "x-pqmsg-auth-nonce";
const AUTH_HEADER_SIGNATURE: &str = "x-pqmsg-auth-signature";
const AUTH_MAX_NONCE_LEN: usize = 96;
const AUTH_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
const AUTH_REPLAY_WINDOW_SECONDS: u64 = 600;
const AUTH_REPLAY_MAX_ENTRIES: usize = 100_000;
const AUTH_TAG_ENDPOINT: u16 = critical_type(0x3201);
const AUTH_TAG_USER_ID: u16 = critical_type(0x3202);
const AUTH_TAG_DEVICE_ID: u16 = critical_type(0x3203);
const AUTH_TAG_TIMESTAMP: u16 = critical_type(0x3204);
const AUTH_TAG_NONCE: u16 = critical_type(0x3205);
const AUTH_TAG_RECIPIENT_ID: u16 = critical_type(0x3206);
const AUTH_TAG_SINCE: u16 = critical_type(0x3207);
const AUTH_TAG_MESSAGE_BLOB: u16 = critical_type(0x3208);

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct AppState {
    pool: SqlitePool,
    rate_limiter: Arc<RateLimiter>,
    auth_replay: Arc<AuthReplayCache>,
    security_profile: SecurityProfile,
}

impl AppState {
    pub fn new(pool: SqlitePool, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            pool,
            rate_limiter,
            auth_replay: Arc::new(AuthReplayCache::new(
                AUTH_REPLAY_MAX_ENTRIES,
                StdDuration::from_secs(AUTH_REPLAY_WINDOW_SECONDS),
            )),
            security_profile: SecurityProfile::Research,
        }
    }

    pub fn with_security_profile(
        pool: SqlitePool,
        rate_limiter: Arc<RateLimiter>,
        security_profile: SecurityProfile,
    ) -> Self {
        Self {
            pool,
            rate_limiter,
            auth_replay: Arc::new(AuthReplayCache::new(
                AUTH_REPLAY_MAX_ENTRIES,
                StdDuration::from_secs(AUTH_REPLAY_WINDOW_SECONDS),
            )),
            security_profile,
        }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn security_profile(&self) -> SecurityProfile {
        self.security_profile
    }

    pub fn auth_replay(&self) -> &AuthReplayCache {
        &self.auth_replay
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_second: f64,
    max_entries: usize,
    bucket_ttl: StdDuration,
    inner: Arc<Mutex<HashMap<String, BucketState>>>,
}

#[derive(Clone, Copy)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Clone)]
pub struct AuthReplayCache {
    max_entries: usize,
    ttl: StdDuration,
    inner: Arc<Mutex<HashMap<String, Instant>>>,
}

impl RateLimiter {
    pub fn new(
        capacity: f64,
        refill_per_second: f64,
        max_entries: usize,
        bucket_ttl: StdDuration,
    ) -> Self {
        Self {
            capacity,
            refill_per_second,
            max_entries,
            bucket_ttl,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        let now = Instant::now();
        map.retain(|_, bucket| now.duration_since(bucket.last_refill) <= self.bucket_ttl);
        if !map.contains_key(key) && map.len() >= self.max_entries {
            if let Some(evict_key) = map
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_refill)
                .map(|(k, _)| k.clone())
            {
                map.remove(&evict_key);
            }
        }
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

impl AuthReplayCache {
    pub fn new(max_entries: usize, ttl: StdDuration) -> Self {
        Self {
            max_entries,
            ttl,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn observe(&self, user_id: &str, nonce: &str) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        let now = Instant::now();
        map.retain(|_, seen| now.duration_since(*seen) <= self.ttl);
        let key = format!("{user_id}:{nonce}");
        if map.contains_key(&key) {
            return false;
        }
        if map.len() >= self.max_entries {
            if let Some(evict_key) = map
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(k, _)| k.clone())
            {
                map.remove(&evict_key);
            }
        }
        map.insert(key, now);
        true
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

#[derive(Debug, Deserialize)]
struct RotateInitRequest {
    new_identity_x25519_pub: String,
    new_identity_sig_pub: String,
    new_device_id: String,
}

#[derive(Debug, Serialize)]
struct RotateInitResponse {
    user_id: String,
    challenge_id: String,
    challenge_nonce: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct RotateConfirmRequest {
    challenge_id: String,
    sig_by_current_identity: String,
    sig_by_new_identity: String,
}

#[derive(Debug, Serialize)]
struct RotateConfirmResponse {
    user_id: String,
    identity_key_version: u32,
    identity_fingerprint_sha256: String,
    rotated_at: String,
}

#[derive(Debug, Serialize)]
struct IdentityLogItem {
    version: u32,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    device_id: String,
    event_type: String,
    changed_at: String,
    identity_fingerprint_sha256: String,
}

#[derive(Debug, Serialize)]
struct IdentityLogResponse {
    user_id: String,
    events: Vec<IdentityLogItem>,
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
    identity_key_version: u32,
    identity_fingerprint_sha256: String,
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
    security_profile: String,
}

#[derive(Debug)]
struct RequestAuth {
    user_id: String,
    device_id: String,
    timestamp: i64,
    nonce: String,
    signature: Vec<u8>,
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
        .route("/v1/users/:user_id/rotate/init", post(rotate_init))
        .route("/v1/users/:user_id/rotate/confirm", post(rotate_confirm))
        .route("/v1/users/:user_id/identity-log", get(get_identity_log))
        .route("/v1/relay/:recipient_user_id", post(relay_message))
        .route("/v1/inbox/:user_id", get(get_inbox))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok",
        security_profile: state.security_profile().as_str().to_string(),
    })
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

    sqlx::query(
        "INSERT OR IGNORE INTO identity_events (
            user_id, version, identity_x25519_pub, identity_sig_pub, device_id, event_type, changed_at
         ) VALUES (?1, 1, ?2, ?3, ?4, 'initial', ?5)",
    )
    .bind(&request.user_id)
    .bind(&identity_x25519)
    .bind(&identity_sig)
    .bind(&request.device_id)
    .bind(&now)
    .execute(&state.pool)
    .await?;

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
            p.sig_over_pqspk,
            COALESCE((
                SELECT MAX(ie.version)
                FROM identity_events ie
                WHERE ie.user_id = u.user_id
            ), 1) AS identity_key_version
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

    let identity_x25519_pub_bytes = row.try_get::<Vec<u8>, _>("identity_x25519_pub")?;
    let identity_fingerprint = identity_fingerprint_sha256(&identity_x25519_pub_bytes);
    let identity_key_version_i64: i64 = row.try_get("identity_key_version")?;
    let identity_key_version = u32::try_from(identity_key_version_i64)
        .map_err(|_| AppError::internal("identity_key_version overflow"))?;

    Ok(Json(BundleResponse {
        user_id: row.try_get("user_id")?,
        device_id: row.try_get("device_id")?,
        identity_x25519_pub: B64.encode(identity_x25519_pub_bytes),
        identity_sig_pub: B64.encode(row.try_get::<Vec<u8>, _>("identity_sig_pub")?),
        signed_prekey_x25519_pub: B64
            .encode(row.try_get::<Vec<u8>, _>("signed_prekey_x25519_pub")?),
        sig_over_spk: B64.encode(row.try_get::<Vec<u8>, _>("sig_over_spk")?),
        pq_signed_prekey_pub_mlkem768: B64
            .encode(row.try_get::<Vec<u8>, _>("pq_signed_prekey_pub_mlkem768")?),
        sig_over_pqspk: B64.encode(row.try_get::<Vec<u8>, _>("sig_over_pqspk")?),
        one_time_prekey_x25519: x25519_otk.map(|bytes| B64.encode(bytes)),
        one_time_prekey_mlkem768: mlkem_otk.map(|bytes| B64.encode(bytes)),
        identity_key_version,
        identity_fingerprint_sha256: identity_fingerprint,
        bundle_generated_at: Utc::now().to_rfc3339(),
    }))
}

async fn rotate_init(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(request): Json<RotateInitRequest>,
) -> Result<Json<RotateInitResponse>, AppError> {
    check_rate_limit(&state, &format!("rotate-init:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("new_device_id", &request.new_device_id)?;

    let new_identity_x25519 = decode_base64_exact(
        "new_identity_x25519_pub",
        &request.new_identity_x25519_pub,
        X25519_KEY_LEN,
    )?;
    let new_identity_sig = decode_base64_exact(
        "new_identity_sig_pub",
        &request.new_identity_sig_pub,
        SIG_PUB_KEY_LEN,
    )?;
    validate_ed25519_public_key(&new_identity_sig)?;

    let user_row = sqlx::query(
        "SELECT identity_x25519_pub, identity_sig_pub, device_id
         FROM users
         WHERE user_id = ?1",
    )
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(user_row) = user_row else {
        return Err(AppError::not_found("user not found"));
    };

    let current_identity_x25519: Vec<u8> = user_row.try_get("identity_x25519_pub")?;
    let current_identity_sig: Vec<u8> = user_row.try_get("identity_sig_pub")?;
    let current_device_id: String = user_row.try_get("device_id")?;
    if current_identity_x25519 == new_identity_x25519
        && current_identity_sig == new_identity_sig
        && current_device_id == request.new_device_id
    {
        return Err(AppError::bad_request(
            "rotation request matches current identity material",
        ));
    }

    let mut nonce = [0u8; ROTATION_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let challenge_id = Uuid::new_v4().to_string();
    let created_at = Utc::now();
    let expires_at = created_at + Duration::minutes(ROTATION_CHALLENGE_TTL_MINUTES);
    let created_at_rfc3339 = created_at.to_rfc3339();
    let expires_at_rfc3339 = expires_at.to_rfc3339();

    sqlx::query(
        "INSERT INTO identity_rotation_challenges (
            challenge_id,
            user_id,
            nonce,
            new_identity_x25519_pub,
            new_identity_sig_pub,
            new_device_id,
            created_at,
            expires_at,
            consumed
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
    )
    .bind(&challenge_id)
    .bind(&user_id)
    .bind(nonce.to_vec())
    .bind(new_identity_x25519)
    .bind(new_identity_sig)
    .bind(&request.new_device_id)
    .bind(created_at_rfc3339)
    .bind(&expires_at_rfc3339)
    .execute(&state.pool)
    .await?;

    Ok(Json(RotateInitResponse {
        user_id,
        challenge_id,
        challenge_nonce: B64.encode(nonce),
        expires_at: expires_at_rfc3339,
    }))
}

async fn rotate_confirm(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(request): Json<RotateConfirmRequest>,
) -> Result<Json<RotateConfirmResponse>, AppError> {
    check_rate_limit(&state, &format!("rotate-confirm:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_rotation_challenge_id(&request.challenge_id)?;

    let sig_by_current = decode_base64_exact(
        "sig_by_current_identity",
        &request.sig_by_current_identity,
        SIG_LEN,
    )?;
    let sig_by_new =
        decode_base64_exact("sig_by_new_identity", &request.sig_by_new_identity, SIG_LEN)?;

    let now = Utc::now();
    let mut tx = state.pool.begin().await?;

    let challenge_row = sqlx::query(
        "SELECT nonce, new_identity_x25519_pub, new_identity_sig_pub, new_device_id, expires_at
         FROM identity_rotation_challenges
         WHERE challenge_id = ?1 AND user_id = ?2 AND consumed = 0",
    )
    .bind(&request.challenge_id)
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(challenge_row) = challenge_row else {
        return Err(AppError::not_found("rotation challenge not found"));
    };

    let nonce: Vec<u8> = challenge_row.try_get("nonce")?;
    let new_identity_x25519: Vec<u8> = challenge_row.try_get("new_identity_x25519_pub")?;
    let new_identity_sig: Vec<u8> = challenge_row.try_get("new_identity_sig_pub")?;
    let new_device_id: String = challenge_row.try_get("new_device_id")?;
    let expires_at_str: String = challenge_row.try_get("expires_at")?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| AppError::internal("invalid rotation challenge expiry"))?
        .with_timezone(&Utc);
    if now > expires_at {
        return Err(AppError::bad_request("rotation challenge expired"));
    }

    let user_row = sqlx::query("SELECT identity_sig_pub FROM users WHERE user_id = ?1")
        .bind(&user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(user_row) = user_row else {
        return Err(AppError::not_found("user not found"));
    };
    let current_identity_sig: Vec<u8> = user_row.try_get("identity_sig_pub")?;

    let message = rotation_signature_message(
        &user_id,
        &request.challenge_id,
        &nonce,
        &new_identity_x25519,
        &new_identity_sig,
        &new_device_id,
    )?;
    verify_ed25519_signature(
        &current_identity_sig,
        &sig_by_current,
        &message,
        "sig_by_current_identity",
    )?;
    verify_ed25519_signature(
        &new_identity_sig,
        &sig_by_new,
        &message,
        "sig_by_new_identity",
    )?;

    let consume_result = sqlx::query(
        "UPDATE identity_rotation_challenges
         SET consumed = 1
         WHERE challenge_id = ?1 AND user_id = ?2 AND consumed = 0",
    )
    .bind(&request.challenge_id)
    .bind(&user_id)
    .execute(&mut *tx)
    .await?;
    if consume_result.rows_affected() != 1 {
        return Err(AppError::conflict("rotation challenge already consumed"));
    }

    let rotated_at = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE users
         SET identity_x25519_pub = ?1, identity_sig_pub = ?2, device_id = ?3, updated_at = ?4
         WHERE user_id = ?5",
    )
    .bind(&new_identity_x25519)
    .bind(&new_identity_sig)
    .bind(&new_device_id)
    .bind(&rotated_at)
    .bind(&user_id)
    .execute(&mut *tx)
    .await?;

    let next_version_i64: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1
         FROM identity_events
         WHERE user_id = ?1",
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await?;
    let next_version = u32::try_from(next_version_i64)
        .map_err(|_| AppError::internal("identity version overflow"))?;

    sqlx::query(
        "INSERT INTO identity_events (
            user_id,
            version,
            identity_x25519_pub,
            identity_sig_pub,
            device_id,
            event_type,
            changed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'rotation', ?6)",
    )
    .bind(&user_id)
    .bind(i64::from(next_version))
    .bind(&new_identity_x25519)
    .bind(&new_identity_sig)
    .bind(&new_device_id)
    .bind(&rotated_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Json(RotateConfirmResponse {
        user_id,
        identity_key_version: next_version,
        identity_fingerprint_sha256: identity_fingerprint_sha256(&new_identity_x25519),
        rotated_at,
    }))
}

async fn get_identity_log(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<IdentityLogResponse>, AppError> {
    check_rate_limit(&state, &format!("identity-log:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = identity_log_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let rows = sqlx::query(
        "SELECT
            version,
            identity_x25519_pub,
            identity_sig_pub,
            device_id,
            event_type,
            changed_at
         FROM identity_events
         WHERE user_id = ?1
         ORDER BY version DESC
         LIMIT ?2",
    )
    .bind(&user_id)
    .bind(MAX_IDENTITY_LOG_ITEMS)
    .fetch_all(&state.pool)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let version_i64: i64 = row.try_get("version")?;
        let version = u32::try_from(version_i64)
            .map_err(|_| AppError::internal("identity version overflow"))?;
        let identity_x25519_pub: Vec<u8> = row.try_get("identity_x25519_pub")?;
        let identity_sig_pub: Vec<u8> = row.try_get("identity_sig_pub")?;
        events.push(IdentityLogItem {
            version,
            identity_x25519_pub: B64.encode(&identity_x25519_pub),
            identity_sig_pub: B64.encode(identity_sig_pub),
            device_id: row.try_get("device_id")?,
            event_type: row.try_get("event_type")?,
            changed_at: row.try_get("changed_at")?,
            identity_fingerprint_sha256: identity_fingerprint_sha256(&identity_x25519_pub),
        });
    }

    Ok(Json(IdentityLogResponse { user_id, events }))
}

async fn relay_message(
    State(state): State<AppState>,
    Path(recipient_user_id): Path<String>,
    headers: HeaderMap,
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
    headers: HeaderMap,
    Query(query): Query<InboxQuery>,
) -> Result<Json<InboxResponse>, AppError> {
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

fn parse_request_auth(headers: &HeaderMap) -> Result<RequestAuth, AppError> {
    let user_id = require_header_value(headers, AUTH_HEADER_USER, MAX_USER_ID_LEN)?;
    let device_id = require_header_value(headers, AUTH_HEADER_DEVICE, MAX_DEVICE_ID_LEN)?;
    validate_id("auth.user_id", &user_id)?;
    validate_id("auth.device_id", &device_id)?;

    let timestamp_raw = require_header_value(headers, AUTH_HEADER_TIMESTAMP, 32)?;
    let timestamp = timestamp_raw
        .parse::<i64>()
        .map_err(|_| AppError::bad_request("x-pqmsg-auth-timestamp must be an integer"))?;

    let nonce = require_header_value(headers, AUTH_HEADER_NONCE, AUTH_MAX_NONCE_LEN)?;
    let signature_b64 = require_header_value(headers, AUTH_HEADER_SIGNATURE, 256)?;
    let signature = decode_base64_exact(AUTH_HEADER_SIGNATURE, &signature_b64, SIG_LEN)?;

    Ok(RequestAuth {
        user_id,
        device_id,
        timestamp,
        nonce,
        signature,
    })
}

fn require_header_value(
    headers: &HeaderMap,
    name: &'static str,
    max_len: usize,
) -> Result<String, AppError> {
    let value = headers
        .get(name)
        .ok_or_else(|| AppError::bad_request(format!("missing header '{name}'")))?;
    let value = value
        .to_str()
        .map_err(|_| AppError::bad_request(format!("header '{name}' must be ASCII")))?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        return Err(AppError::bad_request(format!(
            "header '{name}' must be 1..={max_len} characters"
        )));
    }
    Ok(trimmed.to_string())
}

async fn verify_request_auth(
    state: &AppState,
    auth: &RequestAuth,
    message: &[u8],
) -> Result<(), AppError> {
    let now = Utc::now().timestamp();
    if (now - auth.timestamp).abs() > AUTH_MAX_CLOCK_SKEW_SECONDS {
        return Err(AppError::bad_request(
            "request timestamp outside allowed skew",
        ));
    }
    if !state.auth_replay().observe(&auth.user_id, &auth.nonce) {
        return Err(AppError::conflict("request nonce replayed"));
    }

    let user_row = sqlx::query("SELECT device_id, identity_sig_pub FROM users WHERE user_id = ?1")
        .bind(&auth.user_id)
        .fetch_optional(state.pool())
        .await?;
    let Some(user_row) = user_row else {
        return Err(AppError::not_found("auth user not found"));
    };
    let registered_device: String = user_row.try_get("device_id")?;
    if registered_device != auth.device_id {
        return Err(AppError::bad_request("auth device mismatch for user"));
    }
    let identity_sig_pub: Vec<u8> = user_row.try_get("identity_sig_pub")?;
    verify_ed25519_signature(
        &identity_sig_pub,
        &auth.signature,
        message,
        AUTH_HEADER_SIGNATURE,
    )
}

fn auth_common_records(auth: &RequestAuth, endpoint: &'static str) -> Vec<TlvRecord> {
    vec![
        TlvRecord {
            ty: AUTH_TAG_ENDPOINT,
            value: endpoint.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_USER_ID,
            value: auth.user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_DEVICE_ID,
            value: auth.device_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_TIMESTAMP,
            value: auth.timestamp.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_NONCE,
            value: auth.nonce.as_bytes().to_vec(),
        },
    ]
}

fn relay_auth_message(
    auth: &RequestAuth,
    recipient_user_id: &str,
    message_blob: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "relay");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_MESSAGE_BLOB,
        value: message_blob.to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode relay auth transcript"))
}

fn inbox_auth_message(auth: &RequestAuth, user_id: &str, since: i64) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "inbox");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode inbox auth transcript"))
}

fn identity_log_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "identity-log");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode identity-log auth transcript"))
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

fn validate_rotation_challenge_id(value: &str) -> Result<(), AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ROTATION_CHALLENGE_ID_LEN {
        return Err(AppError::bad_request(format!(
            "challenge_id must be 1..{MAX_ROTATION_CHALLENGE_ID_LEN} characters"
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

fn verify_ed25519_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    field: &'static str,
) -> Result<(), AppError> {
    let public_key: [u8; SIG_PUB_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| AppError::bad_request("identity_sig_pub must be 32 bytes"))?;
    let verifier = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AppError::bad_request("identity_sig_pub is not a valid Ed25519 public key"))?;
    let signature: [u8; SIG_LEN] = signature
        .try_into()
        .map_err(|_| AppError::bad_request(format!("{field} must be 64 bytes")))?;
    let signature = Signature::from_bytes(&signature);
    verifier
        .verify(message, &signature)
        .map_err(|_| AppError::bad_request(format!("{field} verification failed")))?;
    Ok(())
}

fn validate_ed25519_public_key(identity_sig_pub: &[u8]) -> Result<(), AppError> {
    let key_bytes: [u8; SIG_PUB_KEY_LEN] = identity_sig_pub
        .try_into()
        .map_err(|_| AppError::bad_request("identity_sig_pub must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| AppError::bad_request("identity_sig_pub is not a valid Ed25519 public key"))?;
    Ok(())
}

fn rotation_signature_message(
    user_id: &str,
    challenge_id: &str,
    challenge_nonce: &[u8],
    new_identity_x25519: &[u8],
    new_identity_sig: &[u8],
    new_device_id: &str,
) -> Result<Vec<u8>, AppError> {
    encode(&[
        TlvRecord {
            ty: ROTATE_SIG_TAG_USER_ID,
            value: user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_CHALLENGE_ID,
            value: challenge_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_CHALLENGE_NONCE,
            value: challenge_nonce.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_IDENTITY_X25519,
            value: new_identity_x25519.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_IDENTITY_SIG,
            value: new_identity_sig.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_DEVICE_ID,
            value: new_device_id.as_bytes().to_vec(),
        },
    ])
    .map_err(|_| AppError::internal("rotation signature transcript encoding failed"))
}

fn identity_fingerprint_sha256(identity_key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(identity_key);
    hex::encode(hasher.finalize())
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
