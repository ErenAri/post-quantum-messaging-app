use axum::extract::{MatchedPath, State};
use axum::http::HeaderValue;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;

use pqmsg_core::alg::SecurityProfile;
use pqmsg_core::tlv::critical_type;
use serde_json::json;

use sqlx::AnyPool;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::mpsc;
use tracing::Instrument;
use tracing::{info, warn};
use uuid::Uuid;

mod db;
mod error;
mod types;
mod auth;
mod validation;

pub use db::{DbBackend, init_db, parse_db_backend};
pub use error::AppError;

use types::*;
use auth::*;
use validation::*;
mod handlers;
use handlers::*;

pub(crate) const MAX_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_USER_ID_LEN: usize = 128;
pub(crate) const MAX_DEVICE_ID_LEN: usize = 128;
pub(crate) const X25519_KEY_LEN: usize = 32;
pub(crate) const SIG_PUB_KEY_LEN: usize = 32;
pub(crate) const SIG_LEN: usize = 64;
pub(crate) const MIN_PQ_KEY_LEN: usize = 32;
pub(crate) const MAX_PQ_KEY_LEN: usize = 4096;
pub(crate) const MAX_ONE_TIME_KEYS: usize = 256;
pub(crate) const MAX_MESSAGE_BYTES: usize = 1_000_000;
pub(crate) const MAX_INBOX_PAGE: i64 = 200;
pub(crate) const MAX_PUSH_TOKEN_LEN: usize = 4096;
pub(crate) const MAX_CONTACT_ALIAS_LEN: usize = 128;
pub(crate) const MAX_PROFILE_DISPLAY_NAME_LEN: usize = 128;
pub(crate) const MAX_MIME_TYPE_LEN: usize = 128;
pub(crate) const MAX_FILE_ID_LEN: usize = 128;
pub(crate) const SHA256_HEX_LEN: usize = 64;
pub(crate) const MAX_DISCOVERY_HASHES: usize = 4096;
pub(crate) const MAX_GROUP_MEMBERS: usize = 512;
pub(crate) const MAX_FILE_BLOB_BYTES: usize = 900_000;
pub(crate) const MAX_AVATAR_BLOB_BYTES: usize = 262_144;
pub(crate) const MAX_TYPING_EVENTS: i64 = 128;
pub(crate) const PRESENCE_TTL_SECONDS: i64 = 180;
pub(crate) const TYPING_TTL_SECONDS: i64 = 15;
pub(crate) const MAX_ROTATION_CHALLENGE_ID_LEN: usize = 128;
pub(crate) const ROTATION_CHALLENGE_BYTES: usize = 32;
pub(crate) const ROTATION_CHALLENGE_TTL_MINUTES: i64 = 10;
pub(crate) const MAX_IDENTITY_LOG_ITEMS: i64 = 128;
pub(crate) const ROTATE_SIG_TAG_USER_ID: u16 = critical_type(0x3101);
pub(crate) const ROTATE_SIG_TAG_CHALLENGE_ID: u16 = critical_type(0x3102);
pub(crate) const ROTATE_SIG_TAG_CHALLENGE_NONCE: u16 = critical_type(0x3103);
pub(crate) const ROTATE_SIG_TAG_NEW_IDENTITY_X25519: u16 = critical_type(0x3104);
pub(crate) const ROTATE_SIG_TAG_NEW_IDENTITY_SIG: u16 = critical_type(0x3105);
pub(crate) const ROTATE_SIG_TAG_NEW_DEVICE_ID: u16 = critical_type(0x3106);
pub(crate) const AUTH_HEADER_USER: &str = "x-pqmsg-auth-user";
pub(crate) const AUTH_HEADER_DEVICE: &str = "x-pqmsg-auth-device";
pub(crate) const AUTH_HEADER_TIMESTAMP: &str = "x-pqmsg-auth-timestamp";
pub(crate) const AUTH_HEADER_NONCE: &str = "x-pqmsg-auth-nonce";
pub(crate) const AUTH_HEADER_SIGNATURE: &str = "x-pqmsg-auth-signature";
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";
pub(crate) const AUTH_MAX_NONCE_LEN: usize = 96;
pub(crate) const MAX_REQUEST_ID_LEN: usize = 128;
pub(crate) const AUTH_MAX_CLOCK_SKEW_SECONDS: i64 = 300;
pub(crate) const AUTH_REPLAY_WINDOW_SECONDS: u64 = 600;
pub(crate) const AUTH_REPLAY_MAX_ENTRIES: usize = 100_000;
pub(crate) const RELAY_DEDUP_TTL_SECONDS: i64 = 900;
pub(crate) const PREKEY_LOW_WATERMARK: i64 = 4;
pub(crate) const PREKEY_REPLENISH_TARGET: i64 = 16;
pub(crate) const AUTH_TAG_ENDPOINT: u16 = critical_type(0x3201);
pub(crate) const AUTH_TAG_USER_ID: u16 = critical_type(0x3202);
pub(crate) const AUTH_TAG_DEVICE_ID: u16 = critical_type(0x3203);
pub(crate) const AUTH_TAG_TIMESTAMP: u16 = critical_type(0x3204);
pub(crate) const AUTH_TAG_NONCE: u16 = critical_type(0x3205);
pub(crate) const AUTH_TAG_RECIPIENT_ID: u16 = critical_type(0x3206);
pub(crate) const AUTH_TAG_SINCE: u16 = critical_type(0x3207);
pub(crate) const AUTH_TAG_MESSAGE_BLOB: u16 = critical_type(0x3208);
pub(crate) const AUTH_TAG_PREKEY_SPK_HASH: u16 = critical_type(0x3209);
pub(crate) const AUTH_TAG_PREKEY_PQSPK_HASH: u16 = critical_type(0x320A);
pub(crate) const AUTH_TAG_ROTATE_NEW_X25519_HASH: u16 = critical_type(0x320B);
pub(crate) const AUTH_TAG_ROTATE_NEW_SIG_HASH: u16 = critical_type(0x320C);
pub(crate) const AUTH_TAG_ROTATE_CHALLENGE_ID: u16 = critical_type(0x320D);
pub(crate) const AUTH_TAG_ROTATE_SIG_CURRENT_HASH: u16 = critical_type(0x320E);
pub(crate) const AUTH_TAG_ROTATE_SIG_NEW_HASH: u16 = critical_type(0x320F);
pub(crate) const AUTH_TAG_PUSH_DEVICE_ID: u16 = critical_type(0x3210);
pub(crate) const AUTH_TAG_PUSH_TOKEN_HASH: u16 = critical_type(0x3211);
pub(crate) const AUTH_TAG_LINK_DEVICE_ID: u16 = critical_type(0x3212);
pub(crate) const AUTH_TAG_REVOKE_DEVICE_ID: u16 = critical_type(0x3213);
pub(crate) const AUTH_TAG_DELETE_IDS_HASH: u16 = critical_type(0x3214);
pub(crate) const AUTH_TAG_DELETE_BEFORE_ID: u16 = critical_type(0x3215);
pub(crate) const AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH: u16 = critical_type(0x3216);
pub(crate) const AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH: u16 = critical_type(0x3217);
pub(crate) const AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH: u16 = critical_type(0x3218);
pub(crate) const AUTH_TAG_CONTACT_USER_ID: u16 = critical_type(0x3219);
pub(crate) const AUTH_TAG_CONTACT_ALIAS_HASH: u16 = critical_type(0x321A);
pub(crate) const AUTH_TAG_CONTACT_VERIFIED_FLAG: u16 = critical_type(0x321B);
pub(crate) const AUTH_TAG_CONTACT_FINGERPRINT: u16 = critical_type(0x321C);
pub(crate) const AUTH_TAG_GROUP_ID: u16 = critical_type(0x321D);
pub(crate) const AUTH_TAG_GROUP_MEMBER_USER_ID: u16 = critical_type(0x321E);
pub(crate) const AUTH_TAG_GROUP_MEMBERS_HASH: u16 = critical_type(0x321F);
pub(crate) const AUTH_TAG_GROUP_SENDER_USER_ID: u16 = critical_type(0x3220);
pub(crate) const AUTH_TAG_GROUP_MESSAGE_BLOB_HASH: u16 = critical_type(0x3221);
pub(crate) const AUTH_TAG_FILE_ID: u16 = critical_type(0x3222);
pub(crate) const AUTH_TAG_FILE_RECIPIENT_ID: u16 = critical_type(0x3223);
pub(crate) const AUTH_TAG_FILE_BLOB_HASH: u16 = critical_type(0x3224);
pub(crate) const AUTH_TAG_FILE_MIME_HASH: u16 = critical_type(0x3225);
pub(crate) const AUTH_TAG_PROFILE_DISPLAY_NAME_HASH: u16 = critical_type(0x3226);
pub(crate) const AUTH_TAG_PROFILE_AVATAR_HASH: u16 = critical_type(0x3227);
pub(crate) const AUTH_TAG_PROFILE_AVATAR_MIME_HASH: u16 = critical_type(0x3228);
pub(crate) const AUTH_TAG_PRESENCE_STATUS: u16 = critical_type(0x3229);
pub(crate) const AUTH_TAG_TYPING_PEER_ID: u16 = critical_type(0x322A);
pub(crate) const AUTH_TAG_TYPING_STATE_FLAG: u16 = critical_type(0x322B);
pub(crate) const MAX_DELETE_MESSAGE_IDS: usize = 512;
pub(crate) const MAX_POW_NONCE_LEN: usize = 128;
pub(crate) const DEFAULT_REGISTRATION_POW_BITS_HARDENED: u8 = 18;
pub(crate) const DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_HARDENED: i64 = 30;
pub(crate) const DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_HARDENED: i64 = 2;
pub(crate) const DEFAULT_REGISTRATION_POW_BITS_RESEARCH: u8 = 0;
pub(crate) const DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_RESEARCH: i64 = 0;
pub(crate) const DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_RESEARCH: i64 = 0;
pub(crate) const DEFAULT_RATE_LIMIT_REDIS_KEY_PREFIX: &str = "pqmsg:ratelimit:";
pub(crate) const REDIS_RATE_LIMIT_SCRIPT: &str = r#"
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill_per_ms = tonumber(ARGV[3])
local ttl_ms = tonumber(ARGV[4])
local requested = 1

local current = redis.call('HMGET', key, 'tokens', 'last_ms')
local tokens = tonumber(current[1])
local last_ms = tonumber(current[2])
if tokens == nil then
  tokens = capacity
  last_ms = now_ms
end

local elapsed = now_ms - last_ms
if elapsed < 0 then
  elapsed = 0
end
tokens = math.min(capacity, tokens + (elapsed * refill_per_ms))

local allowed = 0
if tokens >= requested then
  tokens = tokens - requested
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'last_ms', now_ms)
redis.call('PEXPIRE', key, ttl_ms)
return allowed
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DosHardeningPolicy {
    registration_pow_bits: u8,
    prekey_publish_min_interval_seconds: i64,
    prekey_bundle_reserve_count: i64,
}

impl DosHardeningPolicy {
    pub fn for_security_profile(profile: SecurityProfile) -> Self {
        match profile {
            SecurityProfile::Research => Self {
                registration_pow_bits: DEFAULT_REGISTRATION_POW_BITS_RESEARCH,
                prekey_publish_min_interval_seconds:
                    DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_RESEARCH,
                prekey_bundle_reserve_count: DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_RESEARCH,
            },
            SecurityProfile::HighAssurance | SecurityProfile::NssAligned => Self {
                registration_pow_bits: DEFAULT_REGISTRATION_POW_BITS_HARDENED,
                prekey_publish_min_interval_seconds:
                    DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_HARDENED,
                prekey_bundle_reserve_count: DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_HARDENED,
            },
        }
    }

    pub fn registration_pow_bits(self) -> u8 {
        self.registration_pow_bits
    }

    pub fn prekey_publish_min_interval_seconds(self) -> i64 {
        self.prekey_publish_min_interval_seconds
    }

    pub fn prekey_bundle_reserve_count(self) -> i64 {
        self.prekey_bundle_reserve_count
    }

    pub fn with_registration_pow_bits(mut self, bits: u8) -> Self {
        self.registration_pow_bits = bits;
        self
    }

    pub fn with_prekey_publish_min_interval_seconds(mut self, seconds: i64) -> Self {
        self.prekey_publish_min_interval_seconds = seconds.max(0);
        self
    }

    pub fn with_prekey_bundle_reserve_count(mut self, count: i64) -> Self {
        self.prekey_bundle_reserve_count = count.max(0);
        self
    }
}

#[derive(Clone)]
pub struct AppState {
    pool: AnyPool,
    db_backend: DbBackend,
    rate_limiter: Arc<RateLimiter>,
    auth_replay: Arc<AuthReplayCache>,
    realtime_hub: RealtimeHub,
    push_notifier: Arc<PushNotifier>,
    security_profile: SecurityProfile,
    dos_policy: DosHardeningPolicy,
    metrics: Arc<MetricsRegistry>,
    audit_logger: Arc<AuditLogger>,
}

impl AppState {
    pub fn new(pool: AnyPool, db_backend: DbBackend, rate_limiter: Arc<RateLimiter>) -> Self {
        let security_profile = SecurityProfile::Research;
        Self {
            pool,
            db_backend,
            rate_limiter,
            auth_replay: Arc::new(AuthReplayCache::new(
                AUTH_REPLAY_MAX_ENTRIES,
                StdDuration::from_secs(AUTH_REPLAY_WINDOW_SECONDS),
            )),
            realtime_hub: RealtimeHub::new(),
            push_notifier: Arc::new(PushNotifier::disabled()),
            security_profile,
            dos_policy: DosHardeningPolicy::for_security_profile(security_profile),
            metrics: Arc::new(MetricsRegistry::new()),
            audit_logger: Arc::new(AuditLogger::disabled()),
        }
    }

    pub fn with_security_profile(
        pool: AnyPool,
        db_backend: DbBackend,
        rate_limiter: Arc<RateLimiter>,
        security_profile: SecurityProfile,
    ) -> Self {
        Self {
            pool,
            db_backend,
            rate_limiter,
            auth_replay: Arc::new(AuthReplayCache::new(
                AUTH_REPLAY_MAX_ENTRIES,
                StdDuration::from_secs(AUTH_REPLAY_WINDOW_SECONDS),
            )),
            realtime_hub: RealtimeHub::new(),
            push_notifier: Arc::new(PushNotifier::disabled()),
            security_profile,
            dos_policy: DosHardeningPolicy::for_security_profile(security_profile),
            metrics: Arc::new(MetricsRegistry::new()),
            audit_logger: Arc::new(AuditLogger::disabled()),
        }
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn db_backend(&self) -> DbBackend {
        self.db_backend
    }

    pub fn security_profile(&self) -> SecurityProfile {
        self.security_profile
    }

    pub fn dos_policy(&self) -> DosHardeningPolicy {
        self.dos_policy
    }

    pub fn auth_replay(&self) -> &AuthReplayCache {
        &self.auth_replay
    }

    pub fn realtime_hub(&self) -> &RealtimeHub {
        &self.realtime_hub
    }

    pub fn push_notifier(&self) -> &PushNotifier {
        &self.push_notifier
    }

    pub fn metrics(&self) -> &MetricsRegistry {
        &self.metrics
    }

    pub fn audit_logger(&self) -> &AuditLogger {
        &self.audit_logger
    }

    pub fn with_push_notifier(mut self, push_notifier: Arc<PushNotifier>) -> Self {
        self.push_notifier = push_notifier;
        self
    }

    pub fn with_dos_policy(mut self, dos_policy: DosHardeningPolicy) -> Self {
        self.dos_policy = dos_policy;
        self
    }

    pub fn with_audit_logger(mut self, audit_logger: Arc<AuditLogger>) -> Self {
        self.audit_logger = audit_logger;
        self
    }
}

#[derive(Clone)]
pub struct RealtimeHub {
    inner: Arc<Mutex<HashMap<String, Vec<RealtimeSubscriber>>>>,
    next_id: Arc<AtomicU64>,
}

#[derive(Clone)]
struct RealtimeSubscriber {
    id: u64,
    sender: mpsc::UnboundedSender<InboxItem>,
}

#[derive(Clone)]
pub struct PushNotifier {
    client: reqwest::Client,
    fcm_server_key: Option<String>,
    fcm_endpoint: String,
    apns_bearer_token: Option<String>,
    apns_topic: Option<String>,
    apns_endpoint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PushProvider {
    Fcm,
    Apns,
}

impl PushProvider {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fcm => "fcm",
            Self::Apns => "apns",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "fcm" => Some(Self::Fcm),
            "apns" => Some(Self::Apns),
            _ => None,
        }
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct HttpMetricKey {
    method: String,
    path: String,
    status: u16,
}

#[derive(Clone)]
pub struct MetricsRegistry {
    requests_total: Arc<Mutex<HashMap<HttpMetricKey, u64>>>,
    request_duration_sum_seconds: Arc<Mutex<HashMap<HttpMetricKey, f64>>>,
    security_events_total: Arc<Mutex<HashMap<String, u64>>>,
    in_flight_requests: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct AuditLogger {
    file: Option<Arc<Mutex<std::fs::File>>>,
}

#[derive(Clone)]
struct RedisRateLimiter {
    client: redis::Client,
    key_prefix: String,
}

#[derive(Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_second: f64,
    max_entries: usize,
    bucket_ttl: StdDuration,
    inner: Arc<Mutex<HashMap<String, BucketState>>>,
    redis_backend: Option<RedisRateLimiter>,
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

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            requests_total: Arc::new(Mutex::new(HashMap::new())),
            request_duration_sum_seconds: Arc::new(Mutex::new(HashMap::new())),
            security_events_total: Arc::new(Mutex::new(HashMap::new())),
            in_flight_requests: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn observe_request_start(&self) {
        self.in_flight_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_request_finish(
        &self,
        method: &str,
        path: &str,
        status: u16,
        duration: StdDuration,
    ) {
        let _ =
            self.in_flight_requests
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_sub(1))
                });
        let key = HttpMetricKey {
            method: method.to_string(),
            path: path.to_string(),
            status,
        };
        if let Ok(mut totals) = self.requests_total.lock() {
            *totals.entry(key.clone()).or_insert(0) += 1;
        }
        if let Ok(mut sums) = self.request_duration_sum_seconds.lock() {
            *sums.entry(key).or_insert(0.0) += duration.as_secs_f64();
        }
    }

    pub fn record_security_event(&self, event: &str) {
        if let Ok(mut events) = self.security_events_total.lock() {
            *events.entry(event.to_string()).or_insert(0) += 1;
        }
    }

    pub fn render_prometheus(&self) -> String {
        let in_flight = self.in_flight_requests.load(Ordering::Relaxed);
        let requests_total = self
            .requests_total
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();
        let request_duration_sum_seconds = self
            .request_duration_sum_seconds
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();
        let security_events_total = self
            .security_events_total
            .lock()
            .map(|value| value.clone())
            .unwrap_or_default();

        let mut request_keys: Vec<_> = requests_total.keys().cloned().collect();
        request_keys
            .sort_by(|a, b| (&a.method, &a.path, a.status).cmp(&(&b.method, &b.path, b.status)));
        let mut security_keys: Vec<_> = security_events_total.keys().cloned().collect();
        security_keys.sort_unstable();

        let mut body = String::new();
        body.push_str("# HELP pqmsg_http_in_flight_requests Current in-flight HTTP requests\n");
        body.push_str("# TYPE pqmsg_http_in_flight_requests gauge\n");
        body.push_str(&format!("pqmsg_http_in_flight_requests {in_flight}\n"));
        body.push_str(
            "# HELP pqmsg_http_requests_total Total HTTP requests by method, path and status\n",
        );
        body.push_str("# TYPE pqmsg_http_requests_total counter\n");
        for key in &request_keys {
            let labels = format!(
                "method=\"{}\",path=\"{}\",status=\"{}\"",
                prometheus_escape_label(&key.method),
                prometheus_escape_label(&key.path),
                key.status
            );
            let count = requests_total.get(key).copied().unwrap_or(0);
            body.push_str(&format!("pqmsg_http_requests_total{{{labels}}} {count}\n"));
        }
        body.push_str(
            "# HELP pqmsg_http_request_duration_seconds_sum Total HTTP request duration in seconds\n",
        );
        body.push_str("# TYPE pqmsg_http_request_duration_seconds_sum counter\n");
        for key in &request_keys {
            let labels = format!(
                "method=\"{}\",path=\"{}\",status=\"{}\"",
                prometheus_escape_label(&key.method),
                prometheus_escape_label(&key.path),
                key.status
            );
            let sum = request_duration_sum_seconds
                .get(key)
                .copied()
                .unwrap_or(0.0);
            body.push_str(&format!(
                "pqmsg_http_request_duration_seconds_sum{{{labels}}} {sum}\n"
            ));
            let count = requests_total.get(key).copied().unwrap_or(0);
            body.push_str(&format!(
                "pqmsg_http_request_duration_seconds_count{{{labels}}} {count}\n"
            ));
        }
        body.push_str("# HELP pqmsg_security_events_total Total security events by type\n");
        body.push_str("# TYPE pqmsg_security_events_total counter\n");
        for key in security_keys {
            let count = security_events_total.get(&key).copied().unwrap_or(0);
            body.push_str(&format!(
                "pqmsg_security_events_total{{event=\"{}\"}} {count}\n",
                prometheus_escape_label(&key)
            ));
        }
        body
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn disabled() -> Self {
        Self { file: None }
    }

    pub fn with_path(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Some(Arc::new(Mutex::new(file))),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.file.is_some()
    }

    pub fn log_security_event(
        &self,
        event: &str,
        outcome: &str,
        request_id: Option<&str>,
        user_id: Option<&str>,
        device_id: Option<&str>,
        detail: Option<&str>,
    ) {
        let payload = json!({
            "ts": Utc::now().to_rfc3339(),
            "event": event,
            "outcome": outcome,
            "request_id": request_id,
            "user_id": user_id,
            "device_id": device_id,
            "detail": detail,
        });
        info!(
            target: "pqmsg_server::audit",
            event,
            outcome,
            request_id = request_id.unwrap_or_default(),
            user_id = user_id.unwrap_or_default(),
            device_id = device_id.unwrap_or_default(),
            detail = detail.unwrap_or_default()
        );
        let Some(file) = &self.file else {
            return;
        };
        let serialized = match serde_json::to_string(&payload) {
            Ok(value) => value,
            Err(error) => {
                warn!("failed to serialize audit event: {error}");
                return;
            }
        };
        let Ok(mut guard) = file.lock() else {
            warn!("failed to lock audit log file");
            return;
        };
        if let Err(error) = writeln!(guard, "{serialized}") {
            warn!("failed to append audit log event: {error}");
        }
    }
}

fn prometheus_escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
            redis_backend: None,
        }
    }

    pub fn with_redis(
        capacity: f64,
        refill_per_second: f64,
        max_entries: usize,
        bucket_ttl: StdDuration,
        redis_url: &str,
        key_prefix: Option<String>,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            capacity,
            refill_per_second,
            max_entries,
            bucket_ttl,
            inner: Arc::new(Mutex::new(HashMap::new())),
            redis_backend: Some(RedisRateLimiter {
                client,
                key_prefix: key_prefix
                    .unwrap_or_else(|| DEFAULT_RATE_LIMIT_REDIS_KEY_PREFIX.to_string()),
            }),
        })
    }

    pub fn is_distributed(&self) -> bool {
        self.redis_backend.is_some()
    }

    pub fn allow(&self, key: &str) -> bool {
        if let Some(redis_backend) = &self.redis_backend {
            return self.allow_redis(redis_backend, key);
        }
        self.allow_in_memory(key)
    }

    fn allow_in_memory(&self, key: &str) -> bool {
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

    fn allow_redis(&self, redis_backend: &RedisRateLimiter, key: &str) -> bool {
        if !self.capacity.is_finite()
            || !self.refill_per_second.is_finite()
            || self.capacity <= 0.0
            || self.refill_per_second <= 0.0
        {
            return false;
        }
        let ttl_ms_u128 = self.bucket_ttl.as_millis();
        if ttl_ms_u128 == 0 {
            return false;
        }
        let ttl_ms = i64::try_from(ttl_ms_u128.min(i64::MAX as u128)).unwrap_or(i64::MAX);
        let refill_per_ms = self.refill_per_second / 1000.0;
        if refill_per_ms <= 0.0 {
            return false;
        }
        let now_ms = Utc::now().timestamp_millis();
        let redis_key = format!("{}{}", redis_backend.key_prefix, key);
        let script = redis::Script::new(REDIS_RATE_LIMIT_SCRIPT);
        let mut connection = match redis_backend.client.get_connection() {
            Ok(connection) => connection,
            Err(_) => return false,
        };
        let result: redis::RedisResult<i64> = script
            .key(redis_key)
            .arg(now_ms)
            .arg(self.capacity)
            .arg(refill_per_ms)
            .arg(ttl_ms)
            .invoke(&mut connection);
        matches!(result, Ok(1))
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

impl RealtimeHub {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
        }
    }

    fn subscribe(
        &self,
        user_id: &str,
        device_id: &str,
    ) -> (u64, mpsc::UnboundedReceiver<InboxItem>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let subscriber_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let key = inbox_stream_key(user_id, device_id);
        if let Ok(mut map) = self.inner.lock() {
            map.entry(key).or_default().push(RealtimeSubscriber {
                id: subscriber_id,
                sender,
            });
        }
        (subscriber_id, receiver)
    }

    fn unsubscribe(&self, user_id: &str, device_id: &str, subscriber_id: u64) {
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        let key = inbox_stream_key(user_id, device_id);
        let Some(subscribers) = map.get_mut(&key) else {
            return;
        };
        subscribers.retain(|subscriber| subscriber.id != subscriber_id);
        if subscribers.is_empty() {
            map.remove(&key);
        }
    }

    fn publish(&self, user_id: &str, device_id: &str, message: InboxItem) {
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        let key = inbox_stream_key(user_id, device_id);
        let Some(subscribers) = map.get_mut(&key) else {
            return;
        };
        subscribers.retain(|subscriber| subscriber.sender.send(message.clone()).is_ok());
        if subscribers.is_empty() {
            map.remove(&key);
        }
    }
}

fn inbox_stream_key(user_id: &str, device_id: &str) -> String {
    format!("{user_id}:{device_id}")
}

impl PushNotifier {
    pub fn disabled() -> Self {
        Self {
            client: reqwest::Client::new(),
            fcm_server_key: None,
            fcm_endpoint: "https://fcm.googleapis.com/fcm/send".to_string(),
            apns_bearer_token: None,
            apns_topic: None,
            apns_endpoint: "https://api.push.apple.com".to_string(),
        }
    }

    pub fn with_fcm(fcm_server_key: Option<String>, fcm_endpoint: String) -> Self {
        Self::with_providers(
            fcm_server_key,
            fcm_endpoint,
            None,
            None,
            "https://api.push.apple.com".to_string(),
        )
    }

    pub fn with_providers(
        fcm_server_key: Option<String>,
        fcm_endpoint: String,
        apns_bearer_token: Option<String>,
        apns_topic: Option<String>,
        apns_endpoint: String,
    ) -> Self {
        let key = fcm_server_key.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        let apns_token = apns_bearer_token.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        let apns_topic = apns_topic.and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        Self {
            client: reqwest::Client::new(),
            fcm_server_key: key,
            fcm_endpoint,
            apns_bearer_token: apns_token,
            apns_topic,
            apns_endpoint,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.fcm_server_key.is_some()
            || (self.apns_bearer_token.is_some() && self.apns_topic.is_some())
    }

    pub fn enabled_providers(&self) -> Vec<&'static str> {
        let mut providers = Vec::new();
        if self.fcm_server_key.is_some() {
            providers.push(PushProvider::Fcm.as_str());
        }
        if self.apns_bearer_token.is_some() && self.apns_topic.is_some() {
            providers.push(PushProvider::Apns.as_str());
        }
        providers
    }

    async fn send_wake_signal(&self, provider: PushProvider, token: &str) -> Result<(), String> {
        match provider {
            PushProvider::Fcm => self.send_fcm_wake_signal(token).await,
            PushProvider::Apns => self.send_apns_wake_signal(token).await,
        }
    }

    async fn send_fcm_wake_signal(&self, token: &str) -> Result<(), String> {
        let Some(server_key) = self.fcm_server_key.clone() else {
            return Ok(());
        };
        let payload = json!({
            "to": token,
            "priority": "high",
            "content_available": true,
            "data": {
                "wake": "1",
                "v": "1"
            }
        });
        let response = self
            .client
            .post(&self.fcm_endpoint)
            .header("authorization", format!("key={server_key}"))
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("FCM request failed with status {status}: {body}"));
        }
        Ok(())
    }

    async fn send_apns_wake_signal(&self, token: &str) -> Result<(), String> {
        let Some(bearer) = self.apns_bearer_token.clone() else {
            return Ok(());
        };
        let Some(topic) = self.apns_topic.clone() else {
            return Ok(());
        };
        let endpoint = self.apns_endpoint.trim_end_matches('/');
        let url = format!("{endpoint}/3/device/{token}");
        let payload = json!({
            "aps": {
                "content-available": 1
            },
            "wake": "1",
            "v": "1"
        });
        let response = self
            .client
            .post(url)
            .header("authorization", format!("bearer {bearer}"))
            .header("apns-topic", topic)
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("APNs request failed with status {status}: {body}"));
        }
        Ok(())
    }
}

pub fn build_router(state: AppState) -> Router {
    let hsts_enabled = state.security_profile().requires_tls();
    let middleware_state = state.clone();
    let router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/users/register", post(register_user))
        .route("/v1/users/:user_id/prekeys", post(publish_prekeys))
        .route("/v1/users/:user_id/prekeys/status", get(get_prekeys_status))
        .route(
            "/v1/users/:user_id/discovery/handles",
            post(upload_discovery_handles),
        )
        .route(
            "/v1/users/:user_id/discovery/match",
            post(match_discovery_hashes),
        )
        .route("/v1/users/:user_id/devices", get(list_devices))
        .route("/v1/users/:user_id/devices/link", post(link_device))
        .route(
            "/v1/users/:user_id/devices/:target_device_id/revoke",
            post(revoke_device),
        )
        .route(
            "/v1/users/:user_id/contacts",
            get(list_contacts).post(upsert_contact),
        )
        .route("/v1/users/:user_id/contacts/remove", post(remove_contact))
        .route("/v1/groups", post(create_group))
        .route("/v1/groups/:group_id/members", get(list_group_members))
        .route("/v1/groups/:group_id/members/add", post(add_group_member))
        .route(
            "/v1/groups/:group_id/members/remove",
            post(remove_group_member),
        )
        .route("/v1/groups/:group_id/relay", post(relay_group_message))
        .route("/v1/users/:user_id/push-token", post(register_push_token))
        .route("/v1/files/upload", post(upload_file))
        .route("/v1/files/:file_id", get(download_file))
        .route(
            "/v1/users/:user_id/profile",
            get(get_user_profile).post(upsert_user_profile),
        )
        .route(
            "/v1/users/:user_id/presence",
            get(get_presence).post(update_presence),
        )
        .route("/v1/typing/:user_id", get(get_typing).post(update_typing))
        .route("/v1/users/:user_id/bundle", get(get_bundle))
        .route("/v1/anon/users/:user_id/bundle", get(get_bundle))
        .route("/v1/users/:user_id/rotate/init", post(rotate_init))
        .route("/v1/users/:user_id/rotate/confirm", post(rotate_confirm))
        .route("/v1/users/:user_id/identity-log", get(get_identity_log))
        .route("/v1/relay/:recipient_user_id", post(relay_message))
        .route(
            "/v1/sealed-relay/:recipient_user_id",
            post(relay_sealed_message),
        )
        .route("/v1/inbox/:user_id", get(get_inbox))
        .route("/v1/sealed-inbox/:user_id", get(get_sealed_inbox))
        .route("/v1/inbox/:user_id/delete", post(delete_inbox_messages))
        .route("/v1/ws/inbox/:user_id", get(ws_inbox))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            middleware_state,
            observability_middleware,
        ));
    if hsts_enabled {
        router.layer(axum::middleware::from_fn(hsts_middleware))
    } else {
        router
    }
}

async fn observability_middleware(
    State(state): State<AppState>,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let request_id =
        request_id_from_header(request.headers()).unwrap_or_else(|| Uuid::new_v4().to_string());
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    state.metrics().observe_request_start();
    let start = Instant::now();
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        path = %path
    );
    let mut response = next.run(request).instrument(span).await;
    let status = response.status().as_u16();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    let duration = start.elapsed();
    state
        .metrics()
        .observe_request_finish(&method, &path, status, duration);
    info!(
        target: "pqmsg_server::http",
        request_id,
        method,
        path,
        status,
        latency_ms = duration.as_secs_f64() * 1000.0
    );
    if status >= 400 {
        let event = if status == 429 {
            "rate_limit_rejected"
        } else if status == 409 {
            "conflict_rejected"
        } else if status >= 500 {
            "server_error"
        } else {
            "client_error"
        };
        if status >= 500 {
            tracing::error!(
                target: "pqmsg_server::http",
                request_id,
                method,
                path,
                status,
                latency_ms = duration.as_secs_f64() * 1000.0
            );
        }
        record_security_event(
            &state,
            event,
            "reject",
            Some(request_id.as_str()),
            None,
            None,
            Some(format!("method={method} path={path} status={status}")),
        );
    }
    response
}

async fn hsts_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains"
            .parse()
            .expect("valid HSTS header"),
    );
    response
}

