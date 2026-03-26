use axum::extract::{MatchedPath, State};
use axum::http::{header, HeaderValue, Method};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use tower_http::cors::CorsLayer;

use pqmsg_core::alg::{runtime_crypto_profile, RuntimeCryptoProfile, SecurityProfile};
use pqmsg_core::tlv::critical_type;
use pqmsg_core::wire::SupportedSuites;
use serde::{Deserialize, Serialize};
use serde_json::json;

use sqlx::AnyPool;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tracing::Instrument;
use tracing::{info, warn};
use uuid::Uuid;

mod auth;
mod blob_store;
mod db;
mod ephemeral_state;
mod error;
mod types;
mod validation;

pub use blob_store::BlobStore;
pub use db::{
    connect_db_pool, init_db, parse_db_backend, prepare_sqlite_encrypted_database,
    rotate_sqlite_encrypted_database_key, DbBackend, SqliteEncryptionConfig,
    SqliteEncryptionPreparation, SqliteEncryptionRotation,
};
pub use ephemeral_state::EphemeralStateStore;
pub use error::AppError;

use auth::*;
use types::*;
use validation::*;
mod handlers;
pub use handlers::run_message_expiry_reaper;
use handlers::*;

pub(crate) const MAX_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_USER_ID_LEN: usize = 128;
pub(crate) const MAX_DEVICE_ID_LEN: usize = 128;
pub(crate) const X25519_KEY_LEN: usize = 32;
pub(crate) const SIG_PUB_KEY_LEN: usize = 32;
pub(crate) const SIG_LEN: usize = 64;
pub(crate) const PQ_SIG_PUB_KEY_LEN: usize = pqmsg_core::pq_sig::ML_DSA_65_PK_LEN;
pub(crate) const PQ_SIG_LEN: usize = pqmsg_core::pq_sig::ML_DSA_65_SIG_LEN;
pub(crate) const MIN_PQ_KEY_LEN: usize = 32;
pub(crate) const MAX_PQ_KEY_LEN: usize = 4096;
pub(crate) const MAX_ONE_TIME_KEYS: usize = 256;
pub(crate) const MAX_MESSAGE_BYTES: usize = 1_000_000;
pub(crate) const MAX_INBOX_PAGE: i64 = 200;
pub(crate) const MAX_PUSH_TOKEN_LEN: usize = 4096;
pub(crate) const MAX_CONTACT_ALIAS_LEN: usize = 128;
pub(crate) const MAX_PROFILE_DISPLAY_NAME_LEN: usize = 128;
pub(crate) const MAX_USERNAME_LEN: usize = 32;
pub(crate) const MAX_MIME_TYPE_LEN: usize = 128;
pub(crate) const MAX_FILE_ID_LEN: usize = 128;
pub(crate) const SHA256_HEX_LEN: usize = 64;
pub(crate) const MAX_DISCOVERY_HASHES: usize = 4096;
pub(crate) const MAX_GROUP_MEMBERS: usize = 512;
pub(crate) const MAX_FILE_BLOB_BYTES: usize = 900_000;
pub(crate) const MAX_BACKUP_BLOB_BYTES: usize = 5_000_000;
pub(crate) const MAX_AVATAR_BLOB_BYTES: usize = 262_144;
pub(crate) const SEALED_DELIVERY_TOKEN_LEN: usize = 12;
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
pub(crate) const ROTATE_SIG_TAG_NEW_IDENTITY_PQ_SIG: u16 = critical_type(0x3107);
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
pub(crate) const AUTH_TAG_GROUP_RECIPIENTS_HASH: u16 = critical_type(0x322C);
pub(crate) const AUTH_TAG_PROFILE_USERNAME_HASH: u16 = critical_type(0x322D);
pub(crate) const AUTH_TAG_PROFILE_USERNAME_LOOKUP_ENABLED: u16 = critical_type(0x322E);
/// Development-only sender certificate signing key. Only available in debug
/// builds to prevent accidental use in production release binaries.
#[cfg(debug_assertions)]
const DEVELOPMENT_SENDER_CERT_SIGNING_KEY_BYTES: [u8; 32] = [0x53; 32];
pub(crate) const AUTH_TAG_ROTATE_NEW_PQ_SIG_HASH: u16 = critical_type(0x3230);
pub(crate) const AUTH_TAG_ROTATE_PQ_SIG_CURRENT_HASH: u16 = critical_type(0x3231);
pub(crate) const AUTH_TAG_ROTATE_PQ_SIG_NEW_HASH: u16 = critical_type(0x3232);
pub(crate) const AUTH_TAG_DISCOVERY_PURPOSE: u16 = critical_type(0x3233);
pub(crate) const MAX_DELETE_MESSAGE_IDS: usize = 512;
pub(crate) const MAX_POW_NONCE_LEN: usize = 128;
pub(crate) const DEFAULT_REGISTRATION_POW_BITS_HARDENED: u8 = 18;
pub(crate) const DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_HARDENED: i64 = 30;
pub(crate) const DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_HARDENED: i64 = 2;
pub(crate) const DEFAULT_REGISTRATION_POW_BITS_RESEARCH: u8 = 0;
pub(crate) const DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_RESEARCH: i64 = 0;
pub(crate) const DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_RESEARCH: i64 = 0;
pub(crate) const DEFAULT_RATE_LIMIT_REDIS_KEY_PREFIX: &str = "pqmsg:ratelimit:";
pub(crate) const DEFAULT_WEB_CLIENT_POLICY: &str = "demo_only";
/// Maximum age for signed prekeys before the server flags them as stale (7 days).
pub(crate) const SIGNED_PREKEY_MAX_AGE_SECONDS: i64 = 7 * 24 * 3600;
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
    pq_ratchet_interval: u32,
}

impl DosHardeningPolicy {
    pub fn for_security_profile(profile: SecurityProfile) -> Self {
        match profile {
            SecurityProfile::Research => Self {
                registration_pow_bits: DEFAULT_REGISTRATION_POW_BITS_RESEARCH,
                prekey_publish_min_interval_seconds:
                    DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_RESEARCH,
                prekey_bundle_reserve_count: DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_RESEARCH,
                pq_ratchet_interval: pqmsg_core::ratchet::pq::DEFAULT_PQ_RATCHET_INTERVAL,
            },
            SecurityProfile::HighAssurance | SecurityProfile::NssAligned => Self {
                registration_pow_bits: DEFAULT_REGISTRATION_POW_BITS_HARDENED,
                prekey_publish_min_interval_seconds:
                    DEFAULT_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS_HARDENED,
                prekey_bundle_reserve_count: DEFAULT_PREKEY_BUNDLE_RESERVE_COUNT_HARDENED,
                pq_ratchet_interval: pqmsg_core::ratchet::pq::DEFAULT_PQ_RATCHET_INTERVAL,
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

    pub fn pq_ratchet_interval(self) -> u32 {
        self.pq_ratchet_interval
    }

    pub fn with_pq_ratchet_interval(mut self, interval: u32) -> Self {
        self.pq_ratchet_interval = interval;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentMode {
    #[default]
    Development,
    Pilot,
    Production,
}

impl DeploymentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Pilot => "pilot",
            Self::Production => "production",
        }
    }

    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value.trim().to_ascii_lowercase().as_str() {
            "development" | "dev" => Ok(Self::Development),
            "pilot" | "enterprise_pilot" | "enterprise-pilot" => Ok(Self::Pilot),
            "production" | "prod" => Ok(Self::Production),
            _ => Err("deployment_mode"),
        }
    }

    pub const fn requires_production_baseline(self) -> bool {
        !matches!(self, Self::Development)
    }
}

#[derive(Clone)]
pub struct AppState {
    pool: AnyPool,
    db_backend: DbBackend,
    rate_limiter: Arc<RateLimiter>,
    auth_replay: Arc<AuthReplayCache>,
    realtime_hub: RealtimeHub,
    sealed_realtime_hub: SealedRealtimeHub,
    push_notifier: Arc<PushNotifier>,
    security_profile: SecurityProfile,
    deployment_mode: DeploymentMode,
    runtime_crypto_profile: RuntimeCryptoProfile,
    tls_enabled: bool,
    structured_logging: bool,
    dos_policy: DosHardeningPolicy,
    metrics: Arc<MetricsRegistry>,
    audit_logger: Arc<AuditLogger>,
    cors_allowed_origins: Vec<String>,
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
    push_spawn_semaphore: Arc<Semaphore>,
    blob_store: Arc<BlobStore>,
    ephemeral_state: Arc<EphemeralStateStore>,
    sender_certificate_signing_key: Arc<SigningKey>,
    authenticated_direct_messaging_supported: bool,
    contact_discovery_service_origin: Option<String>,
    contact_discovery_manifest_issuer_ed25519_pub: Option<String>,
    contact_discovery_directory_backend: Option<String>,
    contact_discovery_host_enclave_protocol_version: Option<u32>,
    contact_discovery_attestation_verifier: Option<String>,
    contact_discovery_expected_measurement_hex: Option<String>,
    contact_discovery_attestation_document_sha256: Option<String>,
    contact_discovery_attestation_max_age_seconds: Option<u32>,
    web_client_policy: String,
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
            sealed_realtime_hub: SealedRealtimeHub::new(),
            push_notifier: Arc::new(PushNotifier::disabled()),
            security_profile,
            deployment_mode: DeploymentMode::Development,
            runtime_crypto_profile: runtime_crypto_profile().expect("runtime crypto profile"),
            tls_enabled: false,
            structured_logging: false,
            dos_policy: DosHardeningPolicy::for_security_profile(security_profile),
            metrics: Arc::new(MetricsRegistry::new()),
            audit_logger: Arc::new(AuditLogger::disabled()),
            cors_allowed_origins: Vec::new(),
            trusted_proxies: Arc::new(Vec::new()),
            push_spawn_semaphore: Arc::new(Semaphore::new(64)),
            blob_store: Arc::new(BlobStore::in_memory()),
            ephemeral_state: Arc::new(EphemeralStateStore::disabled()),
            sender_certificate_signing_key: Arc::new(default_sender_certificate_signing_key()),
            authenticated_direct_messaging_supported: false,
            contact_discovery_service_origin: None,
            contact_discovery_manifest_issuer_ed25519_pub: None,
            contact_discovery_directory_backend: None,
            contact_discovery_host_enclave_protocol_version: None,
            contact_discovery_attestation_verifier: None,
            contact_discovery_expected_measurement_hex: None,
            contact_discovery_attestation_document_sha256: None,
            contact_discovery_attestation_max_age_seconds: None,
            web_client_policy: DEFAULT_WEB_CLIENT_POLICY.to_string(),
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
            sealed_realtime_hub: SealedRealtimeHub::new(),
            push_notifier: Arc::new(PushNotifier::disabled()),
            security_profile,
            deployment_mode: DeploymentMode::Development,
            runtime_crypto_profile: runtime_crypto_profile().expect("runtime crypto profile"),
            tls_enabled: false,
            structured_logging: false,
            dos_policy: DosHardeningPolicy::for_security_profile(security_profile),
            metrics: Arc::new(MetricsRegistry::new()),
            audit_logger: Arc::new(AuditLogger::disabled()),
            cors_allowed_origins: Vec::new(),
            trusted_proxies: Arc::new(Vec::new()),
            push_spawn_semaphore: Arc::new(Semaphore::new(64)),
            blob_store: Arc::new(BlobStore::in_memory()),
            ephemeral_state: Arc::new(EphemeralStateStore::disabled()),
            sender_certificate_signing_key: Arc::new(default_sender_certificate_signing_key()),
            authenticated_direct_messaging_supported: false,
            contact_discovery_service_origin: None,
            contact_discovery_manifest_issuer_ed25519_pub: None,
            contact_discovery_directory_backend: None,
            contact_discovery_host_enclave_protocol_version: None,
            contact_discovery_attestation_verifier: None,
            contact_discovery_expected_measurement_hex: None,
            contact_discovery_attestation_document_sha256: None,
            contact_discovery_attestation_max_age_seconds: None,
            web_client_policy: DEFAULT_WEB_CLIENT_POLICY.to_string(),
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

    pub fn deployment_mode(&self) -> DeploymentMode {
        self.deployment_mode
    }

    pub fn runtime_crypto_profile(&self) -> RuntimeCryptoProfile {
        self.runtime_crypto_profile.clone()
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_enabled
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

    pub fn sealed_realtime_hub(&self) -> &SealedRealtimeHub {
        &self.sealed_realtime_hub
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

    pub fn production_baseline_met(&self) -> bool {
        self.deployment_mode.requires_production_baseline()
            && !matches!(self.security_profile, SecurityProfile::Research)
            && self.runtime_crypto_profile.pq_oqs_enabled
            && self.db_backend == DbBackend::Postgres
            && self.tls_enabled
            && self.structured_logging
            && self.audit_logger.is_enabled()
            && self.rate_limiter.is_distributed()
            && self.auth_replay.is_distributed()
            && self.realtime_hub.is_distributed()
            && self.sealed_realtime_hub.is_distributed()
            && !self.authenticated_direct_messaging_supported
    }

    pub fn supported_suite_ids(&self) -> Vec<u16> {
        SupportedSuites::for_profile(self.security_profile).suite_ids
    }

    pub fn contact_discovery_supported(&self) -> bool {
        self.contact_discovery_private_service_allowed()
    }

    pub fn contact_discovery_mode(&self) -> &'static str {
        if self.contact_discovery_private_service_allowed() {
            "private_service"
        } else {
            "manual_only"
        }
    }

    pub fn contact_discovery_ticket_supported(&self) -> bool {
        self.contact_discovery_private_service_allowed()
    }

    pub fn contact_discovery_service_origin(&self) -> Option<String> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_service_origin.clone()
        } else {
            None
        }
    }

    pub fn contact_discovery_manifest_issuer_public_key_b64(&self) -> Option<String> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_manifest_issuer_ed25519_pub.clone()
        } else {
            None
        }
    }

    pub fn contact_discovery_directory_backend(&self) -> Option<String> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_directory_backend
                .clone()
                .or_else(|| Some("simulated_enclave_preview".to_string()))
        } else {
            None
        }
    }

    pub fn contact_discovery_host_enclave_protocol_version(&self) -> Option<u32> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_host_enclave_protocol_version
                .or(Some(1))
        } else {
            None
        }
    }

    pub fn contact_discovery_attestation_verifier(&self) -> Option<String> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_attestation_verifier.clone()
        } else {
            None
        }
    }

    pub fn contact_discovery_expected_measurement_hex(&self) -> Option<String> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_expected_measurement_hex.clone()
        } else {
            None
        }
    }

    pub fn contact_discovery_attestation_document_sha256(&self) -> Option<String> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_attestation_document_sha256.clone()
        } else {
            None
        }
    }

    pub fn contact_discovery_attestation_max_age_seconds(&self) -> Option<u32> {
        if self.contact_discovery_private_service_allowed() {
            self.contact_discovery_attestation_max_age_seconds
        } else {
            None
        }
    }

    pub fn contact_discovery_private_service_allowed(&self) -> bool {
        self.contact_discovery_service_origin.is_some()
            && self.contact_discovery_manifest_issuer_ed25519_pub.is_some()
            && matches!(self.deployment_mode, DeploymentMode::Development)
    }

    pub fn presence_supported(&self) -> bool {
        false
    }

    pub fn typing_indicators_supported(&self) -> bool {
        false
    }

    pub fn read_receipts_supported(&self) -> bool {
        false
    }

    pub fn calling_supported(&self) -> bool {
        false
    }

    pub fn stories_supported(&self) -> bool {
        false
    }

    pub fn channels_supported(&self) -> bool {
        false
    }

    pub fn group_messaging_supported(&self) -> bool {
        false
    }

    pub fn private_group_state_supported(&self) -> bool {
        true
    }

    pub fn private_group_messaging_supported(&self) -> bool {
        self.private_group_state_supported()
            && self.sealed_sender_required()
            && self.sender_certificate_supported()
            && self.key_transparency_supported()
    }

    pub fn supported_beta_clients(&self) -> Vec<String> {
        let mut clients = vec!["android".to_string()];
        if self.web_client_policy() != DEFAULT_WEB_CLIENT_POLICY {
            clients.push("web".to_string());
        }
        clients
    }

    pub fn sealed_sender_required(&self) -> bool {
        true
    }

    pub fn sender_certificate_supported(&self) -> bool {
        true
    }

    pub fn key_transparency_supported(&self) -> bool {
        true
    }

    pub fn sender_certificate_signing_key(&self) -> &SigningKey {
        self.sender_certificate_signing_key.as_ref()
    }

    pub fn sender_certificate_issuer_public_key_b64(&self) -> String {
        B64.encode(
            self.sender_certificate_signing_key()
                .verifying_key()
                .to_bytes(),
        )
    }

    pub fn transparency_log_issuer_public_key_b64(&self) -> String {
        self.sender_certificate_issuer_public_key_b64()
    }

    pub fn authenticated_direct_messaging_supported(&self) -> bool {
        self.authenticated_direct_messaging_supported
    }

    pub fn ephemeral_messaging_supported(&self) -> bool {
        false
    }

    pub fn web_client_policy(&self) -> &str {
        self.web_client_policy.as_str()
    }

    pub fn with_push_notifier(mut self, push_notifier: Arc<PushNotifier>) -> Self {
        self.push_notifier = push_notifier;
        self
    }

    pub fn with_deployment_mode(mut self, deployment_mode: DeploymentMode) -> Self {
        self.deployment_mode = deployment_mode;
        self
    }

    pub fn with_runtime_crypto_profile(
        mut self,
        runtime_crypto_profile: RuntimeCryptoProfile,
    ) -> Self {
        self.runtime_crypto_profile = runtime_crypto_profile;
        self
    }

    pub fn with_transport_security(mut self, tls_enabled: bool) -> Self {
        self.tls_enabled = tls_enabled;
        self
    }

    pub fn with_authenticated_direct_messaging_supported(mut self, supported: bool) -> Self {
        self.authenticated_direct_messaging_supported = supported;
        self
    }

    pub fn with_contact_discovery_service_origin(
        mut self,
        contact_discovery_service_origin: Option<String>,
    ) -> Self {
        self.contact_discovery_service_origin = contact_discovery_service_origin;
        self
    }

    pub fn with_contact_discovery_manifest_issuer_public_key_b64(
        mut self,
        manifest_issuer_public_key_b64: Option<String>,
    ) -> Self {
        self.contact_discovery_manifest_issuer_ed25519_pub = manifest_issuer_public_key_b64;
        self
    }

    pub fn with_contact_discovery_directory_backend(
        mut self,
        directory_backend: Option<String>,
    ) -> Self {
        self.contact_discovery_directory_backend = directory_backend;
        self
    }

    pub fn with_contact_discovery_host_enclave_protocol_version(
        mut self,
        host_enclave_protocol_version: Option<u32>,
    ) -> Self {
        self.contact_discovery_host_enclave_protocol_version = host_enclave_protocol_version;
        self
    }

    pub fn with_contact_discovery_attestation_verifier(
        mut self,
        attestation_verifier: Option<String>,
    ) -> Self {
        self.contact_discovery_attestation_verifier = attestation_verifier;
        self
    }

    pub fn with_contact_discovery_expected_measurement_hex(
        mut self,
        expected_measurement_hex: Option<String>,
    ) -> Self {
        self.contact_discovery_expected_measurement_hex = expected_measurement_hex;
        self
    }

    pub fn with_contact_discovery_attestation_document_sha256(
        mut self,
        attestation_document_sha256: Option<String>,
    ) -> Self {
        self.contact_discovery_attestation_document_sha256 = attestation_document_sha256;
        self
    }

    pub fn with_contact_discovery_attestation_max_age_seconds(
        mut self,
        attestation_max_age_seconds: Option<u32>,
    ) -> Self {
        self.contact_discovery_attestation_max_age_seconds = attestation_max_age_seconds;
        self
    }

    pub fn with_web_client_policy(mut self, web_client_policy: impl Into<String>) -> Self {
        self.web_client_policy = web_client_policy.into();
        self
    }

    pub fn with_structured_logging(mut self, structured_logging: bool) -> Self {
        self.structured_logging = structured_logging;
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

    pub fn with_auth_replay(mut self, auth_replay: Arc<AuthReplayCache>) -> Self {
        self.auth_replay = auth_replay;
        self
    }

    pub fn with_cors_allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.cors_allowed_origins = origins;
        self
    }

    pub fn with_trusted_proxies(mut self, proxies: Vec<std::net::IpAddr>) -> Self {
        self.trusted_proxies = Arc::new(proxies);
        self
    }

    pub fn trusted_proxies(&self) -> &[std::net::IpAddr] {
        &self.trusted_proxies
    }

    pub fn push_spawn_semaphore(&self) -> &Arc<Semaphore> {
        &self.push_spawn_semaphore
    }

    pub(crate) fn blob_store(&self) -> &BlobStore {
        &self.blob_store
    }

    pub(crate) fn ephemeral_state(&self) -> &EphemeralStateStore {
        &self.ephemeral_state
    }

    pub fn with_realtime_hub(mut self, hub: RealtimeHub) -> Self {
        self.realtime_hub = hub;
        self
    }

    pub fn with_sealed_realtime_hub(mut self, hub: SealedRealtimeHub) -> Self {
        self.sealed_realtime_hub = hub;
        self
    }

    pub fn with_blob_store(mut self, blob_store: Arc<BlobStore>) -> Self {
        self.blob_store = blob_store;
        self
    }

    pub fn with_ephemeral_state(mut self, ephemeral_state: Arc<EphemeralStateStore>) -> Self {
        self.ephemeral_state = ephemeral_state;
        self
    }

    pub fn with_sender_certificate_signing_key(
        mut self,
        sender_certificate_signing_key: Arc<SigningKey>,
    ) -> Self {
        self.sender_certificate_signing_key = sender_certificate_signing_key;
        self
    }
}

#[cfg(debug_assertions)]
fn default_sender_certificate_signing_key() -> SigningKey {
    tracing::warn!(
        "using DEVELOPMENT sender certificate signing key — \
         set PQMSG_SENDER_CERT_SIGNING_KEY for production"
    );
    SigningKey::from_bytes(&DEVELOPMENT_SENDER_CERT_SIGNING_KEY_BYTES)
}

#[cfg(not(debug_assertions))]
fn default_sender_certificate_signing_key() -> SigningKey {
    panic!(
        "PQMSG_SENDER_CERT_SIGNING_KEY must be configured; \
         default development key is not available in release builds"
    );
}

#[derive(Clone)]
pub struct RealtimeHub {
    inner: Arc<Mutex<HashMap<String, Vec<RealtimeSubscriber>>>>,
    next_id: Arc<AtomicU64>,
    redis_client: Option<redis::Client>,
    instance_id: Arc<String>,
}

#[derive(Clone)]
pub struct SealedRealtimeHub {
    inner: Arc<Mutex<HashMap<String, Vec<SealedRealtimeSubscriber>>>>,
    next_id: Arc<AtomicU64>,
    redis_client: Option<redis::Client>,
    instance_id: Arc<String>,
}

#[derive(Clone)]
struct RealtimeSubscriber {
    id: u64,
    sender: mpsc::Sender<InboxItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RealtimePubSubEnvelope {
    origin_instance_id: Option<String>,
    message: InboxItem,
}

#[derive(Clone)]
struct SealedRealtimeSubscriber {
    id: u64,
    sender: mpsc::Sender<SealedInboxItem>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SealedRealtimePubSubEnvelope {
    origin_instance_id: Option<String>,
    message: SealedInboxItem,
}

#[allow(dead_code)]
enum RedisSubscription {
    Pattern(String),
    Channels(Vec<String>),
}

#[derive(Clone)]
pub struct PushNotifier {
    client: reqwest::Client,
    fcm_server_key: Option<String>,
    fcm_endpoint: String,
    apns_bearer_token: Option<String>,
    apns_topic: Option<String>,
    apns_endpoint: String,
    fcm_circuit: Arc<std::sync::Mutex<CircuitBreakerState>>,
    apns_circuit: Arc<std::sync::Mutex<CircuitBreakerState>>,
}

const CIRCUIT_FAILURE_THRESHOLD: u32 = 5;
const CIRCUIT_COOLDOWN_SECS: u64 = 30;

#[derive(Debug)]
struct CircuitBreakerState {
    consecutive_failures: u32,
    opened_at: Option<std::time::Instant>,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            opened_at: None,
        }
    }

    fn is_open(&self) -> bool {
        if let Some(opened_at) = self.opened_at {
            opened_at.elapsed().as_secs() < CIRCUIT_COOLDOWN_SECS
        } else {
            false
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.opened_at = None;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= CIRCUIT_FAILURE_THRESHOLD {
            self.opened_at = Some(std::time::Instant::now());
        }
    }
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
    pq_ratchet_steps_total: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct AuditLogger {
    inner: Option<Arc<AuditLoggerInner>>,
}

struct AuditLoggerInner {
    file: Mutex<std::fs::File>,
    path: String,
    max_file_bytes: u64,
    max_rotated_files: u32,
    bytes_written: AtomicU64,
    rotation_lock: Mutex<()>,
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
    redis_backend: Option<RedisReplayBackend>,
}

#[derive(Clone)]
struct RedisReplayBackend {
    client: redis::Client,
    key_prefix: String,
    ttl_seconds: u64,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            requests_total: Arc::new(Mutex::new(HashMap::new())),
            request_duration_sum_seconds: Arc::new(Mutex::new(HashMap::new())),
            security_events_total: Arc::new(Mutex::new(HashMap::new())),
            in_flight_requests: Arc::new(AtomicU64::new(0)),
            pq_ratchet_steps_total: Arc::new(AtomicU64::new(0)),
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

    pub fn record_pq_ratchet_step(&self) {
        self.pq_ratchet_steps_total.fetch_add(1, Ordering::Relaxed);
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
        let pq_steps = self.pq_ratchet_steps_total.load(Ordering::Relaxed);
        body.push_str(
            "# HELP pqmsg_pq_ratchet_steps_total Total PQ ratchet re-key steps observed\n",
        );
        body.push_str("# TYPE pqmsg_pq_ratchet_steps_total counter\n");
        body.push_str(&format!("pqmsg_pq_ratchet_steps_total {pq_steps}\n"));
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
        Self { inner: None }
    }

    pub fn with_path(path: &str) -> std::io::Result<Self> {
        Self::with_path_and_rotation(path, 50 * 1024 * 1024, 5)
    }

    pub fn with_path_and_rotation(
        path: &str,
        max_file_bytes: u64,
        max_rotated_files: u32,
    ) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let current_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            inner: Some(Arc::new(AuditLoggerInner {
                file: Mutex::new(file),
                path: path.to_string(),
                max_file_bytes,
                max_rotated_files,
                bytes_written: AtomicU64::new(current_len),
                rotation_lock: Mutex::new(()),
            })),
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
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
        // Emit scrubbed PII to structured logs — full values stay in the audit file only.
        info!(
            target: "pqmsg_server::audit",
            event,
            outcome,
            request_id = request_id.unwrap_or_default(),
            user_id = scrub_pii(user_id.unwrap_or_default()),
            device_id = scrub_pii(device_id.unwrap_or_default()),
            detail = detail.unwrap_or_default()
        );
        let Some(inner) = &self.inner else {
            return;
        };
        let serialized = match serde_json::to_string(&payload) {
            Ok(value) => value,
            Err(error) => {
                warn!("failed to serialize audit event: {error}");
                return;
            }
        };
        let line = format!("{serialized}\n");
        let line_len = line.len() as u64;

        // Check if rotation is needed before writing
        let current = inner.bytes_written.load(Ordering::Relaxed);
        if current + line_len > inner.max_file_bytes {
            self.rotate_log(inner);
        }

        let Ok(mut guard) = inner.file.lock() else {
            warn!("failed to lock audit log file");
            return;
        };
        if let Err(error) = guard.write_all(line.as_bytes()) {
            warn!("failed to append audit log event: {error}");
            return;
        }
        inner.bytes_written.fetch_add(line_len, Ordering::Relaxed);
    }

    fn rotate_log(&self, inner: &AuditLoggerInner) {
        let Ok(_rotation_guard) = inner.rotation_lock.try_lock() else {
            return; // another thread is already rotating
        };
        // Re-check size under lock
        if inner.bytes_written.load(Ordering::Relaxed) < inner.max_file_bytes {
            return;
        }

        // Shift existing rotated files: .4 -> .5, .3 -> .4, etc.
        for i in (1..inner.max_rotated_files).rev() {
            let from = format!("{}.{}", inner.path, i);
            let to = format!("{}.{}", inner.path, i + 1);
            let _ = std::fs::rename(&from, &to);
        }
        // Rename current -> .1
        let rotated = format!("{}.1", inner.path);
        let Ok(mut file_guard) = inner.file.lock() else {
            return;
        };
        // Flush current file
        let _ = file_guard.flush();
        drop(file_guard);
        let _ = std::fs::rename(&inner.path, &rotated);

        // Open a new file
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&inner.path)
        {
            Ok(new_file) => {
                if let Ok(mut file_guard) = inner.file.lock() {
                    *file_guard = new_file;
                    inner.bytes_written.store(0, Ordering::Relaxed);
                }
            }
            Err(error) => {
                warn!("failed to create new audit log file after rotation: {error}");
            }
        }
        // Delete the oldest rotated file if it exceeds max_rotated_files
        let oldest = format!("{}.{}", inner.path, inner.max_rotated_files + 1);
        let _ = std::fs::remove_file(oldest);
    }
}

/// Replace PII values with a truncated SHA-256 prefix for structured log output.
/// The full value is preserved in the audit log file only.
fn scrub_pii(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(value.as_bytes());
    format!("sha256:{}", hex::encode(&hash[..8]))
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
            redis_backend: None,
        }
    }

    pub fn with_redis(
        max_entries: usize,
        ttl: StdDuration,
        redis_url: &str,
        key_prefix: String,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self {
            max_entries,
            ttl,
            inner: Arc::new(Mutex::new(HashMap::new())),
            redis_backend: Some(RedisReplayBackend {
                client,
                key_prefix,
                ttl_seconds: ttl.as_secs().max(1),
            }),
        })
    }

    pub fn is_distributed(&self) -> bool {
        self.redis_backend.is_some()
    }

    pub fn observe(&self, user_id: &str, nonce: &str) -> bool {
        let key = format!("{user_id}:{nonce}");
        if let Some(redis_backend) = &self.redis_backend {
            return self.observe_redis(redis_backend, &key);
        }
        self.observe_in_memory(&key)
    }

    fn observe_in_memory(&self, key: &str) -> bool {
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        let now = Instant::now();
        map.retain(|_, seen| now.duration_since(*seen) <= self.ttl);
        if map.contains_key(key) {
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
        map.insert(key.to_string(), now);
        true
    }

    fn observe_redis(&self, backend: &RedisReplayBackend, key: &str) -> bool {
        let redis_key = format!("{}replay:{}", backend.key_prefix, key);
        let mut connection = match backend.client.get_connection() {
            Ok(connection) => connection,
            Err(_) => return self.observe_in_memory(key),
        };
        let result: redis::RedisResult<bool> = redis::cmd("SET")
            .arg(&redis_key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(backend.ttl_seconds)
            .query(&mut connection);
        match result {
            Ok(was_set) => was_set,
            Err(_) => self.observe_in_memory(key),
        }
    }
}

impl RealtimeHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            redis_client: None,
            instance_id: Arc::new(Uuid::new_v4().to_string()),
        }
    }

    pub fn with_redis(redis_client: redis::Client) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            redis_client: Some(redis_client),
            instance_id: Arc::new(Uuid::new_v4().to_string()),
        }
    }

    pub fn is_distributed(&self) -> bool {
        self.redis_client.is_some()
    }

    /// Maximum buffered messages per WebSocket subscriber before backpressure
    /// drops the subscriber. Prevents unbounded memory growth from slow clients.
    const SUBSCRIBER_CHANNEL_CAPACITY: usize = 256;

    fn subscribe(&self, user_id: &str, device_id: &str) -> (u64, mpsc::Receiver<InboxItem>) {
        let (sender, receiver) = mpsc::channel(Self::SUBSCRIBER_CHANNEL_CAPACITY);
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
        // Publish to Redis channel when available so other server instances
        // can forward to their local subscribers.
        if let Some(ref client) = self.redis_client {
            let channel = redis_inbox_channel(user_id, device_id);
            if let Ok(payload) = serde_json::to_string(&RealtimePubSubEnvelope {
                origin_instance_id: Some(self.instance_id.as_ref().clone()),
                message: message.clone(),
            }) {
                if let Ok(mut conn) = client.get_connection() {
                    let _: redis::RedisResult<i64> = redis::cmd("PUBLISH")
                        .arg(&channel)
                        .arg(&payload)
                        .query(&mut conn);
                }
            }
        }

        self.dispatch_local(user_id, device_id, message);
    }

    fn dispatch_local(&self, user_id: &str, device_id: &str, message: InboxItem) {
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        let key = inbox_stream_key(user_id, device_id);
        let Some(subscribers) = map.get_mut(&key) else {
            return;
        };
        subscribers.retain(|subscriber| subscriber.sender.try_send(message.clone()).is_ok());
        if subscribers.is_empty() {
            map.remove(&key);
        }
    }

    /// Spawn a background task that subscribes to Redis pub/sub channels and
    /// dispatches incoming messages to local WebSocket subscribers.
    pub fn spawn_redis_subscriber(&self) {
        self.spawn_redis_subscriber_with_subscription(RedisSubscription::Pattern(
            "pqmsg:inbox:*".to_string(),
        ));
    }

    fn spawn_redis_subscriber_with_subscription(
        &self,
        subscription: RedisSubscription,
    ) -> Arc<AtomicBool> {
        let Some(ref client) = self.redis_client else {
            return Arc::new(AtomicBool::new(true));
        };
        let client = client.clone();
        let inner = self.inner.clone();
        let instance_id = self.instance_id.as_ref().clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_signal = stop.clone();
        std::thread::spawn(move || {
            loop {
                if stop_signal.load(Ordering::Relaxed) {
                    break;
                }
                let mut conn = match client.get_connection() {
                    Ok(c) => c,
                    Err(e) => {
                        if stop_signal.load(Ordering::Relaxed) {
                            break;
                        }
                        tracing::warn!("realtime redis subscriber connection failed: {e}");
                        std::thread::sleep(StdDuration::from_secs(2));
                        continue;
                    }
                };
                let mut pubsub = conn.as_pubsub();
                let _ = pubsub.set_read_timeout(Some(StdDuration::from_millis(250)));
                let subscribe_result = match &subscription {
                    RedisSubscription::Pattern(pattern) => pubsub.psubscribe(pattern.as_str()),
                    RedisSubscription::Channels(channels) => {
                        let mut result = Ok(());
                        for channel in channels {
                            if let Err(err) = pubsub.subscribe(channel.as_str()) {
                                result = Err(err);
                                break;
                            }
                        }
                        result
                    }
                };
                if let Err(e) = subscribe_result {
                    if stop_signal.load(Ordering::Relaxed) {
                        break;
                    }
                    tracing::warn!("realtime redis subscribe failed: {e}");
                    std::thread::sleep(StdDuration::from_secs(2));
                    continue;
                }
                loop {
                    let msg: redis::Msg = match pubsub.get_message() {
                        Ok(m) => m,
                        Err(e) => {
                            if stop_signal.load(Ordering::Relaxed) {
                                return;
                            }
                            if e.is_timeout() {
                                continue;
                            }
                            tracing::warn!("realtime redis get_message error: {e}");
                            break; // reconnect
                        }
                    };
                    let channel: String = match msg.get_channel() {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let payload: String = match msg.get_payload() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    // channel format: pqmsg:inbox:{user_id}:{device_id}
                    let key = channel.strip_prefix("pqmsg:inbox:").unwrap_or(&channel);
                    let Some(envelope) = decode_realtime_pubsub_envelope(&payload) else {
                        continue;
                    };
                    if envelope.origin_instance_id.as_deref() == Some(instance_id.as_str()) {
                        continue;
                    }
                    let item = envelope.message;
                    if let Ok(mut map) = inner.lock() {
                        if let Some(subscribers) = map.get_mut(key) {
                            subscribers.retain(|sub| sub.sender.try_send(item.clone()).is_ok());
                            if subscribers.is_empty() {
                                map.remove(key);
                            }
                        }
                    }
                }
            }
        });
        stop
    }
}

impl Default for RealtimeHub {
    fn default() -> Self {
        Self::new()
    }
}

impl SealedRealtimeHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            redis_client: None,
            instance_id: Arc::new(Uuid::new_v4().to_string()),
        }
    }

    pub fn with_redis(redis_client: redis::Client) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            redis_client: Some(redis_client),
            instance_id: Arc::new(Uuid::new_v4().to_string()),
        }
    }

    pub fn is_distributed(&self) -> bool {
        self.redis_client.is_some()
    }

    const SUBSCRIBER_CHANNEL_CAPACITY: usize = 256;

    fn subscribe(&self, user_id: &str, device_id: &str) -> (u64, mpsc::Receiver<SealedInboxItem>) {
        let (sender, receiver) = mpsc::channel(Self::SUBSCRIBER_CHANNEL_CAPACITY);
        let subscriber_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let key = inbox_stream_key(user_id, device_id);
        if let Ok(mut map) = self.inner.lock() {
            map.entry(key).or_default().push(SealedRealtimeSubscriber {
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

    fn publish(&self, user_id: &str, device_id: &str, message: SealedInboxItem) {
        if let Some(ref client) = self.redis_client {
            let channel = redis_sealed_inbox_channel(user_id, device_id);
            if let Ok(payload) = serde_json::to_string(&SealedRealtimePubSubEnvelope {
                origin_instance_id: Some(self.instance_id.as_ref().clone()),
                message: message.clone(),
            }) {
                if let Ok(mut conn) = client.get_connection() {
                    let _: redis::RedisResult<i64> = redis::cmd("PUBLISH")
                        .arg(&channel)
                        .arg(&payload)
                        .query(&mut conn);
                }
            }
        }

        self.dispatch_local(user_id, device_id, message);
    }

    fn dispatch_local(&self, user_id: &str, device_id: &str, message: SealedInboxItem) {
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        let key = inbox_stream_key(user_id, device_id);
        let Some(subscribers) = map.get_mut(&key) else {
            return;
        };
        subscribers.retain(|subscriber| subscriber.sender.try_send(message.clone()).is_ok());
        if subscribers.is_empty() {
            map.remove(&key);
        }
    }

    pub fn spawn_redis_subscriber(&self) {
        self.spawn_redis_subscriber_with_subscription(RedisSubscription::Pattern(
            "pqmsg:sealed-inbox:*".to_string(),
        ));
    }

    fn spawn_redis_subscriber_with_subscription(
        &self,
        subscription: RedisSubscription,
    ) -> Arc<AtomicBool> {
        let Some(ref client) = self.redis_client else {
            return Arc::new(AtomicBool::new(true));
        };
        let client = client.clone();
        let inner = self.inner.clone();
        let instance_id = self.instance_id.as_ref().clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_signal = stop.clone();
        std::thread::spawn(move || loop {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }
            let mut conn = match client.get_connection() {
                Ok(c) => c,
                Err(e) => {
                    if stop_signal.load(Ordering::Relaxed) {
                        break;
                    }
                    tracing::warn!("sealed realtime redis subscriber connection failed: {e}");
                    std::thread::sleep(StdDuration::from_secs(2));
                    continue;
                }
            };
            let mut pubsub = conn.as_pubsub();
            let _ = pubsub.set_read_timeout(Some(StdDuration::from_millis(250)));
            let subscribe_result = match &subscription {
                RedisSubscription::Pattern(pattern) => pubsub.psubscribe(pattern.as_str()),
                RedisSubscription::Channels(channels) => {
                    let mut result = Ok(());
                    for channel in channels {
                        if let Err(err) = pubsub.subscribe(channel.as_str()) {
                            result = Err(err);
                            break;
                        }
                    }
                    result
                }
            };
            if let Err(e) = subscribe_result {
                if stop_signal.load(Ordering::Relaxed) {
                    break;
                }
                tracing::warn!("sealed realtime redis subscribe failed: {e}");
                std::thread::sleep(StdDuration::from_secs(2));
                continue;
            }
            loop {
                let msg: redis::Msg = match pubsub.get_message() {
                    Ok(m) => m,
                    Err(e) => {
                        if stop_signal.load(Ordering::Relaxed) {
                            return;
                        }
                        if e.is_timeout() {
                            continue;
                        }
                        tracing::warn!("sealed realtime redis get_message error: {e}");
                        break;
                    }
                };
                let channel: String = match msg.get_channel() {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                let key = channel
                    .strip_prefix("pqmsg:sealed-inbox:")
                    .unwrap_or(&channel);
                let Some(envelope) = decode_sealed_realtime_pubsub_envelope(&payload) else {
                    continue;
                };
                if envelope.origin_instance_id.as_deref() == Some(instance_id.as_str()) {
                    continue;
                }
                let item = envelope.message;
                if let Ok(mut map) = inner.lock() {
                    if let Some(subscribers) = map.get_mut(key) {
                        subscribers.retain(|sub| sub.sender.try_send(item.clone()).is_ok());
                        if subscribers.is_empty() {
                            map.remove(key);
                        }
                    }
                }
            }
        });
        stop
    }
}

impl Default for SealedRealtimeHub {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_realtime_pubsub_envelope(payload: &str) -> Option<RealtimePubSubEnvelope> {
    serde_json::from_str::<RealtimePubSubEnvelope>(payload)
        .ok()
        .or_else(|| {
            serde_json::from_str::<InboxItem>(payload)
                .ok()
                .map(|message| RealtimePubSubEnvelope {
                    origin_instance_id: None,
                    message,
                })
        })
}

fn decode_sealed_realtime_pubsub_envelope(payload: &str) -> Option<SealedRealtimePubSubEnvelope> {
    serde_json::from_str::<SealedRealtimePubSubEnvelope>(payload)
        .ok()
        .or_else(|| {
            serde_json::from_str::<SealedInboxItem>(payload)
                .ok()
                .map(|message| SealedRealtimePubSubEnvelope {
                    origin_instance_id: None,
                    message,
                })
        })
}

fn redis_inbox_channel(user_id: &str, device_id: &str) -> String {
    format!("pqmsg:inbox:{}", inbox_stream_key(user_id, device_id))
}

fn redis_sealed_inbox_channel(user_id: &str, device_id: &str) -> String {
    format!(
        "pqmsg:sealed-inbox:{}",
        inbox_stream_key(user_id, device_id)
    )
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
            fcm_circuit: Arc::new(std::sync::Mutex::new(CircuitBreakerState::new())),
            apns_circuit: Arc::new(std::sync::Mutex::new(CircuitBreakerState::new())),
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
            fcm_circuit: Arc::new(std::sync::Mutex::new(CircuitBreakerState::new())),
            apns_circuit: Arc::new(std::sync::Mutex::new(CircuitBreakerState::new())),
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
        let circuit = match provider {
            PushProvider::Fcm => &self.fcm_circuit,
            PushProvider::Apns => &self.apns_circuit,
        };
        {
            let state = circuit.lock().unwrap_or_else(|e| e.into_inner());
            if state.is_open() {
                return Err(format!(
                    "{} circuit breaker open, skipping push",
                    provider.as_str()
                ));
            }
        }
        let result = match provider {
            PushProvider::Fcm => self.send_fcm_wake_signal(token).await,
            PushProvider::Apns => self.send_apns_wake_signal(token).await,
        };
        {
            let mut state = circuit.lock().unwrap_or_else(|e| e.into_inner());
            if result.is_ok() {
                state.record_success();
            } else {
                state.record_failure();
            }
        }
        result
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
    let cors_origins = state.cors_allowed_origins.clone();
    let middleware_state = state.clone();
    let router = Router::new()
        .route("/health", get(health))
        .route("/v1/capabilities", get(capabilities))
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
            "/v1/users/:user_id/devices/current/retire",
            post(retire_current_device),
        )
        .route(
            "/v1/users/:user_id/devices/:target_device_id/revoke",
            post(revoke_device),
        )
        .route(
            "/v1/users/:user_id/contacts",
            get(list_contacts).post(upsert_contact),
        )
        .route(
            "/v1/users/:user_id/contact-invites",
            post(create_contact_invite),
        )
        .route("/v1/users/:user_id/contacts/remove", post(remove_contact))
        .route(
            "/v1/contact-invites/:invite_token",
            get(resolve_contact_invite),
        )
        .route(
            "/v1/contact-invites/:invite_token/bundle",
            get(get_contact_invite_bundle),
        )
        .route(
            "/v1/users/:user_id/contact-discovery/ticket",
            post(create_contact_discovery_ticket),
        )
        .route("/v1/usernames/:username", get(resolve_username))
        .route("/v1/usernames/:username/bundle", get(get_username_bundle))
        .route(
            "/v1/private-groups/state/publish",
            post(publish_private_group_state),
        )
        .route(
            "/v1/private-groups/state/fetch",
            post(fetch_private_group_state),
        )
        .route(
            "/v1/private-groups/invites",
            post(create_private_group_invite),
        )
        .route(
            "/v1/private-groups/invites/:invite_token",
            get(resolve_private_group_invite).post(consume_private_group_invite),
        )
        .route(
            "/v1/private-groups/messages/publish",
            post(publish_private_group_message),
        )
        .route(
            "/v1/private-groups/messages/fetch",
            post(fetch_private_group_messages),
        )
        .route("/v1/users/:user_id/groups", get(list_user_groups))
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
        .route("/v1/users/:user_id/backups", post(upload_backup))
        .route(
            "/v1/users/:user_id/backups/latest",
            get(download_latest_backup),
        )
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
        .route(
            "/v1/transparency/users/:user_id/proof",
            get(get_transparency_proof),
        )
        .route(
            "/v1/users/:user_id/sender-certificate",
            get(issue_sender_certificate),
        )
        .route("/v1/relay/:recipient_user_id", post(relay_message))
        .route(
            "/v1/sealed-relay/:recipient_user_id",
            post(relay_sealed_message),
        )
        .route("/v1/inbox/:user_id", get(get_inbox))
        .route("/v1/sealed-inbox/:user_id", get(get_sealed_inbox))
        .route("/v1/inbox/:user_id/delete", post(delete_inbox_messages))
        .route("/v1/ws/inbox/:user_id/ticket", post(create_ws_inbox_ticket))
        .route("/v1/ws/inbox/:user_id", get(ws_inbox))
        .route(
            "/v1/ws/sealed-inbox/:user_id/ticket",
            post(create_ws_sealed_inbox_ticket),
        )
        .route("/v1/ws/sealed-inbox/:user_id", get(ws_sealed_inbox))
        .route("/v1/users/:user_id/receipts", post(send_receipt))
        .route("/v1/users/:user_id/receipts/poll", get(get_receipts))
        .route(
            "/v1/ephemeral-relay/:recipient_user_id",
            post(relay_ephemeral_message),
        )
        .route("/v1/calls/:callee_user_id/offer", post(call_offer))
        .route("/v1/calls/:call_id/answer", post(call_answer))
        .route("/v1/calls/:call_id/ice", post(call_ice_candidate))
        .route("/v1/calls/:call_id/hangup", post(call_hangup))
        .route("/v1/calls/:call_id/signals", get(poll_call_signals))
        .route("/v1/stories", post(create_story))
        .route("/v1/stories/feed", get(get_stories_feed))
        .route("/v1/stories/:story_id/view", post(view_story))
        .route("/v1/channels", get(list_channels).post(create_channel))
        .route(
            "/v1/channels/:channel_id/messages",
            get(get_channel_messages).post(post_channel_message),
        )
        .route(
            "/v1/channels/:channel_id/subscribe",
            post(subscribe_channel),
        )
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            middleware_state,
            observability_middleware,
        ))
        .layer(axum::middleware::from_fn(security_headers_middleware));

    // When no CORS origins are configured, deny all cross-origin requests
    // by not adding any allowed origins (CorsLayer::new() defaults to none).
    // Previously this was ambiguous; now it's explicit.
    let cors_layer = if cors_origins.is_empty() {
        CorsLayer::new()
    } else {
        let origins: Vec<HeaderValue> =
            cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                "x-request-id".parse().expect("valid header name"),
                AUTH_HEADER_USER.parse().expect("valid header name"),
                AUTH_HEADER_DEVICE.parse().expect("valid header name"),
                AUTH_HEADER_TIMESTAMP.parse().expect("valid header name"),
                AUTH_HEADER_NONCE.parse().expect("valid header name"),
                AUTH_HEADER_SIGNATURE.parse().expect("valid header name"),
            ])
            .max_age(StdDuration::from_secs(3600))
    };
    let router = router.layer(cors_layer);

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

async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("interest-cohort=(), camera=(), microphone=(), geolocation=()"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-permitted-cross-domain-policies",
        HeaderValue::from_static("none"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::{
        decode_realtime_pubsub_envelope, redis_inbox_channel, InboxItem, RealtimeHub,
        RealtimePubSubEnvelope, RedisSubscription,
    };
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::time::timeout;

    fn sample_inbox_item() -> InboxItem {
        InboxItem {
            message_id: 7,
            sender_user_id: "alice".to_string(),
            message_bytes_base64: "Y2lwaGVydGV4dA==".to_string(),
            received_at: "2026-03-07T00:00:00Z".to_string(),
        }
    }

    fn redis_test_url() -> String {
        std::env::var("PQMSG_TEST_REDIS_URL")
            .expect("set PQMSG_TEST_REDIS_URL to run realtime redis integration tests")
    }

    #[test]
    fn realtime_pubsub_ignores_same_instance_echo() {
        let hub = RealtimeHub::new();
        let payload = serde_json::to_string(&RealtimePubSubEnvelope {
            origin_instance_id: Some(hub.instance_id.as_ref().clone()),
            message: sample_inbox_item(),
        })
        .expect("serialize envelope");

        let envelope = decode_realtime_pubsub_envelope(&payload).expect("decode envelope");
        assert_eq!(
            envelope.origin_instance_id.as_deref(),
            Some(hub.instance_id.as_str())
        );
    }

    #[test]
    fn realtime_pubsub_decodes_legacy_payloads() {
        let payload =
            serde_json::to_string(&sample_inbox_item()).expect("serialize legacy payload");

        let envelope = decode_realtime_pubsub_envelope(&payload).expect("decode payload");
        assert_eq!(envelope.origin_instance_id, None);
        assert_eq!(envelope.message.message_id, 7);
    }

    #[tokio::test]
    #[ignore = "requires PQMSG_TEST_REDIS_URL"]
    async fn realtime_pubsub_delivers_messages_across_redis_nodes() {
        let redis_url = redis_test_url();
        let channel = redis_inbox_channel("bob", "bob-dev-1");
        let hub_a = RealtimeHub::with_redis(
            redis::Client::open(redis_url.as_str()).expect("redis client a"),
        );
        let hub_b = RealtimeHub::with_redis(
            redis::Client::open(redis_url.as_str()).expect("redis client b"),
        );

        let stop_a =
            hub_a.spawn_redis_subscriber_with_subscription(RedisSubscription::Channels(vec![
                channel.clone(),
            ]));
        let stop_b = hub_b
            .spawn_redis_subscriber_with_subscription(RedisSubscription::Channels(vec![channel]));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (_subscriber_id, mut receiver) = hub_b.subscribe("bob", "bob-dev-1");
        hub_a.publish("bob", "bob-dev-1", sample_inbox_item());

        let received = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("timeout waiting for redis delivery")
            .expect("redis-delivered message");
        assert_eq!(received.message_id, 7);
        assert_eq!(received.sender_user_id, "alice");

        stop_a.store(true, Ordering::Relaxed);
        stop_b.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    #[tokio::test]
    #[ignore = "requires PQMSG_TEST_REDIS_URL"]
    async fn realtime_pubsub_does_not_duplicate_on_publishing_node() {
        let redis_url = redis_test_url();
        let channel = redis_inbox_channel("bob", "bob-dev-1");
        let hub =
            RealtimeHub::with_redis(redis::Client::open(redis_url.as_str()).expect("redis client"));

        let stop = hub
            .spawn_redis_subscriber_with_subscription(RedisSubscription::Channels(vec![channel]));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (_subscriber_id, mut receiver) = hub.subscribe("bob", "bob-dev-1");
        hub.publish("bob", "bob-dev-1", sample_inbox_item());

        let first = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("timeout waiting for local delivery")
            .expect("local message");
        assert_eq!(first.message_id, 7);
        assert!(
            timeout(Duration::from_millis(250), receiver.recv())
                .await
                .is_err(),
            "publishing node should not receive a duplicate redis echo"
        );

        stop.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
