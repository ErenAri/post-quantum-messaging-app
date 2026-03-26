use axum::body::Body;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use pqmsg_core::alg::SecurityProfile;
use pqmsg_core::alg::PROTOCOL_VERSION_V1;
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_core::key_transparency::{
    verify_consistency_proof, verify_inclusion_proof, ConsistencyProof, InclusionProof,
    SignedTreeHead, TransparencyLeaf,
};
use pqmsg_core::pq_sig::{MlDsa65, PqSignatureProvider, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN};
use pqmsg_core::ratchet::pq::DEFAULT_PQ_RATCHET_INTERVAL;
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_server::{
    build_router, init_db, parse_db_backend, AppState, AuditLogger, DbBackend, DeploymentMode,
    DosHardeningPolicy, RateLimiter,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::any::AnyPoolOptions;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;

const ROTATE_SIG_TAG_USER_ID: u16 = critical_type(0x3101);
const ROTATE_SIG_TAG_CHALLENGE_ID: u16 = critical_type(0x3102);
const ROTATE_SIG_TAG_CHALLENGE_NONCE: u16 = critical_type(0x3103);
const ROTATE_SIG_TAG_NEW_IDENTITY_X25519: u16 = critical_type(0x3104);
const ROTATE_SIG_TAG_NEW_IDENTITY_SIG: u16 = critical_type(0x3105);
const ROTATE_SIG_TAG_NEW_DEVICE_ID: u16 = critical_type(0x3106);
const ROTATE_SIG_TAG_NEW_IDENTITY_PQ_SIG: u16 = critical_type(0x3107);
const AUTH_HEADER_USER: &str = "x-pqmsg-auth-user";
const AUTH_HEADER_DEVICE: &str = "x-pqmsg-auth-device";
const AUTH_HEADER_TIMESTAMP: &str = "x-pqmsg-auth-timestamp";
const AUTH_HEADER_NONCE: &str = "x-pqmsg-auth-nonce";
const AUTH_HEADER_SIGNATURE: &str = "x-pqmsg-auth-signature";
const AUTH_TAG_ENDPOINT: u16 = critical_type(0x3201);
const AUTH_TAG_USER_ID: u16 = critical_type(0x3202);
const AUTH_TAG_DEVICE_ID: u16 = critical_type(0x3203);
const AUTH_TAG_TIMESTAMP: u16 = critical_type(0x3204);
const AUTH_TAG_NONCE: u16 = critical_type(0x3205);
const AUTH_TAG_RECIPIENT_ID: u16 = critical_type(0x3206);
const AUTH_TAG_SINCE: u16 = critical_type(0x3207);
const AUTH_TAG_MESSAGE_BLOB: u16 = critical_type(0x3208);
const AUTH_TAG_PREKEY_SPK_HASH: u16 = critical_type(0x3209);
const AUTH_TAG_PREKEY_PQSPK_HASH: u16 = critical_type(0x320A);
const AUTH_TAG_ROTATE_NEW_X25519_HASH: u16 = critical_type(0x320B);
const AUTH_TAG_ROTATE_NEW_SIG_HASH: u16 = critical_type(0x320C);
const AUTH_TAG_ROTATE_CHALLENGE_ID: u16 = critical_type(0x320D);
const AUTH_TAG_ROTATE_SIG_CURRENT_HASH: u16 = critical_type(0x320E);
const AUTH_TAG_ROTATE_SIG_NEW_HASH: u16 = critical_type(0x320F);
const AUTH_TAG_ROTATE_NEW_PQ_SIG_HASH: u16 = critical_type(0x3230);
const AUTH_TAG_ROTATE_PQ_SIG_CURRENT_HASH: u16 = critical_type(0x3231);
const AUTH_TAG_ROTATE_PQ_SIG_NEW_HASH: u16 = critical_type(0x3232);
const AUTH_TAG_DISCOVERY_PURPOSE: u16 = critical_type(0x3233);
const AUTH_TAG_PUSH_DEVICE_ID: u16 = critical_type(0x3210);
const AUTH_TAG_PUSH_TOKEN_HASH: u16 = critical_type(0x3211);
const AUTH_TAG_LINK_DEVICE_ID: u16 = critical_type(0x3212);
const AUTH_TAG_REVOKE_DEVICE_ID: u16 = critical_type(0x3213);
const AUTH_TAG_DELETE_IDS_HASH: u16 = critical_type(0x3214);
const AUTH_TAG_DELETE_BEFORE_ID: u16 = critical_type(0x3215);
const AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH: u16 = critical_type(0x3216);
const AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH: u16 = critical_type(0x3217);
const AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH: u16 = critical_type(0x3218);
const AUTH_TAG_CONTACT_USER_ID: u16 = critical_type(0x3219);
const AUTH_TAG_CONTACT_ALIAS_HASH: u16 = critical_type(0x321A);
const AUTH_TAG_CONTACT_VERIFIED_FLAG: u16 = critical_type(0x321B);
const AUTH_TAG_CONTACT_FINGERPRINT: u16 = critical_type(0x321C);
const AUTH_TAG_GROUP_ID: u16 = critical_type(0x321D);
const AUTH_TAG_GROUP_MEMBER_USER_ID: u16 = critical_type(0x321E);
const AUTH_TAG_GROUP_MEMBERS_HASH: u16 = critical_type(0x321F);
const AUTH_TAG_GROUP_SENDER_USER_ID: u16 = critical_type(0x3220);
const AUTH_TAG_GROUP_RECIPIENTS_HASH: u16 = critical_type(0x322C);
const AUTH_TAG_FILE_ID: u16 = critical_type(0x3222);
const AUTH_TAG_FILE_RECIPIENT_ID: u16 = critical_type(0x3223);
const AUTH_TAG_FILE_BLOB_HASH: u16 = critical_type(0x3224);
const AUTH_TAG_FILE_MIME_HASH: u16 = critical_type(0x3225);
const AUTH_TAG_PROFILE_DISPLAY_NAME_HASH: u16 = critical_type(0x3226);
const AUTH_TAG_PROFILE_AVATAR_HASH: u16 = critical_type(0x3227);
const AUTH_TAG_PROFILE_AVATAR_MIME_HASH: u16 = critical_type(0x3228);
const AUTH_TAG_PRESENCE_STATUS: u16 = critical_type(0x3229);
const AUTH_TAG_TYPING_PEER_ID: u16 = critical_type(0x322A);
const AUTH_TAG_TYPING_STATE_FLAG: u16 = critical_type(0x322B);
const AUTH_TAG_PROFILE_USERNAME_HASH: u16 = critical_type(0x322D);
const AUTH_TAG_PROFILE_USERNAME_LOOKUP_ENABLED: u16 = critical_type(0x322E);
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

struct TestIdentityKeyPair {
    classical: SigningKey,
    pq_public: Vec<u8>,
    pq_secret: Vec<u8>,
}

impl Deref for TestIdentityKeyPair {
    type Target = SigningKey;

    fn deref(&self) -> &Self::Target {
        &self.classical
    }
}

async fn test_app() -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    );
    build_router(state)
}

fn load_support_matrix() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("docs")
        .join("SUPPORT_MATRIX.json");
    serde_json::from_str(
        &fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read support matrix {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("parse support matrix {}: {error}", path.display()))
}

async fn test_app_with_rate_limit_settings(capacity: f64, refill_per_second: f64) -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            capacity,
            refill_per_second,
            100_000,
            StdDuration::from_secs(600),
        )),
    );
    build_router(state)
}

async fn test_app_with_profile(profile: SecurityProfile) -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::with_security_profile(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
        profile,
    );
    build_router(state)
}

async fn test_app_with_authenticated_dm_compat() -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    )
    .with_authenticated_direct_messaging_supported(true);
    build_router(state)
}

async fn test_app_with_contact_discovery_service_origin(service_origin: &str) -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    )
    .with_contact_discovery_service_origin(Some(service_origin.to_string()))
    .with_contact_discovery_manifest_issuer_public_key_b64(Some(
        B64.encode(
            SigningKey::from_bytes(&[201u8; 32])
                .verifying_key()
                .to_bytes(),
        ),
    ))
    .with_contact_discovery_attestation_verifier(Some("sgx-dcap-preview".to_string()))
    .with_contact_discovery_expected_measurement_hex(Some("ab".repeat(32)))
    .with_contact_discovery_attestation_document_sha256(Some("cd".repeat(32)))
    .with_contact_discovery_attestation_max_age_seconds(Some(900));
    build_router(state)
}

async fn test_app_with_contact_discovery_service_origin_and_deployment_mode(
    service_origin: &str,
    deployment_mode: DeploymentMode,
) -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    )
    .with_deployment_mode(deployment_mode)
    .with_contact_discovery_service_origin(Some(service_origin.to_string()))
    .with_contact_discovery_manifest_issuer_public_key_b64(Some(
        B64.encode(
            SigningKey::from_bytes(&[201u8; 32])
                .verifying_key()
                .to_bytes(),
        ),
    ))
    .with_contact_discovery_attestation_verifier(Some("sgx-dcap-preview".to_string()))
    .with_contact_discovery_expected_measurement_hex(Some("ab".repeat(32)))
    .with_contact_discovery_attestation_document_sha256(Some("cd".repeat(32)))
    .with_contact_discovery_attestation_max_age_seconds(Some(900));
    build_router(state)
}

async fn test_app_with_dos_policy(dos_policy: DosHardeningPolicy) -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    )
    .with_dos_policy(dos_policy);
    build_router(state)
}

async fn test_app_with_audit_log(audit_log_path: &str) -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    )
    .with_audit_logger(Arc::new(
        AuditLogger::with_path(audit_log_path).expect("audit logger"),
    ));
    build_router(state)
}

fn with_postgres_search_path(database_url: &str, schema: &str) -> String {
    let separator = if database_url.contains('?') { "&" } else { "?" };
    format!("{database_url}{separator}options=-csearch_path%3D{schema}")
}

async fn test_app_with_postgres_env() -> Option<axum::Router> {
    sqlx::any::install_default_drivers();
    let base_url = std::env::var("PQMSG_DATABASE_URL").ok()?;
    let db_backend = parse_db_backend(&base_url).ok()?;
    if db_backend != DbBackend::Postgres {
        return None;
    }

    let schema = format!(
        "pqmsg_test_{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let admin_pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&base_url)
        .await
        .expect("connect postgres base database");
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin_pool)
        .await
        .expect("create postgres test schema");

    let scoped_url = with_postgres_search_path(&base_url, &schema);
    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect(&scoped_url)
        .await
        .expect("connect postgres schema");
    init_db(&pool, db_backend)
        .await
        .expect("migrate postgres schema");
    let state = AppState::new(
        pool,
        db_backend,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    );
    Some(build_router(state))
}

async fn spawn_http_server(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("serve app");
    });
    (format!("ws://{}", addr), handle)
}

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    json_request_with_headers(app, method, uri, body, &[]).await
}

async fn json_request_with_headers(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, String)],
) -> (StatusCode, Value) {
    let (status, _, payload) = json_request_with_headers_raw(app, method, uri, body, headers).await;
    (status, payload)
}

async fn json_request_with_headers_raw(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, String)],
) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder
        .body(Body::from(body.to_string()))
        .expect("build request");
    let response = app.oneshot(request).await.expect("request");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let payload: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
    (status, headers, payload)
}

async fn text_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&str, String)],
) -> (StatusCode, HeaderMap, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder.body(Body::empty()).expect("build request");
    let response = app.oneshot(request).await.expect("request");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    (status, headers, String::from_utf8_lossy(&bytes).to_string())
}

fn signing_key(seed: u8) -> TestIdentityKeyPair {
    let provider = MlDsa65::new().expect("ml-dsa init");
    let pq_keypair = provider.keypair().expect("ml-dsa keypair");
    TestIdentityKeyPair {
        classical: SigningKey::from_bytes(&[seed; 32]),
        pq_public: pq_keypair.public_key,
        pq_secret: pq_keypair.secret_key.as_slice().to_vec(),
    }
}

fn register_payload(
    user_id: &str,
    device_id: &str,
    identity_x25519_pub: [u8; 32],
    identity_signing_key: &TestIdentityKeyPair,
) -> Value {
    json!({
        "user_id": user_id,
        "identity_x25519_pub": B64.encode(identity_x25519_pub),
        "identity_sig_pub": B64.encode(identity_signing_key.verifying_key().to_bytes()),
        "identity_pq_sig_pub": B64.encode(&identity_signing_key.pq_public),
        "device_id": device_id,
    })
}

fn register_payload_with_pow(base: Value, bits: u8) -> Value {
    if bits == 0 {
        return base;
    }
    let mut payload = base;
    let user_id = payload["user_id"].as_str().expect("user_id").to_string();
    let device_id = payload["device_id"]
        .as_str()
        .expect("device_id")
        .to_string();
    let identity_x25519_pub = payload["identity_x25519_pub"]
        .as_str()
        .expect("identity_x25519_pub")
        .to_string();
    let identity_sig_pub = payload["identity_sig_pub"]
        .as_str()
        .expect("identity_sig_pub")
        .to_string();
    let identity_pq_sig_pub = payload["identity_pq_sig_pub"]
        .as_str()
        .expect("identity_pq_sig_pub")
        .to_string();
    let mut nonce_counter: u64 = 0;
    loop {
        let nonce = format!("{nonce_counter:x}");
        let digest = Sha256::digest(
            [
                b"register".as_slice(),
                user_id.as_bytes(),
                device_id.as_bytes(),
                identity_x25519_pub.as_bytes(),
                identity_sig_pub.as_bytes(),
                identity_pq_sig_pub.as_bytes(),
                nonce.as_bytes(),
            ]
            .join(&[0u8][..]),
        );
        if hash_has_leading_zero_bits(&digest, bits) {
            payload["pow_nonce"] = json!(nonce);
            return payload;
        }
        nonce_counter = nonce_counter
            .checked_add(1)
            .expect("pow nonce counter overflow");
    }
}

fn hash_has_leading_zero_bits(bytes: &[u8], bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let full_bytes = usize::from(bits / 8);
    let remaining_bits = bits % 8;
    if bytes.len() < full_bytes {
        return false;
    }
    if bytes.iter().take(full_bytes).any(|byte| *byte != 0) {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    if bytes.len() <= full_bytes {
        return false;
    }
    let mask = 0xFFu8 << (8 - remaining_bits);
    bytes[full_bytes] & mask == 0
}

fn publish_prekeys_payload(
    identity_signing_key: &TestIdentityKeyPair,
    signed_prekey_x25519_pub: [u8; 32],
    pq_signed_prekey_pub_mlkem768: Vec<u8>,
    one_time_prekeys_x25519: Vec<[u8; 32]>,
    one_time_prekeys_mlkem768: Vec<Vec<u8>>,
) -> Value {
    let pq_provider = MlDsa65::new().expect("ml-dsa init");
    let spk_message = signed_prekey_signature_message(
        PROTOCOL_VERSION_V1,
        &DhPublicKey(signed_prekey_x25519_pub),
    )
    .expect("spk message");
    let pq_message =
        pq_signed_prekey_signature_message(PROTOCOL_VERSION_V1, &pq_signed_prekey_pub_mlkem768)
            .expect("pqspk message");
    let sig_over_spk = identity_signing_key.sign(&spk_message).to_bytes();
    let sig_over_pqspk = identity_signing_key.sign(&pq_message).to_bytes();
    let pq_sig_over_spk = pq_provider
        .sign(&identity_signing_key.pq_secret, &spk_message)
        .expect("pq sign spk");
    let pq_sig_over_pqspk = pq_provider
        .sign(&identity_signing_key.pq_secret, &pq_message)
        .expect("pq sign pqspk");

    json!({
        "signed_prekey_x25519_pub": B64.encode(signed_prekey_x25519_pub),
        "sig_over_spk": B64.encode(sig_over_spk),
        "pq_signed_prekey_pub_mlkem768": B64.encode(pq_signed_prekey_pub_mlkem768),
        "sig_over_pqspk": B64.encode(sig_over_pqspk),
        "pq_sig_over_spk": B64.encode(pq_sig_over_spk),
        "pq_sig_over_pqspk": B64.encode(pq_sig_over_pqspk),
        "one_time_prekeys_x25519": one_time_prekeys_x25519
            .into_iter()
            .map(|value| B64.encode(value))
            .collect::<Vec<_>>(),
        "one_time_prekeys_mlkem768": one_time_prekeys_mlkem768
            .into_iter()
            .map(|value| B64.encode(value))
            .collect::<Vec<_>>()
    })
}

fn pq_signature_b64(identity_signing_key: &TestIdentityKeyPair, message: &[u8]) -> String {
    let provider = MlDsa65::new().expect("ml-dsa init");
    B64.encode(
        provider
            .sign(&identity_signing_key.pq_secret, message)
            .expect("ml-dsa sign"),
    )
}

fn rotation_signature_message(
    user_id: &str,
    challenge_id: &str,
    challenge_nonce: &[u8],
    new_identity_x25519: &[u8; 32],
    new_identity_sig: &[u8; 32],
    new_identity_pq_sig: &[u8],
    new_device_id: &str,
) -> Vec<u8> {
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
            ty: ROTATE_SIG_TAG_NEW_IDENTITY_PQ_SIG,
            value: new_identity_pq_sig.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_DEVICE_ID,
            value: new_device_id.as_bytes().to_vec(),
        },
    ])
    .expect("rotation signature message")
}

fn auth_common_records(
    endpoint: &str,
    user_id: &str,
    device_id: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<TlvRecord> {
    vec![
        TlvRecord {
            ty: AUTH_TAG_ENDPOINT,
            value: endpoint.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_USER_ID,
            value: user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_DEVICE_ID,
            value: device_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_TIMESTAMP,
            value: timestamp.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_NONCE,
            value: nonce.as_bytes().to_vec(),
        },
    ]
}

fn relay_auth_headers(
    signing_key: &SigningKey,
    sender_user_id: &str,
    sender_device_id: &str,
    recipient_user_id: &str,
    message_blob: &[u8],
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("relay-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records =
        auth_common_records("relay", sender_user_id, sender_device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_MESSAGE_BLOB,
        value: message_blob.to_vec(),
    });
    let message = encode(&records).expect("relay auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, sender_user_id.to_string()),
        (AUTH_HEADER_DEVICE, sender_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn inbox_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("inbox-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records = auth_common_records("inbox", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    let message = encode(&records).expect("inbox auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn sealed_inbox_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "sealed-inbox-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("sealed-inbox", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    let message = encode(&records).expect("sealed-inbox auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn ws_inbox_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("ws-inbox-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records = auth_common_records("ws-inbox", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    let message = encode(&records).expect("ws-inbox auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn format_string_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    message: impl AsRef<[u8]>,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("fmt-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let signature = signing_key.sign(message.as_ref()).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn identity_log_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("ilog-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records = auth_common_records("identity-log", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("identity-log auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn transparency_leaf_from_value(value: &Value) -> TransparencyLeaf {
    let identity_x25519_pub = B64
        .decode(
            value["identity_x25519_pub"]
                .as_str()
                .expect("identity_x25519_pub"),
        )
        .expect("decode identity_x25519_pub");
    let identity_sig_pub = B64
        .decode(
            value["identity_sig_pub"]
                .as_str()
                .expect("identity_sig_pub"),
        )
        .expect("decode identity_sig_pub");
    let identity_pq_sig_pub = value["identity_pq_sig_pub"]
        .as_str()
        .map(|raw| B64.decode(raw).expect("decode identity_pq_sig_pub"));
    TransparencyLeaf {
        user_id: value["user_id"].as_str().expect("leaf.user_id").to_string(),
        version: value["version"].as_u64().expect("leaf.version"),
        identity_x25519_pub: identity_x25519_pub
            .try_into()
            .expect("32-byte identity_x25519_pub"),
        identity_sig_pub,
        identity_pq_sig_pub,
        timestamp: value["timestamp"].as_u64().expect("leaf.timestamp"),
    }
}

fn transparency_sth_from_value(value: &Value) -> SignedTreeHead {
    SignedTreeHead {
        epoch: value["epoch"].as_u64().expect("sth.epoch"),
        tree_size: value["tree_size"].as_u64().expect("sth.tree_size"),
        root_hash: B64
            .decode(value["root_hash"].as_str().expect("sth.root_hash"))
            .expect("decode root_hash")
            .try_into()
            .expect("32-byte root_hash"),
        signature: B64
            .decode(value["signature"].as_str().expect("sth.signature"))
            .expect("decode sth signature"),
    }
}

fn transparency_inclusion_proof_from_value(value: &Value) -> InclusionProof {
    InclusionProof {
        leaf_index: value["leaf_index"].as_u64().expect("proof.leaf_index"),
        path: value["path"]
            .as_array()
            .expect("proof.path")
            .iter()
            .map(|item| {
                let hash = B64
                    .decode(item["hash"].as_str().expect("path.hash"))
                    .expect("decode path hash");
                (
                    hash.try_into().expect("32-byte path hash"),
                    item["is_left"].as_bool().expect("path.is_left"),
                )
            })
            .collect(),
    }
}

fn transparency_consistency_proof_from_value(value: &Value) -> ConsistencyProof {
    ConsistencyProof {
        old_size: value["old_size"].as_u64().expect("consistency.old_size"),
        new_size: value["new_size"].as_u64().expect("consistency.new_size"),
        proof_hashes: value["proof_hashes"]
            .as_array()
            .expect("consistency.proof_hashes")
            .iter()
            .map(|item| {
                B64.decode(item.as_str().expect("proof hash"))
                    .expect("decode consistency proof hash")
                    .try_into()
                    .expect("32-byte consistency proof hash")
            })
            .collect(),
    }
}

fn transparency_verifying_key_from_capabilities(capabilities: &Value) -> VerifyingKey {
    let issuer = B64
        .decode(
            capabilities["transparency_log_issuer_ed25519_pub"]
                .as_str()
                .expect("transparency issuer"),
        )
        .expect("decode transparency issuer");
    VerifyingKey::from_bytes(&issuer.try_into().expect("32-byte transparency issuer"))
        .expect("verifying key")
}

fn prekeys_status_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "prekeys-status-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("prekeys-status", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("prekeys-status auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn devices_list_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "devices-list-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("devices-list", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("devices-list auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn link_device_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    auth_device_id: &str,
    new_device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "devices-link-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records =
        auth_common_records("devices-link", user_id, auth_device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_LINK_DEVICE_ID,
        value: new_device_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("devices-link auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, auth_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn revoke_device_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    auth_device_id: &str,
    target_device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "devices-revoke-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records =
        auth_common_records("devices-revoke", user_id, auth_device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_REVOKE_DEVICE_ID,
        value: target_device_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("devices-revoke auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, auth_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn retire_device_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "devices-retire-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("devices-retire", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_REVOKE_DEVICE_ID,
        value: device_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("devices-retire auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn normalize_message_ids(message_ids: &[i64]) -> Vec<i64> {
    let mut ids = message_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn inbox_delete_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    message_ids: &[i64],
    delete_before_id: Option<i64>,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "inbox-delete-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("inbox-delete", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let normalized_ids = normalize_message_ids(message_ids);
    let mut hasher = Sha256::new();
    for message_id in &normalized_ids {
        hasher.update(message_id.to_be_bytes());
    }
    records.push(TlvRecord {
        ty: AUTH_TAG_DELETE_IDS_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    if let Some(delete_before) = delete_before_id {
        records.push(TlvRecord {
            ty: AUTH_TAG_DELETE_BEFORE_ID,
            value: delete_before.to_be_bytes().to_vec(),
        });
    }
    let message = encode(&records).expect("inbox-delete auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn normalize_sha256_hashes(values: &[String]) -> Vec<String> {
    let mut hashes = values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

fn hash_string_list_sha256(values: &[String]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_vec()
}

fn discovery_handles_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    phone_hashes: &[String],
    email_hashes: &[String],
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "discovery-handles-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records =
        auth_common_records("discovery-handles", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH,
        value: hash_string_list_sha256(&normalize_sha256_hashes(phone_hashes)),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH,
        value: hash_string_list_sha256(&normalize_sha256_hashes(email_hashes)),
    });
    let message = encode(&records).expect("discovery-handles auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn discovery_match_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    hashes: &[String],
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "discovery-match-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("discovery-match", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH,
        value: hash_string_list_sha256(&normalize_sha256_hashes(hashes)),
    });
    let message = encode(&records).expect("discovery-match auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn contacts_list_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "contacts-list-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("contacts-list", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("contacts-list auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn contact_invite_create_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "contact-invite-create-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records(
        "contact-invite-create",
        user_id,
        device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("contact-invite-create auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn contact_discovery_ticket_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    purpose: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("cdt-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records = auth_common_records(
        "contact-discovery-ticket",
        user_id,
        device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_PURPOSE,
        value: purpose.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("contact-discovery-ticket auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn contacts_upsert_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    contact_user_id: &str,
    alias: Option<&str>,
    verified_by_qr: bool,
    verified_fingerprint_sha256: Option<&str>,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "contacts-upsert-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("contacts-upsert", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    let mut alias_hasher = Sha256::new();
    alias_hasher.update(alias.unwrap_or_default().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_ALIAS_HASH,
        value: alias_hasher.finalize().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_VERIFIED_FLAG,
        value: vec![if verified_by_qr { 1 } else { 0 }],
    });
    if let Some(fingerprint) = verified_fingerprint_sha256 {
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_FINGERPRINT,
            value: fingerprint.as_bytes().to_vec(),
        });
    }
    let message = encode(&records).expect("contacts-upsert auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn contacts_remove_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    contact_user_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "contacts-remove-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("contacts-remove", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("contacts-remove auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn groups_create_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    member_user_ids: &[String],
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "groups-create-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("groups-create", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    let mut normalized = member_user_ids.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBERS_HASH,
        value: hash_string_list_sha256(&normalized),
    });
    let message = encode(&records).expect("groups-create auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn groups_list_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "groups-list-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("groups-list", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("groups-list auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn groups_members_list_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "groups-members-list-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records =
        auth_common_records("groups-members-list", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("groups-members-list auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn groups_members_add_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    member_user_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "groups-members-add-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records =
        auth_common_records("groups-members-add", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("groups-members-add auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn groups_members_remove_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    member_user_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "groups-members-remove-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records(
        "groups-members-remove",
        user_id,
        device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("groups-members-remove auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn groups_relay_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    sender_user_id: &str,
    recipients: &[(&str, &[u8])],
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "groups-relay-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("groups-relay", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_SENDER_USER_ID,
        value: sender_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_RECIPIENTS_HASH,
        value: hash_group_recipients(recipients),
    });
    let message = encode(&records).expect("groups-relay auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn hash_group_recipients(recipients: &[(&str, &[u8])]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut normalized: Vec<(&str, Vec<u8>)> = recipients
        .iter()
        .map(|(recipient_user_id, message_blob)| {
            let mut blob_hasher = Sha256::new();
            blob_hasher.update(message_blob);
            (*recipient_user_id, blob_hasher.finalize().to_vec())
        })
        .collect();
    normalized.sort_by(|left, right| left.0.cmp(right.0));

    let mut hasher = Sha256::new();
    for (recipient_user_id, message_hash) in normalized {
        hasher.update(recipient_user_id.as_bytes());
        hasher.update([0x00]);
        hasher.update(&message_hash);
        hasher.update([0x01]);
    }
    hasher.finalize().to_vec()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct PrivateGroupMemberFixture {
    record: Value,
    membership_handle_sha256: String,
    fetch_key_base64: String,
    publish_key_base64: Option<String>,
}

fn private_group_member_fixture(seed: u8, allow_publish: bool) -> PrivateGroupMemberFixture {
    let handle_material = [seed; 16];
    let member_commitment_material = [seed.wrapping_add(1); 16];
    let fetch_key = [seed.wrapping_add(2); 32];
    let publish_key = allow_publish.then(|| [seed.wrapping_add(3); 32]);

    let membership_handle_sha256 = sha256_hex(&handle_material);
    let member_commitment_sha256 = sha256_hex(&member_commitment_material);
    let fetch_key_sha256 = sha256_hex(&fetch_key);
    let publish_key_sha256 = publish_key.as_ref().map(|bytes| sha256_hex(bytes));
    let fetch_key_base64 = B64.encode(fetch_key);
    let publish_key_base64 = publish_key.map(|bytes| B64.encode(bytes));

    PrivateGroupMemberFixture {
        record: json!({
            "membership_handle_sha256": membership_handle_sha256,
            "member_commitment_sha256": member_commitment_sha256,
            "fetch_key_sha256": fetch_key_sha256,
            "publish_key_sha256": publish_key_sha256,
        }),
        membership_handle_sha256,
        fetch_key_base64,
        publish_key_base64,
    }
}

fn prekeys_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    prekeys_body: &Value,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!("prekeys-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records = auth_common_records("prekeys", user_id, device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(
        prekeys_body["signed_prekey_x25519_pub"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_SPK_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(
        prekeys_body["pq_signed_prekey_pub_mlkem768"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_PQSPK_HASH,
        value: hasher.finalize().to_vec(),
    });
    let message = encode(&records).expect("prekeys auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn push_token_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    fcm_token: &str,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "push-token-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("push-token", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PUSH_DEVICE_ID,
        value: device_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(fcm_token.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PUSH_TOKEN_HASH,
        value: hasher.finalize().to_vec(),
    });
    let message = encode(&records).expect("push-token auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn files_upload_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    recipient_user_id: &str,
    file_blob: &[u8],
    mime_type: &str,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "files-upload-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("files-upload", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(file_blob);
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_BLOB_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(mime_type.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_MIME_HASH,
        value: hasher.finalize().to_vec(),
    });
    let message = encode(&records).expect("files-upload auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn files_download_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    file_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "files-download-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("files-download", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_ID,
        value: file_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("files-download auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn profile_upsert_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    target_user_id: &str,
    display_name: Option<&str>,
    username: Option<&str>,
    username_lookup_enabled: bool,
    avatar_mime: Option<&str>,
    avatar_blob: Option<&[u8]>,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "profile-upsert-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("profile-upsert", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: target_user_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(display_name.unwrap_or_default().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_DISPLAY_NAME_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    let normalized_username = username
        .unwrap_or_default()
        .trim()
        .trim_start_matches('@')
        .to_ascii_lowercase();
    hasher.update(normalized_username.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_USERNAME_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_USERNAME_LOOKUP_ENABLED,
        value: vec![if username_lookup_enabled { 1 } else { 0 }],
    });
    hasher.update(avatar_blob.unwrap_or_default());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_AVATAR_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(avatar_mime.unwrap_or_default().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_AVATAR_MIME_HASH,
        value: hasher.finalize().to_vec(),
    });
    let message = encode(&records).expect("profile-upsert auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn profile_get_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    target_user_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "profile-get-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("profile-get", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: target_user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("profile-get auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

async fn fetch_sealed_delivery_token(
    app: Router,
    signing_key: &SigningKey,
    requester_user_id: &str,
    requester_device_id: &str,
    target_user_id: &str,
) -> String {
    let headers = profile_get_auth_headers(
        signing_key,
        requester_user_id,
        requester_device_id,
        target_user_id,
    );
    let (status, body) = json_request_with_headers(
        app,
        Method::GET,
        &format!("/v1/users/{target_user_id}/profile"),
        json!({}),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body["sealed_delivery_token"]
        .as_str()
        .expect("sealed_delivery_token")
        .to_string()
}

async fn add_contact_for_delivery_access(
    app: Router,
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    contact_user_id: &str,
) {
    let headers = contacts_upsert_auth_headers(
        signing_key,
        user_id,
        device_id,
        contact_user_id,
        None,
        false,
        None,
    );
    let (status, body) = json_request_with_headers(
        app,
        Method::POST,
        &format!("/v1/users/{user_id}/contacts"),
        json!({ "contact_user_id": contact_user_id }),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "contact upsert failed: {body}");
}

fn backup_upload_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    backup_version: i64,
    encrypted_backup_blob: &[u8],
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "backups-upload-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let blob_hash = hex::encode(Sha256::digest(encrypted_backup_blob));
    let message = format!(
        "backups-upload:{user_id}:{device_id}:{timestamp}:{nonce}:{backup_version}:{blob_hash}"
    );
    let signature = signing_key.sign(message.as_bytes()).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn backup_download_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "backups-download-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let message = format!("backups-download:{user_id}:{device_id}:{timestamp}:{nonce}:{user_id}");
    let signature = signing_key.sign(message.as_bytes()).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn presence_update_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    target_user_id: &str,
    status: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "presence-update-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("presence-update", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: target_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PRESENCE_STATUS,
        value: status.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("presence-update auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn presence_get_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    target_user_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "presence-get-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("presence-get", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: target_user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("presence-get auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn typing_update_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    peer_user_id: &str,
    is_typing: bool,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "typing-update-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("typing-update", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_TYPING_PEER_ID,
        value: peer_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_TYPING_STATE_FLAG,
        value: vec![if is_typing { 1 } else { 0 }],
    });
    let message = encode(&records).expect("typing-update auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn typing_get_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    target_user_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "typing-get-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("typing-get", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: target_user_id.as_bytes().to_vec(),
    });
    let message = encode(&records).expect("typing-get auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn rotate_init_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    rotate_body: &Value,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!("rot-init-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records = auth_common_records("rotate-init", user_id, device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(
        rotate_body["new_identity_x25519_pub"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_X25519_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(
        rotate_body["new_identity_sig_pub"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_SIG_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(
        rotate_body["new_identity_pq_sig_pub"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_PQ_SIG_HASH,
        value: hasher.finalize().to_vec(),
    });
    let message = encode(&records).expect("rotate-init auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn rotate_confirm_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    confirm_body: &Value,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "rot-confirm-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("rotate-confirm", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_CHALLENGE_ID,
        value: confirm_body["challenge_id"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(
        confirm_body["sig_by_current_identity"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_SIG_CURRENT_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(
        confirm_body["sig_by_new_identity"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_SIG_NEW_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(
        confirm_body["pq_sig_by_current_identity"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_PQ_SIG_CURRENT_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(
        confirm_body["pq_sig_by_new_identity"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_PQ_SIG_NEW_HASH,
        value: hasher.finalize().to_vec(),
    });
    let message = encode(&records).expect("rotate-confirm auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

#[tokio::test]
async fn happy_path_register_publish_bundle_relay_inbox() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(7);
    let alice_sig = signing_key(11);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [3u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &bob_sig,
        [5u8; 32],
        vec![7u8; 64],
        vec![[9u8; 32], [10u8; 32]],
        vec![vec![11u8; 64], vec![12u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_publish, publish_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_publish, StatusCode::OK);
    assert_eq!(
        publish_body["uploaded_one_time_prekeys_x25519"].as_u64(),
        Some(2)
    );

    let (status_bundle1, bundle1) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle1, StatusCode::OK);
    assert!(bundle1["one_time_prekey_x25519"].is_string());
    assert_eq!(bundle1["identity_key_version"].as_u64(), Some(1));
    assert!(bundle1["identity_fingerprint_sha256"].as_str().is_some());

    let (status_bundle2, bundle2) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle2, StatusCode::OK);
    assert!(bundle2["one_time_prekey_x25519"].is_string());
    assert_ne!(
        bundle1["one_time_prekey_x25519"].as_str(),
        bundle2["one_time_prekey_x25519"].as_str()
    );

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("opaque-ciphertext-bytes")
    });
    let relay_bytes = B64
        .decode("b3BhcXVlLWNpcGhlcnRleHQtYnl0ZXM=")
        .expect("relay payload");
    let relay_headers = relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", &relay_bytes);
    let (status_relay, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &relay_headers,
    )
    .await;
    assert_eq!(status_relay, StatusCode::OK);
    let message_id = relay_body["message_id"].as_i64().expect("message_id");

    let inbox_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_inbox, inbox_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_headers,
    )
    .await;
    assert_eq!(status_inbox, StatusCode::OK);
    let messages = inbox_body["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["message_id"].as_i64(), Some(message_id));
    assert_eq!(messages[0]["sender_user_id"].as_str(), Some("alice"));

    let uri = format!("/v1/inbox/bob?since={message_id}");
    let inbox_headers_2 = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", message_id);
    let (status_inbox2, inbox_body2) =
        json_request_with_headers(app.clone(), Method::GET, &uri, json!({}), &inbox_headers_2)
            .await;
    assert_eq!(status_inbox2, StatusCode::OK);
    assert_eq!(inbox_body2["messages"].as_array().map(|v| v.len()), Some(0));
}

#[tokio::test]
async fn invalid_inputs_are_rejected() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(7);
    let alice_sig = signing_key(11);

    let invalid_register = json!({
        "user_id": "bob",
        "identity_x25519_pub": B64.encode([1u8; 31]),
        "identity_sig_pub": B64.encode(bob_sig.verifying_key().to_bytes()),
        "identity_pq_sig_pub": B64.encode(vec![9u8; ML_DSA_65_PK_LEN]),
        "device_id": "bob-dev-1"
    });
    let (status_register, body_register) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        invalid_register,
    )
    .await;
    assert_eq!(status_register, StatusCode::BAD_REQUEST);
    assert_eq!(body_register["status"].as_u64(), Some(400));

    let valid_register = register_payload("bob", "bob-dev-1", [3u8; 32], &bob_sig);
    let (status_valid_register, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        valid_register,
    )
    .await;
    assert_eq!(status_valid_register, StatusCode::OK);

    let valid_register_alice = register_payload("alice", "alice-dev-1", [4u8; 32], &alice_sig);
    let (status_valid_register_alice, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        valid_register_alice,
    )
    .await;
    assert_eq!(status_valid_register_alice, StatusCode::OK);

    let invalid_prekeys = json!({
        "signed_prekey_x25519_pub": B64.encode([5u8; 31]),
        "sig_over_spk": B64.encode([6u8; 64]),
        "pq_signed_prekey_pub_mlkem768": B64.encode([7u8; 64]),
        "sig_over_pqspk": B64.encode([8u8; 64]),
        "pq_sig_over_spk": B64.encode(vec![9u8; ML_DSA_65_SIG_LEN]),
        "pq_sig_over_pqspk": B64.encode(vec![10u8; ML_DSA_65_SIG_LEN]),
        "one_time_prekeys_x25519": [],
        "one_time_prekeys_mlkem768": []
    });
    let prekeys_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &invalid_prekeys);
    let (status_prekeys, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        invalid_prekeys,
        &prekeys_auth,
    )
    .await;
    assert_eq!(status_prekeys, StatusCode::BAD_REQUEST);

    let big_message = vec![0u8; 1_100_000];
    let invalid_relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode(big_message)
    });
    let (status_relay, body_relay) =
        json_request(app.clone(), Method::POST, "/v1/relay/bob", invalid_relay).await;
    assert_eq!(status_relay, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body_relay["raw"].is_string() || body_relay["status"].is_number());
}

#[tokio::test]
async fn identity_registration_is_immutable() {
    let app = test_app().await;
    let key_a = signing_key(3);
    let key_b = signing_key(4);

    let first = register_payload("bob", "bob-dev-1", [1u8; 32], &key_a);
    let (status_first, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", first).await;
    assert_eq!(status_first, StatusCode::OK);

    let conflict = register_payload("bob", "bob-dev-1", [2u8; 32], &key_b);
    let (status_conflict, body_conflict) =
        json_request(app.clone(), Method::POST, "/v1/users/register", conflict).await;
    assert_eq!(status_conflict, StatusCode::CONFLICT);
    assert_eq!(body_conflict["status"].as_u64(), Some(409));

    let repeat = register_payload("bob", "bob-dev-1", [1u8; 32], &key_a);
    let (status_repeat, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", repeat).await;
    assert_eq!(status_repeat, StatusCode::OK);
}

#[tokio::test]
async fn publish_prekeys_rejects_invalid_signature() {
    let app = test_app().await;
    let bob_sig = signing_key(7);
    let wrong_sig = signing_key(8);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &wrong_sig,
        [5u8; 32],
        vec![7u8; 64],
        vec![[9u8; 32]],
        vec![vec![11u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_publish, body_publish) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_publish, StatusCode::BAD_REQUEST);
    assert_eq!(body_publish["status"].as_u64(), Some(400));
}

#[tokio::test]
async fn health_reports_security_profile() {
    let app = test_app().await;
    let (status, headers, body) =
        json_request_with_headers_raw(app, Method::GET, "/health", json!({}), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    assert!(request_id.is_some());
    assert_eq!(body["status"].as_str(), Some("ok"));
    assert_eq!(body["security_profile"].as_str(), Some("research"));
    assert_eq!(body["deployment_mode"].as_str(), Some("development"));
    assert_eq!(body["db_backend"].as_str(), Some("sqlite"));
    assert_eq!(body["db_ready"].as_bool(), Some(true));
    assert_eq!(body["push_enabled"].as_bool(), Some(false));
    assert_eq!(body["audit_logger_enabled"].as_bool(), Some(false));
    assert_eq!(body["tls_enabled"].as_bool(), Some(false));
    assert_eq!(body["rate_limiter_mode"].as_str(), Some("in_memory"));
    assert_eq!(body["replay_cache_mode"].as_str(), Some("in_memory"));
    assert_eq!(body["realtime_mode"].as_str(), Some("in_memory"));
    assert_eq!(body["production_baseline_met"].as_bool(), Some(false));
    assert_eq!(
        body["runtime_crypto_profile"]["protocol_version"].as_u64(),
        Some(PROTOCOL_VERSION_V1 as u64)
    );
    assert!(body["supported_suite_ids"]
        .as_array()
        .is_some_and(|suite_ids| !suite_ids.is_empty()));
}

#[tokio::test]
async fn capabilities_reports_client_contract() {
    let app = test_app_with_profile(SecurityProfile::HighAssurance).await;
    let support_matrix = load_support_matrix();
    let current_beta_scope = &support_matrix["current_beta_scope"];
    let (status, headers, body) =
        json_request_with_headers_raw(app, Method::GET, "/v1/capabilities", json!({}), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    assert!(request_id.is_some());
    assert_eq!(body["capability_schema_version"].as_u64(), Some(1));
    assert_eq!(body["security_profile"].as_str(), Some("high_assurance"));
    assert_eq!(body["deployment_mode"].as_str(), Some("development"));
    assert_eq!(body["tls_required"].as_bool(), Some(true));
    assert_eq!(body["tls_enabled"].as_bool(), Some(false));
    assert_eq!(body["production_baseline_met"].as_bool(), Some(false));
    assert_eq!(
        body["web_client_policy"],
        current_beta_scope["web_client_policy"]
    );
    assert_eq!(
        body["supported_beta_clients"],
        current_beta_scope["supported_beta_clients"]
    );
    assert_eq!(
        body["calling_supported"],
        current_beta_scope["calling_supported"]
    );
    assert_eq!(
        body["group_messaging_supported"],
        current_beta_scope["group_messaging_supported"]
    );
    assert_eq!(
        body["private_group_messaging_supported"],
        current_beta_scope["private_group_messaging_supported"]
    );
    assert_eq!(
        body["pq_ratchet_interval"].as_u64(),
        Some(DEFAULT_PQ_RATCHET_INTERVAL as u64)
    );
    assert_eq!(body["contact_discovery_supported"].as_bool(), Some(false));
    assert_eq!(body["contact_discovery_mode"].as_str(), Some("manual_only"));
    assert_eq!(
        body["contact_discovery_ticket_supported"].as_bool(),
        Some(false)
    );
    assert!(body["contact_discovery_service_origin"].is_null());
    assert!(body["contact_discovery_manifest_issuer_ed25519_pub"].is_null());
    assert!(body["contact_discovery_directory_backend"].is_null());
    assert!(body["contact_discovery_host_enclave_protocol_version"].is_null());
    assert!(body["contact_discovery_attestation_verifier"].is_null());
    assert!(body["contact_discovery_expected_measurement_hex"].is_null());
    assert!(body["contact_discovery_attestation_document_sha256"].is_null());
    assert!(body["contact_discovery_attestation_max_age_seconds"].is_null());
    assert!(body["contact_discovery_ticket_issuer_ed25519_pub"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(body["presence_supported"].as_bool(), Some(false));
    assert_eq!(body["typing_indicators_supported"].as_bool(), Some(false));
    assert_eq!(
        body["authenticated_direct_messaging_supported"].as_bool(),
        Some(false)
    );
    assert_eq!(body["read_receipts_supported"].as_bool(), Some(false));
    assert_eq!(body["calling_supported"].as_bool(), Some(false));
    assert_eq!(body["stories_supported"].as_bool(), Some(false));
    assert_eq!(body["channels_supported"].as_bool(), Some(false));
    assert_eq!(body["group_messaging_supported"].as_bool(), Some(false));
    assert_eq!(body["private_group_state_supported"].as_bool(), Some(true));
    assert_eq!(
        body["private_group_messaging_supported"].as_bool(),
        Some(true)
    );
    assert_eq!(body["sealed_sender_required"].as_bool(), Some(true));
    assert_eq!(
        body["sealed_delivery_tokens_supported"].as_bool(),
        Some(true)
    );
    assert_eq!(body["ephemeral_messaging_supported"].as_bool(), Some(false));
    assert_eq!(
        body["runtime_crypto_profile"]["protocol_version"].as_u64(),
        Some(PROTOCOL_VERSION_V1 as u64)
    );
    assert!(body["supported_suite_ids"]
        .as_array()
        .is_some_and(|suite_ids| !suite_ids.is_empty()));
}

#[tokio::test]
async fn capabilities_report_private_contact_discovery_service_when_configured() {
    let app = test_app_with_contact_discovery_service_origin("https://cdsi.example").await;
    let (status, body) = json_request(app, Method::GET, "/v1/capabilities", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["contact_discovery_supported"].as_bool(), Some(true));
    assert_eq!(
        body["contact_discovery_mode"].as_str(),
        Some("private_service")
    );
    assert_eq!(
        body["contact_discovery_ticket_supported"].as_bool(),
        Some(true)
    );
    assert_eq!(
        body["contact_discovery_service_origin"].as_str(),
        Some("https://cdsi.example")
    );
    assert!(body["contact_discovery_manifest_issuer_ed25519_pub"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(
        body["contact_discovery_directory_backend"].as_str(),
        Some("simulated_enclave_preview")
    );
    assert_eq!(
        body["contact_discovery_host_enclave_protocol_version"].as_u64(),
        Some(1)
    );
    assert_eq!(
        body["contact_discovery_attestation_verifier"].as_str(),
        Some("sgx-dcap-preview")
    );
    assert_eq!(
        body["contact_discovery_expected_measurement_hex"].as_str(),
        Some("abababababababababababababababababababababababababababababababab")
    );
    assert_eq!(
        body["contact_discovery_attestation_document_sha256"].as_str(),
        Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
    );
    assert_eq!(
        body["contact_discovery_attestation_max_age_seconds"].as_u64(),
        Some(900)
    );
}

#[tokio::test]
async fn capabilities_do_not_advertise_development_only_private_discovery_in_pilot() {
    let app = test_app_with_contact_discovery_service_origin_and_deployment_mode(
        "https://cdsi.example",
        DeploymentMode::Pilot,
    )
    .await;
    let (status, body) = json_request(app, Method::GET, "/v1/capabilities", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["contact_discovery_supported"].as_bool(), Some(false));
    assert_eq!(body["contact_discovery_mode"].as_str(), Some("manual_only"));
    assert_eq!(
        body["contact_discovery_ticket_supported"].as_bool(),
        Some(false)
    );
    assert!(body["contact_discovery_service_origin"].is_null());
    assert!(body["contact_discovery_manifest_issuer_ed25519_pub"].is_null());
    assert!(body["contact_discovery_directory_backend"].is_null());
    assert!(body["contact_discovery_host_enclave_protocol_version"].is_null());
    assert!(body["contact_discovery_attestation_verifier"].is_null());
    assert!(body["contact_discovery_expected_measurement_hex"].is_null());
    assert!(body["contact_discovery_attestation_document_sha256"].is_null());
    assert!(body["contact_discovery_attestation_max_age_seconds"].is_null());
}

#[tokio::test]
async fn contact_discovery_ticket_requires_configured_service() {
    let app = test_app().await;
    let alice_sig = signing_key(31);
    let reg = register_payload(
        "alice-discovery",
        "alice-discovery-dev",
        [31u8; 32],
        &alice_sig,
    );
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);
    let headers = contact_discovery_ticket_auth_headers(
        &alice_sig,
        "alice-discovery",
        "alice-discovery-dev",
        "match",
    );
    let (status, body) = json_request_with_headers(
        app,
        Method::POST,
        "/v1/users/alice-discovery/contact-discovery/ticket",
        json!({ "purpose": "match" }),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["detail"].as_str(),
        Some("private contact discovery service is not configured; use manual contacts or invite links")
    );
}

#[tokio::test]
async fn contact_discovery_ticket_is_forbidden_outside_development_deployments() {
    let app = test_app_with_contact_discovery_service_origin_and_deployment_mode(
        "https://cdsi.example",
        DeploymentMode::Pilot,
    )
    .await;
    let alice_sig = signing_key(131);
    let reg = register_payload(
        "alice-discovery-pilot",
        "alice-discovery-pilot-dev",
        [131u8; 32],
        &alice_sig,
    );
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);
    let headers = contact_discovery_ticket_auth_headers(
        &alice_sig,
        "alice-discovery-pilot",
        "alice-discovery-pilot-dev",
        "match",
    );
    let (status, body) = json_request_with_headers(
        app,
        Method::POST,
        "/v1/users/alice-discovery-pilot/contact-discovery/ticket",
        json!({ "purpose": "match" }),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body["detail"].as_str(),
        Some("private contact discovery service is only available in development deployments; use manual contacts or invite links")
    );
}

#[tokio::test]
async fn contact_discovery_ticket_is_issued_for_configured_service() {
    let app = test_app_with_contact_discovery_service_origin("https://cdsi.example").await;
    let alice_sig = signing_key(32);
    let reg = register_payload("alice-cdsi", "alice-cdsi-dev", [32u8; 32], &alice_sig);
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);
    let headers =
        contact_discovery_ticket_auth_headers(&alice_sig, "alice-cdsi", "alice-cdsi-dev", "match");
    let (status, body) = json_request_with_headers(
        app,
        Method::POST,
        "/v1/users/alice-cdsi/contact-discovery/ticket",
        json!({ "purpose": "match" }),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["user_id"].as_str(), Some("alice-cdsi"));
    assert_eq!(body["device_id"].as_str(), Some("alice-cdsi-dev"));
    assert_eq!(
        body["service_origin"].as_str(),
        Some("https://cdsi.example")
    );
    let ticket = body["ticket"].as_str().expect("ticket string");
    let mut parts = ticket.split('.');
    let payload_b64 = parts.next().expect("ticket payload");
    assert!(parts.next().is_some_and(|value| !value.is_empty()));
    assert!(parts.next().is_none());
    let payload_bytes = B64
        .decode(payload_b64.as_bytes())
        .expect("decode ticket payload");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("parse ticket payload");
    assert_eq!(payload["user_id"].as_str(), Some("alice-cdsi"));
    assert_eq!(payload["purpose"].as_str(), Some("match"));
    assert!(payload["contact_invite_token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert!(payload["contact_invite_expires_at"].as_str().is_some());
    assert!(body["expires_at"].as_str().is_some());
}

#[tokio::test]
async fn contact_discovery_ticket_reuses_bootstrap_invite_without_rotating_manual_invite() {
    let app = test_app_with_contact_discovery_service_origin("https://cdsi.example").await;
    let alice_sig = signing_key(232);
    let reg = register_payload(
        "alice-bootstrap",
        "alice-bootstrap-dev",
        [232u8; 32],
        &alice_sig,
    );
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);

    let manual_headers =
        contact_invite_create_auth_headers(&alice_sig, "alice-bootstrap", "alice-bootstrap-dev");
    let (status_manual, manual_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice-bootstrap/contact-invites",
        json!({}),
        &manual_headers,
    )
    .await;
    assert_eq!(status_manual, StatusCode::OK);
    let manual_token = manual_payload["invite_token"]
        .as_str()
        .expect("manual invite token")
        .to_string();

    let discovery_headers = contact_discovery_ticket_auth_headers(
        &alice_sig,
        "alice-bootstrap",
        "alice-bootstrap-dev",
        "match",
    );
    let (status_ticket_first, ticket_first_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice-bootstrap/contact-discovery/ticket",
        json!({ "purpose": "match" }),
        &discovery_headers,
    )
    .await;
    assert_eq!(status_ticket_first, StatusCode::OK);
    let first_ticket_payload_bytes = B64
        .decode(
            ticket_first_payload["ticket"]
                .as_str()
                .expect("first ticket")
                .split('.')
                .next()
                .expect("first ticket payload")
                .as_bytes(),
        )
        .expect("decode first ticket payload");
    let first_ticket_payload: Value =
        serde_json::from_slice(&first_ticket_payload_bytes).expect("parse first ticket payload");
    let bootstrap_token = first_ticket_payload["contact_invite_token"]
        .as_str()
        .expect("bootstrap invite token")
        .to_string();
    assert_ne!(bootstrap_token, manual_token);

    let discovery_headers_second = contact_discovery_ticket_auth_headers(
        &alice_sig,
        "alice-bootstrap",
        "alice-bootstrap-dev",
        "match",
    );
    let (status_ticket_second, ticket_second_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice-bootstrap/contact-discovery/ticket",
        json!({ "purpose": "match" }),
        &discovery_headers_second,
    )
    .await;
    assert_eq!(status_ticket_second, StatusCode::OK);
    let second_ticket_payload_bytes = B64
        .decode(
            ticket_second_payload["ticket"]
                .as_str()
                .expect("second ticket")
                .split('.')
                .next()
                .expect("second ticket payload")
                .as_bytes(),
        )
        .expect("decode second ticket payload");
    let second_ticket_payload: Value =
        serde_json::from_slice(&second_ticket_payload_bytes).expect("parse second ticket payload");
    assert_eq!(
        second_ticket_payload["contact_invite_token"].as_str(),
        Some(bootstrap_token.as_str())
    );

    let (status_manual_resolve, manual_resolve_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/contact-invites/{manual_token}"),
        json!({}),
    )
    .await;
    assert_eq!(status_manual_resolve, StatusCode::OK);
    assert_eq!(
        manual_resolve_payload["user_id"].as_str(),
        Some("alice-bootstrap")
    );

    let (status_bootstrap_resolve, bootstrap_resolve_payload) = json_request(
        app,
        Method::GET,
        &format!("/v1/contact-invites/{bootstrap_token}"),
        json!({}),
    )
    .await;
    assert_eq!(status_bootstrap_resolve, StatusCode::OK);
    assert_eq!(
        bootstrap_resolve_payload["user_id"].as_str(),
        Some("alice-bootstrap")
    );
}

#[tokio::test]
async fn high_assurance_sets_hsts_header() {
    let app = test_app_with_profile(SecurityProfile::HighAssurance).await;
    let request = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::from("{}"))
        .expect("request");
    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let hsts = response
        .headers()
        .get("strict-transport-security")
        .and_then(|value| value.to_str().ok());
    assert_eq!(hsts, Some("max-age=31536000; includeSubDomains"));
}

#[tokio::test]
async fn metrics_endpoint_exports_prometheus_counters() {
    let app = test_app().await;
    let (status_health, _, _) =
        json_request_with_headers_raw(app.clone(), Method::GET, "/health", json!({}), &[]).await;
    assert_eq!(status_health, StatusCode::OK);

    let (status_metrics, headers_metrics, metrics_body) =
        text_request(app.clone(), Method::GET, "/metrics", &[]).await;
    assert_eq!(status_metrics, StatusCode::OK);
    let content_type = headers_metrics
        .get("content-type")
        .and_then(|value| value.to_str().ok());
    assert_eq!(
        content_type,
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    assert!(metrics_body.contains("pqmsg_http_requests_total"));
    assert!(metrics_body.contains("path=\"/health\""));
    assert!(metrics_body.contains("pqmsg_security_events_total"));
}

#[tokio::test]
async fn audit_log_file_captures_security_rejects() {
    let file_name = format!(
        "pqmsg-audit-{}.jsonl",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let path = std::env::temp_dir().join(file_name);
    let _ = fs::remove_file(&path);
    let app = test_app_with_audit_log(path.to_str().expect("audit path")).await;

    let invalid_register = json!({
        "user_id": "",
        "identity_x25519_pub": B64.encode([7u8; 32]),
        "identity_sig_pub": B64.encode([8u8; 32]),
        "identity_pq_sig_pub": B64.encode(vec![9u8; ML_DSA_65_PK_LEN]),
        "device_id": "bad-dev"
    });
    let (status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        invalid_register,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let audit_contents = fs::read_to_string(&path).expect("read audit file");
    assert!(audit_contents.contains("\"event\":\"client_error\""));
    assert!(audit_contents.contains("\"outcome\":\"reject\""));
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn identity_rotation_happy_path_and_log() {
    let app = test_app().await;
    let key_old = signing_key(33);
    let key_new = signing_key(34);

    let reg = register_payload("bob", "bob-dev-1", [1u8; 32], &key_old);
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &key_old,
        [7u8; 32],
        vec![8u8; 64],
        vec![[9u8; 32]],
        vec![vec![10u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&key_old, "bob", "bob-dev-1", &publish);
    let (status_publish, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_publish, StatusCode::OK);

    let new_identity_x25519 = [2u8; 32];
    let new_identity_sig = key_new.verifying_key().to_bytes();
    let rotate_init = json!({
        "new_identity_x25519_pub": B64.encode(new_identity_x25519),
        "new_identity_sig_pub": B64.encode(new_identity_sig),
        "new_identity_pq_sig_pub": B64.encode(&key_new.pq_public),
        "new_device_id": "bob-dev-2"
    });
    let rotate_init_auth = rotate_init_auth_headers(&key_old, "bob", "bob-dev-1", &rotate_init);
    let (status_init, body_init) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/init",
        rotate_init,
        &rotate_init_auth,
    )
    .await;
    assert_eq!(status_init, StatusCode::OK);
    let challenge_id = body_init["challenge_id"].as_str().expect("challenge_id");
    let challenge_nonce = B64
        .decode(
            body_init["challenge_nonce"]
                .as_str()
                .expect("challenge_nonce"),
        )
        .expect("challenge nonce");

    let message = rotation_signature_message(
        "bob",
        challenge_id,
        &challenge_nonce,
        &new_identity_x25519,
        &new_identity_sig,
        &key_new.pq_public,
        "bob-dev-2",
    );
    let rotate_confirm = json!({
        "challenge_id": challenge_id,
        "sig_by_current_identity": B64.encode(key_old.sign(&message).to_bytes()),
        "sig_by_new_identity": B64.encode(key_new.sign(&message).to_bytes()),
        "pq_sig_by_current_identity": pq_signature_b64(&key_old, &message),
        "pq_sig_by_new_identity": pq_signature_b64(&key_new, &message)
    });
    let rotate_confirm_auth =
        rotate_confirm_auth_headers(&key_old, "bob", "bob-dev-1", &rotate_confirm);
    let (status_confirm, body_confirm) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/confirm",
        rotate_confirm,
        &rotate_confirm_auth,
    )
    .await;
    assert_eq!(status_confirm, StatusCode::OK);
    assert_eq!(body_confirm["identity_key_version"].as_u64(), Some(2));

    let publish_after_rotate = publish_prekeys_payload(
        &key_new,
        [17u8; 32],
        vec![18u8; 64],
        vec![[19u8; 32]],
        vec![vec![20u8; 64]],
    );
    let publish_after_rotate_auth =
        prekeys_auth_headers(&key_new, "bob", "bob-dev-2", &publish_after_rotate);
    let (status_publish_after_rotate, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish_after_rotate,
        &publish_after_rotate_auth,
    )
    .await;
    assert_eq!(status_publish_after_rotate, StatusCode::OK);

    let (status_bundle, bundle) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle, StatusCode::OK);
    assert_eq!(
        bundle["identity_x25519_pub"].as_str(),
        Some(B64.encode(new_identity_x25519).as_str())
    );
    assert_eq!(
        bundle["identity_pq_sig_pub"].as_str(),
        Some(B64.encode(&key_new.pq_public).as_str())
    );
    assert_eq!(bundle["identity_key_version"].as_u64(), Some(2));

    let log_headers = identity_log_auth_headers(&key_new, "bob", "bob-dev-2");
    let (status_log, log_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/identity-log",
        json!({}),
        &log_headers,
    )
    .await;
    assert_eq!(status_log, StatusCode::OK);
    let events = log_body["events"].as_array().expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["version"].as_u64(), Some(2));
    assert_eq!(events[0]["event_type"].as_str(), Some("rotation"));
    assert_eq!(
        events[0]["identity_pq_sig_pub"].as_str(),
        Some(B64.encode(&key_new.pq_public).as_str())
    );
    assert_eq!(events[1]["version"].as_u64(), Some(1));
    assert_eq!(events[1]["event_type"].as_str(), Some("initial"));
}

#[tokio::test]
async fn transparency_proof_verifies_current_hybrid_identity_leaf() {
    let app = test_app().await;
    let key = signing_key(77);

    let reg = register_payload("alice-transparency", "alice-device", [3u8; 32], &key);
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);

    let (status_caps, caps) =
        json_request(app.clone(), Method::GET, "/v1/capabilities", json!({})).await;
    assert_eq!(status_caps, StatusCode::OK);
    assert_eq!(caps["key_transparency_supported"].as_bool(), Some(true));
    let verifying_key = transparency_verifying_key_from_capabilities(&caps);

    let (status_proof, proof_body) = json_request(
        app.clone(),
        Method::GET,
        "/v1/transparency/users/alice-transparency/proof",
        json!({}),
    )
    .await;
    assert_eq!(status_proof, StatusCode::OK);
    assert_eq!(proof_body["user_id"].as_str(), Some("alice-transparency"));
    assert!(proof_body["consistency_proof"].is_null());

    let leaf = transparency_leaf_from_value(&proof_body["leaf"]);
    let inclusion = transparency_inclusion_proof_from_value(&proof_body["inclusion_proof"]);
    let sth = transparency_sth_from_value(&proof_body["signed_tree_head"]);
    verify_inclusion_proof(&leaf.hash(), &inclusion, &sth, &verifying_key)
        .expect("inclusion proof should verify");
    assert_eq!(
        B64.encode(&key.pq_public),
        proof_body["leaf"]["identity_pq_sig_pub"]
            .as_str()
            .expect("identity_pq_sig_pub")
    );
}

#[tokio::test]
async fn transparency_proof_returns_consistency_proof_after_rotation() {
    let app = test_app().await;
    let key_old = signing_key(88);
    let key_new = signing_key(89);

    let reg = register_payload("bob-transparency", "bob-dev-1", [1u8; 32], &key_old);
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);

    let (status_caps, caps) =
        json_request(app.clone(), Method::GET, "/v1/capabilities", json!({})).await;
    assert_eq!(status_caps, StatusCode::OK);
    let verifying_key = transparency_verifying_key_from_capabilities(&caps);

    let (status_first, first_proof_body) = json_request(
        app.clone(),
        Method::GET,
        "/v1/transparency/users/bob-transparency/proof",
        json!({}),
    )
    .await;
    assert_eq!(status_first, StatusCode::OK);
    let first_sth = transparency_sth_from_value(&first_proof_body["signed_tree_head"]);
    assert_eq!(first_sth.tree_size, 1);

    let new_identity_x25519 = [2u8; 32];
    let new_identity_sig = key_new.verifying_key().to_bytes();
    let rotate_init = json!({
        "new_identity_x25519_pub": B64.encode(new_identity_x25519),
        "new_identity_sig_pub": B64.encode(new_identity_sig),
        "new_identity_pq_sig_pub": B64.encode(&key_new.pq_public),
        "new_device_id": "bob-dev-2"
    });
    let rotate_init_auth =
        rotate_init_auth_headers(&key_old, "bob-transparency", "bob-dev-1", &rotate_init);
    let (status_init, body_init) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob-transparency/rotate/init",
        rotate_init,
        &rotate_init_auth,
    )
    .await;
    assert_eq!(status_init, StatusCode::OK);
    let challenge_id = body_init["challenge_id"].as_str().expect("challenge_id");
    let challenge_nonce = B64
        .decode(
            body_init["challenge_nonce"]
                .as_str()
                .expect("challenge_nonce"),
        )
        .expect("challenge nonce");
    let message = rotation_signature_message(
        "bob-transparency",
        challenge_id,
        &challenge_nonce,
        &new_identity_x25519,
        &new_identity_sig,
        &key_new.pq_public,
        "bob-dev-2",
    );
    let rotate_confirm = json!({
        "challenge_id": challenge_id,
        "sig_by_current_identity": B64.encode(key_old.sign(&message).to_bytes()),
        "sig_by_new_identity": B64.encode(key_new.sign(&message).to_bytes()),
        "pq_sig_by_current_identity": pq_signature_b64(&key_old, &message),
        "pq_sig_by_new_identity": pq_signature_b64(&key_new, &message)
    });
    let rotate_confirm_auth =
        rotate_confirm_auth_headers(&key_old, "bob-transparency", "bob-dev-1", &rotate_confirm);
    let (status_confirm, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob-transparency/rotate/confirm",
        rotate_confirm,
        &rotate_confirm_auth,
    )
    .await;
    assert_eq!(status_confirm, StatusCode::OK);

    let (status_second, second_proof_body) = json_request(
        app.clone(),
        Method::GET,
        "/v1/transparency/users/bob-transparency/proof?previous_tree_size=1",
        json!({}),
    )
    .await;
    assert_eq!(status_second, StatusCode::OK);
    let second_leaf = transparency_leaf_from_value(&second_proof_body["leaf"]);
    let second_inclusion =
        transparency_inclusion_proof_from_value(&second_proof_body["inclusion_proof"]);
    let second_sth = transparency_sth_from_value(&second_proof_body["signed_tree_head"]);
    let consistency =
        transparency_consistency_proof_from_value(&second_proof_body["consistency_proof"]);
    verify_inclusion_proof(
        &second_leaf.hash(),
        &second_inclusion,
        &second_sth,
        &verifying_key,
    )
    .expect("second inclusion proof should verify");
    verify_consistency_proof(&first_sth, &second_sth, &consistency, &verifying_key)
        .expect("consistency proof should verify");
    assert_eq!(second_sth.tree_size, 2);
    assert_eq!(second_leaf.version, 2);
}

#[tokio::test]
async fn current_device_retire_clears_device_scoped_server_state() {
    let app = test_app_with_authenticated_dm_compat().await;
    let alice_sig = signing_key(201);
    let bob_sig = signing_key(202);

    for (user_id, device_id, identity_bytes, signing_key) in [
        ("alice", "alice-dev-1", [1u8; 32], &alice_sig),
        ("bob", "bob-dev-1", [2u8; 32], &bob_sig),
    ] {
        let registration = register_payload(user_id, device_id, identity_bytes, signing_key);
        let (status_register, _) = json_request(
            app.clone(),
            Method::POST,
            "/v1/users/register",
            registration,
        )
        .await;
        assert_eq!(status_register, StatusCode::OK);
    }

    let publish = publish_prekeys_payload(
        &bob_sig,
        [11u8; 32],
        vec![12u8; 64],
        vec![[13u8; 32]],
        vec![vec![14u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_prekeys, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_prekeys, StatusCode::OK);

    let push_auth = push_token_auth_headers(&bob_sig, "bob", "bob-dev-1", "push-token-bob");
    let (status_push, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/push-token",
        json!({
            "device_id": "bob-dev-1",
            "provider": "fcm",
            "token": "push-token-bob",
            "fcm_token": null
        }),
        &push_auth,
    )
    .await;
    assert_eq!(status_push, StatusCode::OK);

    let relay_blob = b"retire-test-relay".to_vec();
    let relay_auth = relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", &relay_blob);
    let (status_relay, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        json!({
            "sender_user_id": "alice",
            "device_id": "alice-dev-1",
            "message_bytes_base64": B64.encode(&relay_blob)
        }),
        &relay_auth,
    )
    .await;
    assert_eq!(status_relay, StatusCode::OK);

    let sealed_blob = b"retire-test-sealed".to_vec();
    add_contact_for_delivery_access(app.clone(), &alice_sig, "alice", "alice-dev-1", "bob").await;
    let bob_delivery_token =
        fetch_sealed_delivery_token(app.clone(), &alice_sig, "alice", "alice-dev-1", "bob").await;
    let (status_sealed_relay, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/sealed-relay/bob",
        json!({
            "delivery_token": bob_delivery_token,
            "message_bytes_base64": B64.encode(&sealed_blob)
        }),
    )
    .await;
    assert_eq!(status_sealed_relay, StatusCode::OK);

    let inbox_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_inbox, inbox_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_headers,
    )
    .await;
    assert_eq!(status_inbox, StatusCode::OK);
    assert_eq!(
        inbox_body["messages"].as_array().map(|items| items.len()),
        Some(1)
    );

    let sealed_inbox_headers = sealed_inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_sealed_inbox, sealed_inbox_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/sealed-inbox/bob?since=0",
        json!({}),
        &sealed_inbox_headers,
    )
    .await;
    assert_eq!(status_sealed_inbox, StatusCode::OK);
    assert_eq!(
        sealed_inbox_body["messages"]
            .as_array()
            .map(|items| items.len()),
        Some(1)
    );

    let retire_headers = retire_device_auth_headers(&bob_sig, "bob", "bob-dev-1");
    let (status_retire, retire_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/devices/current/retire",
        json!({}),
        &retire_headers,
    )
    .await;
    assert_eq!(status_retire, StatusCode::OK);
    assert_eq!(retire_body["retired_device_id"].as_str(), Some("bob-dev-1"));
    assert_eq!(retire_body["remaining_active_devices"].as_u64(), Some(0));

    let (status_bundle_after_retire, _) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle_after_retire, StatusCode::NOT_FOUND);

    let (status_inbox_after_retire, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0),
    )
    .await;
    assert_eq!(status_inbox_after_retire, StatusCode::BAD_REQUEST);

    let re_register = register_payload("bob", "bob-dev-1", [2u8; 32], &bob_sig);
    let (status_re_register, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", re_register).await;
    assert_eq!(status_re_register, StatusCode::OK);

    let publish_after_retire = publish_prekeys_payload(
        &bob_sig,
        [21u8; 32],
        vec![22u8; 64],
        vec![[23u8; 32]],
        vec![vec![24u8; 64]],
    );
    let publish_after_retire_auth =
        prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish_after_retire);
    let (status_publish_after_retire, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish_after_retire,
        &publish_after_retire_auth,
    )
    .await;
    assert_eq!(status_publish_after_retire, StatusCode::OK);

    let (status_inbox_after_reactivate, inbox_after_reactivate_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0),
    )
    .await;
    assert_eq!(status_inbox_after_reactivate, StatusCode::OK);
    assert_eq!(
        inbox_after_reactivate_body["messages"]
            .as_array()
            .map(|items| items.len()),
        Some(0)
    );

    let (status_sealed_after_reactivate, sealed_after_reactivate_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/sealed-inbox/bob?since=0",
        json!({}),
        &sealed_inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0),
    )
    .await;
    assert_eq!(status_sealed_after_reactivate, StatusCode::OK);
    assert_eq!(
        sealed_after_reactivate_body["messages"]
            .as_array()
            .map(|items| items.len()),
        Some(0)
    );
}

#[tokio::test]
async fn identity_rotation_rejects_invalid_signature() {
    let app = test_app().await;
    let key_old = signing_key(45);
    let key_new = signing_key(46);
    let attacker = signing_key(47);

    let reg = register_payload("bob", "bob-dev-1", [1u8; 32], &key_old);
    let (status_reg, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(status_reg, StatusCode::OK);

    let rotate_init = json!({
        "new_identity_x25519_pub": B64.encode([2u8; 32]),
        "new_identity_sig_pub": B64.encode(key_new.verifying_key().to_bytes()),
        "new_identity_pq_sig_pub": B64.encode(&key_new.pq_public),
        "new_device_id": "bob-dev-2"
    });
    let rotate_init_auth = rotate_init_auth_headers(&key_old, "bob", "bob-dev-1", &rotate_init);
    let (status_init, body_init) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/init",
        rotate_init,
        &rotate_init_auth,
    )
    .await;
    assert_eq!(status_init, StatusCode::OK);

    let challenge_id = body_init["challenge_id"].as_str().expect("challenge_id");
    let rotate_confirm = json!({
        "challenge_id": challenge_id,
        "sig_by_current_identity": B64.encode(attacker.sign(b"bad").to_bytes()),
        "sig_by_new_identity": B64.encode(attacker.sign(b"bad").to_bytes()),
        "pq_sig_by_current_identity": pq_signature_b64(&attacker, b"bad"),
        "pq_sig_by_new_identity": pq_signature_b64(&attacker, b"bad")
    });
    let rotate_confirm_auth =
        rotate_confirm_auth_headers(&key_old, "bob", "bob-dev-1", &rotate_confirm);
    let (status_confirm, body_confirm) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/confirm",
        rotate_confirm,
        &rotate_confirm_auth,
    )
    .await;
    assert_eq!(status_confirm, StatusCode::BAD_REQUEST);
    assert_eq!(body_confirm["status"].as_u64(), Some(400));
}

#[tokio::test]
async fn legacy_authenticated_direct_message_routes_are_disabled_by_default() {
    let app = test_app().await;
    let bob_sig = signing_key(69);
    let alice_sig = signing_key(70);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [2u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("ciphertext")
    });
    let relay_headers =
        relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", b"ciphertext");
    let (status_relay, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &relay_headers,
    )
    .await;
    assert_eq!(status_relay, StatusCode::FORBIDDEN);
    assert!(relay_body["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("sealed relay/inbox")));

    let inbox_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_inbox, inbox_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_headers,
    )
    .await;
    assert_eq!(status_inbox, StatusCode::FORBIDDEN);
    assert!(inbox_body["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("sealed relay/inbox")));
}

#[tokio::test]
async fn relay_and_inbox_require_authenticated_headers() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(71);
    let alice_sig = signing_key(72);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [2u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("ciphertext")
    });
    let (status_relay_missing, _) =
        json_request(app.clone(), Method::POST, "/v1/relay/bob", relay.clone()).await;
    assert_eq!(status_relay_missing, StatusCode::BAD_REQUEST);

    let relay_headers =
        relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", b"ciphertext");
    let (status_relay_ok, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay.clone(),
        &relay_headers,
    )
    .await;
    assert_eq!(status_relay_ok, StatusCode::OK);

    let (status_relay_replay, body_relay_replay) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &relay_headers,
    )
    .await;
    assert_eq!(status_relay_replay, StatusCode::CONFLICT);
    assert_eq!(body_relay_replay["status"].as_u64(), Some(409));

    let (status_inbox_missing, _) =
        json_request(app.clone(), Method::GET, "/v1/inbox/bob?since=0", json!({})).await;
    assert_eq!(status_inbox_missing, StatusCode::BAD_REQUEST);

    let inbox_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_inbox_ok, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_headers,
    )
    .await;
    assert_eq!(status_inbox_ok, StatusCode::OK);

    let (status_prekeys_status_missing, _) = json_request(
        app.clone(),
        Method::GET,
        "/v1/users/bob/prekeys/status",
        json!({}),
    )
    .await;
    assert_eq!(status_prekeys_status_missing, StatusCode::BAD_REQUEST);

    let prekeys_status_headers = prekeys_status_auth_headers(&bob_sig, "bob", "bob-dev-1");
    let (status_prekeys_status_ok, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/prekeys/status",
        json!({}),
        &prekeys_status_headers,
    )
    .await;
    assert_eq!(status_prekeys_status_ok, StatusCode::OK);
}

#[tokio::test]
async fn relay_dedup_rejects_duplicate_ciphertext_with_fresh_auth_nonce() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(74);
    let alice_sig = signing_key(75);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [2u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("same-ciphertext")
    });

    let first_headers = relay_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"same-ciphertext",
    );
    let (status_first, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay.clone(),
        &first_headers,
    )
    .await;
    assert_eq!(status_first, StatusCode::OK);

    let second_headers = relay_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"same-ciphertext",
    );
    let (status_second, body_second) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &second_headers,
    )
    .await;
    assert_eq!(status_second, StatusCode::CONFLICT);
    assert_eq!(body_second["status"].as_u64(), Some(409));
}

#[tokio::test]
async fn inbox_since_must_be_monotonic_for_authenticated_device_session() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(76);
    let alice_sig = signing_key(77);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [2u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("cursor-ciphertext")
    });
    let relay_headers = relay_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"cursor-ciphertext",
    );
    let (status_relay, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &relay_headers,
    )
    .await;
    assert_eq!(status_relay, StatusCode::OK);
    let message_id = relay_body["message_id"].as_i64().expect("message_id");

    let first_inbox_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_first, first_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &first_inbox_headers,
    )
    .await;
    assert_eq!(status_first, StatusCode::OK);
    assert_eq!(first_body["messages"].as_array().map(|v| v.len()), Some(1));

    let regressed_inbox_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_regressed, regressed_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &regressed_inbox_headers,
    )
    .await;
    assert_eq!(status_regressed, StatusCode::CONFLICT);
    assert_eq!(regressed_body["status"].as_u64(), Some(409));

    let advanced_inbox_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", message_id);
    let uri = format!("/v1/inbox/bob?since={message_id}");
    let (status_advanced, advanced_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        &uri,
        json!({}),
        &advanced_inbox_headers,
    )
    .await;
    assert_eq!(status_advanced, StatusCode::OK);
    assert_eq!(
        advanced_body["messages"].as_array().map(|v| v.len()),
        Some(0)
    );
}

#[tokio::test]
async fn push_token_registration_requires_authenticated_headers() {
    let app = test_app().await;
    let alice_sig = signing_key(73);
    let reg_alice = register_payload("alice", "alice-dev-1", [2u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let body = json!({
        "device_id": "alice-dev-1",
        "fcm_token": "demo-fcm-token-123"
    });
    let (status_missing, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/alice/push-token",
        body.clone(),
    )
    .await;
    assert_eq!(status_missing, StatusCode::BAD_REQUEST);

    let auth_headers =
        push_token_auth_headers(&alice_sig, "alice", "alice-dev-1", "demo-fcm-token-123");
    let (status_ok, payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/push-token",
        body,
        &auth_headers,
    )
    .await;
    assert_eq!(status_ok, StatusCode::OK);
    assert_eq!(payload["provider"].as_str(), Some("fcm"));
}

#[tokio::test]
async fn push_token_registration_accepts_apns_provider() {
    let app = test_app().await;
    let alice_sig = signing_key(74);
    let reg_alice = register_payload("alice", "alice-dev-1", [3u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let apns_token = "a".repeat(64);
    let body = json!({
        "device_id": "alice-dev-1",
        "provider": "apns",
        "token": apns_token
    });
    let auth_headers = push_token_auth_headers(&alice_sig, "alice", "alice-dev-1", &apns_token);
    let (status_ok, payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/push-token",
        body,
        &auth_headers,
    )
    .await;
    assert_eq!(status_ok, StatusCode::OK);
    assert_eq!(payload["provider"].as_str(), Some("apns"));
}

#[tokio::test]
async fn prekeys_status_reports_low_inventory_and_last_resort_fallback() {
    let app = test_app().await;
    let bob_sig = signing_key(78);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &bob_sig,
        [5u8; 32],
        vec![7u8; 64],
        vec![[9u8; 32]],
        vec![vec![11u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_publish, publish_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_publish, StatusCode::OK);
    assert_eq!(
        publish_body["remaining_one_time_prekeys_x25519"].as_u64(),
        Some(1)
    );
    assert_eq!(
        publish_body["remaining_one_time_prekeys_mlkem768"].as_u64(),
        Some(1)
    );
    assert_eq!(publish_body["low_one_time_prekeys"].as_bool(), Some(true));

    let status_auth = prekeys_status_auth_headers(&bob_sig, "bob", "bob-dev-1");
    let (status_status, status_body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/prekeys/status",
        json!({}),
        &status_auth,
    )
    .await;
    assert_eq!(status_status, StatusCode::OK);
    assert_eq!(
        status_body["remaining_one_time_prekeys_x25519"].as_u64(),
        Some(1)
    );
    assert_eq!(
        status_body["remaining_one_time_prekeys_mlkem768"].as_u64(),
        Some(1)
    );
    assert_eq!(status_body["low_one_time_prekeys"].as_bool(), Some(true));

    let (status_bundle1, bundle1) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle1, StatusCode::OK);
    assert!(bundle1["one_time_prekey_x25519"].is_string());
    assert!(bundle1["one_time_prekey_mlkem768"].is_string());
    assert_eq!(bundle1["last_resort_prekey_only"].as_bool(), Some(false));

    let (status_bundle2, bundle2) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle2, StatusCode::OK);
    assert!(bundle2["one_time_prekey_x25519"].is_null());
    assert!(bundle2["one_time_prekey_mlkem768"].is_null());
    assert_eq!(bundle2["last_resort_prekey_only"].as_bool(), Some(true));

    let status_auth_2 = prekeys_status_auth_headers(&bob_sig, "bob", "bob-dev-1");
    let (status_status2, status_body2) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/prekeys/status",
        json!({}),
        &status_auth_2,
    )
    .await;
    assert_eq!(status_status2, StatusCode::OK);
    assert_eq!(
        status_body2["remaining_one_time_prekeys_x25519"].as_u64(),
        Some(0)
    );
    assert_eq!(
        status_body2["remaining_one_time_prekeys_mlkem768"].as_u64(),
        Some(0)
    );
    assert_eq!(status_body2["low_one_time_prekeys"].as_bool(), Some(true));
}

#[tokio::test]
async fn legacy_authenticated_websocket_inbox_is_disabled_by_default() {
    let app = test_app().await;
    let bob_sig = signing_key(81);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let (base_ws_url, server_handle) = spawn_http_server(app.clone()).await;
    let connect = connect_async(format!("{base_ws_url}/v1/ws/inbox/bob?since=0")).await;
    match connect {
        Ok(_) => panic!("legacy websocket inbox should be disabled"),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        Err(err) => panic!("unexpected websocket error: {err}"),
    }
    server_handle.abort();
}

#[tokio::test]
async fn websocket_inbox_requires_authenticated_headers() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(81);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let (base_ws_url, server_handle) = spawn_http_server(app.clone()).await;
    let connect = connect_async(format!("{base_ws_url}/v1/ws/inbox/bob?since=0")).await;
    match connect {
        Ok(_) => panic!("websocket connection should require auth headers"),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        Err(err) => panic!("unexpected websocket error: {err}"),
    }
    server_handle.abort();
}

#[tokio::test]
async fn websocket_inbox_streams_relay_messages() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(91);
    let alice_sig = signing_key(92);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [2u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let (base_ws_url, server_handle) = spawn_http_server(app.clone()).await;
    let ws_headers = ws_inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let mut ws_request = format!("{base_ws_url}/v1/ws/inbox/bob?since=0")
        .into_client_request()
        .expect("ws request");
    for (name, value) in ws_headers {
        ws_request.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value).expect("header value"),
        );
    }

    let (mut ws_stream, _) = connect_async(ws_request).await.expect("ws connect");

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("realtime-ciphertext")
    });
    let relay_headers = relay_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"realtime-ciphertext",
    );
    let (status_relay, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &relay_headers,
    )
    .await;
    assert_eq!(status_relay, StatusCode::OK);
    let expected_message_id = relay_body["message_id"].as_i64().expect("message id");

    let inbound = timeout(Duration::from_secs(3), ws_stream.next())
        .await
        .expect("timeout waiting for websocket frame");
    let Some(Ok(Message::Text(frame))) = inbound else {
        panic!("expected websocket text frame");
    };

    let payload: Value = serde_json::from_str(&frame).expect("ws payload json");
    assert_eq!(payload["event"].as_str(), Some("relay"));
    assert_eq!(payload["user_id"].as_str(), Some("bob"));
    let messages = payload["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0]["message_id"].as_i64(),
        Some(expected_message_id)
    );
    assert_eq!(messages[0]["sender_user_id"].as_str(), Some("alice"));

    server_handle.abort();
}

#[tokio::test]
async fn websocket_inbox_accepts_one_time_ticket_query() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(93);
    let alice_sig = signing_key(94);

    let reg_bob = register_payload("bob", "bob-dev-1", [3u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [4u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let ticket_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_ticket, ticket_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/ws/inbox/bob/ticket?since=0",
        json!({}),
        &ticket_headers,
    )
    .await;
    assert_eq!(status_ticket, StatusCode::OK);
    let ticket = ticket_body["ticket"].as_str().expect("ticket").to_string();

    let (base_ws_url, server_handle) = spawn_http_server(app.clone()).await;
    let (mut ws_stream, _) =
        connect_async(format!("{base_ws_url}/v1/ws/inbox/bob?ticket={ticket}"))
            .await
            .expect("ws connect");

    let replay_connect =
        connect_async(format!("{base_ws_url}/v1/ws/inbox/bob?ticket={ticket}")).await;
    match replay_connect {
        Ok(_) => panic!("ticket reuse should fail"),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        Err(err) => panic!("unexpected websocket error: {err}"),
    }

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("ticket-ciphertext")
    });
    let relay_headers = relay_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"ticket-ciphertext",
    );
    let (status_relay, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &relay_headers,
    )
    .await;
    assert_eq!(status_relay, StatusCode::OK);
    let expected_message_id = relay_body["message_id"].as_i64().expect("message id");

    let inbound = timeout(Duration::from_secs(3), ws_stream.next())
        .await
        .expect("timeout waiting for websocket frame");
    let Some(Ok(Message::Text(frame))) = inbound else {
        panic!("expected websocket text frame");
    };
    let payload: Value = serde_json::from_str(&frame).expect("ws payload json");
    assert_eq!(payload["event"].as_str(), Some("relay"));
    let messages = payload["messages"].as_array().expect("messages");
    assert_eq!(
        messages[0]["message_id"].as_i64(),
        Some(expected_message_id)
    );
    assert_eq!(messages[0]["sender_user_id"].as_str(), Some("alice"));

    server_handle.abort();
}

#[tokio::test]
async fn sealed_websocket_inbox_accepts_one_time_ticket_query() {
    let app = test_app().await;
    let bob_sig = signing_key(95);
    let alice_sig = signing_key(96);
    let bob_identity = [5u8; 32];
    let alice_identity = [6u8; 32];

    let reg_bob = register_payload("bob", "bob-dev-1", bob_identity, &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", alice_identity, &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let ticket_headers = sealed_inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_ticket, ticket_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/ws/sealed-inbox/bob/ticket?since=0",
        json!({}),
        &ticket_headers,
    )
    .await;
    assert_eq!(status_ticket, StatusCode::OK);
    let ticket = ticket_body["ticket"].as_str().expect("ticket").to_string();

    let (base_ws_url, server_handle) = spawn_http_server(app.clone()).await;
    let (mut ws_stream, _) = connect_async(format!(
        "{base_ws_url}/v1/ws/sealed-inbox/bob?ticket={ticket}"
    ))
    .await
    .expect("sealed ws connect");

    let replay_connect = connect_async(format!(
        "{base_ws_url}/v1/ws/sealed-inbox/bob?ticket={ticket}"
    ))
    .await;
    match replay_connect {
        Ok(_) => panic!("ticket reuse should fail"),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        Err(err) => panic!("unexpected websocket error: {err}"),
    }

    let sealed_blob = b"sealed-ws-ticket-ciphertext".to_vec();
    add_contact_for_delivery_access(app.clone(), &alice_sig, "alice", "alice-dev-1", "bob").await;
    let bob_delivery_token =
        fetch_sealed_delivery_token(app.clone(), &alice_sig, "alice", "alice-dev-1", "bob").await;
    let relay = json!({
        "delivery_token": bob_delivery_token,
        "message_bytes_base64": B64.encode(&sealed_blob)
    });
    let (status_relay, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/sealed-relay/bob",
        relay,
        &[],
    )
    .await;
    assert_eq!(status_relay, StatusCode::OK);
    let expected_message_id = relay_body["first_message_id"]
        .as_i64()
        .expect("first message id");

    let inbound = timeout(Duration::from_secs(3), ws_stream.next())
        .await
        .expect("timeout waiting for websocket frame");
    let Some(Ok(Message::Text(frame))) = inbound else {
        panic!("expected websocket text frame");
    };
    let payload: Value = serde_json::from_str(&frame).expect("ws payload json");
    assert_eq!(payload["event"].as_str(), Some("relay"));
    let messages = payload["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0]["message_id"].as_i64(),
        Some(expected_message_id)
    );
    assert_eq!(
        messages[0]["message_bytes_base64"].as_str(),
        Some(B64.encode(&sealed_blob).as_str())
    );
    assert!(messages[0].get("sender_identity_x25519_pub").is_none());
    assert!(messages[0].get("sender_user_id").is_none());

    server_handle.abort();
}

#[tokio::test]
async fn multi_device_link_list_revoke_and_bundle_selection() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(101);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let publish_dev1 = publish_prekeys_payload(
        &bob_sig,
        [5u8; 32],
        vec![7u8; 64],
        vec![[9u8; 32]],
        vec![vec![11u8; 64]],
    );
    let publish_dev1_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish_dev1);
    let (status_publish_dev1, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish_dev1,
        &publish_dev1_auth,
    )
    .await;
    assert_eq!(status_publish_dev1, StatusCode::OK);

    let link_body = json!({
        "new_device_id": "bob-dev-2"
    });
    let link_headers = link_device_auth_headers(&bob_sig, "bob", "bob-dev-1", "bob-dev-2");
    let (status_link, link_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/devices/link",
        link_body,
        &link_headers,
    )
    .await;
    assert_eq!(status_link, StatusCode::OK);
    assert_eq!(link_payload["linked_device_id"].as_str(), Some("bob-dev-2"));

    let list_headers = devices_list_auth_headers(&bob_sig, "bob", "bob-dev-1");
    let (status_list, list_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/devices",
        json!({}),
        &list_headers,
    )
    .await;
    assert_eq!(status_list, StatusCode::OK);
    let devices = list_payload["devices"].as_array().expect("devices array");
    assert_eq!(devices.len(), 2);
    assert!(devices
        .iter()
        .any(|item| item["device_id"].as_str() == Some("bob-dev-2") && item["active"] == true));

    let publish_dev2 = publish_prekeys_payload(
        &bob_sig,
        [15u8; 32],
        vec![17u8; 64],
        vec![[19u8; 32]],
        vec![vec![21u8; 64]],
    );
    let publish_dev2_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-2", &publish_dev2);
    let (status_publish_dev2, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish_dev2,
        &publish_dev2_auth,
    )
    .await;
    assert_eq!(status_publish_dev2, StatusCode::OK);

    let (status_bundle_dev2, bundle_dev2) = json_request(
        app.clone(),
        Method::GET,
        "/v1/users/bob/bundle?device_id=bob-dev-2",
        json!({}),
    )
    .await;
    assert_eq!(status_bundle_dev2, StatusCode::OK);
    assert_eq!(bundle_dev2["device_id"].as_str(), Some("bob-dev-2"));

    let revoke_headers = revoke_device_auth_headers(&bob_sig, "bob", "bob-dev-1", "bob-dev-2");
    let (status_revoke, revoke_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/devices/bob-dev-2/revoke",
        json!({}),
        &revoke_headers,
    )
    .await;
    assert_eq!(status_revoke, StatusCode::OK);
    assert_eq!(
        revoke_payload["revoked_device_id"].as_str(),
        Some("bob-dev-2")
    );

    let list_headers_after = devices_list_auth_headers(&bob_sig, "bob", "bob-dev-1");
    let (status_list_after, list_after_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/devices",
        json!({}),
        &list_headers_after,
    )
    .await;
    assert_eq!(status_list_after, StatusCode::OK);
    let devices_after = list_after_payload["devices"]
        .as_array()
        .expect("devices array");
    assert!(devices_after
        .iter()
        .any(|item| item["device_id"].as_str() == Some("bob-dev-2") && item["active"] == false));

    let dev2_status_headers = prekeys_status_auth_headers(&bob_sig, "bob", "bob-dev-2");
    let (status_dev2_status, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/prekeys/status",
        json!({}),
        &dev2_status_headers,
    )
    .await;
    assert_eq!(status_dev2_status, StatusCode::BAD_REQUEST);

    let (status_bundle_dev2_after_revoke, _) = json_request(
        app.clone(),
        Method::GET,
        "/v1/users/bob/bundle?device_id=bob-dev-2",
        json!({}),
    )
    .await;
    assert_eq!(status_bundle_dev2_after_revoke, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn relay_fans_out_to_all_active_recipient_devices() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(111);
    let alice_sig = signing_key(112);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [3u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let link_body = json!({
        "new_device_id": "bob-dev-2"
    });
    let link_headers = link_device_auth_headers(&bob_sig, "bob", "bob-dev-1", "bob-dev-2");
    let (status_link, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/devices/link",
        link_body,
        &link_headers,
    )
    .await;
    assert_eq!(status_link, StatusCode::OK);

    let relay_first = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("fanout-1")
    });
    let relay_first_headers =
        relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", b"fanout-1");
    let (status_relay_first, relay_first_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay_first,
        &relay_first_headers,
    )
    .await;
    assert_eq!(status_relay_first, StatusCode::OK);
    assert_eq!(
        relay_first_payload["delivered_device_count"].as_u64(),
        Some(2)
    );

    let inbox_dev1_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_inbox_dev1, inbox_dev1_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_dev1_headers,
    )
    .await;
    assert_eq!(status_inbox_dev1, StatusCode::OK);
    assert_eq!(
        inbox_dev1_payload["messages"].as_array().map(|v| v.len()),
        Some(1)
    );
    let dev1_first_message_id = inbox_dev1_payload["messages"][0]["message_id"]
        .as_i64()
        .expect("device 1 first message id");

    let inbox_dev2_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-2", 0);
    let (status_inbox_dev2, inbox_dev2_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_dev2_headers,
    )
    .await;
    assert_eq!(status_inbox_dev2, StatusCode::OK);
    assert_eq!(
        inbox_dev2_payload["messages"].as_array().map(|v| v.len()),
        Some(1)
    );

    let revoke_headers = revoke_device_auth_headers(&bob_sig, "bob", "bob-dev-1", "bob-dev-2");
    let (status_revoke, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/devices/bob-dev-2/revoke",
        json!({}),
        &revoke_headers,
    )
    .await;
    assert_eq!(status_revoke, StatusCode::OK);

    let relay_second = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("fanout-2")
    });
    let relay_second_headers =
        relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", b"fanout-2");
    let (status_relay_second, relay_second_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay_second,
        &relay_second_headers,
    )
    .await;
    assert_eq!(status_relay_second, StatusCode::OK);
    assert_eq!(
        relay_second_payload["delivered_device_count"].as_u64(),
        Some(1)
    );

    let inbox_dev1_second_headers =
        inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", dev1_first_message_id);
    let inbox_dev1_second_uri = format!("/v1/inbox/bob?since={dev1_first_message_id}");
    let (status_inbox_dev1_second, inbox_dev1_second_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        &inbox_dev1_second_uri,
        json!({}),
        &inbox_dev1_second_headers,
    )
    .await;
    assert_eq!(status_inbox_dev1_second, StatusCode::OK);
    assert_eq!(
        inbox_dev1_second_payload["messages"]
            .as_array()
            .map(|v| v.len()),
        Some(1)
    );

    let inbox_dev2_after_revoke_headers = inbox_auth_headers(&bob_sig, "bob", "bob-dev-2", 0);
    let (status_inbox_dev2_after_revoke, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_dev2_after_revoke_headers,
    )
    .await;
    assert_eq!(status_inbox_dev2_after_revoke, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn inbox_delete_endpoint_removes_remote_messages_for_device() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(121);
    let alice_sig = signing_key(122);

    let reg_bob = register_payload("bob", "bob-dev-1", [1u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [2u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let relay_1 = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("delete-me-1")
    });
    let relay_1_headers =
        relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", b"delete-me-1");
    let (status_relay_1, relay_1_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay_1,
        &relay_1_headers,
    )
    .await;
    assert_eq!(status_relay_1, StatusCode::OK);
    let first_id = relay_1_payload["message_id"]
        .as_i64()
        .expect("first message id");

    let relay_2 = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("delete-me-2")
    });
    let relay_2_headers =
        relay_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", b"delete-me-2");
    let (status_relay_2, relay_2_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay_2,
        &relay_2_headers,
    )
    .await;
    assert_eq!(status_relay_2, StatusCode::OK);
    let second_id = relay_2_payload["message_id"]
        .as_i64()
        .expect("second message id");

    let delete_body = json!({
        "message_ids": [first_id],
        "delete_before_id": null
    });
    let delete_headers = inbox_delete_auth_headers(&bob_sig, "bob", "bob-dev-1", &[first_id], None);
    let (status_delete_first, delete_first_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/inbox/bob/delete",
        delete_body,
        &delete_headers,
    )
    .await;
    assert_eq!(status_delete_first, StatusCode::OK);
    assert_eq!(delete_first_payload["deleted_count"].as_u64(), Some(1));

    let inbox_after_first_delete_headers =
        inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", first_id);
    let after_first_uri = format!("/v1/inbox/bob?since={first_id}");
    let (status_after_first_delete, after_first_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        &after_first_uri,
        json!({}),
        &inbox_after_first_delete_headers,
    )
    .await;
    assert_eq!(status_after_first_delete, StatusCode::OK);
    assert_eq!(
        after_first_payload["messages"]
            .as_array()
            .map(|items| items.len()),
        Some(1)
    );
    assert_eq!(
        after_first_payload["messages"][0]["message_id"].as_i64(),
        Some(second_id)
    );

    let delete_before_body = json!({
        "message_ids": [],
        "delete_before_id": second_id
    });
    let delete_before_headers =
        inbox_delete_auth_headers(&bob_sig, "bob", "bob-dev-1", &[], Some(second_id));
    let (status_delete_before, delete_before_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/inbox/bob/delete",
        delete_before_body,
        &delete_before_headers,
    )
    .await;
    assert_eq!(status_delete_before, StatusCode::OK);
    assert_eq!(delete_before_payload["deleted_count"].as_u64(), Some(1));

    let inbox_after_all_delete_headers =
        inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", second_id);
    let after_all_uri = format!("/v1/inbox/bob?since={second_id}");
    let (status_after_all_delete, after_all_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        &after_all_uri,
        json!({}),
        &inbox_after_all_delete_headers,
    )
    .await;
    assert_eq!(status_after_all_delete, StatusCode::OK);
    assert_eq!(
        after_all_payload["messages"]
            .as_array()
            .map(|items| items.len()),
        Some(0)
    );
}

#[tokio::test]
async fn discovery_disabled_and_contacts_flow() {
    use sha2::{Digest, Sha256};

    let app = test_app().await;
    let alice_sig = signing_key(131);
    let bob_sig = signing_key(132);

    let reg_alice = register_payload("alice", "alice-dev-1", [1u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let reg_bob = register_payload("bob", "bob-dev-1", [2u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let bob_profile_headers = profile_upsert_auth_headers(
        &bob_sig,
        "bob",
        "bob-dev-1",
        "bob",
        Some("Bob"),
        Some("bob.secure"),
        true,
        None,
        None,
    );
    let (status_bob_profile, bob_profile_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/profile",
        json!({
            "display_name": "Bob",
            "username": "bob.secure"
        }),
        &bob_profile_headers,
    )
    .await;
    assert_eq!(status_bob_profile, StatusCode::OK);
    assert_eq!(bob_profile_payload["username"].as_str(), Some("bob.secure"));

    let bob_phone_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"+15550001111");
        hex::encode(hasher.finalize())
    };
    let bob_email_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"bob@example.com");
        hex::encode(hasher.finalize())
    };

    let upload_phone_hashes = vec![bob_phone_hash.clone()];
    let upload_email_hashes = vec![bob_email_hash.clone()];
    let discovery_upload = json!({
        "phone_hashes_sha256": upload_phone_hashes,
        "email_hashes_sha256": upload_email_hashes
    });
    let discovery_upload_headers = discovery_handles_auth_headers(
        &bob_sig,
        "bob",
        "bob-dev-1",
        &upload_phone_hashes,
        &upload_email_hashes,
    );
    let (status_upload, upload_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/discovery/handles",
        discovery_upload,
        &discovery_upload_headers,
    )
    .await;
    assert_eq!(status_upload, StatusCode::FORBIDDEN);
    assert_eq!(upload_payload["status"].as_u64(), Some(403));

    let unknown_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"unknown@example.com");
        hex::encode(hasher.finalize())
    };
    let match_hashes = vec![bob_phone_hash.clone(), unknown_hash];
    let discovery_match_body = json!({
        "hashes_sha256": match_hashes
    });
    let discovery_match_headers =
        discovery_match_auth_headers(&alice_sig, "alice", "alice-dev-1", &match_hashes);
    let (status_match, match_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/discovery/match",
        discovery_match_body,
        &discovery_match_headers,
    )
    .await;
    assert_eq!(status_match, StatusCode::FORBIDDEN);
    assert_eq!(match_payload["status"].as_u64(), Some(403));

    let fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let contact_add_body = json!({
        "contact_user_id": "bob",
        "alias": "Bobby",
        "verified_by_qr": true,
        "verified_fingerprint_sha256": fingerprint
    });
    let contact_add_headers = contacts_upsert_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        Some("Bobby"),
        true,
        Some(fingerprint),
    );
    let (status_contact_add, contact_add_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/contacts",
        contact_add_body,
        &contact_add_headers,
    )
    .await;
    assert_eq!(status_contact_add, StatusCode::OK);
    assert_eq!(contact_add_payload["contact_user_id"].as_str(), Some("bob"));
    assert_eq!(contact_add_payload["verified_by_qr"].as_bool(), Some(true));

    let contacts_list_headers = contacts_list_auth_headers(&alice_sig, "alice", "alice-dev-1");
    let (status_contacts_list, contacts_list_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/contacts",
        json!({}),
        &contacts_list_headers,
    )
    .await;
    assert_eq!(status_contacts_list, StatusCode::OK);
    let contacts = contacts_list_payload["contacts"]
        .as_array()
        .expect("contacts");
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0]["contact_user_id"].as_str(), Some("bob"));
    assert_eq!(contacts[0]["username"].as_str(), Some("bob.secure"));
    assert_eq!(contacts[0]["alias"].as_str(), Some("Bobby"));
    assert_eq!(contacts[0]["verified_by_qr"].as_bool(), Some(true));

    let contact_remove_body = json!({
        "contact_user_id": "bob"
    });
    let contact_remove_headers =
        contacts_remove_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob");
    let (status_contact_remove, contact_remove_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/contacts/remove",
        contact_remove_body,
        &contact_remove_headers,
    )
    .await;
    assert_eq!(status_contact_remove, StatusCode::OK);
    assert_eq!(contact_remove_payload["removed"].as_bool(), Some(true));
}

#[tokio::test]
async fn opaque_contact_invites_resolve_and_rotate() {
    let app = test_app().await;
    let alice_sig = signing_key(151);

    let reg_alice = register_payload("alice", "alice-dev-1", [21u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let create_headers = contact_invite_create_auth_headers(&alice_sig, "alice", "alice-dev-1");
    let (status_create, create_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/contact-invites",
        json!({}),
        &create_headers,
    )
    .await;
    assert_eq!(status_create, StatusCode::OK);
    assert_eq!(create_payload["user_id"].as_str(), Some("alice"));
    let first_token = create_payload["invite_token"]
        .as_str()
        .expect("first invite token")
        .to_string();
    assert!(!first_token.is_empty());

    let publish = publish_prekeys_payload(
        &alice_sig,
        [22u8; 32],
        vec![23u8; 64],
        vec![[24u8; 32]],
        vec![vec![25u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&alice_sig, "alice", "alice-dev-1", &publish);
    let (status_publish, publish_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(
        status_publish,
        StatusCode::OK,
        "prekey publish failed: {publish_payload}"
    );

    let (status_resolve_first, resolve_first_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/contact-invites/{first_token}"),
        json!({}),
    )
    .await;
    assert_eq!(status_resolve_first, StatusCode::OK);
    assert_eq!(resolve_first_payload["user_id"].as_str(), Some("alice"));
    assert_eq!(
        resolve_first_payload["invite_token"].as_str(),
        Some(first_token.as_str())
    );

    let (status_bundle, bundle_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/contact-invites/{first_token}/bundle"),
        json!({}),
    )
    .await;
    assert_eq!(status_bundle, StatusCode::OK);
    assert_eq!(bundle_payload["user_id"].as_str(), Some("alice"));
    assert_eq!(bundle_payload["identity_key_version"].as_u64(), Some(1));
    assert!(bundle_payload["identity_pq_sig_pub"].as_str().is_some());

    let rotate_headers = contact_invite_create_auth_headers(&alice_sig, "alice", "alice-dev-1");
    let (status_rotate, rotate_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/contact-invites",
        json!({}),
        &rotate_headers,
    )
    .await;
    assert_eq!(status_rotate, StatusCode::OK);
    let second_token = rotate_payload["invite_token"]
        .as_str()
        .expect("second invite token")
        .to_string();
    assert_ne!(first_token, second_token);

    let (status_old_token, old_token_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/contact-invites/{first_token}"),
        json!({}),
    )
    .await;
    assert_eq!(status_old_token, StatusCode::NOT_FOUND);
    assert!(old_token_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("not found or expired")));

    let (status_old_bundle, old_bundle_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/contact-invites/{first_token}/bundle"),
        json!({}),
    )
    .await;
    assert_eq!(status_old_bundle, StatusCode::NOT_FOUND);
    assert!(old_bundle_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("not found or expired")));

    let (status_resolve_second, resolve_second_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/contact-invites/{second_token}"),
        json!({}),
    )
    .await;
    assert_eq!(status_resolve_second, StatusCode::OK);
    assert_eq!(resolve_second_payload["user_id"].as_str(), Some("alice"));
    assert_eq!(
        resolve_second_payload["invite_token"].as_str(),
        Some(second_token.as_str())
    );
}

#[tokio::test]
async fn group_endpoints_are_disabled() {
    let app = test_app().await;
    let alice_sig = signing_key(141);
    let bob_sig = signing_key(142);
    let carol_sig = signing_key(143);

    let reg_alice = register_payload("alice", "alice-dev-1", [11u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let reg_bob = register_payload("bob", "bob-dev-1", [12u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_carol = register_payload("carol", "carol-dev-1", [13u8; 32], &carol_sig);
    let (status_carol, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_carol).await;
    assert_eq!(status_carol, StatusCode::OK);

    let initial_members = vec!["bob".to_string()];
    let create_group_body = json!({
        "group_id": "alpha",
        "member_user_ids": initial_members
    });
    let create_group_headers = groups_create_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "alpha",
        &initial_members,
    );
    let (status_create_group, create_group_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups",
        create_group_body,
        &create_group_headers,
    )
    .await;
    assert_eq!(status_create_group, StatusCode::FORBIDDEN);
    assert!(create_group_payload["detail"]
        .as_str()
        .unwrap_or("")
        .contains("private group design"));

    let list_bob_groups_headers = groups_list_auth_headers(&bob_sig, "bob", "bob-dev-1");
    let (status_bob_groups, bob_groups_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/bob/groups",
        json!({}),
        &list_bob_groups_headers,
    )
    .await;
    assert_eq!(status_bob_groups, StatusCode::FORBIDDEN);
    assert!(bob_groups_payload["detail"]
        .as_str()
        .unwrap_or("")
        .contains("group messaging is disabled"));

    let list_members_headers =
        groups_members_list_auth_headers(&bob_sig, "bob", "bob-dev-1", "alpha");
    let (status_list_members, list_members_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/groups/alpha/members",
        json!({}),
        &list_members_headers,
    )
    .await;
    assert_eq!(status_list_members, StatusCode::FORBIDDEN);
    assert!(list_members_payload["detail"]
        .as_str()
        .unwrap_or("")
        .contains("group messaging is disabled"));

    let add_member_body = json!({
        "member_user_id": "carol"
    });
    let add_member_headers =
        groups_members_add_auth_headers(&alice_sig, "alice", "alice-dev-1", "alpha", "carol");
    let (status_add_member, add_member_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/alpha/members/add",
        add_member_body,
        &add_member_headers,
    )
    .await;
    assert_eq!(status_add_member, StatusCode::FORBIDDEN);
    assert!(add_member_payload["detail"]
        .as_str()
        .unwrap_or("")
        .contains("group messaging is disabled"));

    let group_message_1 = b"group-message-1".to_vec();
    let group_message_1_b64 = B64.encode(&group_message_1);
    let group_message_1_carol = b"group-message-1-carol".to_vec();
    let group_message_1_carol_b64 = B64.encode(&group_message_1_carol);
    let relay_group_body_1 = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "recipients": [
            {
                "recipient_user_id": "bob",
                "message_bytes_base64": group_message_1_b64.clone()
            },
            {
                "recipient_user_id": "carol",
                "message_bytes_base64": group_message_1_carol_b64.clone()
            }
        ]
    });
    let relay_group_headers_1 = groups_relay_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "alpha",
        "alice",
        &[
            ("bob", group_message_1.as_slice()),
            ("carol", group_message_1_carol.as_slice()),
        ],
    );
    let (status_group_relay_1, group_relay_payload_1) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/alpha/relay",
        relay_group_body_1,
        &relay_group_headers_1,
    )
    .await;
    assert_eq!(status_group_relay_1, StatusCode::FORBIDDEN);
    assert!(group_relay_payload_1["detail"]
        .as_str()
        .unwrap_or("")
        .contains("group messaging is disabled"));

    let remove_member_body = json!({
        "member_user_id": "bob"
    });
    let remove_member_headers =
        groups_members_remove_auth_headers(&alice_sig, "alice", "alice-dev-1", "alpha", "bob");
    let (status_remove_member, remove_member_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/alpha/members/remove",
        remove_member_body,
        &remove_member_headers,
    )
    .await;
    assert_eq!(status_remove_member, StatusCode::FORBIDDEN);
    assert!(remove_member_payload["detail"]
        .as_str()
        .unwrap_or("")
        .contains("group messaging is disabled"));

    let group_message_2 = b"group-message-2".to_vec();
    let group_message_2_b64 = B64.encode(&group_message_2);
    let relay_group_body_2 = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "recipients": [
            {
                "recipient_user_id": "carol",
                "message_bytes_base64": group_message_2_b64.clone()
            }
        ]
    });
    let relay_group_headers_2 = groups_relay_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "alpha",
        "alice",
        &[("carol", group_message_2.as_slice())],
    );
    let (status_group_relay_2, group_relay_payload_2) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/alpha/relay",
        relay_group_body_2,
        &relay_group_headers_2,
    )
    .await;
    assert_eq!(status_group_relay_2, StatusCode::FORBIDDEN);
    assert!(group_relay_payload_2["detail"]
        .as_str()
        .unwrap_or("")
        .contains("group messaging is disabled"));
}

#[tokio::test]
async fn inbox_auth_compatibility_accepts_mobile_secondary_flows() {
    let app = test_app().await;
    let alice_sig = signing_key(181);
    let bob_sig = signing_key(182);

    let reg_alice = register_payload("alice", "alice-dev-1", [41u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let reg_bob = register_payload("bob", "bob-dev-1", [42u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let (status_create_group, create_group_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups",
        json!({
            "group_id": "compat-alpha",
            "member_user_ids": ["bob"]
        }),
        &inbox_auth_headers(&alice_sig, "alice", "alice-dev-1", 0),
    )
    .await;
    assert_eq!(status_create_group, StatusCode::FORBIDDEN);
    assert!(create_group_payload["detail"]
        .as_str()
        .unwrap_or("")
        .contains("group messaging is disabled"));

    let (status_contacts_upsert, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/contacts",
        json!({
            "contact_user_id": "bob",
            "alias": "B",
            "verified_by_qr": false
        }),
        &inbox_auth_headers(&alice_sig, "alice", "alice-dev-1", 0),
    )
    .await;
    assert_eq!(status_contacts_upsert, StatusCode::OK);

    let (status_contacts_list, contacts_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/contacts",
        json!({}),
        &inbox_auth_headers(&alice_sig, "alice", "alice-dev-1", 0),
    )
    .await;
    assert_eq!(status_contacts_list, StatusCode::OK);
    assert_eq!(
        contacts_payload["contacts"]
            .as_array()
            .map(|contacts| contacts.len()),
        Some(1)
    );

    let (status_presence_update, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/presence",
        json!({ "status": "online" }),
        &inbox_auth_headers(&alice_sig, "alice", "alice-dev-1", 0),
    )
    .await;
    assert_eq!(status_presence_update, StatusCode::FORBIDDEN);

    let (status_presence_get, presence_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/presence",
        json!({}),
        &inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0),
    )
    .await;
    assert_eq!(status_presence_get, StatusCode::FORBIDDEN);
    assert!(presence_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("presence is disabled")));

    let (status_typing_update, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/typing/bob",
        json!({ "is_typing": true }),
        &inbox_auth_headers(&alice_sig, "alice", "alice-dev-1", 0),
    )
    .await;
    assert_eq!(status_typing_update, StatusCode::FORBIDDEN);

    let (status_typing_get, typing_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/typing/bob",
        json!({}),
        &inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0),
    )
    .await;
    assert_eq!(status_typing_get, StatusCode::FORBIDDEN);
    assert!(typing_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("typing indicators are disabled")));

    let (status_receipt_send, receipt_send_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/receipts",
        json!({
            "message_id": 1,
            "receipt_type": "read"
        }),
        &[],
    )
    .await;
    assert_eq!(status_receipt_send, StatusCode::FORBIDDEN);
    assert!(receipt_send_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("read receipts are disabled")));

    let (status_receipts_get, receipts_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/receipts/poll",
        json!({}),
        &[],
    )
    .await;
    assert_eq!(status_receipts_get, StatusCode::FORBIDDEN);
    assert!(receipts_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("read receipts are disabled")));
}

#[tokio::test]
async fn sealed_sender_relay_and_inbox_flow() {
    let app = test_app().await;
    let bob_sig = signing_key(151);
    let alice_sig = signing_key(152);

    let reg_bob = register_payload("bob", "bob-dev-1", [31u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = register_payload("alice", "alice-dev-1", [32u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &bob_sig,
        [7u8; 32],
        vec![8u8; 32],
        vec![[9u8; 32]],
        vec![vec![10u8; 32]],
    );
    let publish_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_prekeys, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_prekeys, StatusCode::OK);

    let (status_bundle, bundle_payload) = json_request(
        app.clone(),
        Method::GET,
        "/v1/anon/users/bob/bundle",
        json!({}),
    )
    .await;
    assert_eq!(status_bundle, StatusCode::OK);
    assert_eq!(bundle_payload["user_id"].as_str(), Some("bob"));

    let sealed_blob = b"sealed-ciphertext-placeholder".to_vec();
    add_contact_for_delivery_access(app.clone(), &alice_sig, "alice", "alice-dev-1", "bob").await;
    let bob_delivery_token =
        fetch_sealed_delivery_token(app.clone(), &alice_sig, "alice", "alice-dev-1", "bob").await;
    let relay_body = json!({
        "delivery_token": bob_delivery_token,
        "message_bytes_base64": B64.encode(&sealed_blob)
    });
    let (status_relay, relay_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/sealed-relay/bob",
        relay_body,
    )
    .await;
    assert_eq!(status_relay, StatusCode::OK);
    assert_eq!(relay_payload["delivered_device_count"].as_u64(), Some(1));

    let sealed_inbox_headers = sealed_inbox_auth_headers(&bob_sig, "bob", "bob-dev-1", 0);
    let (status_inbox, inbox_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/sealed-inbox/bob?since=0",
        json!({}),
        &sealed_inbox_headers,
    )
    .await;
    assert_eq!(status_inbox, StatusCode::OK);
    let messages = inbox_payload["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1);
    let sealed_blob_b64 = B64.encode(&sealed_blob);
    assert_eq!(
        messages[0]["message_bytes_base64"].as_str(),
        Some(sealed_blob_b64.as_str())
    );
    assert!(messages[0].get("sender_user_id").is_none());
}

#[tokio::test]
async fn sealed_sender_rejects_wrong_delivery_token() {
    let app = test_app().await;
    let bob_sig = signing_key(153);
    let alice_sig = signing_key(154);
    let carol_sig = signing_key(155);

    let (status_bob, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        register_payload("bob", "bob-dev-1", [33u8; 32], &bob_sig),
    )
    .await;
    assert_eq!(status_bob, StatusCode::OK);

    let (status_alice, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        register_payload("alice", "alice-dev-1", [34u8; 32], &alice_sig),
    )
    .await;
    assert_eq!(status_alice, StatusCode::OK);

    let (status_carol, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        register_payload("carol", "carol-dev-1", [35u8; 32], &carol_sig),
    )
    .await;
    assert_eq!(status_carol, StatusCode::OK);

    add_contact_for_delivery_access(app.clone(), &alice_sig, "alice", "alice-dev-1", "carol").await;
    let carol_delivery_token =
        fetch_sealed_delivery_token(app.clone(), &alice_sig, "alice", "alice-dev-1", "carol").await;
    let (status_relay, relay_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/sealed-relay/bob",
        json!({
            "delivery_token": carol_delivery_token,
            "message_bytes_base64": B64.encode(b"sealed-ciphertext-placeholder"),
        }),
    )
    .await;
    assert_eq!(status_relay, StatusCode::FORBIDDEN);
    assert!(relay_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("invalid sealed delivery token")));
}

#[tokio::test]
async fn sealed_sender_uses_peer_ip_when_proxy_headers_are_untrusted() {
    let app = test_app_with_rate_limit_settings(1.0, 0.0).await;
    let bob_sig = signing_key(161);
    let carol_sig = signing_key(162);

    for (user_id, device_id, identity_bytes, signing_key, spk_seed, pq_seed) in [
        (
            "bob",
            "bob-dev-1",
            [41u8; 32],
            &bob_sig,
            [11u8; 32],
            vec![12u8; 32],
        ),
        (
            "carol",
            "carol-dev-1",
            [42u8; 32],
            &carol_sig,
            [13u8; 32],
            vec![14u8; 32],
        ),
    ] {
        let registration = register_payload(user_id, device_id, identity_bytes, signing_key);
        let (status_register, _) = json_request(
            app.clone(),
            Method::POST,
            "/v1/users/register",
            registration,
        )
        .await;
        assert_eq!(status_register, StatusCode::OK);

        let publish = publish_prekeys_payload(
            signing_key,
            spk_seed,
            pq_seed.clone(),
            vec![[15u8; 32]],
            vec![vec![16u8; 32]],
        );
        let publish_auth = prekeys_auth_headers(signing_key, user_id, device_id, &publish);
        let (status_prekeys, _) = json_request_with_headers(
            app.clone(),
            Method::POST,
            &format!("/v1/users/{user_id}/prekeys"),
            publish,
            &publish_auth,
        )
        .await;
        assert_eq!(status_prekeys, StatusCode::OK);
    }

    add_contact_for_delivery_access(app.clone(), &carol_sig, "carol", "carol-dev-1", "bob").await;
    let bob_delivery_token =
        fetch_sealed_delivery_token(app.clone(), &carol_sig, "carol", "carol-dev-1", "bob").await;
    add_contact_for_delivery_access(app.clone(), &bob_sig, "bob", "bob-dev-1", "carol").await;
    let carol_delivery_token =
        fetch_sealed_delivery_token(app.clone(), &bob_sig, "bob", "bob-dev-1", "carol").await;

    let (base_ws_url, server_handle) = spawn_http_server(app).await;
    let base_http_url = base_ws_url.replacen("ws://", "http://", 1);
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{base_http_url}/v1/sealed-relay/bob"))
        .header("x-forwarded-for", "203.0.113.10")
        .json(&json!({
            "delivery_token": bob_delivery_token,
            "message_bytes_base64": B64.encode("sealed-one")
        }))
        .send()
        .await
        .expect("first sealed relay");
    assert_eq!(first.status(), StatusCode::OK);

    let second = client
        .post(format!("{base_http_url}/v1/sealed-relay/carol"))
        .header("x-forwarded-for", "198.51.100.20")
        .json(&json!({
            "delivery_token": carol_delivery_token,
            "message_bytes_base64": B64.encode("sealed-two")
        }))
        .send()
        .await
        .expect("second sealed relay");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    server_handle.abort();
}

#[tokio::test]
async fn registration_requires_pow_when_enabled() {
    let app = test_app_with_dos_policy(
        DosHardeningPolicy::for_security_profile(SecurityProfile::Research)
            .with_registration_pow_bits(12),
    )
    .await;
    let bob_sig = signing_key(161);

    let base_register = register_payload("bob", "bob-dev-1", [71u8; 32], &bob_sig);
    let (status_missing_pow, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        base_register.clone(),
    )
    .await;
    assert_eq!(status_missing_pow, StatusCode::BAD_REQUEST);

    let solved = register_payload_with_pow(base_register, 12);
    let (status_with_pow, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", solved).await;
    assert_eq!(status_with_pow, StatusCode::OK);
}

#[tokio::test]
async fn prekey_publish_interval_throttles_immediate_reupload() {
    let app = test_app_with_dos_policy(
        DosHardeningPolicy::for_security_profile(SecurityProfile::Research)
            .with_prekey_publish_min_interval_seconds(3600),
    )
    .await;
    let bob_sig = signing_key(162);

    let reg_bob = register_payload("bob", "bob-dev-1", [72u8; 32], &bob_sig);
    let (status_reg, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_reg, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &bob_sig,
        [8u8; 32],
        vec![9u8; 64],
        vec![[10u8; 32], [11u8; 32]],
        vec![vec![12u8; 64], vec![13u8; 64]],
    );
    let publish_auth_1 = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_publish_1, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish.clone(),
        &publish_auth_1,
    )
    .await;
    assert_eq!(status_publish_1, StatusCode::OK);

    let publish_auth_2 = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_publish_2, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth_2,
    )
    .await;
    assert_eq!(status_publish_2, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn bundle_reserve_prevents_full_prekey_exhaustion() {
    let app = test_app_with_dos_policy(
        DosHardeningPolicy::for_security_profile(SecurityProfile::Research)
            .with_prekey_bundle_reserve_count(2),
    )
    .await;
    let bob_sig = signing_key(163);

    let reg_bob = register_payload("bob", "bob-dev-1", [73u8; 32], &bob_sig);
    let (status_reg, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_reg, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &bob_sig,
        [14u8; 32],
        vec![15u8; 64],
        vec![[16u8; 32], [17u8; 32], [18u8; 32]],
        vec![vec![19u8; 64], vec![20u8; 64], vec![21u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&bob_sig, "bob", "bob-dev-1", &publish);
    let (status_publish, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_publish, StatusCode::OK);

    let (status_bundle_1, bundle_1) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle_1, StatusCode::OK);
    assert!(bundle_1["one_time_prekey_x25519"].as_str().is_some());
    assert!(bundle_1["one_time_prekey_mlkem768"].as_str().is_some());
    assert_eq!(
        bundle_1["remaining_one_time_prekeys_x25519"].as_u64(),
        Some(2)
    );
    assert_eq!(
        bundle_1["remaining_one_time_prekeys_mlkem768"].as_u64(),
        Some(2)
    );

    let (status_bundle_2, bundle_2) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle_2, StatusCode::OK);
    assert!(bundle_2["one_time_prekey_x25519"].is_null());
    assert!(bundle_2["one_time_prekey_mlkem768"].is_null());
    assert_eq!(
        bundle_2["remaining_one_time_prekeys_x25519"].as_u64(),
        Some(2)
    );
    assert_eq!(
        bundle_2["remaining_one_time_prekeys_mlkem768"].as_u64(),
        Some(2)
    );
    assert_eq!(bundle_2["last_resort_prekey_only"].as_bool(), Some(true));
}

#[tokio::test]
async fn rich_media_profile_and_disabled_metadata_signals_flow() {
    let app = test_app().await;
    let alice_sig = signing_key(171);
    let bob_sig = signing_key(172);
    let carol_sig = signing_key(173);

    let reg_alice = register_payload("alice", "alice-dev-1", [81u8; 32], &alice_sig);
    let reg_bob = register_payload("bob", "bob-dev-1", [82u8; 32], &bob_sig);
    let reg_carol = register_payload("carol", "carol-dev-1", [83u8; 32], &carol_sig);
    let (status_reg_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_reg_alice, StatusCode::OK);
    let (status_reg_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_reg_bob, StatusCode::OK);
    let (status_reg_carol, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_carol).await;
    assert_eq!(status_reg_carol, StatusCode::OK);

    let file_blob = b"opaque-encrypted-media".to_vec();
    let mime_type = "application/octet-stream";
    let upload_body = json!({
        "recipient_user_id": "bob",
        "device_id": "alice-dev-1",
        "mime_type": mime_type,
        "file_bytes_base64": B64.encode(&file_blob)
    });
    let upload_headers = files_upload_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        &file_blob,
        mime_type,
    );
    let (status_upload, upload_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/files/upload",
        upload_body,
        &upload_headers,
    )
    .await;
    assert_eq!(status_upload, StatusCode::OK);
    let file_id = upload_payload["file_id"].as_str().expect("file_id");

    let bob_download_headers = files_download_auth_headers(&bob_sig, "bob", "bob-dev-1", file_id);
    let (status_download_bob, download_payload_bob) = json_request_with_headers(
        app.clone(),
        Method::GET,
        &format!("/v1/files/{file_id}"),
        json!({}),
        &bob_download_headers,
    )
    .await;
    assert_eq!(status_download_bob, StatusCode::OK);
    assert_eq!(
        download_payload_bob["file_bytes_base64"].as_str(),
        Some(B64.encode(&file_blob).as_str())
    );

    let carol_download_headers =
        files_download_auth_headers(&carol_sig, "carol", "carol-dev-1", file_id);
    let (status_download_carol, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        &format!("/v1/files/{file_id}"),
        json!({}),
        &carol_download_headers,
    )
    .await;
    assert_eq!(status_download_carol, StatusCode::NOT_FOUND);

    let avatar = vec![1u8, 2, 3, 4];
    let profile_body = json!({
        "display_name": "Alice Example",
        "username": "alice.secure",
        "avatar_mime": "image/png",
        "avatar_bytes_base64": B64.encode(&avatar)
    });
    let profile_headers = profile_upsert_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "alice",
        Some("Alice Example"),
        Some("alice.secure"),
        true,
        Some("image/png"),
        Some(&avatar),
    );
    let (status_profile_upsert, profile_upsert_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/profile",
        profile_body,
        &profile_headers,
    )
    .await;
    assert_eq!(status_profile_upsert, StatusCode::OK);
    assert_eq!(
        profile_upsert_payload["display_name"].as_str(),
        Some("Alice Example")
    );
    assert_eq!(
        profile_upsert_payload["username"].as_str(),
        Some("alice.secure")
    );

    let profile_get_headers = profile_get_auth_headers(&bob_sig, "bob", "bob-dev-1", "alice");
    let (status_profile_get, profile_get_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/profile",
        json!({}),
        &profile_get_headers,
    )
    .await;
    assert_eq!(status_profile_get, StatusCode::OK);
    assert!(profile_get_payload["display_name"].is_null());
    assert!(profile_get_payload["username"].is_null());
    assert!(profile_get_payload["avatar_bytes_base64"].is_null());
    assert!(profile_get_payload["sealed_delivery_token"].is_null());

    add_contact_for_delivery_access(app.clone(), &bob_sig, "bob", "bob-dev-1", "alice").await;
    let profile_get_after_contact_headers =
        profile_get_auth_headers(&bob_sig, "bob", "bob-dev-1", "alice");
    let (status_profile_get_after_contact, profile_get_after_contact_payload) =
        json_request_with_headers(
            app.clone(),
            Method::GET,
            "/v1/users/alice/profile",
            json!({}),
            &profile_get_after_contact_headers,
        )
        .await;
    assert_eq!(status_profile_get_after_contact, StatusCode::OK);
    assert_eq!(
        profile_get_after_contact_payload["display_name"].as_str(),
        Some("Alice Example")
    );
    assert_eq!(
        profile_get_after_contact_payload["username"].as_str(),
        Some("alice.secure")
    );
    assert_eq!(
        profile_get_after_contact_payload["avatar_bytes_base64"].as_str(),
        Some(B64.encode(avatar).as_str())
    );
    assert!(profile_get_after_contact_payload["sealed_delivery_token"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));

    let presence_update_headers =
        presence_update_auth_headers(&alice_sig, "alice", "alice-dev-1", "alice", "online");
    let (status_presence_update, presence_update_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/presence",
        json!({ "status": "online" }),
        &presence_update_headers,
    )
    .await;
    assert_eq!(status_presence_update, StatusCode::FORBIDDEN);
    assert!(presence_update_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("presence is disabled")));

    let presence_get_headers = presence_get_auth_headers(&bob_sig, "bob", "bob-dev-1", "alice");
    let (status_presence_get, presence_get_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/presence",
        json!({}),
        &presence_get_headers,
    )
    .await;
    assert_eq!(status_presence_get, StatusCode::FORBIDDEN);
    assert!(presence_get_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("presence is disabled")));

    let typing_on_headers =
        typing_update_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", true);
    let (status_typing_on, typing_on_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/typing/bob",
        json!({ "is_typing": true }),
        &typing_on_headers,
    )
    .await;
    assert_eq!(status_typing_on, StatusCode::FORBIDDEN);
    assert!(typing_on_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("typing indicators are disabled")));

    let typing_get_headers = typing_get_auth_headers(&bob_sig, "bob", "bob-dev-1", "bob");
    let (status_typing_get, typing_get_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/typing/bob",
        json!({}),
        &typing_get_headers,
    )
    .await;
    assert_eq!(status_typing_get, StatusCode::FORBIDDEN);
    assert!(typing_get_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("typing indicators are disabled")));

    let typing_off_headers =
        typing_update_auth_headers(&alice_sig, "alice", "alice-dev-1", "bob", false);
    let (status_typing_off, typing_off_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/typing/bob",
        json!({ "is_typing": false }),
        &typing_off_headers,
    )
    .await;
    assert_eq!(status_typing_off, StatusCode::FORBIDDEN);
    assert!(typing_off_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("typing indicators are disabled")));

    let typing_get_headers_after_off = typing_get_auth_headers(&bob_sig, "bob", "bob-dev-1", "bob");
    let (status_typing_get_after_off, typing_get_payload_after_off) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/typing/bob",
        json!({}),
        &typing_get_headers_after_off,
    )
    .await;
    assert_eq!(status_typing_get_after_off, StatusCode::FORBIDDEN);
    assert!(typing_get_payload_after_off["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("typing indicators are disabled")));
}

#[tokio::test]
async fn profile_usernames_round_trip_and_enforce_uniqueness() {
    let app = test_app().await;
    let alice_sig = signing_key(181);
    let bob_sig = signing_key(182);

    let reg_alice = register_payload("alice", "alice-dev-1", [91u8; 32], &alice_sig);
    let reg_bob = register_payload("bob", "bob-dev-1", [92u8; 32], &bob_sig);
    let (status_reg_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_reg_alice, StatusCode::OK);
    let (status_reg_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_reg_bob, StatusCode::OK);

    let publish = publish_prekeys_payload(
        &alice_sig,
        [93u8; 32],
        vec![94u8; 64],
        vec![[95u8; 32]],
        vec![vec![96u8; 64]],
    );
    let publish_auth = prekeys_auth_headers(&alice_sig, "alice", "alice-dev-1", &publish);
    let (status_publish, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/prekeys",
        publish,
        &publish_auth,
    )
    .await;
    assert_eq!(status_publish, StatusCode::OK);

    let alice_headers = profile_upsert_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "alice",
        Some("Alice"),
        Some("@Alice.Secure"),
        true,
        None,
        None,
    );
    let (status_profile_upsert, profile_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/profile",
        json!({
            "display_name": "Alice",
            "username": "@Alice.Secure"
        }),
        &alice_headers,
    )
    .await;
    assert_eq!(status_profile_upsert, StatusCode::OK);
    assert_eq!(profile_payload["username"].as_str(), Some("alice.secure"));
    assert_eq!(
        profile_payload["username_lookup_enabled"].as_bool(),
        Some(true)
    );

    let alice_get_headers = profile_get_auth_headers(&alice_sig, "alice", "alice-dev-1", "alice");
    let (status_profile_get, profile_get_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/profile",
        json!({}),
        &alice_get_headers,
    )
    .await;
    assert_eq!(status_profile_get, StatusCode::OK);
    assert_eq!(
        profile_get_payload["username"].as_str(),
        Some("alice.secure")
    );
    assert_eq!(
        profile_get_payload["username_lookup_enabled"].as_bool(),
        Some(true)
    );

    let bob_get_headers = profile_get_auth_headers(&bob_sig, "bob", "bob-dev-1", "alice");
    let (status_bob_profile_get, bob_profile_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/profile",
        json!({}),
        &bob_get_headers,
    )
    .await;
    assert_eq!(status_bob_profile_get, StatusCode::OK);
    assert!(bob_profile_payload["username"].is_null());
    assert!(bob_profile_payload["display_name"].is_null());

    let (status_lookup, lookup_payload) = json_request(
        app.clone(),
        Method::GET,
        "/v1/usernames/Alice.Secure",
        json!({}),
    )
    .await;
    assert_eq!(status_lookup, StatusCode::OK);
    assert_eq!(lookup_payload["username"].as_str(), Some("alice.secure"));
    assert_eq!(lookup_payload["user_id"].as_str(), Some("alice"));

    let (status_bundle_lookup, bundle_lookup_payload) = json_request(
        app.clone(),
        Method::GET,
        "/v1/usernames/alice.secure/bundle",
        json!({}),
    )
    .await;
    assert_eq!(status_bundle_lookup, StatusCode::OK);
    assert_eq!(bundle_lookup_payload["user_id"].as_str(), Some("alice"));
    assert!(bundle_lookup_payload["identity_x25519_pub"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));

    let hidden_headers = profile_upsert_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "alice",
        Some("Alice"),
        Some("alice.secure"),
        false,
        None,
        None,
    );
    let (status_hidden_update, hidden_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/profile",
        json!({
            "display_name": "Alice",
            "username": "alice.secure",
            "username_lookup_enabled": false
        }),
        &hidden_headers,
    )
    .await;
    assert_eq!(status_hidden_update, StatusCode::OK);
    assert_eq!(
        hidden_payload["username_lookup_enabled"].as_bool(),
        Some(false)
    );

    let (status_hidden_lookup, hidden_lookup_payload) = json_request(
        app.clone(),
        Method::GET,
        "/v1/usernames/Alice.Secure",
        json!({}),
    )
    .await;
    assert_eq!(status_hidden_lookup, StatusCode::NOT_FOUND);
    assert_eq!(hidden_lookup_payload["status"].as_u64(), Some(404));

    let (status_hidden_bundle, hidden_bundle_payload) = json_request(
        app.clone(),
        Method::GET,
        "/v1/usernames/alice.secure/bundle",
        json!({}),
    )
    .await;
    assert_eq!(status_hidden_bundle, StatusCode::NOT_FOUND);
    assert_eq!(hidden_bundle_payload["status"].as_u64(), Some(404));

    let bob_headers = profile_upsert_auth_headers(
        &bob_sig,
        "bob",
        "bob-dev-1",
        "bob",
        Some("Bob"),
        Some("alice.secure"),
        true,
        None,
        None,
    );
    let (status_bob_profile, bob_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/profile",
        json!({
            "display_name": "Bob",
            "username": "alice.secure"
        }),
        &bob_headers,
    )
    .await;
    assert_eq!(status_bob_profile, StatusCode::CONFLICT);
    assert!(bob_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("username is already claimed")));
}

#[tokio::test]
async fn rich_media_profile_and_disabled_metadata_signals_reject_before_input_validation() {
    let app = test_app().await;
    let alice_sig = signing_key(174);
    let bob_sig = signing_key(175);

    let reg_alice = register_payload("alice", "alice-dev-1", [84u8; 32], &alice_sig);
    let reg_bob = register_payload("bob", "bob-dev-1", [85u8; 32], &bob_sig);
    let (status_reg_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_reg_alice, StatusCode::OK);
    let (status_reg_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_reg_bob, StatusCode::OK);

    let bad_mime = "not-a-mime";
    let file_blob = b"opaque-bytes".to_vec();
    let upload_body = json!({
        "recipient_user_id": "bob",
        "device_id": "alice-dev-1",
        "mime_type": bad_mime,
        "file_bytes_base64": B64.encode(&file_blob)
    });
    let upload_headers = files_upload_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        &file_blob,
        bad_mime,
    );
    let (status_upload, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/files/upload",
        upload_body,
        &upload_headers,
    )
    .await;
    assert_eq!(status_upload, StatusCode::BAD_REQUEST);

    let profile_headers = profile_upsert_auth_headers(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "alice",
        Some("Alice"),
        None,
        false,
        Some("image/png"),
        None,
    );
    let (status_profile, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/profile",
        json!({
            "display_name": "Alice",
            "avatar_mime": "image/png"
        }),
        &profile_headers,
    )
    .await;
    assert_eq!(status_profile, StatusCode::BAD_REQUEST);

    let typing_headers =
        typing_update_auth_headers(&alice_sig, "alice", "alice-dev-1", "alice", true);
    let (status_typing_self, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/typing/alice",
        json!({"is_typing": true}),
        &typing_headers,
    )
    .await;
    assert_eq!(status_typing_self, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn encrypted_backups_roundtrip_and_replace_latest_blob() {
    let app = test_app().await;
    let alice_sig = signing_key(14);
    let alice_x = [14u8; 32];

    let (status_register, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        register_payload("alice", "alice-dev-1", alice_x, &alice_sig),
    )
    .await;
    assert_eq!(status_register, StatusCode::OK);

    let first_backup = b"encrypted-backup-v1";
    let first_upload_headers =
        backup_upload_auth_headers(&alice_sig, "alice", "alice-dev-1", 1, first_backup);
    let (status_first_upload, first_upload_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/backups",
        json!({
            "device_id": "alice-dev-1",
            "backup_version": 1,
            "recovery_hint": "first-device",
            "encrypted_backup_bytes_base64": B64.encode(first_backup),
        }),
        &first_upload_headers,
    )
    .await;
    assert_eq!(status_first_upload, StatusCode::OK);
    assert_eq!(first_upload_payload["backup_version"].as_i64(), Some(1));
    assert_eq!(
        first_upload_payload["byte_len"].as_u64(),
        Some(first_backup.len() as u64)
    );

    let second_backup = b"encrypted-backup-v2";
    let second_backup_b64 = B64.encode(second_backup);
    let second_upload_headers =
        backup_upload_auth_headers(&alice_sig, "alice", "alice-dev-1", 2, second_backup);
    let (status_second_upload, second_upload_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice/backups",
        json!({
            "device_id": "alice-dev-1",
            "backup_version": 2,
            "recovery_hint": "replacement",
            "encrypted_backup_bytes_base64": B64.encode(second_backup),
        }),
        &second_upload_headers,
    )
    .await;
    assert_eq!(status_second_upload, StatusCode::OK);
    assert_eq!(second_upload_payload["backup_version"].as_i64(), Some(2));

    let download_headers = backup_download_auth_headers(&alice_sig, "alice", "alice-dev-1");
    let (status_download, download_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice/backups/latest",
        json!({}),
        &download_headers,
    )
    .await;
    assert_eq!(status_download, StatusCode::OK);
    assert_eq!(download_payload["backup_version"].as_i64(), Some(2));
    assert_eq!(
        download_payload["recovery_hint"].as_str(),
        Some("replacement")
    );
    assert_eq!(
        download_payload["encrypted_backup_bytes_base64"].as_str(),
        Some(second_backup_b64.as_str())
    );
}

#[tokio::test]
async fn encrypted_backups_roundtrip_and_replace_latest_version() {
    let app = test_app().await;
    let alice_sig = signing_key(176);

    let reg_alice = register_payload("alice-backup", "alice-backup-dev", [86u8; 32], &alice_sig);
    let (status_reg_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_reg_alice, StatusCode::OK);

    let backup_v1 = vec![0x01, 0x02, 0x03, 0x04];
    let upload_v1_headers = backup_upload_auth_headers(
        &alice_sig,
        "alice-backup",
        "alice-backup-dev",
        1,
        &backup_v1,
    );
    let (status_upload_v1, upload_v1_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice-backup/backups",
        json!({
            "device_id": "alice-backup-dev",
            "backup_version": 1,
            "recovery_hint": "local test hint",
            "encrypted_backup_bytes_base64": B64.encode(&backup_v1),
        }),
        &upload_v1_headers,
    )
    .await;
    assert_eq!(status_upload_v1, StatusCode::OK);
    assert_eq!(upload_v1_payload["backup_version"].as_i64(), Some(1));
    assert_eq!(
        upload_v1_payload["byte_len"].as_u64(),
        Some(backup_v1.len() as u64)
    );

    let download_headers =
        backup_download_auth_headers(&alice_sig, "alice-backup", "alice-backup-dev");
    let (status_download_v1, download_v1_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice-backup/backups/latest",
        json!({}),
        &download_headers,
    )
    .await;
    assert_eq!(status_download_v1, StatusCode::OK);
    assert_eq!(download_v1_payload["backup_version"].as_i64(), Some(1));
    assert_eq!(
        download_v1_payload["encrypted_backup_bytes_base64"].as_str(),
        Some(B64.encode(&backup_v1).as_str())
    );

    let backup_v2 = vec![0x05, 0x06, 0x07, 0x08, 0x09];
    let upload_v2_headers = backup_upload_auth_headers(
        &alice_sig,
        "alice-backup",
        "alice-backup-dev",
        2,
        &backup_v2,
    );
    let (status_upload_v2, upload_v2_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/alice-backup/backups",
        json!({
            "device_id": "alice-backup-dev",
            "backup_version": 2,
            "recovery_hint": "replacement",
            "encrypted_backup_bytes_base64": B64.encode(&backup_v2),
        }),
        &upload_v2_headers,
    )
    .await;
    assert_eq!(status_upload_v2, StatusCode::OK);
    assert_eq!(upload_v2_payload["backup_version"].as_i64(), Some(2));

    let download_v2_headers =
        backup_download_auth_headers(&alice_sig, "alice-backup", "alice-backup-dev");
    let (status_download_v2, download_v2_payload) = json_request_with_headers(
        app,
        Method::GET,
        "/v1/users/alice-backup/backups/latest",
        json!({}),
        &download_v2_headers,
    )
    .await;
    assert_eq!(status_download_v2, StatusCode::OK);
    assert_eq!(download_v2_payload["backup_version"].as_i64(), Some(2));
    assert_eq!(
        download_v2_payload["encrypted_backup_bytes_base64"].as_str(),
        Some(B64.encode(&backup_v2).as_str())
    );
    assert_eq!(
        download_v2_payload["recovery_hint"].as_str(),
        Some("replacement")
    );
}

// ---------------------------------------------------------------------------
// Phase 2 — Test Coverage Expansion
// ---------------------------------------------------------------------------

/// Build a test app with a custom rate-limiter (low capacity for saturation tests).
async fn test_app_with_rate_limiter(rate_limiter: Arc<RateLimiter>) -> axum::Router {
    sqlx::any::install_default_drivers();
    let database_url = "sqlite::memory:";
    let db_backend = parse_db_backend(database_url).expect("sqlite backend");
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .expect("connect sqlite memory");
    init_db(&pool, db_backend).await.expect("migrate");
    let state = AppState::new(pool, db_backend, rate_limiter);
    build_router(state)
}

/// Helper: build relay auth headers with a *custom* timestamp (for clock-skew tests).
fn relay_auth_headers_with_timestamp(
    signing_key: &SigningKey,
    sender_user_id: &str,
    sender_device_id: &str,
    recipient_user_id: &str,
    message_blob: &[u8],
    timestamp: i64,
) -> Vec<(&'static str, String)> {
    let nonce = format!(
        "relay-skew-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records =
        auth_common_records("relay", sender_user_id, sender_device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_MESSAGE_BLOB,
        value: message_blob.to_vec(),
    });
    let message = encode(&records).expect("relay auth transcript");
    let signature = signing_key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, sender_user_id.to_string()),
        (AUTH_HEADER_DEVICE, sender_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

// ---- 1. Auth timestamp / clock-skew rejection ----------------------------

#[tokio::test]
async fn auth_rejects_stale_and_future_timestamps() {
    let app = test_app_with_authenticated_dm_compat().await;
    let alice_sig = signing_key(200);
    let bob_sig = signing_key(201);

    // Register both users
    let reg_alice = register_payload("alice", "alice-dev-1", [41u8; 32], &alice_sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(s, StatusCode::OK);

    let reg_bob = register_payload("bob", "bob-dev-1", [42u8; 32], &bob_sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(s, StatusCode::OK);

    let relay = json!({
        "sender_user_id": "alice",
        "device_id": "alice-dev-1",
        "message_bytes_base64": B64.encode("clock-test")
    });

    // Stale timestamp: 10 minutes in the past (skew limit is 300 s)
    let stale_ts = Utc::now().timestamp() - 600;
    let stale_headers = relay_auth_headers_with_timestamp(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"clock-test",
        stale_ts,
    );
    let (status_stale, body_stale) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay.clone(),
        &stale_headers,
    )
    .await;
    assert_eq!(status_stale, StatusCode::BAD_REQUEST);
    assert!(
        body_stale["detail"]
            .as_str()
            .unwrap_or("")
            .contains("timestamp"),
        "stale body should mention timestamp: {body_stale}"
    );

    // Future timestamp: 10 minutes ahead
    let future_ts = Utc::now().timestamp() + 600;
    let future_headers = relay_auth_headers_with_timestamp(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"clock-test",
        future_ts,
    );
    let (status_future, body_future) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay.clone(),
        &future_headers,
    )
    .await;
    assert_eq!(status_future, StatusCode::BAD_REQUEST);
    assert!(
        body_future["detail"]
            .as_str()
            .unwrap_or("")
            .contains("timestamp"),
        "future body should mention timestamp: {body_future}"
    );

    // Just inside the window (4 minutes ago, limit is 5 min) → should succeed
    let ok_ts = Utc::now().timestamp() - 240;
    let ok_headers = relay_auth_headers_with_timestamp(
        &alice_sig,
        "alice",
        "alice-dev-1",
        "bob",
        b"clock-test",
        ok_ts,
    );
    let (status_ok, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay,
        &ok_headers,
    )
    .await;
    assert_eq!(status_ok, StatusCode::OK);
}

// ---- 2. Group owner-only enforcement -------------------------------------

#[tokio::test]
async fn group_member_mutation_endpoints_are_disabled_before_owner_checks() {
    let app = test_app().await;
    let alice_sig = signing_key(210);
    let bob_sig = signing_key(211);
    let carol_sig = signing_key(212);

    // Register alice, bob, carol
    for (name, dev, seed, sig) in [
        ("alice", "alice-dev-1", [51u8; 32], &alice_sig),
        ("bob", "bob-dev-1", [52u8; 32], &bob_sig),
        ("carol", "carol-dev-1", [53u8; 32], &carol_sig),
    ] {
        let reg = register_payload(name, dev, seed, sig);
        let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
        assert_eq!(s, StatusCode::OK);
    }

    // Alice creates group "beta" with bob
    let members = vec!["bob".to_string()];
    let headers = groups_create_auth_headers(&alice_sig, "alice", "alice-dev-1", "beta", &members);
    let (s, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups",
        json!({"group_id": "beta", "member_user_ids": members}),
        &headers,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Bob (non-owner) tries to add carol → should fail
    let add_headers =
        groups_members_add_auth_headers(&bob_sig, "bob", "bob-dev-1", "beta", "carol");
    let (status_add, body_add) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/beta/members/add",
        json!({"member_user_id": "carol"}),
        &add_headers,
    )
    .await;
    assert_eq!(status_add, StatusCode::FORBIDDEN);
    assert!(
        body_add["detail"]
            .as_str()
            .unwrap_or("")
            .contains("group messaging is disabled"),
        "group add should fail before owner checks: {body_add}"
    );

    // Bob (non-owner) tries to remove alice → should fail
    let remove_headers =
        groups_members_remove_auth_headers(&bob_sig, "bob", "bob-dev-1", "beta", "alice");
    let (status_remove, body_remove) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/beta/members/remove",
        json!({"member_user_id": "alice"}),
        &remove_headers,
    )
    .await;
    assert_eq!(status_remove, StatusCode::FORBIDDEN);
    assert!(
        body_remove["detail"]
            .as_str()
            .unwrap_or("")
            .contains("group messaging is disabled"),
        "group remove should fail before owner checks: {body_remove}"
    );

    // Owner cannot remove themselves
    let self_remove_headers =
        groups_members_remove_auth_headers(&alice_sig, "alice", "alice-dev-1", "beta", "alice");
    let (status_self, body_self) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/beta/members/remove",
        json!({"member_user_id": "alice"}),
        &self_remove_headers,
    )
    .await;
    assert_eq!(status_self, StatusCode::FORBIDDEN);
    assert!(
        body_self["detail"]
            .as_str()
            .unwrap_or("")
            .contains("group messaging is disabled"),
        "group remove should fail before owner checks: {body_self}"
    );

    // Owner (alice) CAN add carol — sanity check
    let owner_add_headers =
        groups_members_add_auth_headers(&alice_sig, "alice", "alice-dev-1", "beta", "carol");
    let (status_owner_add, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups/beta/members/add",
        json!({"member_user_id": "carol"}),
        &owner_add_headers,
    )
    .await;
    assert_eq!(status_owner_add, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn private_group_state_bootstrap_publish_and_fetch_work() {
    let app = test_app().await;
    let admin = private_group_member_fixture(10, true);
    let member = private_group_member_fixture(20, false);

    let publish_body = json!({
        "group_id": "private-group-alpha",
        "epoch": 1,
        "state_commitment_sha256": sha256_hex(b"private-group-alpha-state-v1"),
        "ciphertext_nonce_base64": B64.encode([7u8; 12]),
        "ciphertext_base64": B64.encode(b"encrypted-private-group-state-v1"),
        "ciphertext_aad_base64": B64.encode(b"private-group-aad-v1"),
        "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
        "authorizing_publish_key_base64": admin
            .publish_key_base64
            .clone()
            .expect("admin publish key"),
        "members": [admin.record.clone(), member.record.clone()],
    });
    let (publish_status, publish_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        publish_body,
    )
    .await;
    assert_eq!(publish_status, StatusCode::OK);
    assert_eq!(
        publish_payload["group_id"].as_str(),
        Some("private-group-alpha")
    );
    assert_eq!(publish_payload["epoch"].as_u64(), Some(1));
    assert_eq!(publish_payload["stored_member_count"].as_u64(), Some(2));

    let fetch_body = json!({
        "membership_handle_sha256": member.membership_handle_sha256,
        "fetch_key_base64": member.fetch_key_base64,
    });
    let (fetch_status, fetch_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/fetch",
        fetch_body,
    )
    .await;
    assert_eq!(fetch_status, StatusCode::OK);
    assert_eq!(
        fetch_payload["group_id"].as_str(),
        Some("private-group-alpha")
    );
    assert_eq!(fetch_payload["epoch"].as_u64(), Some(1));
    assert_eq!(
        fetch_payload["state_commitment_sha256"].as_str(),
        Some(sha256_hex(b"private-group-alpha-state-v1").as_str())
    );
    assert_eq!(
        fetch_payload["ciphertext_base64"].as_str(),
        Some(B64.encode(b"encrypted-private-group-state-v1").as_str())
    );
}

#[tokio::test]
async fn private_group_state_epoch_rotation_revokes_old_handles() {
    let app = test_app().await;
    let admin_v1 = private_group_member_fixture(30, true);
    let member_v1 = private_group_member_fixture(31, false);
    let admin_v2 = private_group_member_fixture(40, true);
    let member_v2 = private_group_member_fixture(41, false);

    let (publish_v1_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-rotation",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-rotation-v1"),
            "ciphertext_nonce_base64": B64.encode([8u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-rotation-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-rotation-aad-v1"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1
                .publish_key_base64
                .clone()
                .expect("admin v1 publish key"),
            "members": [admin_v1.record.clone(), member_v1.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_v1_status, StatusCode::OK);

    let (publish_v2_status, publish_v2_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-rotation",
            "epoch": 2,
            "state_commitment_sha256": sha256_hex(b"private-group-rotation-v2"),
            "ciphertext_nonce_base64": B64.encode([9u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-rotation-v2"),
            "ciphertext_aad_base64": B64.encode(b"private-group-rotation-aad-v2"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1
                .publish_key_base64
                .clone()
                .expect("admin v1 publish key"),
            "members": [admin_v2.record.clone(), member_v2.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_v2_status, StatusCode::OK);
    assert_eq!(publish_v2_payload["epoch"].as_u64(), Some(2));

    let (old_fetch_status, old_fetch_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/fetch",
        json!({
            "membership_handle_sha256": member_v1.membership_handle_sha256,
            "fetch_key_base64": member_v1.fetch_key_base64,
        }),
    )
    .await;
    assert_eq!(old_fetch_status, StatusCode::NOT_FOUND);
    assert_eq!(
        old_fetch_payload["detail"].as_str(),
        Some("private group state not found")
    );

    let (new_fetch_status, new_fetch_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/fetch",
        json!({
            "membership_handle_sha256": member_v2.membership_handle_sha256,
            "fetch_key_base64": member_v2.fetch_key_base64,
        }),
    )
    .await;
    assert_eq!(new_fetch_status, StatusCode::OK);
    assert_eq!(new_fetch_payload["epoch"].as_u64(), Some(2));
    assert_eq!(
        new_fetch_payload["ciphertext_base64"].as_str(),
        Some(B64.encode(b"encrypted-private-group-rotation-v2").as_str())
    );
}

#[tokio::test]
async fn private_group_state_rejects_invalid_publish_and_fetch_capabilities() {
    let app = test_app().await;
    let admin_v1 = private_group_member_fixture(50, true);
    let member_v1 = private_group_member_fixture(51, false);

    let (publish_v1_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-invalid-capability",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-invalid-capability-v1"),
            "ciphertext_nonce_base64": B64.encode([10u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-invalid-capability-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-invalid-capability-aad-v1"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1
                .publish_key_base64
                .clone()
                .expect("admin v1 publish key"),
            "members": [admin_v1.record.clone(), member_v1.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_v1_status, StatusCode::OK);

    let (bad_publish_status, bad_publish_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-invalid-capability",
            "epoch": 2,
            "state_commitment_sha256": sha256_hex(b"private-group-invalid-capability-v2"),
            "ciphertext_nonce_base64": B64.encode([11u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-invalid-capability-v2"),
            "ciphertext_aad_base64": B64.encode(b"private-group-invalid-capability-aad-v2"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": B64.encode([0xFFu8; 32]),
            "members": [private_group_member_fixture(52, true).record, private_group_member_fixture(53, false).record],
        }),
    )
    .await;
    assert_eq!(bad_publish_status, StatusCode::FORBIDDEN);
    assert_eq!(
        bad_publish_payload["detail"].as_str(),
        Some("authorizing private group publish key is invalid")
    );

    let (bad_fetch_status, bad_fetch_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/fetch",
        json!({
            "membership_handle_sha256": member_v1.membership_handle_sha256,
            "fetch_key_base64": B64.encode([0xEEu8; 32]),
        }),
    )
    .await;
    assert_eq!(bad_fetch_status, StatusCode::FORBIDDEN);
    assert_eq!(
        bad_fetch_payload["detail"].as_str(),
        Some("private group fetch credential is invalid")
    );
}

#[tokio::test]
async fn private_group_invite_create_and_resolve_work() {
    let app = test_app().await;
    let admin = private_group_member_fixture(60, true);
    let member = private_group_member_fixture(61, false);

    let (publish_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-invite-alpha",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-invite-alpha-state-v1"),
            "ciphertext_nonce_base64": B64.encode([12u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-invite-alpha-state-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-invite-alpha-aad-v1"),
            "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
            "authorizing_publish_key_base64": admin.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin.record.clone(), member.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_status, StatusCode::OK);

    let invite_commitment = sha256_hex(b"opaque-private-group-join-package-v1");
    let invite_blob = B64.encode(b"opaque-private-group-join-package-v1");
    let (create_status, create_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/invites",
        json!({
            "group_id": "private-group-invite-alpha",
            "epoch": 1,
            "invite_commitment_sha256": invite_commitment,
            "invite_ciphertext_nonce_base64": B64.encode([13u8; 12]),
            "invite_ciphertext_base64": invite_blob,
            "invite_ciphertext_aad_base64": B64.encode(b"private-group-invite-envelope-aad"),
            "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
            "authorizing_publish_key_base64": admin.publish_key_base64.clone().expect("admin publish key"),
            "expires_in_seconds": 3600,
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::OK);
    let invite_token = create_payload["invite_token"]
        .as_str()
        .expect("invite token")
        .to_string();
    assert_eq!(
        create_payload["group_id"].as_str(),
        Some("private-group-invite-alpha")
    );
    assert_eq!(create_payload["epoch"].as_u64(), Some(1));

    let (resolve_status, resolve_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/private-groups/invites/{invite_token}"),
        json!({}),
    )
    .await;
    assert_eq!(resolve_status, StatusCode::OK);
    assert_eq!(
        resolve_payload["invite_token"].as_str(),
        Some(invite_token.as_str())
    );
    assert_eq!(
        resolve_payload["invite_commitment_sha256"].as_str(),
        Some(invite_commitment.as_str())
    );
    assert_eq!(
        resolve_payload["invite_ciphertext_base64"].as_str(),
        Some(invite_blob.as_str())
    );
}

#[tokio::test]
async fn private_group_invite_consume_revokes_token() {
    let app = test_app().await;
    let admin = private_group_member_fixture(62, true);
    let member = private_group_member_fixture(63, false);

    let (publish_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-invite-consume",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-invite-consume-v1"),
            "ciphertext_nonce_base64": B64.encode([19u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-invite-consume-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-invite-consume-aad-v1"),
            "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
            "authorizing_publish_key_base64": admin.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin.record.clone(), member.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_status, StatusCode::OK);

    let (create_status, create_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/invites",
        json!({
            "group_id": "private-group-invite-consume",
            "epoch": 1,
            "invite_commitment_sha256": sha256_hex(b"opaque-private-group-join-package-consume"),
            "invite_ciphertext_nonce_base64": B64.encode([20u8; 12]),
            "invite_ciphertext_base64": B64.encode(b"opaque-private-group-join-package-consume"),
            "invite_ciphertext_aad_base64": B64.encode(b"private-group-invite-envelope-aad-consume"),
            "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
            "authorizing_publish_key_base64": admin.publish_key_base64.clone().expect("admin publish key"),
            "expires_in_seconds": 3600,
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::OK);
    let invite_token = create_payload["invite_token"]
        .as_str()
        .expect("invite token")
        .to_string();

    let (consume_status, consume_payload) = json_request(
        app.clone(),
        Method::POST,
        &format!("/v1/private-groups/invites/{invite_token}"),
        json!({}),
    )
    .await;
    assert_eq!(consume_status, StatusCode::OK);
    assert_eq!(
        consume_payload["invite_token"].as_str(),
        Some(invite_token.as_str())
    );
    assert_eq!(consume_payload["consumed"].as_bool(), Some(true));
    assert!(consume_payload["revoked_at"].as_str().is_some());

    let (resolve_status, resolve_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/private-groups/invites/{invite_token}"),
        json!({}),
    )
    .await;
    assert_eq!(resolve_status, StatusCode::NOT_FOUND);
    assert_eq!(
        resolve_payload["detail"].as_str(),
        Some("private group invite not found or expired")
    );
}

#[tokio::test]
async fn private_group_invite_rejects_stale_epoch_after_rotation() {
    let app = test_app().await;
    let admin_v1 = private_group_member_fixture(70, true);
    let member_v1 = private_group_member_fixture(71, false);
    let admin_v2 = private_group_member_fixture(72, true);
    let member_v2 = private_group_member_fixture(73, false);

    let (publish_v1_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-invite-rotation",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-invite-rotation-v1"),
            "ciphertext_nonce_base64": B64.encode([14u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-invite-rotation-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-invite-rotation-aad-v1"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin_v1.record.clone(), member_v1.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_v1_status, StatusCode::OK);

    let (create_status, create_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/invites",
        json!({
            "group_id": "private-group-invite-rotation",
            "epoch": 1,
            "invite_commitment_sha256": sha256_hex(b"opaque-private-group-join-package-rotation-v1"),
            "invite_ciphertext_nonce_base64": B64.encode([15u8; 12]),
            "invite_ciphertext_base64": B64.encode(b"opaque-private-group-join-package-rotation-v1"),
            "invite_ciphertext_aad_base64": B64.encode(b"private-group-invite-envelope-aad-v1"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1.publish_key_base64.clone().expect("admin publish key"),
            "expires_in_seconds": 3600,
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::OK);
    let invite_token = create_payload["invite_token"]
        .as_str()
        .expect("invite token")
        .to_string();

    let (publish_v2_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-invite-rotation",
            "epoch": 2,
            "state_commitment_sha256": sha256_hex(b"private-group-invite-rotation-v2"),
            "ciphertext_nonce_base64": B64.encode([16u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-invite-rotation-v2"),
            "ciphertext_aad_base64": B64.encode(b"private-group-invite-rotation-aad-v2"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin_v2.record.clone(), member_v2.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_v2_status, StatusCode::OK);

    let (resolve_status, resolve_payload) = json_request(
        app.clone(),
        Method::GET,
        &format!("/v1/private-groups/invites/{invite_token}"),
        json!({}),
    )
    .await;
    assert_eq!(resolve_status, StatusCode::NOT_FOUND);
    assert_eq!(
        resolve_payload["detail"].as_str(),
        Some("private group invite not found or expired")
    );
}

#[tokio::test]
async fn private_group_invite_rejects_invalid_publish_capability() {
    let app = test_app().await;
    let admin = private_group_member_fixture(80, true);
    let member = private_group_member_fixture(81, false);

    let (publish_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-invite-invalid-capability",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-invite-invalid-capability-v1"),
            "ciphertext_nonce_base64": B64.encode([17u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-invite-invalid-capability-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-invite-invalid-capability-aad-v1"),
            "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
            "authorizing_publish_key_base64": admin.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin.record.clone(), member.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_status, StatusCode::OK);

    let (create_status, create_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/invites",
        json!({
            "group_id": "private-group-invite-invalid-capability",
            "epoch": 1,
            "invite_commitment_sha256": sha256_hex(b"opaque-private-group-invalid-capability"),
            "invite_ciphertext_nonce_base64": B64.encode([18u8; 12]),
            "invite_ciphertext_base64": B64.encode(b"opaque-private-group-invalid-capability"),
            "invite_ciphertext_aad_base64": B64.encode(b"private-group-invite-envelope-aad-invalid"),
            "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
            "authorizing_publish_key_base64": B64.encode([0xAAu8; 32]),
            "expires_in_seconds": 3600,
        }),
    )
    .await;
    assert_eq!(create_status, StatusCode::FORBIDDEN);
    assert_eq!(
        create_payload["detail"].as_str(),
        Some("authorizing private group publish key is invalid")
    );
}

#[tokio::test]
async fn private_group_message_publish_and_fetch_work() {
    let app = test_app().await;
    let admin = private_group_member_fixture(90, true);
    let member = private_group_member_fixture(91, false);

    let (publish_state_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-message-alpha",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-message-alpha-state-v1"),
            "ciphertext_nonce_base64": B64.encode([21u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-message-alpha-state-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-message-alpha-aad-v1"),
            "authorizing_membership_handle_sha256": admin.membership_handle_sha256,
            "authorizing_publish_key_base64": admin.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin.record.clone(), member.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_state_status, StatusCode::OK);

    let (publish_message_status, publish_message_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/messages/publish",
        json!({
            "group_id": "private-group-message-alpha",
            "epoch": 1,
            "sent_at_unix_ms": 1_775_000_000_000u64,
            "ciphertext_nonce_base64": B64.encode([22u8; 12]),
            "ciphertext_base64": B64.encode(b"opaque-private-group-message-v1"),
            "ciphertext_aad_base64": B64.encode(b"opaque-private-group-message-aad-v1"),
            "sender_hybrid_signature_base64": B64.encode(vec![0x55u8; 128]),
            "authorizing_membership_handle_sha256": member.membership_handle_sha256,
            "authorizing_fetch_key_base64": member.fetch_key_base64,
        }),
    )
    .await;
    assert_eq!(publish_message_status, StatusCode::OK);
    let message_id = publish_message_payload["message_id"]
        .as_i64()
        .expect("message id");
    assert_eq!(
        publish_message_payload["group_id"].as_str(),
        Some("private-group-message-alpha")
    );
    assert_eq!(publish_message_payload["epoch"].as_u64(), Some(1));

    let (fetch_status, fetch_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/messages/fetch",
        json!({
            "membership_handle_sha256": admin.membership_handle_sha256,
            "fetch_key_base64": admin.fetch_key_base64,
            "since_message_id": 0,
        }),
    )
    .await;
    assert_eq!(fetch_status, StatusCode::OK);
    assert_eq!(
        fetch_payload["group_id"].as_str(),
        Some("private-group-message-alpha")
    );
    assert_eq!(fetch_payload["epoch"].as_u64(), Some(1));
    let messages = fetch_payload["messages"]
        .as_array()
        .expect("messages array");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["message_id"].as_i64(), Some(message_id));
    assert!(messages[0].get("sender_user_id").is_none());
    assert_eq!(
        messages[0]["ciphertext_base64"].as_str(),
        Some(B64.encode(b"opaque-private-group-message-v1").as_str())
    );
}

#[tokio::test]
async fn private_group_message_rejects_stale_epoch_and_revoked_fetch_capability() {
    let app = test_app().await;
    let admin_v1 = private_group_member_fixture(92, true);
    let member_v1 = private_group_member_fixture(93, false);
    let admin_v2 = private_group_member_fixture(94, true);
    let member_v2 = private_group_member_fixture(95, false);

    let (publish_v1_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-message-rotation",
            "epoch": 1,
            "state_commitment_sha256": sha256_hex(b"private-group-message-rotation-v1"),
            "ciphertext_nonce_base64": B64.encode([23u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-message-rotation-v1"),
            "ciphertext_aad_base64": B64.encode(b"private-group-message-rotation-aad-v1"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin_v1.record.clone(), member_v1.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_v1_status, StatusCode::OK);

    let (publish_v2_status, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/state/publish",
        json!({
            "group_id": "private-group-message-rotation",
            "epoch": 2,
            "state_commitment_sha256": sha256_hex(b"private-group-message-rotation-v2"),
            "ciphertext_nonce_base64": B64.encode([24u8; 12]),
            "ciphertext_base64": B64.encode(b"encrypted-private-group-message-rotation-v2"),
            "ciphertext_aad_base64": B64.encode(b"private-group-message-rotation-aad-v2"),
            "authorizing_membership_handle_sha256": admin_v1.membership_handle_sha256,
            "authorizing_publish_key_base64": admin_v1.publish_key_base64.clone().expect("admin publish key"),
            "members": [admin_v2.record.clone(), member_v2.record.clone()],
        }),
    )
    .await;
    assert_eq!(publish_v2_status, StatusCode::OK);

    let (stale_publish_status, stale_publish_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/messages/publish",
        json!({
            "group_id": "private-group-message-rotation",
            "epoch": 1,
            "sent_at_unix_ms": 1_775_000_000_001u64,
            "ciphertext_nonce_base64": B64.encode([25u8; 12]),
            "ciphertext_base64": B64.encode(b"opaque-private-group-message-stale"),
            "ciphertext_aad_base64": B64.encode(b"opaque-private-group-message-stale-aad"),
            "sender_hybrid_signature_base64": B64.encode(vec![0x44u8; 128]),
            "authorizing_membership_handle_sha256": member_v1.membership_handle_sha256,
            "authorizing_fetch_key_base64": member_v1.fetch_key_base64,
        }),
    )
    .await;
    assert_eq!(stale_publish_status, StatusCode::CONFLICT);
    assert_eq!(
        stale_publish_payload["detail"].as_str(),
        Some("private group epoch is stale; refresh state first")
    );

    let (revoked_fetch_status, revoked_fetch_payload) = json_request(
        app.clone(),
        Method::POST,
        "/v1/private-groups/messages/fetch",
        json!({
            "membership_handle_sha256": member_v1.membership_handle_sha256,
            "fetch_key_base64": member_v1.fetch_key_base64,
            "since_message_id": 0,
        }),
    )
    .await;
    assert_eq!(revoked_fetch_status, StatusCode::NOT_FOUND);
    assert_eq!(
        revoked_fetch_payload["detail"].as_str(),
        Some("private group state not found")
    );
}

// ---- 3. Rate-limiter saturation ------------------------------------------

#[tokio::test]
async fn rate_limiter_rejects_after_bucket_exhaustion() {
    // Capacity = 2, refill = 0/s → third request should be rejected
    let rate_limiter = Arc::new(RateLimiter::new(2.0, 0.0, 100, StdDuration::from_secs(600)));
    let app = test_app_with_rate_limiter(rate_limiter).await;
    let sig = signing_key(220);
    let reg = register_payload("rate-user", "dev-1", [61u8; 32], &sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(s, StatusCode::OK);

    // The registration itself consumed one token from "register:rate-user".
    // Now hammer a *different* keyed endpoint (health is unauthenticated and has no
    // rate-limit call, so use prekeys-status which calls check_rate_limit).
    let h1 = prekeys_status_auth_headers(&sig, "rate-user", "dev-1");
    let (s1, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/rate-user/prekeys/status",
        json!({}),
        &h1,
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let h2 = prekeys_status_auth_headers(&sig, "rate-user", "dev-1");
    let (s2, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/rate-user/prekeys/status",
        json!({}),
        &h2,
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // Third call — bucket is exhausted (capacity=2, 0 refill)
    let h3 = prekeys_status_auth_headers(&sig, "rate-user", "dev-1");
    let (s3, body3) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/rate-user/prekeys/status",
        json!({}),
        &h3,
    )
    .await;
    assert_eq!(s3, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body3["status"].as_u64(), Some(429));
}

// ---- 4. Max prekey count boundary ----------------------------------------

#[tokio::test]
async fn publish_prekeys_rejects_exceeding_max_one_time_keys() {
    let app = test_app().await;
    let sig = signing_key(230);
    let reg = register_payload("prekey-max-user", "dev-1", [71u8; 32], &sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg).await;
    assert_eq!(s, StatusCode::OK);

    // 257 one-time keys (limit is 256)
    let too_many_x = vec![[99u8; 32]; 257];
    let too_many_pq = vec![vec![99u8; 64]; 257];
    let publish = publish_prekeys_payload(&sig, [5u8; 32], vec![7u8; 64], too_many_x, too_many_pq);
    let auth = prekeys_auth_headers(&sig, "prekey-max-user", "dev-1", &publish);
    let (status, body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/prekey-max-user/prekeys",
        publish,
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["detail"].as_str().unwrap_or("").contains("256"),
        "should mention the 256 limit: {body}"
    );

    // Exactly 256 → should succeed
    let ok_x = vec![[88u8; 32]; 256];
    let ok_pq = vec![vec![88u8; 64]; 256];
    let publish_ok = publish_prekeys_payload(&sig, [5u8; 32], vec![7u8; 64], ok_x, ok_pq);
    let auth_ok = prekeys_auth_headers(&sig, "prekey-max-user", "dev-1", &publish_ok);
    let (status_ok, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/prekey-max-user/prekeys",
        publish_ok,
        &auth_ok,
    )
    .await;
    assert_eq!(status_ok, StatusCode::OK);
}

// ---- 5. Max group members boundary ---------------------------------------

#[tokio::test]
async fn group_create_is_disabled_before_member_limit_validation() {
    let app = test_app().await;
    let owner_sig = signing_key(240);
    let reg_owner = register_payload("group-owner", "dev-1", [81u8; 32], &owner_sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg_owner).await;
    assert_eq!(s, StatusCode::OK);

    // Try creating a group with 513 members (limit is 512 including owner)
    let member_ids: Vec<String> = (0..513).map(|i| format!("member-{i}")).collect();
    let headers = groups_create_auth_headers(
        &owner_sig,
        "group-owner",
        "dev-1",
        "huge-group",
        &member_ids,
    );
    let (status, body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/groups",
        json!({"group_id": "huge-group", "member_user_ids": member_ids}),
        &headers,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("group messaging is disabled"),
        "group create should fail before member-limit validation: {body}"
    );
}

// ---- 6. WebSocket disconnect and reconnect --------------------------------

#[tokio::test]
async fn websocket_inbox_disconnect_and_reconnect_delivers_messages() {
    let app = test_app_with_authenticated_dm_compat().await;
    let bob_sig = signing_key(250);
    let alice_sig = signing_key(251);

    let reg_bob = register_payload("bob-ws2", "bob-ws2-dev", [91u8; 32], &bob_sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(s, StatusCode::OK);

    let reg_alice = register_payload("alice-ws2", "alice-ws2-dev", [92u8; 32], &alice_sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(s, StatusCode::OK);

    let (ws_base, _handle) = spawn_http_server(app.clone()).await;

    // --- First WS connection ---
    let ws_headers_1 = ws_inbox_auth_headers(&bob_sig, "bob-ws2", "bob-ws2-dev", 0);
    let mut ws_url_1 = format!("{ws_base}/v1/ws/inbox/bob-ws2?since=0");
    let mut request_1 = ws_url_1.into_client_request().expect("ws request");
    for (name, value) in &ws_headers_1 {
        request_1
            .headers_mut()
            .insert(HeaderName::from_static(name), value.parse().unwrap());
    }
    let (mut ws_1, _) = connect_async(request_1).await.expect("ws connect 1");

    // Send a message while connected
    let relay_1 = json!({
        "sender_user_id": "alice-ws2",
        "device_id": "alice-ws2-dev",
        "message_bytes_base64": B64.encode("ws-msg-1")
    });
    let relay_headers_1 = relay_auth_headers(
        &alice_sig,
        "alice-ws2",
        "alice-ws2-dev",
        "bob-ws2",
        b"ws-msg-1",
    );
    let (s, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob-ws2",
        relay_1,
        &relay_headers_1,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Receive on WS 1
    let msg_1 = timeout(Duration::from_secs(5), ws_1.next())
        .await
        .expect("ws timeout")
        .expect("ws closed")
        .expect("ws error");
    assert!(msg_1.is_text(), "expected text message");
    let parsed_1: Value = serde_json::from_str(msg_1.to_text().unwrap()).expect("json");
    assert_eq!(parsed_1["event"].as_str(), Some("relay"));
    let msgs_1 = parsed_1["messages"].as_array().expect("messages");
    assert_eq!(msgs_1.len(), 1);
    assert_eq!(
        msgs_1[0]["message_bytes_base64"].as_str(),
        Some(B64.encode("ws-msg-1").as_str())
    );
    let msg_1_id = msgs_1[0]["message_id"].as_i64().expect("message_id");

    // Drop (disconnect) ws 1
    drop(ws_1);

    // Send another message while bob is disconnected
    let relay_2 = json!({
        "sender_user_id": "alice-ws2",
        "device_id": "alice-ws2-dev",
        "message_bytes_base64": B64.encode("ws-msg-2")
    });
    let relay_headers_2 = relay_auth_headers(
        &alice_sig,
        "alice-ws2",
        "alice-ws2-dev",
        "bob-ws2",
        b"ws-msg-2",
    );
    let (s, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob-ws2",
        relay_2,
        &relay_headers_2,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Reconnect WS with since = msg_1_id to get only the missed message
    let ws_headers_2 = ws_inbox_auth_headers(&bob_sig, "bob-ws2", "bob-ws2-dev", msg_1_id);
    ws_url_1 = format!("{ws_base}/v1/ws/inbox/bob-ws2?since={msg_1_id}");
    let mut request_2 = ws_url_1.into_client_request().expect("ws request");
    for (name, value) in &ws_headers_2 {
        request_2
            .headers_mut()
            .insert(HeaderName::from_static(name), value.parse().unwrap());
    }
    let (mut ws_2, _) = connect_async(request_2).await.expect("ws connect 2");

    // Should receive the missed message on backfill
    let msg_2 = timeout(Duration::from_secs(5), ws_2.next())
        .await
        .expect("ws timeout 2")
        .expect("ws closed 2")
        .expect("ws error 2");
    assert!(msg_2.is_text(), "expected text message");
    let parsed_2: Value = serde_json::from_str(msg_2.to_text().unwrap()).expect("json 2");
    let msgs_2 = parsed_2["messages"].as_array().expect("messages 2");
    assert!(
        msgs_2
            .iter()
            .any(|m| m["message_bytes_base64"].as_str() == Some(B64.encode("ws-msg-2").as_str())),
        "reconnect should deliver missed message: {parsed_2}"
    );
}

#[tokio::test]
async fn postgres_channel_endpoints_are_disabled() {
    let Some(app) = test_app_with_postgres_env().await else {
        return;
    };
    let alice_sig = signing_key(193);
    let bob_sig = signing_key(194);

    let reg_alice = register_payload("alice-pg-chan", "alice-pg-chan-dev", [21u8; 32], &alice_sig);
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let reg_bob = register_payload("bob-pg-chan", "bob-pg-chan-dev", [22u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let create_channel_body = json!({
        "owner_user_id": "alice-pg-chan",
        "device_id": "alice-pg-chan-dev",
        "display_name": "General",
        "description": "postgres coverage"
    });
    let create_headers = format_string_auth_headers(
        &alice_sig,
        "alice-pg-chan",
        "alice-pg-chan-dev",
        "channel-create:alice-pg-chan:alice-pg-chan-dev",
    );
    let (status_create, create_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/channels",
        create_channel_body,
        &create_headers,
    )
    .await;
    assert_eq!(status_create, StatusCode::FORBIDDEN);
    assert!(create_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("channels are disabled")));

    let subscribe_message = format!(
        "channel-subscribe:{}:{}:{}",
        "bob-pg-chan", "bob-pg-chan-dev", "disabled-channel"
    );
    let subscribe_headers = format_string_auth_headers(
        &bob_sig,
        "bob-pg-chan",
        "bob-pg-chan-dev",
        subscribe_message,
    );
    let (status_subscribe, subscribe_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/channels/disabled-channel/subscribe",
        json!({}),
        &subscribe_headers,
    )
    .await;
    assert_eq!(status_subscribe, StatusCode::FORBIDDEN);
    assert!(subscribe_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("channels are disabled")));

    let list_headers = format_string_auth_headers(
        &bob_sig,
        "bob-pg-chan",
        "bob-pg-chan-dev",
        "channel-list:bob-pg-chan:bob-pg-chan-dev",
    );
    let (status_list, list_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/channels",
        json!({}),
        &list_headers,
    )
    .await;
    assert_eq!(status_list, StatusCode::FORBIDDEN);
    assert!(list_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("channels are disabled")));
}

#[tokio::test]
async fn postgres_story_endpoints_are_disabled() {
    let Some(app) = test_app_with_postgres_env().await else {
        return;
    };
    let alice_sig = signing_key(197);
    let bob_sig = signing_key(198);

    let reg_alice = register_payload(
        "alice-pg-story",
        "alice-pg-story-dev",
        [23u8; 32],
        &alice_sig,
    );
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let reg_bob = register_payload("bob-pg-story", "bob-pg-story-dev", [24u8; 32], &bob_sig);
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let create_story_body = json!({
        "author_user_id": "alice-pg-story",
        "device_id": "alice-pg-story-dev",
        "content_base64": B64.encode("story-payload"),
        "media_type": "text"
    });
    let create_headers = format_string_auth_headers(
        &alice_sig,
        "alice-pg-story",
        "alice-pg-story-dev",
        "story-create:alice-pg-story:alice-pg-story-dev",
    );
    let (status_create, create_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/stories",
        create_story_body,
        &create_headers,
    )
    .await;
    assert_eq!(status_create, StatusCode::FORBIDDEN);
    assert!(create_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("stories are disabled")));

    let view_message = format!(
        "story-view:{}:{}:{}",
        "bob-pg-story", "bob-pg-story-dev", "disabled-story"
    );
    let view_headers =
        format_string_auth_headers(&bob_sig, "bob-pg-story", "bob-pg-story-dev", view_message);
    let (status_view, view_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/stories/disabled-story/view",
        json!({}),
        &view_headers,
    )
    .await;
    assert_eq!(status_view, StatusCode::FORBIDDEN);
    assert!(view_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("stories are disabled")));

    let feed_headers = format_string_auth_headers(
        &bob_sig,
        "bob-pg-story",
        "bob-pg-story-dev",
        "story-feed:bob-pg-story:bob-pg-story-dev",
    );
    let (status_feed, feed_payload) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/stories/feed?user_id=alice-pg-story",
        json!({}),
        &feed_headers,
    )
    .await;
    assert_eq!(status_feed, StatusCode::FORBIDDEN);
    assert!(feed_payload["detail"]
        .as_str()
        .is_some_and(|detail| detail.contains("stories are disabled")));
}

// ---- 7. Negative identity-log queries ------------------------------------

#[tokio::test]
async fn identity_log_rejects_wrong_user_and_nonexistent() {
    let app = test_app().await;
    let alice_sig = signing_key(195);
    let bob_sig = signing_key(196);

    let reg_alice = register_payload("alice-log", "alice-log-dev", [101u8; 32], &alice_sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(s, StatusCode::OK);

    let reg_bob = register_payload("bob-log", "bob-log-dev", [102u8; 32], &bob_sig);
    let (s, _) = json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(s, StatusCode::OK);

    // Bob tries to query alice's identity-log with bob's credentials
    // The auth system binds endpoint+user_id into the TLV, so bob's signature
    // won't verify for alice's user_id path — should fail with 400.
    let bob_headers = identity_log_auth_headers(&bob_sig, "bob-log", "bob-log-dev");
    let (status_wrong, _) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice-log/identity-log",
        json!({}),
        &bob_headers,
    )
    .await;
    assert_eq!(status_wrong, StatusCode::BAD_REQUEST);

    // Query identity-log for a user that exists but has no rotation events
    // (only the initial registration event should be returned)
    let alice_headers = identity_log_auth_headers(&alice_sig, "alice-log", "alice-log-dev");
    let (status_ok, body) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/alice-log/identity-log",
        json!({}),
        &alice_headers,
    )
    .await;
    assert_eq!(status_ok, StatusCode::OK);
    let events = body["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1, "fresh user has only initial event");
    assert_eq!(events[0]["event_type"].as_str(), Some("initial"));

    // Query without any auth headers → should fail
    let (status_no_auth, _) = json_request(
        app.clone(),
        Method::GET,
        "/v1/users/alice-log/identity-log",
        json!({}),
    )
    .await;
    assert_eq!(status_no_auth, StatusCode::BAD_REQUEST);
}
