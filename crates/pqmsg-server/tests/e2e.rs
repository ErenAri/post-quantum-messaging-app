//! End-to-end client-to-client test suite.
//!
//! Tests full messaging flows between two simulated clients including
//! registration, prekey publishing, message relay, inbox retrieval,
//! delivery receipts, ephemeral messages, and multi-device scenarios.

use axum::body::Body;
use axum::http::header::HeaderMap;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use pqmsg_core::alg::PROTOCOL_VERSION_V1;
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_core::pq_sig::{MlDsa65, PqSignatureProvider};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_server::{build_router, init_db, parse_db_backend, AppState, RateLimiter};
use serde_json::{json, Value};
use sqlx::any::AnyPoolOptions;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tower::ServiceExt;

// ── Auth header constants ──────────────────────────────────────────

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
const AUTH_TAG_LINK_DEVICE_ID: u16 = critical_type(0x3212);

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(100_000);

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

// ── Test infrastructure ────────────────────────────────────────────

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

fn signing_key(seed: u8) -> TestIdentityKeyPair {
    let provider = MlDsa65::new().expect("ml-dsa init");
    let pq_keypair = provider.keypair().expect("ml-dsa keypair");
    TestIdentityKeyPair {
        classical: SigningKey::from_bytes(&[seed; 32]),
        pq_public: pq_keypair.public_key,
        pq_secret: pq_keypair.secret_key.as_slice().to_vec(),
    }
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

// ── Auth helpers ───────────────────────────────────────────────────

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

fn make_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    message: &[u8],
    nonce_prefix: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "{}-{}",
        nonce_prefix,
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let _ = (timestamp, &nonce); // used below
    let signature = signing_key.sign(message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
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
    let nonce = format!(
        "e2e-relay-{}",
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

fn inbox_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "e2e-inbox-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
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

fn prekeys_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    prekeys: &Value,
) -> Vec<(&'static str, String)> {
    use sha2::{Digest, Sha256};
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "e2e-prekeys-{}",
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let mut records = auth_common_records("prekeys", user_id, device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(
        prekeys["signed_prekey_x25519_pub"]
            .as_str()
            .unwrap()
            .as_bytes(),
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_SPK_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(
        prekeys["pq_signed_prekey_pub_mlkem768"]
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

/// Auth headers for receipt sending (simple string-based auth message).
fn receipt_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    message_id: i64,
    receipt_type: &str,
) -> Vec<(&'static str, String)> {
    let auth_message = format!("receipt:{user_id}:{device_id}:{message_id}:{receipt_type}");
    make_auth_headers(
        signing_key,
        user_id,
        device_id,
        auth_message.as_bytes(),
        "e2e-receipt",
    )
}

/// Auth headers for receipt polling (simple string-based auth message).
fn get_receipts_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since_id: i64,
) -> Vec<(&'static str, String)> {
    let auth_message = format!("get-receipts:{user_id}:{device_id}:{since_id}");
    make_auth_headers(
        signing_key,
        user_id,
        device_id,
        auth_message.as_bytes(),
        "e2e-get-receipts",
    )
}

/// Auth headers for ephemeral relay (simple string-based auth message).
fn ephemeral_relay_auth_headers(
    signing_key: &SigningKey,
    sender_user_id: &str,
    sender_device_id: &str,
    recipient_user_id: &str,
    ttl_seconds: u64,
) -> Vec<(&'static str, String)> {
    let auth_message = format!(
        "ephemeral-relay:{sender_user_id}:{sender_device_id}:{recipient_user_id}:{ttl_seconds}"
    );
    make_auth_headers(
        signing_key,
        sender_user_id,
        sender_device_id,
        auth_message.as_bytes(),
        "e2e-ephemeral",
    )
}

fn link_device_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    auth_device_id: &str,
    new_device_id: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("e2e-link-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
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

// ── Payload helpers ────────────────────────────────────────────────

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
            .map(|v| B64.encode(v))
            .collect::<Vec<_>>(),
        "one_time_prekeys_mlkem768": one_time_prekeys_mlkem768
            .into_iter()
            .map(|v| B64.encode(v))
            .collect::<Vec<_>>()
    })
}

// ── Composite helper: register + publish ───────────────────────────

struct Client {
    user_id: &'static str,
    device_id: &'static str,
    signing_key: TestIdentityKeyPair,
    x25519_pub: [u8; 32],
}

impl Client {
    fn new(user_id: &'static str, device_id: &'static str, seed: u8) -> Self {
        Self {
            user_id,
            device_id,
            signing_key: signing_key(seed),
            x25519_pub: [seed; 32],
        }
    }

    async fn register(&self, app: &axum::Router) {
        let payload = register_payload(
            self.user_id,
            self.device_id,
            self.x25519_pub,
            &self.signing_key,
        );
        let (status, _) =
            json_request(app.clone(), Method::POST, "/v1/users/register", payload).await;
        assert_eq!(status, StatusCode::OK, "register {}", self.user_id);
    }

    async fn publish_prekeys(&self, app: &axum::Router) {
        let payload = publish_prekeys_payload(
            &self.signing_key,
            [self.x25519_pub[0].wrapping_add(10); 32],
            vec![self.x25519_pub[0].wrapping_add(20); 64],
            vec![
                [self.x25519_pub[0].wrapping_add(30); 32],
                [self.x25519_pub[0].wrapping_add(31); 32],
            ],
            vec![
                vec![self.x25519_pub[0].wrapping_add(40); 64],
                vec![self.x25519_pub[0].wrapping_add(41); 64],
            ],
        );
        let auth = prekeys_auth_headers(&self.signing_key, self.user_id, self.device_id, &payload);
        let (status, _) = json_request_with_headers(
            app.clone(),
            Method::POST,
            &format!("/v1/users/{}/prekeys", self.user_id),
            payload,
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "publish_prekeys {}", self.user_id);
    }

    async fn link_device(&self, app: &axum::Router, new_device_id: &str) {
        let auth = link_device_auth_headers(
            &self.signing_key,
            self.user_id,
            self.device_id,
            new_device_id,
        );
        let (status, _) = json_request_with_headers(
            app.clone(),
            Method::POST,
            &format!("/v1/users/{}/devices/link", self.user_id),
            json!({ "new_device_id": new_device_id }),
            &auth,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "link_device {} → {}",
            self.user_id,
            new_device_id
        );
    }
}

// ══════════════════════════════════════════════════════════════════════
// E2E tests
// ══════════════════════════════════════════════════════════════════════

/// Full register → publish → relay → inbox flow while receipts stay disabled.
/// two clients (Alice → Bob).
#[tokio::test]
async fn e2e_full_message_and_receipts_disabled_flow() {
    let app = test_app().await;

    let alice = Client::new("e2e-alice", "alice-d1", 20);
    let bob = Client::new("e2e-bob", "bob-d1", 30);

    // Register both clients
    alice.register(&app).await;
    bob.register(&app).await;

    // Bob publishes prekey bundles
    bob.publish_prekeys(&app).await;

    // Alice fetches Bob's bundle
    let (status, bundle) = json_request(
        app.clone(),
        Method::GET,
        "/v1/users/e2e-bob/bundle",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(bundle["signed_prekey_x25519_pub"].is_string());
    assert!(bundle["one_time_prekey_x25519"].is_string());

    // Alice sends an encrypted message to Bob
    let ciphertext = b"encrypted-pqxdh-initial-message";
    let relay_payload = json!({
        "sender_user_id": "e2e-alice",
        "device_id": "alice-d1",
        "message_bytes_base64": B64.encode(ciphertext)
    });
    let relay_auth = relay_auth_headers(
        &alice.signing_key,
        "e2e-alice",
        "alice-d1",
        "e2e-bob",
        ciphertext,
    );
    let (status, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/e2e-bob",
        relay_payload,
        &relay_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let message_id = relay_body["message_id"].as_i64().expect("message_id");
    assert!(message_id > 0);

    // Bob retrieves the message from inbox
    let inbox_auth = inbox_auth_headers(&bob.signing_key, "e2e-bob", "bob-d1", 0);
    let (status, inbox) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/e2e-bob?since=0",
        json!({}),
        &inbox_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let messages = inbox["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["sender_user_id"].as_str(), Some("e2e-alice"));
    assert_eq!(messages[0]["message_id"].as_i64(), Some(message_id));
    let received_blob = messages[0]["message_bytes_base64"].as_str().unwrap();
    assert_eq!(B64.decode(received_blob).unwrap(), ciphertext);

    // Bob attempts a "delivered" receipt, but the privacy profile keeps receipts disabled.
    let receipt_auth = receipt_auth_headers(
        &bob.signing_key,
        "e2e-bob",
        "bob-d1",
        message_id,
        "delivered",
    );
    let (status, receipt_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/e2e-bob/receipts",
        json!({
            "message_id": message_id,
            "receipt_type": "delivered"
        }),
        &receipt_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "send receipt: {receipt_body}");
    assert!(
        receipt_body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("read receipts are disabled"))
    );

    // Alice cannot poll receipts either.
    let poll_auth = get_receipts_auth_headers(&alice.signing_key, "e2e-alice", "alice-d1", 0);
    let (status, receipts) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/e2e-alice/receipts/poll?since_id=0",
        json!({}),
        &poll_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "poll receipts: {receipts}");
    assert!(
        receipts["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("read receipts are disabled"))
    );

    // Bob cannot upgrade to a "read" receipt while the feature is disabled.
    let read_auth = receipt_auth_headers(&bob.signing_key, "e2e-bob", "bob-d1", message_id, "read");
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/e2e-bob/receipts",
        json!({
            "message_id": message_id,
            "receipt_type": "read"
        }),
        &read_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "read receipt");
}

/// Ephemeral (disappearing) message relay with TTL.
#[tokio::test]
async fn e2e_ephemeral_message_relay() {
    let app = test_app().await;

    let alice = Client::new("eph-alice", "alice-d1", 40);
    let bob = Client::new("eph-bob", "bob-d1", 50);

    alice.register(&app).await;
    bob.register(&app).await;

    let ciphertext = b"self-destructing-message";
    let ttl = 3600u64; // 1 hour

    let auth =
        ephemeral_relay_auth_headers(&alice.signing_key, "eph-alice", "alice-d1", "eph-bob", ttl);
    let (status, body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/ephemeral-relay/eph-bob",
        json!({
            "sender_user_id": "eph-alice",
            "device_id": "alice-d1",
            "message_bytes_base64": B64.encode(ciphertext),
            "ttl_seconds": ttl
        }),
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ephemeral relay: {body}");
    assert!(body["message_id"].as_i64().unwrap() > 0);
    assert_eq!(body["delivered_device_count"].as_u64(), Some(1));

    // Bob can retrieve the ephemeral message from inbox
    let inbox_auth = inbox_auth_headers(&bob.signing_key, "eph-bob", "bob-d1", 0);
    let (status, inbox) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/eph-bob?since=0",
        json!({}),
        &inbox_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let msgs = inbox["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["sender_user_id"].as_str(), Some("eph-alice"));
}

/// Ephemeral relay rejects TTL out of range (0 or > 7 days).
#[tokio::test]
async fn e2e_ephemeral_rejects_invalid_ttl() {
    let app = test_app().await;

    let alice = Client::new("ettl-alice", "alice-d1", 60);
    let bob = Client::new("ettl-bob", "bob-d1", 70);
    alice.register(&app).await;
    bob.register(&app).await;

    // TTL = 0 (too low)
    let auth =
        ephemeral_relay_auth_headers(&alice.signing_key, "ettl-alice", "alice-d1", "ettl-bob", 0);
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/ephemeral-relay/ettl-bob",
        json!({
            "sender_user_id": "ettl-alice",
            "device_id": "alice-d1",
            "message_bytes_base64": B64.encode(b"msg"),
            "ttl_seconds": 0
        }),
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // TTL = 8 days (too high)
    let big_ttl = 8 * 24 * 3600u64;
    let auth2 = ephemeral_relay_auth_headers(
        &alice.signing_key,
        "ettl-alice",
        "alice-d1",
        "ettl-bob",
        big_ttl,
    );
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/ephemeral-relay/ettl-bob",
        json!({
            "sender_user_id": "ettl-alice",
            "device_id": "alice-d1",
            "message_bytes_base64": B64.encode(b"msg"),
            "ttl_seconds": big_ttl
        }),
        &auth2,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Receipts are rejected before receipt_type validation because the feature is disabled.
#[tokio::test]
async fn e2e_receipts_reject_before_type_validation() {
    let app = test_app().await;
    let bob = Client::new("rct-bob", "bob-d1", 80);
    bob.register(&app).await;

    let auth = receipt_auth_headers(&bob.signing_key, "rct-bob", "bob-d1", 1, "seen");
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/rct-bob/receipts",
        json!({
            "message_id": 1,
            "receipt_type": "seen"
        }),
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Multi-device: message relayed to both devices, but receipts stay disabled.
#[tokio::test]
async fn e2e_multi_device_message_and_receipts_disabled() {
    let app = test_app().await;

    let alice = Client::new("md-alice", "alice-d1", 90);
    let bob = Client::new("md-bob", "bob-d1", 100);

    alice.register(&app).await;
    bob.register(&app).await;

    // Link a second device to Bob
    bob.link_device(&app, "bob-d2").await;

    // Alice sends a message to Bob (delivered to both devices)
    let ciphertext = b"multi-device-msg";
    let relay_auth = relay_auth_headers(
        &alice.signing_key,
        "md-alice",
        "alice-d1",
        "md-bob",
        ciphertext,
    );
    let (status, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/md-bob",
        json!({
            "sender_user_id": "md-alice",
            "device_id": "alice-d1",
            "message_bytes_base64": B64.encode(ciphertext)
        }),
        &relay_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        relay_body["delivered_device_count"].as_u64(),
        Some(2),
        "message should be fanned out to both devices"
    );

    // Both Bob devices retrieve from inbox
    let inbox_auth_d1 = inbox_auth_headers(&bob.signing_key, "md-bob", "bob-d1", 0);
    let (status, inbox_d1) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/md-bob?since=0",
        json!({}),
        &inbox_auth_d1,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let msgs_d1 = inbox_d1["messages"].as_array().unwrap();
    assert!(!msgs_d1.is_empty(), "device 1 inbox non-empty");
    let msg_id = msgs_d1[0]["message_id"].as_i64().unwrap();

    let inbox_auth_d2 = inbox_auth_headers(&bob.signing_key, "md-bob", "bob-d2", 0);
    let (status, inbox_d2) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/md-bob?since=0",
        json!({}),
        &inbox_auth_d2,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let msgs_d2 = inbox_d2["messages"].as_array().unwrap();
    assert!(!msgs_d2.is_empty(), "device 2 inbox non-empty");

    // Device 1 cannot send a "delivered" receipt
    let d1_receipt_auth =
        receipt_auth_headers(&bob.signing_key, "md-bob", "bob-d1", msg_id, "delivered");
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/md-bob/receipts",
        json!({ "message_id": msg_id, "receipt_type": "delivered" }),
        &d1_receipt_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Device 2 cannot send a "delivered" receipt either
    let d2_receipt_auth =
        receipt_auth_headers(&bob.signing_key, "md-bob", "bob-d2", msg_id, "delivered");
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/md-bob/receipts",
        json!({ "message_id": msg_id, "receipt_type": "delivered" }),
        &d2_receipt_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Alice cannot poll receipts while the feature is disabled.
    let poll_auth = get_receipts_auth_headers(&alice.signing_key, "md-alice", "alice-d1", 0);
    let (status, receipts) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/md-alice/receipts/poll?since_id=0",
        json!({}),
        &poll_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        receipts["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("read receipts are disabled"))
    );
}

/// Security headers are present on all responses.
#[tokio::test]
async fn e2e_security_headers_present() {
    let app = test_app().await;

    let (status, headers, _) =
        json_request_with_headers_raw(app.clone(), Method::GET, "/health", json!({}), &[]).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        headers
            .get("x-content-type-options")
            .map(|v| v.to_str().unwrap()),
        Some("nosniff"),
    );
    assert_eq!(
        headers.get("x-frame-options").map(|v| v.to_str().unwrap()),
        Some("DENY"),
    );
    assert_eq!(
        headers.get("cache-control").map(|v| v.to_str().unwrap()),
        Some("no-store"),
    );
    assert!(
        headers.get("referrer-policy").is_some(),
        "referrer-policy header should be present"
    );
    assert!(
        headers.get("content-security-policy").is_some(),
        "CSP header should be present"
    );
}

/// Bidirectional messaging: Alice → Bob → Alice.
#[tokio::test]
async fn e2e_bidirectional_messaging() {
    let app = test_app().await;

    let alice = Client::new("bidir-alice", "alice-d1", 110);
    let bob = Client::new("bidir-bob", "bob-d1", 120);

    alice.register(&app).await;
    bob.register(&app).await;
    alice.publish_prekeys(&app).await;
    bob.publish_prekeys(&app).await;

    // Alice → Bob
    let ct1 = b"alice-to-bob-initial-message";
    let relay_auth1 = relay_auth_headers(
        &alice.signing_key,
        "bidir-alice",
        "alice-d1",
        "bidir-bob",
        ct1,
    );
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bidir-bob",
        json!({
            "sender_user_id": "bidir-alice",
            "device_id": "alice-d1",
            "message_bytes_base64": B64.encode(ct1)
        }),
        &relay_auth1,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Bob → Alice (reply)
    let ct2 = b"bob-reply-to-alice";
    let relay_auth2 =
        relay_auth_headers(&bob.signing_key, "bidir-bob", "bob-d1", "bidir-alice", ct2);
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bidir-alice",
        json!({
            "sender_user_id": "bidir-bob",
            "device_id": "bob-d1",
            "message_bytes_base64": B64.encode(ct2)
        }),
        &relay_auth2,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Alice inbox: should have Bob's reply
    let inbox_auth = inbox_auth_headers(&alice.signing_key, "bidir-alice", "alice-d1", 0);
    let (status, inbox) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bidir-alice?since=0",
        json!({}),
        &inbox_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let msgs = inbox["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["sender_user_id"].as_str(), Some("bidir-bob"));

    // Bob inbox: should have Alice's message
    let inbox_auth2 = inbox_auth_headers(&bob.signing_key, "bidir-bob", "bob-d1", 0);
    let (status, inbox2) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/inbox/bidir-bob?since=0",
        json!({}),
        &inbox_auth2,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let msgs2 = inbox2["messages"].as_array().unwrap();
    assert_eq!(msgs2.len(), 1);
    assert_eq!(msgs2[0]["sender_user_id"].as_str(), Some("bidir-alice"));
}

/// Ephemeral messages are delivered to multiple devices.
#[tokio::test]
async fn e2e_ephemeral_multi_device_fan_out() {
    let app = test_app().await;

    let alice = Client::new("emfd-alice", "alice-d1", 130);
    let bob = Client::new("emfd-bob", "bob-d1", 140);

    alice.register(&app).await;
    bob.register(&app).await;
    bob.link_device(&app, "bob-d2").await;

    let ttl = 300u64;
    let auth = ephemeral_relay_auth_headers(
        &alice.signing_key,
        "emfd-alice",
        "alice-d1",
        "emfd-bob",
        ttl,
    );
    let (status, body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/ephemeral-relay/emfd-bob",
        json!({
            "sender_user_id": "emfd-alice",
            "device_id": "alice-d1",
            "message_bytes_base64": B64.encode(b"ephemeral-multidevice"),
            "ttl_seconds": ttl
        }),
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ephemeral multi-device: {body}");
    assert_eq!(
        body["delivered_device_count"].as_u64(),
        Some(2),
        "ephemeral fanned out to 2 devices"
    );
}

/// Receipt endpoints remain consistently forbidden when disabled.
#[tokio::test]
async fn e2e_receipt_endpoint_stays_forbidden() {
    let app = test_app().await;
    let alice = Client::new("idem-alice", "alice-d1", 150);
    let bob = Client::new("idem-bob", "bob-d1", 160);
    alice.register(&app).await;
    bob.register(&app).await;

    // Alice sends a message
    let ct = b"idem-test-msg";
    let relay_auth =
        relay_auth_headers(&alice.signing_key, "idem-alice", "alice-d1", "idem-bob", ct);
    let (status, relay_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/idem-bob",
        json!({
            "sender_user_id": "idem-alice",
            "device_id": "alice-d1",
            "message_bytes_base64": B64.encode(ct)
        }),
        &relay_auth,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let msg_id = relay_body["message_id"].as_i64().unwrap();

    // Bob sends "delivered" receipt twice — both attempts should be forbidden.
    for _ in 0..2 {
        let auth =
            receipt_auth_headers(&bob.signing_key, "idem-bob", "bob-d1", msg_id, "delivered");
        let (status, _) = json_request_with_headers(
            app.clone(),
            Method::POST,
            "/v1/users/idem-bob/receipts",
            json!({ "message_id": msg_id, "receipt_type": "delivered" }),
            &auth,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "receipt endpoint should stay forbidden");
    }

    // Alice cannot poll receipts either.
    let poll_auth = get_receipts_auth_headers(&alice.signing_key, "idem-alice", "alice-d1", 0);
    let (status, receipts) = json_request_with_headers(
        app.clone(),
        Method::GET,
        "/v1/users/idem-alice/receipts/poll?since_id=0",
        json!({}),
        &poll_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        receipts["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("read receipts are disabled"))
    );
}

// ── Call signaling auth helpers ──────────────────────────────────

fn call_offer_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    callee_user_id: &str,
) -> Vec<(&'static str, String)> {
    let auth_message = format!("call-offer:{user_id}:{device_id}:{callee_user_id}");
    make_auth_headers(
        signing_key,
        user_id,
        device_id,
        auth_message.as_bytes(),
        "e2e-call-offer",
    )
}

fn call_answer_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    call_id: &str,
) -> Vec<(&'static str, String)> {
    let auth_message = format!("call-answer:{user_id}:{device_id}:{call_id}");
    make_auth_headers(
        signing_key,
        user_id,
        device_id,
        auth_message.as_bytes(),
        "e2e-call-answer",
    )
}

fn call_ice_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    call_id: &str,
) -> Vec<(&'static str, String)> {
    let auth_message = format!("call-ice:{user_id}:{device_id}:{call_id}");
    make_auth_headers(
        signing_key,
        user_id,
        device_id,
        auth_message.as_bytes(),
        "e2e-call-ice",
    )
}

fn call_hangup_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    call_id: &str,
) -> Vec<(&'static str, String)> {
    let auth_message = format!("call-hangup:{user_id}:{device_id}:{call_id}");
    make_auth_headers(
        signing_key,
        user_id,
        device_id,
        auth_message.as_bytes(),
        "e2e-call-hangup",
    )
}

fn call_signals_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    call_id: &str,
) -> Vec<(&'static str, String)> {
    let auth_message = format!("call-signals:{user_id}:{device_id}:{call_id}");
    make_auth_headers(
        signing_key,
        user_id,
        device_id,
        auth_message.as_bytes(),
        "e2e-call-signals",
    )
}

// ══════════════════════════════════════════════════════════════════════
// Call signaling E2E tests
// ══════════════════════════════════════════════════════════════════════

/// Calling endpoints are disabled in the private-messaging-only profile.
#[tokio::test]
async fn e2e_call_endpoints_are_disabled() {
    let app = test_app().await;

    let alice = Client::new("call-alice", "alice-d1", 170);
    let bob = Client::new("call-bob", "bob-d1", 180);
    alice.register(&app).await;
    bob.register(&app).await;

    let offer_auth =
        call_offer_auth_headers(&alice.signing_key, "call-alice", "alice-d1", "call-bob");
    let (status, offer_body) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/calls/call-bob/offer",
        json!({
            "caller_user_id": "call-alice",
            "device_id": "alice-d1",
            "sdp_offer_base64": B64.encode(b"v=0\r\no=alice SDP offer"),
            "call_type": "audio"
        }),
        &offer_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "offer: {offer_body}");
    assert!(
        offer_body["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("calling is disabled"))
    );
}

/// Answering a non-existent call is still blocked by the calling feature gate.
#[tokio::test]
async fn e2e_call_answer_is_disabled() {
    let app = test_app().await;

    let bob = Client::new("cne-bob", "bob-d1", 190);
    bob.register(&app).await;

    let fake_call_id = "00000000-0000-0000-0000-000000000000";
    let auth = call_answer_auth_headers(&bob.signing_key, "cne-bob", "bob-d1", fake_call_id);
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        &format!("/v1/calls/{fake_call_id}/answer"),
        json!({
            "callee_user_id": "cne-bob",
            "device_id": "bob-d1",
            "sdp_answer_base64": B64.encode(b"fake-sdp")
        }),
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Invalid call_type is never reached because calling is disabled.
#[tokio::test]
async fn e2e_call_offer_rejects_before_type_validation() {
    let app = test_app().await;

    let alice = Client::new("cit-alice", "alice-d1", 200);
    let bob = Client::new("cit-bob", "bob-d1", 210);
    alice.register(&app).await;
    bob.register(&app).await;

    let auth = call_offer_auth_headers(&alice.signing_key, "cit-alice", "alice-d1", "cit-bob");
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/calls/cit-bob/offer",
        json!({
            "caller_user_id": "cit-alice",
            "device_id": "alice-d1",
            "sdp_offer_base64": B64.encode(b"some-sdp"),
            "call_type": "screenshare"
        }),
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Hangup is blocked by the calling feature gate.
#[tokio::test]
async fn e2e_call_hangup_is_disabled() {
    let app = test_app().await;

    let alice = Client::new("che-alice", "alice-d1", 220);
    let bob = Client::new("che-bob", "bob-d1", 230);
    alice.register(&app).await;
    bob.register(&app).await;

    let hangup_auth =
        call_hangup_auth_headers(&alice.signing_key, "che-alice", "alice-d1", "disabled-call");
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/calls/disabled-call/hangup",
        json!({
            "user_id": "che-alice",
            "device_id": "alice-d1"
        }),
        &hangup_auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// ICE candidate exchange is blocked by the calling feature gate.
#[tokio::test]
async fn e2e_call_ice_is_disabled() {
    let app = test_app().await;

    let alice = Client::new("icene-alice", "alice-d1", 240);
    alice.register(&app).await;

    let fake_call_id = "00000000-0000-0000-0000-111111111111";
    let auth = call_ice_auth_headers(&alice.signing_key, "icene-alice", "alice-d1", fake_call_id);
    let (status, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        &format!("/v1/calls/{fake_call_id}/ice"),
        json!({
            "sender_user_id": "icene-alice",
            "device_id": "alice-d1",
            "candidate_base64": B64.encode(b"ice-candidate")
        }),
        &auth,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
