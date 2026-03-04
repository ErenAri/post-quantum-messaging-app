use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use pqmsg_core::alg::PROTOCOL_VERSION_V1;
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_server::{build_router, init_db, AppState, RateLimiter};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tower::ServiceExt;

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
const AUTH_TAG_ENDPOINT: u16 = critical_type(0x3201);
const AUTH_TAG_USER_ID: u16 = critical_type(0x3202);
const AUTH_TAG_DEVICE_ID: u16 = critical_type(0x3203);
const AUTH_TAG_TIMESTAMP: u16 = critical_type(0x3204);
const AUTH_TAG_NONCE: u16 = critical_type(0x3205);
const AUTH_TAG_RECIPIENT_ID: u16 = critical_type(0x3206);
const AUTH_TAG_SINCE: u16 = critical_type(0x3207);
const AUTH_TAG_MESSAGE_BLOB: u16 = critical_type(0x3208);
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

async fn test_app() -> axum::Router {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect sqlite memory");
    init_db(&pool).await.expect("migrate");
    let state = AppState::new(
        pool,
        Arc::new(RateLimiter::new(
            1_000.0,
            1_000.0,
            100_000,
            StdDuration::from_secs(600),
        )),
    );
    build_router(state)
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
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let payload: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
    (status, payload)
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn register_payload(
    user_id: &str,
    device_id: &str,
    identity_x25519_pub: [u8; 32],
    identity_signing_key: &SigningKey,
) -> Value {
    json!({
        "user_id": user_id,
        "identity_x25519_pub": B64.encode(identity_x25519_pub),
        "identity_sig_pub": B64.encode(identity_signing_key.verifying_key().to_bytes()),
        "device_id": device_id,
    })
}

fn publish_prekeys_payload(
    identity_signing_key: &SigningKey,
    signed_prekey_x25519_pub: [u8; 32],
    pq_signed_prekey_pub_mlkem768: Vec<u8>,
    one_time_prekeys_x25519: Vec<[u8; 32]>,
    one_time_prekeys_mlkem768: Vec<Vec<u8>>,
) -> Value {
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

    json!({
        "signed_prekey_x25519_pub": B64.encode(signed_prekey_x25519_pub),
        "sig_over_spk": B64.encode(sig_over_spk),
        "pq_signed_prekey_pub_mlkem768": B64.encode(pq_signed_prekey_pub_mlkem768),
        "sig_over_pqspk": B64.encode(sig_over_pqspk),
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

fn rotation_signature_message(
    user_id: &str,
    challenge_id: &str,
    challenge_nonce: &[u8],
    new_identity_x25519: &[u8; 32],
    new_identity_sig: &[u8; 32],
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

#[tokio::test]
async fn happy_path_register_publish_bundle_relay_inbox() {
    let app = test_app().await;
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
    let (status_publish, publish_body) =
        json_request(app.clone(), Method::POST, "/v1/users/bob/prekeys", publish).await;
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
    let app = test_app().await;
    let bob_sig = signing_key(7);
    let alice_sig = signing_key(11);

    let invalid_register = json!({
        "user_id": "bob",
        "identity_x25519_pub": B64.encode([1u8; 31]),
        "identity_sig_pub": B64.encode(bob_sig.verifying_key().to_bytes()),
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
        "one_time_prekeys_x25519": [],
        "one_time_prekeys_mlkem768": []
    });
    let (status_prekeys, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        invalid_prekeys,
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
    let (status_publish, body_publish) =
        json_request(app.clone(), Method::POST, "/v1/users/bob/prekeys", publish).await;
    assert_eq!(status_publish, StatusCode::BAD_REQUEST);
    assert_eq!(body_publish["status"].as_u64(), Some(400));
}

#[tokio::test]
async fn health_reports_security_profile() {
    let app = test_app().await;
    let (status, body) = json_request(app, Method::GET, "/health", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"].as_str(), Some("ok"));
    assert_eq!(body["security_profile"].as_str(), Some("research"));
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
    let (status_publish, _) =
        json_request(app.clone(), Method::POST, "/v1/users/bob/prekeys", publish).await;
    assert_eq!(status_publish, StatusCode::OK);

    let new_identity_x25519 = [2u8; 32];
    let new_identity_sig = key_new.verifying_key().to_bytes();
    let rotate_init = json!({
        "new_identity_x25519_pub": B64.encode(new_identity_x25519),
        "new_identity_sig_pub": B64.encode(new_identity_sig),
        "new_device_id": "bob-dev-2"
    });
    let (status_init, body_init) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/init",
        rotate_init,
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
        "bob-dev-2",
    );
    let rotate_confirm = json!({
        "challenge_id": challenge_id,
        "sig_by_current_identity": B64.encode(key_old.sign(&message).to_bytes()),
        "sig_by_new_identity": B64.encode(key_new.sign(&message).to_bytes())
    });
    let (status_confirm, body_confirm) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/confirm",
        rotate_confirm,
    )
    .await;
    assert_eq!(status_confirm, StatusCode::OK);
    assert_eq!(body_confirm["identity_key_version"].as_u64(), Some(2));

    let (status_bundle, bundle) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await;
    assert_eq!(status_bundle, StatusCode::OK);
    assert_eq!(
        bundle["identity_x25519_pub"].as_str(),
        Some(B64.encode(new_identity_x25519).as_str())
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
    assert_eq!(events[1]["version"].as_u64(), Some(1));
    assert_eq!(events[1]["event_type"].as_str(), Some("initial"));
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
        "new_device_id": "bob-dev-2"
    });
    let (status_init, body_init) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/init",
        rotate_init,
    )
    .await;
    assert_eq!(status_init, StatusCode::OK);

    let challenge_id = body_init["challenge_id"].as_str().expect("challenge_id");
    let rotate_confirm = json!({
        "challenge_id": challenge_id,
        "sig_by_current_identity": B64.encode(attacker.sign(b"bad").to_bytes()),
        "sig_by_new_identity": B64.encode(attacker.sign(b"bad").to_bytes())
    });
    let (status_confirm, body_confirm) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/bob/rotate/confirm",
        rotate_confirm,
    )
    .await;
    assert_eq!(status_confirm, StatusCode::BAD_REQUEST);
    assert_eq!(body_confirm["status"].as_u64(), Some(400));
}

#[tokio::test]
async fn relay_and_inbox_require_authenticated_headers() {
    let app = test_app().await;
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
}
