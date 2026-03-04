use axum::body::Body;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use pqmsg_core::alg::SecurityProfile;
use pqmsg_core::alg::PROTOCOL_VERSION_V1;
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_server::{build_router, init_db, parse_db_backend, AppState, RateLimiter};
use serde_json::{json, Value};
use sqlx::any::AnyPoolOptions;
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
const AUTH_TAG_PUSH_DEVICE_ID: u16 = critical_type(0x3210);
const AUTH_TAG_PUSH_TOKEN_HASH: u16 = critical_type(0x3211);
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

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

async fn spawn_http_server(app: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve app");
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
    let (status, body) = json_request(app, Method::GET, "/health", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"].as_str(), Some("ok"));
    assert_eq!(body["security_profile"].as_str(), Some("research"));
    assert_eq!(body["db_backend"].as_str(), Some("sqlite"));
    assert_eq!(body["db_ready"].as_bool(), Some(true));
    assert_eq!(body["push_enabled"].as_bool(), Some(false));
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
        "bob-dev-2",
    );
    let rotate_confirm = json!({
        "challenge_id": challenge_id,
        "sig_by_current_identity": B64.encode(key_old.sign(&message).to_bytes()),
        "sig_by_new_identity": B64.encode(key_new.sign(&message).to_bytes())
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
        "sig_by_new_identity": B64.encode(attacker.sign(b"bad").to_bytes())
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
    let app = test_app().await;
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
    let app = test_app().await;
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
async fn websocket_inbox_requires_authenticated_headers() {
    let app = test_app().await;
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
    let app = test_app().await;
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
