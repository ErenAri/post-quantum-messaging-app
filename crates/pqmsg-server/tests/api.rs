use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use pqmsg_core::alg::PROTOCOL_VERSION_V1;
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_server::{build_router, init_db, AppState, RateLimiter};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tower::ServiceExt;

async fn test_app() -> axum::Router {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect sqlite memory");
    init_db(&pool).await.expect("migrate");
    let state = AppState::new(pool, Arc::new(RateLimiter::new(1_000.0, 1_000.0)));
    build_router(state)
}

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
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
    let (status_relay, relay_body) =
        json_request(app.clone(), Method::POST, "/v1/relay/bob", relay).await;
    assert_eq!(status_relay, StatusCode::OK);
    let message_id = relay_body["message_id"].as_i64().expect("message_id");

    let (status_inbox, inbox_body) =
        json_request(app.clone(), Method::GET, "/v1/inbox/bob?since=0", json!({})).await;
    assert_eq!(status_inbox, StatusCode::OK);
    let messages = inbox_body["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["message_id"].as_i64(), Some(message_id));
    assert_eq!(messages[0]["sender_user_id"].as_str(), Some("alice"));

    let uri = format!("/v1/inbox/bob?since={message_id}");
    let (status_inbox2, inbox_body2) =
        json_request(app.clone(), Method::GET, &uri, json!({})).await;
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
