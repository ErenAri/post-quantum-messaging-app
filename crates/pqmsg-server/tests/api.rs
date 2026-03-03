use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
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

#[tokio::test]
async fn happy_path_register_publish_bundle_relay_inbox() {
    let app = test_app().await;

    let x25519 = B64.encode([1u8; 32]);
    let sig_pub = B64.encode([2u8; 32]);
    let reg_bob = json!({
        "user_id": "bob",
        "identity_x25519_pub": x25519,
        "identity_sig_pub": sig_pub,
        "device_id": "bob-dev-1"
    });
    let (status_bob, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_bob).await;
    assert_eq!(status_bob, StatusCode::OK);

    let reg_alice = json!({
        "user_id": "alice",
        "identity_x25519_pub": B64.encode([3u8; 32]),
        "identity_sig_pub": B64.encode([4u8; 32]),
        "device_id": "alice-dev-1"
    });
    let (status_alice, _) =
        json_request(app.clone(), Method::POST, "/v1/users/register", reg_alice).await;
    assert_eq!(status_alice, StatusCode::OK);

    let publish = json!({
        "signed_prekey_x25519_pub": B64.encode([5u8; 32]),
        "sig_over_spk": B64.encode([6u8; 64]),
        "pq_signed_prekey_pub_mlkem768": B64.encode([7u8; 64]),
        "sig_over_pqspk": B64.encode([8u8; 64]),
        "one_time_prekeys_x25519": [B64.encode([9u8; 32]), B64.encode([10u8; 32])],
        "one_time_prekeys_mlkem768": [B64.encode([11u8; 64]), B64.encode([12u8; 64])]
    });
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

    let invalid_register = json!({
        "user_id": "bob",
        "identity_x25519_pub": B64.encode([1u8; 31]),
        "identity_sig_pub": B64.encode([2u8; 32]),
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

    let valid_register = json!({
        "user_id": "bob",
        "identity_x25519_pub": B64.encode([3u8; 32]),
        "identity_sig_pub": B64.encode([4u8; 32]),
        "device_id": "bob-dev-1"
    });
    let (status_valid_register, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        valid_register,
    )
    .await;
    assert_eq!(status_valid_register, StatusCode::OK);

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
