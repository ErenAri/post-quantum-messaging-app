//! Server load benchmarks.
//!
//! Measures throughput of hot-path endpoints under simulated load using
//! in-process tower `oneshot` calls (no TCP overhead).

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ed25519_dalek::{Signer, SigningKey};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_server::{build_router, init_db, parse_db_backend, AppState, RateLimiter};
use serde_json::{json, Value};
use sqlx::any::AnyPoolOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tower::ServiceExt;

// ── Auth constants (mirrored from e2e.rs) ───────────────────────

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

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1_000_000);

// ── Helpers ─────────────────────────────────────────────────────

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
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
    key: &SigningKey,
    sender_user_id: &str,
    sender_device_id: &str,
    recipient_user_id: &str,
    message_blob: &[u8],
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "bench-relay-{}",
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
    let signature = key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, sender_user_id.to_string()),
        (AUTH_HEADER_DEVICE, sender_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

fn inbox_auth_headers(
    key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!(
        "bench-inbox-{}",
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
    let signature = key.sign(&message).to_bytes();
    vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ]
}

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, String)],
) -> StatusCode {
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
    response.status()
}

async fn setup_app() -> axum::Router {
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
            1_000_000.0,
            1_000_000.0,
            10_000_000,
            Duration::from_secs(600),
        )),
    );
    build_router(state)
}

async fn register_user(app: &axum::Router, user_id: &str, device_id: &str, key: &SigningKey) {
    let payload = json!({
        "user_id": user_id,
        "identity_x25519_pub": B64.encode([0x42u8; 32]),
        "identity_sig_pub": B64.encode(key.verifying_key().to_bytes()),
        "device_id": device_id,
    });
    let status = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        payload,
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register {user_id}");
}

// ── Benchmarks ──────────────────────────────────────────────────

fn bench_health(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let app = rt.block_on(setup_app());

    c.bench_function("health_check", |b| {
        b.to_async(&rt).iter(|| {
            let app = app.clone();
            async move {
                let request = Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap();
                let resp = app.oneshot(request).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        })
    });
}

fn bench_relay(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let app = rt.block_on(setup_app());
    let alice_key = signing_key(10);
    let _bob_key = signing_key(20);
    let relay_counter = AtomicU64::new(0);

    rt.block_on(async {
        register_user(&app, "bench-alice", "alice-d1", &alice_key).await;
        register_user(&app, "bench-bob", "bob-d1", &_bob_key).await;
    });

    let mut group = c.benchmark_group("message_relay");
    for payload_size in [64, 256, 1024, 4096] {
        group.throughput(Throughput::Bytes(payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{payload_size}B")),
            &payload_size,
            |b, &size| {
                b.to_async(&rt).iter(|| {
                    let app = app.clone();
                    // Unique payload per iteration to bypass relay dedup
                    let seq = relay_counter.fetch_add(1, Ordering::Relaxed);
                    let mut ct = vec![0xAA; size];
                    ct[..8.min(size)].copy_from_slice(&seq.to_be_bytes()[..8.min(size)]);
                    let auth =
                        relay_auth_headers(&alice_key, "bench-alice", "alice-d1", "bench-bob", &ct);
                    async move {
                        let payload = json!({
                            "sender_user_id": "bench-alice",
                            "device_id": "alice-d1",
                            "message_bytes_base64": B64.encode(&ct)
                        });
                        let status =
                            json_request(app, Method::POST, "/v1/relay/bench-bob", payload, &auth)
                                .await;
                        assert_eq!(status, StatusCode::OK);
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_inbox_poll(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let app = rt.block_on(setup_app());
    let alice_key = signing_key(30);
    let bob_key = signing_key(40);

    rt.block_on(async {
        register_user(&app, "inbox-alice", "alice-d1", &alice_key).await;
        register_user(&app, "inbox-bob", "bob-d1", &bob_key).await;

        // Seed 50 messages in Bob's inbox (unique payloads to bypass dedup)
        for i in 0u64..50 {
            let mut ct = b"bench-message-payload-00000000".to_vec();
            ct[21..29].copy_from_slice(&i.to_be_bytes());
            let auth = relay_auth_headers(&alice_key, "inbox-alice", "alice-d1", "inbox-bob", &ct);
            let payload = json!({
                "sender_user_id": "inbox-alice",
                "device_id": "alice-d1",
                "message_bytes_base64": B64.encode(&ct)
            });
            let status = json_request(
                app.clone(),
                Method::POST,
                "/v1/relay/inbox-bob",
                payload,
                &auth,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
    });

    // Bench inbox poll throughput. The first poll (since=0) returns all 50 messages;
    // subsequent polls use incrementing since values and return fewer/no messages,
    // but still exercise the full auth + query + serialization path.
    let since_counter = AtomicU64::new(0);
    c.bench_function("inbox_poll", |b| {
        b.to_async(&rt).iter(|| {
            let app = app.clone();
            let since = since_counter.fetch_add(1, Ordering::Relaxed) as i64;
            let auth = inbox_auth_headers(&bob_key, "inbox-bob", "bob-d1", since);
            let uri = format!("/v1/inbox/inbox-bob?since={since}");
            async move {
                let _status = json_request(app, Method::GET, &uri, json!({}), &auth).await;
            }
        })
    });
}

fn bench_registration(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let counter = AtomicU64::new(0);

    c.bench_function("user_registration", |b| {
        b.to_async(&rt).iter(|| {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            async move {
                // Each iteration uses a fresh DB to avoid duplicate user_id errors
                let app = setup_app().await;
                let user_id = format!("reg-user-{n}");
                let key = signing_key((n % 200) as u8);
                let payload = json!({
                    "user_id": user_id,
                    "identity_x25519_pub": B64.encode([0x42u8; 32]),
                    "identity_sig_pub": B64.encode(key.verifying_key().to_bytes()),
                    "device_id": "dev1",
                });
                let status =
                    json_request(app, Method::POST, "/v1/users/register", payload, &[]).await;
                assert_eq!(status, StatusCode::OK);
            }
        })
    });
}

criterion_group!(
    benches,
    bench_health,
    bench_relay,
    bench_inbox_poll,
    bench_registration,
);
criterion_main!(benches);
