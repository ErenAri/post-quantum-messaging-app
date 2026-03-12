use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use pqmsg_core::alg::{SecurityProfile, PROTOCOL_VERSION_V1};
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_server::{build_router, init_db, parse_db_backend, AppState, DbBackend, RateLimiter};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::any::AnyPoolOptions;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tower::ServiceExt;

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
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

async fn json_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
) -> anyhow::Result<(StatusCode, Value)> {
    json_request_with_headers(app, method, uri, body, &[]).await
}

async fn json_request_with_headers(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, String)],
) -> anyhow::Result<(StatusCode, Value)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let request = builder.body(Body::from(body.to_string()))?;
    let response = app.oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let payload: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
    Ok((status, payload))
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

fn prekeys_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    signed_prekey_x25519_pub_b64: &str,
    pq_signed_prekey_pub_mlkem768_b64: &str,
) -> Vec<(&'static str, String)> {
    let timestamp = Utc::now().timestamp();
    let nonce = format!("prekeys-{}", NONCE_COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut records = auth_common_records("prekeys", user_id, device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(signed_prekey_x25519_pub_b64.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_SPK_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(pq_signed_prekey_pub_mlkem768_b64.as_bytes());
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    let database_url = env::var("PQMSG_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:admin@localhost:5432/pqmsg".to_string());
    let db_backend = parse_db_backend(&database_url).map_err(anyhow::Error::msg)?;
    if db_backend != DbBackend::Postgres {
        return Err(anyhow::anyhow!(
            "postgres_smoke requires PostgreSQL URL; got '{}'",
            database_url
        ));
    }

    let pool = AnyPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    init_db(&pool, db_backend).await?;

    sqlx::query(
        "TRUNCATE TABLE
            identity_rotation_challenges,
            identity_events,
            relay_messages,
            one_time_prekeys_mlkem768,
            one_time_prekeys_x25519,
            prekeys,
            users
         RESTART IDENTITY CASCADE",
    )
    .execute(&pool)
    .await?;

    let app = build_router(
        AppState::with_security_profile(
            pool,
            db_backend,
            Arc::new(RateLimiter::new(
                1_000.0,
                1_000.0,
                100_000,
                StdDuration::from_secs(600),
            )),
            SecurityProfile::Research,
        )
        .with_authenticated_direct_messaging_supported(true),
    );

    let alice_sig = signing_key(11);
    let bob_sig = signing_key(22);
    let alice_device = "alice-dev-1";
    let bob_device = "bob-dev-1";

    let (status_alice_reg, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        register_payload("alice", alice_device, [1u8; 32], &alice_sig),
    )
    .await?;
    if status_alice_reg != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "alice register failed with status {}",
            status_alice_reg
        ));
    }

    let (status_bob_reg, _) = json_request(
        app.clone(),
        Method::POST,
        "/v1/users/register",
        register_payload("bob", bob_device, [2u8; 32], &bob_sig),
    )
    .await?;
    if status_bob_reg != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "bob register failed with status {}",
            status_bob_reg
        ));
    }

    let bob_pq_spk = vec![5u8; 1184];
    let bob_publish_payload = publish_prekeys_payload(
        &bob_sig,
        [3u8; 32],
        bob_pq_spk.clone(),
        vec![[4u8; 32]],
        vec![vec![6u8; 1184]],
    );
    let bob_spk_b64 = bob_publish_payload["signed_prekey_x25519_pub"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing signed_prekey_x25519_pub in payload"))?
        .to_string();
    let bob_pq_b64 = bob_publish_payload["pq_signed_prekey_pub_mlkem768"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing pq_signed_prekey_pub_mlkem768 in payload"))?
        .to_string();
    let bob_prekey_headers =
        prekeys_auth_headers(&bob_sig, "bob", bob_device, &bob_spk_b64, &bob_pq_b64);

    let (status_publish, _) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/users/bob/prekeys",
        bob_publish_payload,
        &bob_prekey_headers,
    )
    .await?;
    if status_publish != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "bob prekey publish failed with status {}",
            status_publish
        ));
    }

    let (status_bundle, _) =
        json_request(app.clone(), Method::GET, "/v1/users/bob/bundle", json!({})).await?;
    if status_bundle != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "bundle fetch failed with status {}",
            status_bundle
        ));
    }

    let blob = b"opaque-ciphertext";
    let relay_headers = relay_auth_headers(&alice_sig, "alice", alice_device, "bob", blob);
    let relay_body = json!({
        "sender_user_id": "alice",
        "device_id": alice_device,
        "message_bytes_base64": B64.encode(blob)
    });
    let (status_relay, relay_payload) = json_request_with_headers(
        app.clone(),
        Method::POST,
        "/v1/relay/bob",
        relay_body,
        &relay_headers,
    )
    .await?;
    if status_relay != StatusCode::OK {
        return Err(anyhow::anyhow!("relay failed with status {}", status_relay));
    }

    let message_id = relay_payload["message_id"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("relay response missing message_id"))?;
    if message_id <= 0 {
        return Err(anyhow::anyhow!(
            "relay returned invalid message_id {message_id}"
        ));
    }

    let inbox_headers = inbox_auth_headers(&bob_sig, "bob", bob_device, 0);
    let (status_inbox, inbox_payload) = json_request_with_headers(
        app,
        Method::GET,
        "/v1/inbox/bob?since=0",
        json!({}),
        &inbox_headers,
    )
    .await?;
    if status_inbox != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "inbox fetch failed with status {}",
            status_inbox
        ));
    }

    let messages = inbox_payload["messages"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("inbox response missing messages array"))?;
    if messages.is_empty() {
        return Err(anyhow::anyhow!("inbox returned zero messages"));
    }

    let first = &messages[0];
    let sender = first["sender_user_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("inbox message missing sender_user_id"))?;
    if sender != "alice" {
        return Err(anyhow::anyhow!("unexpected sender '{}'", sender));
    }

    let received_blob_b64 = first["message_bytes_base64"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("inbox message missing message_bytes_base64"))?;
    let received_blob = B64.decode(received_blob_b64.as_bytes())?;
    if received_blob != blob {
        return Err(anyhow::anyhow!("inbox blob mismatch"));
    }

    println!(
        "postgres_smoke success: registered users, published prekeys, relayed message_id={}, inbox_count={}",
        message_id,
        messages.len()
    );

    Ok(())
}
