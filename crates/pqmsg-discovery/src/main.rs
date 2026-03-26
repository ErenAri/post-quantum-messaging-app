use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

const DEFAULT_BIND: &str = "127.0.0.1:8082";
const DEFAULT_ATTESTATION_MODE: &str = "unattested_development";
const CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS: i64 = 300;
const CONTACT_DISCOVERY_MANIFEST_MAX_TTL_SECONDS: i64 = 3600;
const MAX_DISCOVERY_HASHES_PER_REQUEST: usize = 2048;

#[derive(Clone)]
struct AppState {
    ticket_issuer_verifying_key: Arc<VerifyingKey>,
    manifest_signing_key: Arc<SigningKey>,
    attestation_mode: String,
    registry: Arc<RwLock<DiscoveryRegistry>>,
}

impl AppState {
    fn ticket_issuer_public_key_b64(&self) -> String {
        B64.encode(self.ticket_issuer_verifying_key.as_bytes())
    }

    fn manifest_issuer_public_key_b64(&self) -> String {
        B64.encode(self.manifest_signing_key.verifying_key().as_bytes())
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    attestation_mode: String,
    ticket_verifier_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ManifestPayload {
    service: &'static str,
    protocol_version: u8,
    attestation_mode: String,
    ticket_format: &'static str,
    ticket_issuer_ed25519_pub: String,
    ticket_max_ttl_seconds: i64,
    lookup_protocol: &'static str,
    privacy_mode: &'static str,
    match_result_format: &'static str,
    signed_at: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct ManifestResponse {
    #[serde(flatten)]
    payload: ManifestPayload,
    manifest_issuer_ed25519_pub: String,
    manifest_signature_ed25519: String,
}

#[derive(Debug, Serialize)]
struct ProblemJson<'a> {
    r#type: &'a str,
    title: &'a str,
    status: u16,
    detail: String,
}

#[derive(Debug)]
struct DiscoveryError {
    status: StatusCode,
    title: &'static str,
    detail: String,
}

impl DiscoveryError {
    fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            title: "Bad Request",
            detail: detail.into(),
        }
    }
}

impl IntoResponse for DiscoveryError {
    fn into_response(self) -> Response {
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(ProblemJson {
                r#type: "about:blank",
                title: self.title,
                status: self.status.as_u16(),
                detail: self.detail,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ContactDiscoveryTicketClaims {
    v: u8,
    user_id: String,
    device_id: String,
    contact_invite_token: String,
    contact_invite_expires_at: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredHandle {
    hash_sha256: String,
    handle_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredUserHandles {
    contact_invite_token: String,
    contact_invite_expires_at: String,
    handles: Vec<StoredHandle>,
}

#[derive(Debug, Default)]
struct DiscoveryRegistry {
    user_handles: HashMap<String, StoredUserHandles>,
}

impl DiscoveryRegistry {
    fn replace_handles(
        &mut self,
        user_id: &str,
        contact_invite_token: &str,
        contact_invite_expires_at: &str,
        phone_hashes: &[String],
        email_hashes: &[String],
    ) {
        let mut handles = Vec::with_capacity(phone_hashes.len() + email_hashes.len());
        handles.extend(
            phone_hashes
                .iter()
                .cloned()
                .map(|hash_sha256| StoredHandle {
                    hash_sha256,
                    handle_kind: "phone".to_string(),
                }),
        );
        handles.extend(
            email_hashes
                .iter()
                .cloned()
                .map(|hash_sha256| StoredHandle {
                    hash_sha256,
                    handle_kind: "email".to_string(),
                }),
        );
        self.user_handles.insert(
            user_id.to_string(),
            StoredUserHandles {
                contact_invite_token: contact_invite_token.to_string(),
                contact_invite_expires_at: contact_invite_expires_at.to_string(),
                handles,
            },
        );
    }

    fn match_hashes(
        &self,
        requester_user_id: &str,
        query_hashes: &[String],
        now: DateTime<Utc>,
    ) -> Vec<DiscoveryMatchItem> {
        let query_set: HashSet<&str> = query_hashes.iter().map(String::as_str).collect();
        let mut matches = Vec::new();
        for (user_id, stored_handles) in &self.user_handles {
            if user_id == requester_user_id {
                continue;
            }
            let invite_expires_at =
                match DateTime::parse_from_rfc3339(&stored_handles.contact_invite_expires_at) {
                    Ok(value) => value.with_timezone(&Utc),
                    Err(_) => continue,
                };
            if invite_expires_at <= now {
                continue;
            }
            for handle in &stored_handles.handles {
                if query_set.contains(handle.hash_sha256.as_str()) {
                    matches.push(DiscoveryMatchItem {
                        hash_sha256: handle.hash_sha256.clone(),
                        contact_invite_token: stored_handles.contact_invite_token.clone(),
                        handle_kind: handle.handle_kind.clone(),
                    });
                }
            }
        }
        matches.sort_by(|left, right| {
            left.hash_sha256
                .cmp(&right.hash_sha256)
                .then_with(|| left.contact_invite_token.cmp(&right.contact_invite_token))
                .then_with(|| left.handle_kind.cmp(&right.handle_kind))
        });
        matches
    }
}

#[derive(Debug, Deserialize)]
struct DiscoveryHandlesUploadRequest {
    ticket: String,
    phone_hashes_sha256: Vec<String>,
    email_hashes_sha256: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiscoveryHandlesUploadResponse {
    user_id: String,
    device_id: String,
    uploaded_phone_hashes: usize,
    uploaded_email_hashes: usize,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct DiscoveryMatchRequest {
    ticket: String,
    hashes_sha256: Vec<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct DiscoveryMatchItem {
    hash_sha256: String,
    contact_invite_token: String,
    handle_kind: String,
}

#[derive(Debug, Serialize)]
struct DiscoveryMatchResponse {
    user_id: String,
    matches: Vec<DiscoveryMatchItem>,
    checked_at: String,
}

fn normalize_sha256_hashes(field: &str, values: &[String]) -> Result<Vec<String>, DiscoveryError> {
    if values.len() > MAX_DISCOVERY_HASHES_PER_REQUEST {
        return Err(DiscoveryError::bad_request(format!(
            "{field} must contain at most {MAX_DISCOVERY_HASHES_PER_REQUEST} values"
        )));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let trimmed = value.trim().to_ascii_lowercase();
        if trimmed.len() != 64 || !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(DiscoveryError::bad_request(format!(
                "{field} entries must be 64-character SHA-256 hex strings"
            )));
        }
        normalized.push(trimmed);
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        attestation_mode: state.attestation_mode.clone(),
        ticket_verifier_ready: true,
    })
}

async fn manifest(State(state): State<AppState>) -> Json<ManifestResponse> {
    let signed_at = Utc::now();
    let expires_at =
        signed_at + chrono::Duration::seconds(CONTACT_DISCOVERY_MANIFEST_MAX_TTL_SECONDS);
    let payload = ManifestPayload {
        service: "pqmsg-discovery",
        protocol_version: 1,
        attestation_mode: state.attestation_mode.clone(),
        ticket_format: "base64(json-payload).base64(ed25519-signature)",
        ticket_issuer_ed25519_pub: state.ticket_issuer_public_key_b64(),
        ticket_max_ttl_seconds: CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS,
        lookup_protocol: "hashed_handle_directory",
        privacy_mode: "service_boundary_only",
        match_result_format: "contact_invite_token",
        signed_at: signed_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };
    let payload_bytes = serde_json::to_vec(&payload).expect("serialize discovery manifest payload");
    let signature = state.manifest_signing_key.sign(&payload_bytes).to_bytes();
    Json(ManifestResponse {
        payload,
        manifest_issuer_ed25519_pub: state.manifest_issuer_public_key_b64(),
        manifest_signature_ed25519: B64.encode(signature),
    })
}

async fn upload_handles(
    State(state): State<AppState>,
    Json(request): Json<DiscoveryHandlesUploadRequest>,
) -> Result<Json<DiscoveryHandlesUploadResponse>, DiscoveryError> {
    let claims = verify_contact_discovery_ticket(
        &state.ticket_issuer_verifying_key,
        &request.ticket,
        Utc::now(),
    )
    .map_err(|error| DiscoveryError::bad_request(error.to_string()))?;
    let phone_hashes =
        normalize_sha256_hashes("phone_hashes_sha256", &request.phone_hashes_sha256)?;
    let email_hashes =
        normalize_sha256_hashes("email_hashes_sha256", &request.email_hashes_sha256)?;
    let now = Utc::now().to_rfc3339();
    state.registry.write().await.replace_handles(
        &claims.user_id,
        &claims.contact_invite_token,
        &claims.contact_invite_expires_at,
        &phone_hashes,
        &email_hashes,
    );
    Ok(Json(DiscoveryHandlesUploadResponse {
        user_id: claims.user_id,
        device_id: claims.device_id,
        uploaded_phone_hashes: phone_hashes.len(),
        uploaded_email_hashes: email_hashes.len(),
        updated_at: now,
    }))
}

async fn match_handles(
    State(state): State<AppState>,
    Json(request): Json<DiscoveryMatchRequest>,
) -> Result<Json<DiscoveryMatchResponse>, DiscoveryError> {
    let claims = verify_contact_discovery_ticket(
        &state.ticket_issuer_verifying_key,
        &request.ticket,
        Utc::now(),
    )
    .map_err(|error| DiscoveryError::bad_request(error.to_string()))?;
    let query_hashes = normalize_sha256_hashes("hashes_sha256", &request.hashes_sha256)?;
    let matches =
        state
            .registry
            .read()
            .await
            .match_hashes(&claims.user_id, &query_hashes, Utc::now());
    Ok(Json(DiscoveryMatchResponse {
        user_id: claims.user_id,
        matches,
        checked_at: Utc::now().to_rfc3339(),
    }))
}

fn parse_ticket_issuer_verifying_key() -> Result<Arc<VerifyingKey>> {
    let raw = env::var("PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB")
        .with_context(|| "PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB is required")?;
    let decoded = B64
        .decode(raw.trim().as_bytes())
        .with_context(|| {
            "invalid PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB: expected base64-encoded 32-byte Ed25519 public key"
        })?;
    let key_bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "invalid PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB: expected 32 decoded bytes"
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).with_context(|| {
        "invalid PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB: invalid Ed25519 public key"
    })?;
    Ok(Arc::new(verifying_key))
}

fn parse_manifest_signing_key() -> Result<Arc<SigningKey>> {
    let raw = env::var("PQMSG_CONTACT_DISCOVERY_MANIFEST_ED25519_SECRET_B64")
        .with_context(|| "PQMSG_CONTACT_DISCOVERY_MANIFEST_ED25519_SECRET_B64 is required")?;
    let decoded = B64
        .decode(raw.trim().as_bytes())
        .with_context(|| {
            "invalid PQMSG_CONTACT_DISCOVERY_MANIFEST_ED25519_SECRET_B64: expected base64-encoded 32-byte Ed25519 secret key"
        })?;
    let key_bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "invalid PQMSG_CONTACT_DISCOVERY_MANIFEST_ED25519_SECRET_B64: expected 32 decoded bytes"
        )
    })?;
    Ok(Arc::new(SigningKey::from_bytes(&key_bytes)))
}

pub(crate) fn verify_contact_discovery_ticket(
    verifying_key: &VerifyingKey,
    ticket: &str,
    now: DateTime<Utc>,
) -> Result<ContactDiscoveryTicketClaims> {
    let trimmed = ticket.trim();
    if trimmed.is_empty() || trimmed.len() > 4096 {
        anyhow::bail!("ticket must be 1..=4096 characters");
    }
    let mut parts = trimmed.split('.');
    let payload_part = parts.next().context("ticket payload missing")?;
    let signature_part = parts.next().context("ticket signature missing")?;
    if parts.next().is_some() {
        anyhow::bail!("ticket must contain exactly one separator");
    }
    let payload_bytes = B64
        .decode(payload_part.as_bytes())
        .context("decode contact discovery ticket payload")?;
    let signature_bytes = B64
        .decode(signature_part.as_bytes())
        .context("decode contact discovery ticket signature")?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("contact discovery ticket signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(&payload_bytes, &signature)
        .context("verify contact discovery ticket signature")?;

    let claims: ContactDiscoveryTicketClaims =
        serde_json::from_slice(&payload_bytes).context("parse contact discovery ticket payload")?;
    if claims.v != 1 {
        anyhow::bail!("unsupported contact discovery ticket version");
    }
    if claims.user_id.trim().is_empty() || claims.device_id.trim().is_empty() {
        anyhow::bail!("contact discovery ticket is missing user or device identity");
    }
    if claims.contact_invite_token.trim().is_empty()
        || claims.contact_invite_token.len() > 128
        || !claims
            .contact_invite_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        anyhow::bail!("contact discovery ticket is missing a valid bootstrap invite token");
    }
    if claims.nonce.trim().is_empty() || claims.nonce.len() > 128 {
        anyhow::bail!("contact discovery ticket nonce is invalid");
    }
    let issued_at = DateTime::parse_from_rfc3339(&claims.issued_at)
        .context("parse contact discovery ticket issued_at")?
        .with_timezone(&Utc);
    let expires_at = DateTime::parse_from_rfc3339(&claims.expires_at)
        .context("parse contact discovery ticket expires_at")?
        .with_timezone(&Utc);
    let contact_invite_expires_at = DateTime::parse_from_rfc3339(&claims.contact_invite_expires_at)
        .context("parse contact discovery ticket bootstrap invite expires_at")?
        .with_timezone(&Utc);
    if expires_at <= issued_at {
        anyhow::bail!("contact discovery ticket expires_at must be after issued_at");
    }
    if contact_invite_expires_at <= issued_at {
        anyhow::bail!(
            "contact discovery ticket bootstrap invite expires_at must be after issued_at"
        );
    }
    if expires_at.signed_duration_since(issued_at).num_seconds()
        > CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS
    {
        anyhow::bail!("contact discovery ticket exceeds max ttl");
    }
    if expires_at <= now {
        anyhow::bail!("contact discovery ticket expired");
    }
    Ok(claims)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pqmsg_discovery=info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let bind = env::var("PQMSG_DISCOVERY_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let bind_addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid PQMSG_DISCOVERY_BIND '{bind}'"))?;
    let attestation_mode = env::var("PQMSG_CONTACT_DISCOVERY_ATTESTATION_MODE")
        .unwrap_or_else(|_| DEFAULT_ATTESTATION_MODE.to_string());
    let ticket_issuer_verifying_key = parse_ticket_issuer_verifying_key()?;
    let manifest_signing_key = parse_manifest_signing_key()?;

    let state = AppState {
        ticket_issuer_verifying_key,
        manifest_signing_key,
        attestation_mode,
        registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/manifest", get(manifest))
        .route("/v1/discovery/handles", post(upload_handles))
        .route("/v1/discovery/match", post(match_handles))
        .with_state(state);

    info!("pqmsg-discovery listening on {}", bind_addr);
    axum::serve(
        tokio::net::TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("bind discovery listener on {bind_addr}"))?,
        app,
    )
    .await
    .context("serve pqmsg-discovery")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;

    fn signed_ticket(
        signing_key: &SigningKey,
        issued_at: &str,
        expires_at: &str,
    ) -> (String, ContactDiscoveryTicketClaims) {
        let claims = ContactDiscoveryTicketClaims {
            v: 1,
            user_id: "alice".to_string(),
            device_id: "alice-dev-1".to_string(),
            contact_invite_token: "invite-bootstrap-1".to_string(),
            contact_invite_expires_at: "2026-03-27T12:00:00Z".to_string(),
            issued_at: issued_at.to_string(),
            expires_at: expires_at.to_string(),
            nonce: "nonce-1".to_string(),
        };
        let payload = serde_json::to_vec(&claims).expect("serialize claims");
        let signature = signing_key.sign(&payload).to_bytes();
        (
            format!("{}.{}", B64.encode(payload), B64.encode(signature)),
            claims,
        )
    }

    #[test]
    fn verify_contact_discovery_ticket_accepts_valid_ticket() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let (ticket, claims) =
            signed_ticket(&signing_key, "2026-03-13T12:00:00Z", "2026-03-13T12:05:00Z");
        let verified = verify_contact_discovery_ticket(
            &verifying_key,
            &ticket,
            DateTime::parse_from_rfc3339("2026-03-13T12:02:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        )
        .expect("verify ticket");
        assert_eq!(verified, claims);
    }

    #[test]
    fn verify_contact_discovery_ticket_rejects_expired_ticket() {
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let (ticket, _) =
            signed_ticket(&signing_key, "2026-03-13T12:00:00Z", "2026-03-13T12:05:00Z");
        let error = verify_contact_discovery_ticket(
            &verifying_key,
            &ticket,
            DateTime::parse_from_rfc3339("2026-03-13T12:06:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        )
        .expect_err("ticket should expire");
        assert!(error.to_string().contains("expired"));
    }

    #[test]
    fn verify_contact_discovery_ticket_rejects_bad_signature() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let (ticket, _) = signed_ticket(
            &SigningKey::from_bytes(&[10u8; 32]),
            "2026-03-13T12:00:00Z",
            "2026-03-13T12:05:00Z",
        );
        let error = verify_contact_discovery_ticket(
            &verifying_key,
            &ticket,
            DateTime::parse_from_rfc3339("2026-03-13T12:01:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        )
        .expect_err("signature mismatch");
        assert!(error.to_string().contains("signature"));
    }

    #[tokio::test]
    async fn manifest_is_signed_by_configured_manifest_key() {
        let ticket_signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let manifest_signing_key = Arc::new(SigningKey::from_bytes(&[12u8; 32]));
        let state = AppState {
            ticket_issuer_verifying_key: Arc::new(ticket_signing_key.verifying_key()),
            manifest_signing_key: manifest_signing_key.clone(),
            attestation_mode: DEFAULT_ATTESTATION_MODE.to_string(),
            registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
        };
        let response = manifest(State(state)).await.0;
        let payload_bytes =
            serde_json::to_vec(&response.payload).expect("serialize manifest payload");
        let signature_bytes = B64
            .decode(response.manifest_signature_ed25519.as_bytes())
            .expect("decode manifest signature");
        let signature = Signature::from_bytes(
            &signature_bytes
                .as_slice()
                .try_into()
                .expect("manifest signature length"),
        );
        manifest_signing_key
            .verifying_key()
            .verify(&payload_bytes, &signature)
            .expect("verify manifest signature");
        assert_eq!(
            response.manifest_issuer_ed25519_pub,
            B64.encode(manifest_signing_key.verifying_key().as_bytes())
        );
        let signed_at = DateTime::parse_from_rfc3339(&response.payload.signed_at)
            .expect("parse signed_at")
            .with_timezone(&Utc);
        let expires_at = DateTime::parse_from_rfc3339(&response.payload.expires_at)
            .expect("parse expires_at")
            .with_timezone(&Utc);
        assert!(expires_at > signed_at);
        assert_eq!(
            expires_at.signed_duration_since(signed_at),
            Duration::seconds(CONTACT_DISCOVERY_MANIFEST_MAX_TTL_SECONDS)
        );
    }

    #[test]
    fn registry_replaces_handles_and_matches_other_users() {
        let mut registry = DiscoveryRegistry::default();
        registry.replace_handles(
            "alice",
            "invite-alice",
            "2026-03-27T12:00:00Z",
            &["11".repeat(32)],
            &["22".repeat(32)],
        );
        registry.replace_handles(
            "bob",
            "invite-bob",
            "2026-03-27T12:00:00Z",
            &["33".repeat(32)],
            &["44".repeat(32), "11".repeat(32)],
        );
        let matches = registry.match_hashes(
            "alice",
            &["11".repeat(32), "44".repeat(32)],
            DateTime::parse_from_rfc3339("2026-03-13T12:01:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        );
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].contact_invite_token, "invite-bob");
        assert_eq!(matches[1].contact_invite_token, "invite-bob");
    }

    #[test]
    fn registry_filters_expired_bootstrap_invites() {
        let mut registry = DiscoveryRegistry::default();
        registry.replace_handles(
            "bob",
            "invite-bob",
            "2026-03-13T11:59:00Z",
            &["11".repeat(32)],
            &[],
        );
        let matches = registry.match_hashes(
            "alice",
            &["11".repeat(32)],
            DateTime::parse_from_rfc3339("2026-03-13T12:01:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        );
        assert!(matches.is_empty());
    }
}
