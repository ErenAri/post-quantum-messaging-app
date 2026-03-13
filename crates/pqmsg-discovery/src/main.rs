use anyhow::{Context, Result};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

const DEFAULT_BIND: &str = "127.0.0.1:8082";
const DEFAULT_ATTESTATION_MODE: &str = "unattested_development";
const CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS: i64 = 300;

#[derive(Clone)]
struct AppState {
    ticket_issuer_verifying_key: Arc<VerifyingKey>,
    attestation_mode: String,
}

impl AppState {
    fn ticket_issuer_public_key_b64(&self) -> String {
        B64.encode(self.ticket_issuer_verifying_key.as_bytes())
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    attestation_mode: String,
    ticket_verifier_ready: bool,
}

#[derive(Debug, Serialize)]
struct ManifestResponse {
    service: &'static str,
    protocol_version: u8,
    attestation_mode: String,
    ticket_format: &'static str,
    ticket_issuer_ed25519_pub: String,
    ticket_max_ttl_seconds: i64,
    lookup_protocol: &'static str,
    privacy_mode: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ContactDiscoveryTicketClaims {
    v: u8,
    user_id: String,
    device_id: String,
    issued_at: String,
    expires_at: String,
    nonce: String,
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        attestation_mode: state.attestation_mode.clone(),
        ticket_verifier_ready: true,
    })
}

async fn manifest(State(state): State<AppState>) -> Json<ManifestResponse> {
    Json(ManifestResponse {
        service: "pqmsg-discovery",
        protocol_version: 1,
        attestation_mode: state.attestation_mode.clone(),
        ticket_format: "base64(json-payload).base64(ed25519-signature)",
        ticket_issuer_ed25519_pub: state.ticket_issuer_public_key_b64(),
        ticket_max_ttl_seconds: CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS,
        lookup_protocol: "not_implemented",
        privacy_mode: "service_boundary_only",
    })
}

fn parse_ticket_issuer_verifying_key() -> Result<Arc<VerifyingKey>> {
    let raw = env::var("PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB").with_context(|| {
        "PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB is required"
    })?;
    let decoded = B64
        .decode(raw.trim().as_bytes())
        .with_context(|| {
            "invalid PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB: expected base64-encoded 32-byte Ed25519 public key"
        })?;
    let key_bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!(
                "invalid PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB: expected 32 decoded bytes"
            )
        })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).with_context(|| {
        "invalid PQMSG_CONTACT_DISCOVERY_TICKET_ISSUER_ED25519_PUB: invalid Ed25519 public key"
    })?;
    Ok(Arc::new(verifying_key))
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

    let claims: ContactDiscoveryTicketClaims = serde_json::from_slice(&payload_bytes)
        .context("parse contact discovery ticket payload")?;
    if claims.v != 1 {
        anyhow::bail!("unsupported contact discovery ticket version");
    }
    if claims.user_id.trim().is_empty() || claims.device_id.trim().is_empty() {
        anyhow::bail!("contact discovery ticket is missing user or device identity");
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
    if expires_at <= issued_at {
        anyhow::bail!("contact discovery ticket expires_at must be after issued_at");
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

    let state = AppState {
        ticket_issuer_verifying_key,
        attestation_mode,
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/manifest", get(manifest))
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
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_ticket(
        signing_key: &SigningKey,
        issued_at: &str,
        expires_at: &str,
    ) -> (String, ContactDiscoveryTicketClaims) {
        let claims = ContactDiscoveryTicketClaims {
            v: 1,
            user_id: "alice".to_string(),
            device_id: "alice-dev-1".to_string(),
            issued_at: issued_at.to_string(),
            expires_at: expires_at.to_string(),
            nonce: "nonce-1".to_string(),
        };
        let payload = serde_json::to_vec(&claims).expect("serialize claims");
        let signature = signing_key.sign(&payload).to_bytes();
        (format!("{}.{}", B64.encode(payload), B64.encode(signature)), claims)
    }

    #[test]
    fn verify_contact_discovery_ticket_accepts_valid_ticket() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let (ticket, claims) = signed_ticket(
            &signing_key,
            "2026-03-13T12:00:00Z",
            "2026-03-13T12:05:00Z",
        );
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
        let (ticket, _) = signed_ticket(
            &signing_key,
            "2026-03-13T12:00:00Z",
            "2026-03-13T12:05:00Z",
        );
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
}


