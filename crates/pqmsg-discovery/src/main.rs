use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

const DEFAULT_BIND: &str = "127.0.0.1:8082";
const DEFAULT_ATTESTATION_MODE: &str = "attested_enclave_v1";
const CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS: i64 = 300;
const CONTACT_DISCOVERY_TICKET_MAX_USES: u8 = 6;
const CONTACT_DISCOVERY_TICKET_UPLOAD_MAX_USES: u8 = 3;
const CONTACT_DISCOVERY_TICKET_MATCH_MAX_USES: u8 = 2;
const CONTACT_DISCOVERY_MANIFEST_MAX_TTL_SECONDS: i64 = 3600;
const MAX_DISCOVERY_HASHES_PER_REQUEST: usize = 2048;
const CONTACT_DISCOVERY_LOOKUP_PROTOCOL: &str = "attested_enclave_voprf_directory_v1";
const CONTACT_DISCOVERY_PRIVACY_MODE: &str = "enclave_backed_private_discovery_v1";
const CONTACT_DISCOVERY_MATCH_RESULT_FORMAT: &str = "contact_invite_token";
const CONTACT_DISCOVERY_OPRF_SUITE: &str = "ristretto255-sha512-v1";
const CONTACT_DISCOVERY_EVALUATION_PROOF_MODE: &str = "dleq_per_element_v1";
const CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_FORMAT: &str = "opaque_b64_v1";
const CONTACT_DISCOVERY_ATTESTATION_CHALLENGE_MODE: &str = "nonce_b64_required_v1";
const CONTACT_DISCOVERY_DIRECTORY_BACKEND: &str = "attested_enclave_directory_v1";
const CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION: u8 = 1;
const DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID: &str = "attested-host-v1";
const DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID: &str = "attested-enclave-v1";
const CONTACT_DISCOVERY_HANDLE_DOMAIN: &[u8] = b"pqmsg-discovery-handle-v1";

#[derive(Clone)]
struct AppState {
    ticket_issuer_verifying_key: Arc<VerifyingKey>,
    manifest_signing_key: Arc<SigningKey>,
    attestation_mode: String,
    attestation_verifier: Option<String>,
    enclave_measurement_hex: Option<String>,
    attestation_pcrs_sha384: Option<BTreeMap<String, String>>,
    attestation_document_base64: Option<String>,
    attestation_document_sha256: Option<String>,
    registry: Arc<RwLock<DiscoveryRegistry>>,
    oprf_secret_scalar: Arc<Scalar>,
    oprf_public_key_ristretto255_b64: String,
    host_release_id: String,
    enclave_release_id: String,
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
    directory_backend: &'static str,
    host_enclave_protocol_version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ManifestPayload {
    service: &'static str,
    protocol_version: u8,
    attestation_mode: String,
    attestation_verifier: Option<String>,
    enclave_measurement_hex: Option<String>,
    attestation_pcrs_sha384: Option<BTreeMap<String, String>>,
    attestation_document_format: Option<String>,
    attestation_document_sha256: Option<String>,
    attestation_challenge_mode: Option<String>,
    ticket_format: &'static str,
    ticket_issuer_ed25519_pub: String,
    ticket_max_ttl_seconds: i64,
    lookup_protocol: &'static str,
    privacy_mode: &'static str,
    directory_backend: &'static str,
    host_enclave_protocol_version: u8,
    host_release_id: String,
    enclave_release_id: String,
    match_result_format: &'static str,
    oprf_suite: &'static str,
    evaluation_proof_mode: &'static str,
    oprf_public_key_ristretto255: String,
    signed_at: String,
    expires_at: String,
}

#[derive(Debug, Serialize)]
struct ManifestContractPayload<'a> {
    service: &'a str,
    protocol_version: u8,
    attestation_mode: &'a str,
    attestation_verifier: Option<&'a str>,
    enclave_measurement_hex: Option<&'a str>,
    attestation_pcrs_sha384: Option<&'a BTreeMap<String, String>>,
    attestation_document_format: Option<&'a str>,
    attestation_document_sha256: Option<&'a str>,
    attestation_challenge_mode: Option<&'a str>,
    ticket_format: &'a str,
    ticket_issuer_ed25519_pub: &'a str,
    ticket_max_ttl_seconds: i64,
    lookup_protocol: &'a str,
    privacy_mode: &'static str,
    directory_backend: &'static str,
    host_enclave_protocol_version: u8,
    host_release_id: &'a str,
    enclave_release_id: &'a str,
    match_result_format: &'static str,
    oprf_suite: &'static str,
    evaluation_proof_mode: &'static str,
    oprf_public_key_ristretto255: &'a str,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DiscoveryEvaluateProof {
    challenge_scalar_base64: String,
    response_scalar_base64: String,
    commitment_base_base64: String,
    commitment_blinded_base64: String,
}

#[derive(Debug, Serialize)]
struct ManifestResponse {
    #[serde(flatten)]
    payload: ManifestPayload,
    manifest_issuer_ed25519_pub: String,
    manifest_signature_ed25519: String,
}

#[derive(Debug, Serialize)]
struct AttestationPayload {
    attestation_mode: String,
    attestation_verifier: String,
    enclave_measurement_hex: String,
    attested_pcrs_sha384: Option<BTreeMap<String, String>>,
    directory_backend: &'static str,
    host_enclave_protocol_version: u8,
    host_release_id: String,
    enclave_release_id: String,
    manifest_contract_sha256: String,
    attested_oprf_public_key_ristretto255: String,
    document_format: &'static str,
    document_base64: String,
    document_sha256: String,
    published_at: String,
    challenge_nonce_base64: String,
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    #[serde(flatten)]
    payload: AttestationPayload,
    attestation_signature_ed25519: String,
}

#[derive(Debug, Deserialize)]
struct AttestationQuery {
    nonce_b64: String,
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
    purpose: String,
    manifest_contract_sha256: String,
    contact_invite_token: String,
    contact_invite_expires_at: String,
    issued_at: String,
    expires_at: String,
    max_uses: u8,
    nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredHandle {
    token_sha256: String,
    handle_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct StoredUserHandles {
    contact_invite_token: String,
    contact_invite_expires_at: String,
    handles: Vec<StoredHandle>,
}

#[derive(Debug, Clone)]
struct TicketUsage {
    expires_at: DateTime<Utc>,
    used: u8,
    max_uses: u8,
}

#[derive(Debug, Default)]
struct DiscoveryRegistry {
    user_handles: HashMap<String, StoredUserHandles>,
    ticket_usage: HashMap<String, TicketUsage>,
}

impl DiscoveryRegistry {
    fn purge_expired_handles(&mut self, now: DateTime<Utc>) {
        self.user_handles.retain(|_, stored_handles| {
            DateTime::parse_from_rfc3339(&stored_handles.contact_invite_expires_at)
                .map(|value| value.with_timezone(&Utc) > now)
                .unwrap_or(false)
        });
    }

    fn consume_ticket_use(
        &mut self,
        claims: &ContactDiscoveryTicketClaims,
        now: DateTime<Utc>,
    ) -> Result<(), DiscoveryError> {
        self.ticket_usage.retain(|_, usage| usage.expires_at > now);
        let expires_at = DateTime::parse_from_rfc3339(&claims.expires_at)
            .map_err(|_| {
                DiscoveryError::bad_request("contact discovery ticket expires_at is invalid")
            })?
            .with_timezone(&Utc);
        let entry = self
            .ticket_usage
            .entry(claims.nonce.clone())
            .or_insert(TicketUsage {
                expires_at,
                used: 0,
                max_uses: claims.max_uses,
            });
        if entry.expires_at != expires_at || entry.max_uses != claims.max_uses {
            return Err(DiscoveryError::bad_request(
                "contact discovery ticket nonce reuse detected with conflicting contract",
            ));
        }
        if entry.used >= entry.max_uses {
            return Err(DiscoveryError::bad_request(
                "contact discovery ticket exceeded max uses",
            ));
        }
        entry.used += 1;
        Ok(())
    }

    fn replace_tokens(
        &mut self,
        user_id: &str,
        contact_invite_token: &str,
        contact_invite_expires_at: &str,
        phone_tokens: &[String],
        email_tokens: &[String],
    ) {
        let mut handles = Vec::with_capacity(phone_tokens.len() + email_tokens.len());
        handles.extend(
            phone_tokens
                .iter()
                .cloned()
                .map(|token_sha256| StoredHandle {
                    token_sha256,
                    handle_kind: "phone".to_string(),
                }),
        );
        handles.extend(
            email_tokens
                .iter()
                .cloned()
                .map(|token_sha256| StoredHandle {
                    token_sha256,
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

    fn match_tokens(
        &self,
        requester_user_id: &str,
        query_tokens: &[String],
        now: DateTime<Utc>,
    ) -> Vec<DiscoveryMatchItem> {
        let query_set: HashSet<&str> = query_tokens.iter().map(String::as_str).collect();
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
                if query_set.contains(handle.token_sha256.as_str()) {
                    matches.push(DiscoveryMatchItem {
                        token_sha256: handle.token_sha256.clone(),
                        contact_invite_token: stored_handles.contact_invite_token.clone(),
                        handle_kind: handle.handle_kind.clone(),
                    });
                }
            }
        }
        matches.sort_by(|left, right| {
            left.token_sha256
                .cmp(&right.token_sha256)
                .then_with(|| left.contact_invite_token.cmp(&right.contact_invite_token))
                .then_with(|| left.handle_kind.cmp(&right.handle_kind))
        });
        matches
    }
}

#[derive(Debug, Deserialize)]
struct DiscoveryEvaluateRequest {
    ticket: String,
    blinded_elements_base64: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiscoveryEvaluateResponse {
    user_id: String,
    device_id: String,
    ticket_nonce: String,
    manifest_contract_sha256: String,
    evaluation_proof_mode: &'static str,
    evaluated_elements_base64: Vec<String>,
    dleq_proofs: Vec<DiscoveryEvaluateProof>,
    evaluated_at: String,
}

#[derive(Debug, Deserialize)]
struct DiscoveryHandlesUploadRequest {
    ticket: String,
    phone_tokens_sha256: Vec<String>,
    email_tokens_sha256: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DiscoveryHandlesUploadResponse {
    user_id: String,
    device_id: String,
    ticket_nonce: String,
    manifest_contract_sha256: String,
    uploaded_phone_tokens: usize,
    uploaded_email_tokens: usize,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct DiscoveryMatchRequest {
    ticket: String,
    tokens_sha256: Vec<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct DiscoveryMatchItem {
    token_sha256: String,
    contact_invite_token: String,
    handle_kind: String,
}

#[derive(Debug, Serialize)]
struct DiscoveryMatchResponse {
    user_id: String,
    ticket_nonce: String,
    manifest_contract_sha256: String,
    matches: Vec<DiscoveryMatchItem>,
    checked_at: String,
}

fn normalize_sha256_hex_values(
    field: &str,
    values: &[String],
) -> Result<Vec<String>, DiscoveryError> {
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

fn normalize_blinded_elements(
    field: &str,
    values: &[String],
) -> Result<Vec<CompressedRistretto>, DiscoveryError> {
    if values.len() > MAX_DISCOVERY_HASHES_PER_REQUEST {
        return Err(DiscoveryError::bad_request(format!(
            "{field} must contain at most {MAX_DISCOVERY_HASHES_PER_REQUEST} values"
        )));
    }
    let mut points = Vec::with_capacity(values.len());
    for value in values {
        let decoded = B64.decode(value.trim().as_bytes()).map_err(|_| {
            DiscoveryError::bad_request(format!(
                "{field} entries must be base64-encoded 32-byte compressed ristretto points"
            ))
        })?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
            DiscoveryError::bad_request(format!("{field} entries must decode to 32 bytes"))
        })?;
        let compressed = CompressedRistretto(bytes);
        if compressed.decompress().is_none() {
            return Err(DiscoveryError::bad_request(format!(
                "{field} entries must decode to valid compressed ristretto points"
            )));
        }
        points.push(compressed);
    }
    Ok(points)
}

fn encode_scalar_b64(scalar: &Scalar) -> String {
    B64.encode(scalar.to_bytes())
}

fn decode_scalar_b64(field: &str, value: &str) -> Result<Scalar, DiscoveryError> {
    let decoded = B64.decode(value.trim().as_bytes()).map_err(|_| {
        DiscoveryError::bad_request(format!(
            "{field} must be base64-encoded 32-byte scalar material"
        ))
    })?;
    if decoded.len() != 32 {
        return Err(DiscoveryError::bad_request(format!(
            "{field} must decode to exactly 32 bytes"
        )));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(Scalar::from_bytes_mod_order(bytes))
}

fn random_nonzero_scalar() -> Scalar {
    let mut rng = OsRng;
    loop {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let candidate = Scalar::from_bytes_mod_order_wide(&wide);
        if candidate != Scalar::ZERO {
            return candidate;
        }
    }
}

fn discovery_evaluation_challenge(
    public_key: &RistrettoPoint,
    blinded_point: &RistrettoPoint,
    evaluated_point: &RistrettoPoint,
    commitment_base: &RistrettoPoint,
    commitment_blinded: &RistrettoPoint,
) -> Scalar {
    let digest = Sha256::new()
        .chain_update(b"pqmsg-discovery-dleq-proof-v1")
        .chain_update(RISTRETTO_BASEPOINT_POINT.compress().to_bytes())
        .chain_update(public_key.compress().to_bytes())
        .chain_update(blinded_point.compress().to_bytes())
        .chain_update(evaluated_point.compress().to_bytes())
        .chain_update(commitment_base.compress().to_bytes())
        .chain_update(commitment_blinded.compress().to_bytes())
        .finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order(bytes)
}

fn generate_discovery_evaluate_proof(
    secret_scalar: &Scalar,
    public_key: &RistrettoPoint,
    blinded_point: &RistrettoPoint,
    evaluated_point: &RistrettoPoint,
) -> DiscoveryEvaluateProof {
    let nonce = random_nonzero_scalar();
    let commitment_base = RISTRETTO_BASEPOINT_POINT * nonce;
    let commitment_blinded = blinded_point * nonce;
    let challenge = discovery_evaluation_challenge(
        public_key,
        blinded_point,
        evaluated_point,
        &commitment_base,
        &commitment_blinded,
    );
    let response = nonce + challenge * secret_scalar;
    DiscoveryEvaluateProof {
        challenge_scalar_base64: encode_scalar_b64(&challenge),
        response_scalar_base64: encode_scalar_b64(&response),
        commitment_base_base64: B64.encode(commitment_base.compress().to_bytes()),
        commitment_blinded_base64: B64.encode(commitment_blinded.compress().to_bytes()),
    }
}

fn decode_hex_32(field: &str, value: &str) -> Result<[u8; 32], DiscoveryError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DiscoveryError::bad_request(format!(
            "{field} must be a 64-character SHA-256 hex string"
        )));
    }
    let mut decoded = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let upper = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| DiscoveryError::bad_request(format!("{field} must be valid hex")))?;
        let lower = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| DiscoveryError::bad_request(format!("{field} must be valid hex")))?;
        decoded[index] = ((upper << 4) | lower) as u8;
    }
    Ok(decoded)
}

fn derive_handle_point(handle_hash_sha256: &str) -> Result<RistrettoPoint, DiscoveryError> {
    let hash_bytes = decode_hex_32("handle_hash_sha256", handle_hash_sha256)?;
    let uniform = Sha512::new()
        .chain_update(CONTACT_DISCOVERY_HANDLE_DOMAIN)
        .chain_update(hash_bytes)
        .finalize();
    let mut uniform_bytes = [0u8; 64];
    uniform_bytes.copy_from_slice(&uniform);
    Ok(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        attestation_mode: state.attestation_mode.clone(),
        ticket_verifier_ready: true,
        directory_backend: CONTACT_DISCOVERY_DIRECTORY_BACKEND,
        host_enclave_protocol_version: CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION,
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
        attestation_verifier: state.attestation_verifier.clone(),
        enclave_measurement_hex: state.enclave_measurement_hex.clone(),
        attestation_pcrs_sha384: state.attestation_pcrs_sha384.clone(),
        attestation_document_format: state
            .attestation_document_sha256
            .as_ref()
            .map(|_| CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_FORMAT.to_string()),
        attestation_document_sha256: state.attestation_document_sha256.clone(),
        attestation_challenge_mode: state
            .attestation_document_sha256
            .as_ref()
            .map(|_| CONTACT_DISCOVERY_ATTESTATION_CHALLENGE_MODE.to_string()),
        ticket_format: "base64(json-payload).base64(ed25519-signature)",
        ticket_issuer_ed25519_pub: state.ticket_issuer_public_key_b64(),
        ticket_max_ttl_seconds: CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS,
        lookup_protocol: CONTACT_DISCOVERY_LOOKUP_PROTOCOL,
        privacy_mode: CONTACT_DISCOVERY_PRIVACY_MODE,
        directory_backend: CONTACT_DISCOVERY_DIRECTORY_BACKEND,
        host_enclave_protocol_version: CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION,
        host_release_id: state.host_release_id.clone(),
        enclave_release_id: state.enclave_release_id.clone(),
        match_result_format: CONTACT_DISCOVERY_MATCH_RESULT_FORMAT,
        oprf_suite: CONTACT_DISCOVERY_OPRF_SUITE,
        evaluation_proof_mode: CONTACT_DISCOVERY_EVALUATION_PROOF_MODE,
        oprf_public_key_ristretto255: state.oprf_public_key_ristretto255_b64.clone(),
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

fn manifest_contract_payload(payload: &ManifestPayload) -> ManifestContractPayload<'_> {
    ManifestContractPayload {
        service: payload.service,
        protocol_version: payload.protocol_version,
        attestation_mode: &payload.attestation_mode,
        attestation_verifier: payload.attestation_verifier.as_deref(),
        enclave_measurement_hex: payload.enclave_measurement_hex.as_deref(),
        attestation_pcrs_sha384: payload.attestation_pcrs_sha384.as_ref(),
        attestation_document_format: payload.attestation_document_format.as_deref(),
        attestation_document_sha256: payload.attestation_document_sha256.as_deref(),
        attestation_challenge_mode: payload.attestation_challenge_mode.as_deref(),
        ticket_format: payload.ticket_format,
        ticket_issuer_ed25519_pub: &payload.ticket_issuer_ed25519_pub,
        ticket_max_ttl_seconds: payload.ticket_max_ttl_seconds,
        lookup_protocol: payload.lookup_protocol,
        privacy_mode: payload.privacy_mode,
        directory_backend: payload.directory_backend,
        host_enclave_protocol_version: payload.host_enclave_protocol_version,
        host_release_id: &payload.host_release_id,
        enclave_release_id: &payload.enclave_release_id,
        match_result_format: payload.match_result_format,
        oprf_suite: payload.oprf_suite,
        evaluation_proof_mode: payload.evaluation_proof_mode,
        oprf_public_key_ristretto255: &payload.oprf_public_key_ristretto255,
    }
}

fn manifest_contract_sha256_hex(payload: &ManifestPayload) -> String {
    let contract_bytes = serde_json::to_vec(&manifest_contract_payload(payload))
        .expect("serialize discovery manifest contract payload");
    bytes_to_hex(&Sha256::digest(&contract_bytes))
}

fn current_manifest_contract_sha256(state: &AppState) -> String {
    let signed_at = Utc::now();
    let expires_at =
        signed_at + chrono::Duration::seconds(CONTACT_DISCOVERY_MANIFEST_MAX_TTL_SECONDS);
    let manifest_payload = ManifestPayload {
        service: "pqmsg-discovery",
        protocol_version: 1,
        attestation_mode: state.attestation_mode.clone(),
        attestation_verifier: state.attestation_verifier.clone(),
        enclave_measurement_hex: state.enclave_measurement_hex.clone(),
        attestation_pcrs_sha384: state.attestation_pcrs_sha384.clone(),
        attestation_document_format: state
            .attestation_document_sha256
            .as_ref()
            .map(|_| CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_FORMAT.to_string()),
        attestation_document_sha256: state.attestation_document_sha256.clone(),
        attestation_challenge_mode: state
            .attestation_document_sha256
            .as_ref()
            .map(|_| CONTACT_DISCOVERY_ATTESTATION_CHALLENGE_MODE.to_string()),
        ticket_format: "base64(json-payload).base64(ed25519-signature)",
        ticket_issuer_ed25519_pub: state.ticket_issuer_public_key_b64(),
        ticket_max_ttl_seconds: CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS,
        lookup_protocol: CONTACT_DISCOVERY_LOOKUP_PROTOCOL,
        privacy_mode: CONTACT_DISCOVERY_PRIVACY_MODE,
        directory_backend: CONTACT_DISCOVERY_DIRECTORY_BACKEND,
        host_enclave_protocol_version: CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION,
        host_release_id: state.host_release_id.clone(),
        enclave_release_id: state.enclave_release_id.clone(),
        match_result_format: CONTACT_DISCOVERY_MATCH_RESULT_FORMAT,
        oprf_suite: CONTACT_DISCOVERY_OPRF_SUITE,
        evaluation_proof_mode: CONTACT_DISCOVERY_EVALUATION_PROOF_MODE,
        oprf_public_key_ristretto255: state.oprf_public_key_ristretto255_b64.clone(),
        signed_at: signed_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };
    manifest_contract_sha256_hex(&manifest_payload)
}

fn normalize_attestation_nonce(name: &str, value: &str) -> Result<String, DiscoveryError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err(DiscoveryError::bad_request(format!(
            "{name} must be 1..=256 base64 characters"
        )));
    }
    let decoded = B64.decode(trimmed.as_bytes()).map_err(|_| {
        DiscoveryError::bad_request(format!("{name} must be valid base64-encoded bytes"))
    })?;
    if !(16..=64).contains(&decoded.len()) {
        return Err(DiscoveryError::bad_request(format!(
            "{name} must decode to 16..=64 bytes"
        )));
    }
    Ok(trimmed.to_string())
}

async fn attestation(
    State(state): State<AppState>,
    Query(query): Query<AttestationQuery>,
) -> Result<Json<AttestationResponse>, DiscoveryError> {
    let verifier = state
        .attestation_verifier
        .clone()
        .ok_or_else(|| DiscoveryError::bad_request("discovery attestation is not configured"))?;
    let measurement = state
        .enclave_measurement_hex
        .clone()
        .ok_or_else(|| DiscoveryError::bad_request("discovery attestation is not configured"))?;
    let attested_pcrs_sha384 = state.attestation_pcrs_sha384.clone();
    let document_base64 = state
        .attestation_document_base64
        .clone()
        .ok_or_else(|| DiscoveryError::bad_request("discovery attestation is not configured"))?;
    let document_sha256 = state
        .attestation_document_sha256
        .clone()
        .ok_or_else(|| DiscoveryError::bad_request("discovery attestation is not configured"))?;
    let challenge_nonce_base64 = normalize_attestation_nonce("nonce_b64", &query.nonce_b64)?;
    let signed_at = Utc::now();
    let expires_at =
        signed_at + chrono::Duration::seconds(CONTACT_DISCOVERY_MANIFEST_MAX_TTL_SECONDS);
    let manifest_payload = ManifestPayload {
        service: "pqmsg-discovery",
        protocol_version: 1,
        attestation_mode: state.attestation_mode.clone(),
        attestation_verifier: state.attestation_verifier.clone(),
        enclave_measurement_hex: state.enclave_measurement_hex.clone(),
        attestation_pcrs_sha384: state.attestation_pcrs_sha384.clone(),
        attestation_document_format: state
            .attestation_document_sha256
            .as_ref()
            .map(|_| CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_FORMAT.to_string()),
        attestation_document_sha256: state.attestation_document_sha256.clone(),
        attestation_challenge_mode: state
            .attestation_document_sha256
            .as_ref()
            .map(|_| CONTACT_DISCOVERY_ATTESTATION_CHALLENGE_MODE.to_string()),
        ticket_format: "base64(json-payload).base64(ed25519-signature)",
        ticket_issuer_ed25519_pub: state.ticket_issuer_public_key_b64(),
        ticket_max_ttl_seconds: CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS,
        lookup_protocol: CONTACT_DISCOVERY_LOOKUP_PROTOCOL,
        privacy_mode: CONTACT_DISCOVERY_PRIVACY_MODE,
        directory_backend: CONTACT_DISCOVERY_DIRECTORY_BACKEND,
        host_enclave_protocol_version: CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION,
        host_release_id: state.host_release_id.clone(),
        enclave_release_id: state.enclave_release_id.clone(),
        match_result_format: CONTACT_DISCOVERY_MATCH_RESULT_FORMAT,
        oprf_suite: CONTACT_DISCOVERY_OPRF_SUITE,
        evaluation_proof_mode: CONTACT_DISCOVERY_EVALUATION_PROOF_MODE,
        oprf_public_key_ristretto255: state.oprf_public_key_ristretto255_b64.clone(),
        signed_at: signed_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };
    let payload = AttestationPayload {
        attestation_mode: state.attestation_mode.clone(),
        attestation_verifier: verifier,
        enclave_measurement_hex: measurement,
        attested_pcrs_sha384,
        directory_backend: CONTACT_DISCOVERY_DIRECTORY_BACKEND,
        host_enclave_protocol_version: CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION,
        host_release_id: state.host_release_id.clone(),
        enclave_release_id: state.enclave_release_id.clone(),
        manifest_contract_sha256: manifest_contract_sha256_hex(&manifest_payload),
        attested_oprf_public_key_ristretto255: state.oprf_public_key_ristretto255_b64.clone(),
        document_format: CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_FORMAT,
        document_base64,
        document_sha256,
        published_at: Utc::now().to_rfc3339(),
        challenge_nonce_base64,
    };
    let payload_bytes =
        serde_json::to_vec(&payload).expect("serialize discovery attestation payload");
    let signature = state.manifest_signing_key.sign(&payload_bytes).to_bytes();
    Ok(Json(AttestationResponse {
        payload,
        attestation_signature_ed25519: B64.encode(signature),
    }))
}

async fn evaluate_blinded_elements(
    State(state): State<AppState>,
    Json(request): Json<DiscoveryEvaluateRequest>,
) -> Result<Json<DiscoveryEvaluateResponse>, DiscoveryError> {
    let now = Utc::now();
    let claims =
        verify_contact_discovery_ticket(&state.ticket_issuer_verifying_key, &request.ticket, now)
            .map_err(|error| DiscoveryError::bad_request(error.to_string()))?;
    ensure_ticket_manifest_contract_matches(&claims, &current_manifest_contract_sha256(&state))?;
    ensure_ticket_purpose_allowed(&claims, &["upload", "match"])?;
    state
        .registry
        .write()
        .await
        .consume_ticket_use(&claims, now)?;
    let blinded_elements =
        normalize_blinded_elements("blinded_elements_base64", &request.blinded_elements_base64)?;
    let public_key = RISTRETTO_BASEPOINT_POINT * *state.oprf_secret_scalar;
    let mut evaluated_elements_base64 = Vec::with_capacity(blinded_elements.len());
    let mut dleq_proofs = Vec::with_capacity(blinded_elements.len());
    for compressed in blinded_elements {
        let point = compressed.decompress().ok_or_else(|| {
            DiscoveryError::bad_request(
                "blinded_elements_base64 entries must decode to valid compressed ristretto points",
            )
        })?;
        let evaluated_point = point * *state.oprf_secret_scalar;
        let proof = generate_discovery_evaluate_proof(
            &state.oprf_secret_scalar,
            &public_key,
            &point,
            &evaluated_point,
        );
        evaluated_elements_base64.push(B64.encode(evaluated_point.compress().to_bytes()));
        dleq_proofs.push(proof);
    }
    Ok(Json(DiscoveryEvaluateResponse {
        user_id: claims.user_id,
        device_id: claims.device_id,
        ticket_nonce: claims.nonce.clone(),
        manifest_contract_sha256: current_manifest_contract_sha256(&state),
        evaluation_proof_mode: CONTACT_DISCOVERY_EVALUATION_PROOF_MODE,
        evaluated_elements_base64,
        dleq_proofs,
        evaluated_at: Utc::now().to_rfc3339(),
    }))
}

async fn upload_handles(
    State(state): State<AppState>,
    Json(request): Json<DiscoveryHandlesUploadRequest>,
) -> Result<Json<DiscoveryHandlesUploadResponse>, DiscoveryError> {
    let now = Utc::now();
    let claims =
        verify_contact_discovery_ticket(&state.ticket_issuer_verifying_key, &request.ticket, now)
            .map_err(|error| DiscoveryError::bad_request(error.to_string()))?;
    ensure_ticket_manifest_contract_matches(&claims, &current_manifest_contract_sha256(&state))?;
    ensure_ticket_purpose_allowed(&claims, &["upload"])?;
    let mut registry = state.registry.write().await;
    registry.consume_ticket_use(&claims, now)?;
    let phone_tokens =
        normalize_sha256_hex_values("phone_tokens_sha256", &request.phone_tokens_sha256)?;
    let email_tokens =
        normalize_sha256_hex_values("email_tokens_sha256", &request.email_tokens_sha256)?;
    let now = Utc::now().to_rfc3339();
    registry.purge_expired_handles(Utc::now());
    registry.replace_tokens(
        &claims.user_id,
        &claims.contact_invite_token,
        &claims.contact_invite_expires_at,
        &phone_tokens,
        &email_tokens,
    );
    Ok(Json(DiscoveryHandlesUploadResponse {
        user_id: claims.user_id,
        device_id: claims.device_id,
        ticket_nonce: claims.nonce.clone(),
        manifest_contract_sha256: current_manifest_contract_sha256(&state),
        uploaded_phone_tokens: phone_tokens.len(),
        uploaded_email_tokens: email_tokens.len(),
        updated_at: now,
    }))
}

async fn match_handles(
    State(state): State<AppState>,
    Json(request): Json<DiscoveryMatchRequest>,
) -> Result<Json<DiscoveryMatchResponse>, DiscoveryError> {
    let now = Utc::now();
    let claims =
        verify_contact_discovery_ticket(&state.ticket_issuer_verifying_key, &request.ticket, now)
            .map_err(|error| DiscoveryError::bad_request(error.to_string()))?;
    ensure_ticket_manifest_contract_matches(&claims, &current_manifest_contract_sha256(&state))?;
    ensure_ticket_purpose_allowed(&claims, &["match"])?;
    let mut registry = state.registry.write().await;
    registry.consume_ticket_use(&claims, now)?;
    registry.purge_expired_handles(now);
    let query_tokens = normalize_sha256_hex_values("tokens_sha256", &request.tokens_sha256)?;
    let matches = registry.match_tokens(&claims.user_id, &query_tokens, Utc::now());
    Ok(Json(DiscoveryMatchResponse {
        user_id: claims.user_id,
        ticket_nonce: claims.nonce.clone(),
        manifest_contract_sha256: current_manifest_contract_sha256(&state),
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

fn parse_oprf_secret_scalar() -> Result<(Arc<Scalar>, String)> {
    let raw = env::var("PQMSG_CONTACT_DISCOVERY_OPRF_RISTRETTO255_SECRET_B64")
        .with_context(|| "PQMSG_CONTACT_DISCOVERY_OPRF_RISTRETTO255_SECRET_B64 is required")?;
    let decoded = B64
        .decode(raw.trim().as_bytes())
        .with_context(|| {
            "invalid PQMSG_CONTACT_DISCOVERY_OPRF_RISTRETTO255_SECRET_B64: expected base64-encoded 32-byte scalar seed"
        })?;
    let secret_bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "invalid PQMSG_CONTACT_DISCOVERY_OPRF_RISTRETTO255_SECRET_B64: expected 32 decoded bytes"
        )
    })?;
    let scalar = Scalar::from_bytes_mod_order(secret_bytes);
    if scalar == Scalar::ZERO {
        anyhow::bail!(
            "invalid PQMSG_CONTACT_DISCOVERY_OPRF_RISTRETTO255_SECRET_B64: scalar must not map to zero"
        );
    }
    let public_key = (RISTRETTO_BASEPOINT_POINT * scalar).compress().to_bytes();
    Ok((Arc::new(scalar), B64.encode(public_key)))
}

fn parse_optional_env_nonempty(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn validate_sha384_hex(name: &str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 96 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{name} must be a 96-character SHA-384 hex string");
    }
    Ok(normalized)
}

fn validate_sha256_hex(name: &str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("{name} must be a 64-character SHA-256 hex string");
    }
    Ok(normalized)
}

fn normalize_attestation_pcr_key(name: &str, key: &str) -> Result<String> {
    let normalized = key.trim().to_ascii_lowercase();
    if !matches!(
        normalized.as_str(),
        "pcr0" | "pcr1" | "pcr2" | "pcr3" | "pcr4" | "pcr8"
    ) {
        anyhow::bail!(
            "{name} contains unsupported PCR key '{key}' (expected one of pcr0, pcr1, pcr2, pcr3, pcr4, pcr8)"
        );
    }
    Ok(normalized)
}

fn parse_optional_attestation_pcrs_sha384_env(
    name: &str,
) -> Result<Option<BTreeMap<String, String>>> {
    let raw = match parse_optional_env_nonempty(name) {
        Some(value) => value,
        None => return Ok(None),
    };
    let parsed = serde_json::from_str::<BTreeMap<String, String>>(&raw)
        .with_context(|| format!("invalid {name}: expected JSON object of PCR->SHA384 hex"))?;
    if parsed.is_empty() {
        anyhow::bail!("{name} must contain at least one PCR entry");
    }
    let mut normalized = BTreeMap::new();
    for (key, value) in parsed {
        let normalized_key = normalize_attestation_pcr_key(name, &key)?;
        let normalized_value = validate_sha384_hex(name, &value)?;
        if normalized
            .insert(normalized_key.clone(), normalized_value)
            .is_some()
        {
            anyhow::bail!("{name} contains duplicate PCR key '{normalized_key}'");
        }
    }
    Ok(Some(normalized))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn parse_optional_base64(name: &str) -> Result<Option<Vec<u8>>> {
    match parse_optional_env_nonempty(name) {
        Some(value) => {
            let decoded = B64.decode(value.as_bytes()).with_context(|| {
                format!("invalid {name}: expected base64-encoded attestation document bytes")
            })?;
            if decoded.is_empty() {
                anyhow::bail!("{name} must not decode to empty bytes");
            }
            Ok(Some(decoded))
        }
        None => Ok(None),
    }
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
    match claims.purpose.as_str() {
        "upload" => {
            if claims.max_uses != CONTACT_DISCOVERY_TICKET_UPLOAD_MAX_USES {
                anyhow::bail!("contact discovery ticket max_uses is invalid for upload purpose");
            }
        }
        "match" => {
            if claims.max_uses != CONTACT_DISCOVERY_TICKET_MATCH_MAX_USES {
                anyhow::bail!("contact discovery ticket max_uses is invalid for match purpose");
            }
        }
        _ => anyhow::bail!("contact discovery ticket purpose is invalid"),
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
    if claims.max_uses == 0 || claims.max_uses > CONTACT_DISCOVERY_TICKET_MAX_USES {
        anyhow::bail!("contact discovery ticket max_uses is invalid");
    }
    validate_sha256_hex(
        "contact discovery ticket manifest_contract_sha256",
        &claims.manifest_contract_sha256,
    )?;
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

fn ensure_ticket_purpose_allowed(
    claims: &ContactDiscoveryTicketClaims,
    allowed_purposes: &[&str],
) -> Result<(), DiscoveryError> {
    if allowed_purposes.contains(&claims.purpose.as_str()) {
        Ok(())
    } else {
        Err(DiscoveryError::bad_request(format!(
            "contact discovery ticket purpose '{}' is not valid for this operation",
            claims.purpose
        )))
    }
}

fn ensure_ticket_manifest_contract_matches(
    claims: &ContactDiscoveryTicketClaims,
    expected_manifest_contract_sha256: &str,
) -> Result<(), DiscoveryError> {
    if claims.manifest_contract_sha256 != expected_manifest_contract_sha256 {
        return Err(DiscoveryError::bad_request(
            "contact discovery ticket manifest contract does not match the current service contract",
        ));
    }
    Ok(())
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
    let attestation_mode = parse_optional_env_nonempty("PQMSG_CONTACT_DISCOVERY_ATTESTATION_MODE")
        .unwrap_or_else(|| DEFAULT_ATTESTATION_MODE.to_string());
    let attestation_verifier =
        parse_optional_env_nonempty("PQMSG_CONTACT_DISCOVERY_ATTESTATION_VERIFIER");
    let enclave_measurement_hex =
        parse_optional_env_nonempty("PQMSG_CONTACT_DISCOVERY_ENCLAVE_MEASUREMENT_HEX")
            .map(|value| {
                validate_sha256_hex("PQMSG_CONTACT_DISCOVERY_ENCLAVE_MEASUREMENT_HEX", &value)
            })
            .transpose()?;
    let attestation_pcrs_sha384 = parse_optional_attestation_pcrs_sha384_env(
        "PQMSG_CONTACT_DISCOVERY_ATTESTATION_PCRS_SHA384_JSON",
    )?;
    let attestation_document_bytes =
        parse_optional_base64("PQMSG_CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_B64")?;
    let attestation_document_base64 = attestation_document_bytes
        .as_ref()
        .map(|value| B64.encode(value));
    let attestation_document_sha256 = attestation_document_bytes
        .as_ref()
        .map(|value| bytes_to_hex(&sha2::Sha256::digest(value)));
    if attestation_verifier.is_none()
        || enclave_measurement_hex.is_none()
        || attestation_document_sha256.is_none()
    {
        anyhow::bail!(
            "PQMSG_CONTACT_DISCOVERY_ATTESTATION_VERIFIER, PQMSG_CONTACT_DISCOVERY_ENCLAVE_MEASUREMENT_HEX, and PQMSG_CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_B64 are required for the attested private discovery service"
        );
    }
    let attestation_fields_present = [
        attestation_verifier.is_some(),
        enclave_measurement_hex.is_some(),
        attestation_document_sha256.is_some(),
    ];
    if attestation_fields_present.iter().any(|present| *present)
        && !attestation_fields_present.iter().all(|present| *present)
    {
        anyhow::bail!(
            "PQMSG_CONTACT_DISCOVERY_ATTESTATION_VERIFIER, PQMSG_CONTACT_DISCOVERY_ENCLAVE_MEASUREMENT_HEX, and PQMSG_CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_B64 must be configured together"
        );
    }
    let ticket_issuer_verifying_key = parse_ticket_issuer_verifying_key()?;
    let manifest_signing_key = parse_manifest_signing_key()?;
    let (oprf_secret_scalar, oprf_public_key_ristretto255_b64) = parse_oprf_secret_scalar()?;
    let host_release_id = parse_optional_env_nonempty("PQMSG_CONTACT_DISCOVERY_HOST_RELEASE_ID")
        .ok_or_else(|| anyhow::anyhow!("PQMSG_CONTACT_DISCOVERY_HOST_RELEASE_ID is required"))?;
    let enclave_release_id = parse_optional_env_nonempty(
        "PQMSG_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID",
    )
    .ok_or_else(|| anyhow::anyhow!("PQMSG_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID is required"))?;

    let state = AppState {
        ticket_issuer_verifying_key,
        manifest_signing_key,
        attestation_mode,
        attestation_verifier,
        enclave_measurement_hex,
        attestation_pcrs_sha384,
        attestation_document_base64,
        attestation_document_sha256,
        registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
        oprf_secret_scalar,
        oprf_public_key_ristretto255_b64,
        host_release_id,
        enclave_release_id,
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/manifest", get(manifest))
        .route("/v1/attestation", get(attestation))
        .route("/v1/discovery/evaluate", post(evaluate_blinded_elements))
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
    use sha2::Sha256;

    fn signed_ticket(
        signing_key: &SigningKey,
        issued_at: &str,
        expires_at: &str,
        purpose: &str,
        manifest_contract_sha256: &str,
    ) -> (String, ContactDiscoveryTicketClaims) {
        let max_uses = match purpose {
            "upload" => CONTACT_DISCOVERY_TICKET_UPLOAD_MAX_USES,
            "match" => CONTACT_DISCOVERY_TICKET_MATCH_MAX_USES,
            _ => panic!("unsupported ticket purpose"),
        };
        let claims = ContactDiscoveryTicketClaims {
            v: 1,
            user_id: "alice".to_string(),
            device_id: "alice-dev-1".to_string(),
            purpose: purpose.to_string(),
            manifest_contract_sha256: manifest_contract_sha256.to_string(),
            contact_invite_token: "invite-bootstrap-1".to_string(),
            contact_invite_expires_at: expires_at.to_string(),
            issued_at: issued_at.to_string(),
            expires_at: expires_at.to_string(),
            max_uses,
            nonce: "nonce-1".to_string(),
        };
        let payload = serde_json::to_vec(&claims).expect("serialize claims");
        let signature = signing_key.sign(&payload).to_bytes();
        (
            format!("{}.{}", B64.encode(payload), B64.encode(signature)),
            claims,
        )
    }

    fn blind_handle_hash(
        handle_hash_sha256: &str,
        blind_scalar: Scalar,
    ) -> (String, RistrettoPoint) {
        let handle_point = derive_handle_point(handle_hash_sha256).expect("derive handle point");
        let blinded = (handle_point * blind_scalar).compress().to_bytes();
        (B64.encode(blinded), handle_point)
    }

    #[test]
    fn verify_contact_discovery_ticket_accepts_valid_ticket() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let (ticket, claims) = signed_ticket(
            &signing_key,
            "2026-03-13T12:00:00Z",
            "2026-03-13T12:05:00Z",
            "match",
            &"11".repeat(32),
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
            "match",
            &"11".repeat(32),
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
            "match",
            &"11".repeat(32),
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

    #[test]
    fn verify_contact_discovery_ticket_rejects_invalid_max_uses() {
        let signing_key = SigningKey::from_bytes(&[40u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut claims = signed_ticket(
            &signing_key,
            "2026-03-13T12:00:00Z",
            "2026-03-13T12:05:00Z",
            "match",
            &"11".repeat(32),
        )
        .1;
        claims.max_uses = CONTACT_DISCOVERY_TICKET_MAX_USES + 1;
        let payload = serde_json::to_vec(&claims).expect("serialize claims");
        let signature = signing_key.sign(&payload).to_bytes();
        let ticket = format!("{}.{}", B64.encode(payload), B64.encode(signature));
        let error = verify_contact_discovery_ticket(
            &verifying_key,
            &ticket,
            DateTime::parse_from_rfc3339("2026-03-13T12:01:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        )
        .expect_err("max uses should be rejected");
        assert!(error.to_string().contains("max_uses"));
    }

    #[tokio::test]
    async fn manifest_is_signed_by_configured_manifest_key() {
        let ticket_signing_key = SigningKey::from_bytes(&[11u8; 32]);
        let manifest_signing_key = Arc::new(SigningKey::from_bytes(&[12u8; 32]));
        let oprf_scalar = Scalar::from_bytes_mod_order([13u8; 32]);
        let oprf_pub_b64 = B64.encode(
            (RISTRETTO_BASEPOINT_POINT * oprf_scalar)
                .compress()
                .to_bytes(),
        );
        let state = AppState {
            ticket_issuer_verifying_key: Arc::new(ticket_signing_key.verifying_key()),
            manifest_signing_key: manifest_signing_key.clone(),
            attestation_mode: DEFAULT_ATTESTATION_MODE.to_string(),
            attestation_verifier: None,
            enclave_measurement_hex: None,
            attestation_pcrs_sha384: None,
            attestation_document_base64: None,
            attestation_document_sha256: None,
            registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
            oprf_secret_scalar: Arc::new(oprf_scalar),
            oprf_public_key_ristretto255_b64: oprf_pub_b64.clone(),
            host_release_id: DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID.to_string(),
            enclave_release_id: DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID.to_string(),
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
        assert_eq!(
            response.payload.lookup_protocol,
            CONTACT_DISCOVERY_LOOKUP_PROTOCOL
        );
        assert_eq!(
            response.payload.privacy_mode,
            CONTACT_DISCOVERY_PRIVACY_MODE
        );
        assert_eq!(
            response.payload.directory_backend,
            CONTACT_DISCOVERY_DIRECTORY_BACKEND
        );
        assert_eq!(
            response.payload.host_enclave_protocol_version,
            CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION
        );
        assert_eq!(
            response.payload.host_release_id,
            DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID
        );
        assert_eq!(
            response.payload.enclave_release_id,
            DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID
        );
        assert_eq!(
            response.payload.match_result_format,
            CONTACT_DISCOVERY_MATCH_RESULT_FORMAT
        );
        assert_eq!(response.payload.oprf_suite, CONTACT_DISCOVERY_OPRF_SUITE);
        assert_eq!(
            response.payload.evaluation_proof_mode,
            CONTACT_DISCOVERY_EVALUATION_PROOF_MODE
        );
        assert_eq!(response.payload.oprf_public_key_ristretto255, oprf_pub_b64);
        assert!(response.payload.attestation_verifier.is_none());
        assert!(response.payload.enclave_measurement_hex.is_none());
        assert!(response.payload.attestation_document_format.is_none());
        assert!(response.payload.attestation_document_sha256.is_none());
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

    #[tokio::test]
    async fn evaluate_endpoint_returns_blind_evaluations() {
        let ticket_signing_key = SigningKey::from_bytes(&[21u8; 32]);
        let oprf_scalar = Scalar::from_bytes_mod_order([22u8; 32]);
        let state = AppState {
            ticket_issuer_verifying_key: Arc::new(ticket_signing_key.verifying_key()),
            manifest_signing_key: Arc::new(SigningKey::from_bytes(&[23u8; 32])),
            attestation_mode: DEFAULT_ATTESTATION_MODE.to_string(),
            attestation_verifier: None,
            enclave_measurement_hex: None,
            attestation_pcrs_sha384: None,
            attestation_document_base64: None,
            attestation_document_sha256: None,
            registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
            oprf_secret_scalar: Arc::new(oprf_scalar),
            oprf_public_key_ristretto255_b64: B64.encode(
                (RISTRETTO_BASEPOINT_POINT * oprf_scalar)
                    .compress()
                    .to_bytes(),
            ),
            host_release_id: DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID.to_string(),
            enclave_release_id: DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID.to_string(),
        };
        let issued_at = Utc::now() - chrono::Duration::minutes(1);
        let expires_at = issued_at + chrono::Duration::minutes(5);
        let manifest_contract_sha256 = current_manifest_contract_sha256(&state);
        let (ticket, claims) = signed_ticket(
            &ticket_signing_key,
            &issued_at.to_rfc3339(),
            &expires_at.to_rfc3339(),
            "match",
            &manifest_contract_sha256,
        );
        let blind_scalar = Scalar::from_bytes_mod_order([24u8; 32]);
        let (blinded_b64, handle_point) = blind_handle_hash(&"11".repeat(32), blind_scalar);
        let response = evaluate_blinded_elements(
            State(state),
            Json(DiscoveryEvaluateRequest {
                ticket,
                blinded_elements_base64: vec![blinded_b64],
            }),
        )
        .await
        .expect("evaluate blinded elements")
        .0;
        assert_eq!(response.user_id, claims.user_id);
        assert_eq!(response.device_id, claims.device_id);
        assert_eq!(
            response.evaluation_proof_mode,
            CONTACT_DISCOVERY_EVALUATION_PROOF_MODE
        );
        assert_eq!(response.evaluated_elements_base64.len(), 1);
        assert_eq!(response.dleq_proofs.len(), 1);
        let evaluated_bytes = B64
            .decode(response.evaluated_elements_base64[0].as_bytes())
            .expect("decode evaluated element");
        let evaluated_point = CompressedRistretto(
            evaluated_bytes
                .as_slice()
                .try_into()
                .expect("compressed point size"),
        )
        .decompress()
        .expect("decompress evaluated point");
        let expected = handle_point * blind_scalar * oprf_scalar;
        assert_eq!(
            evaluated_point.compress().to_bytes(),
            expected.compress().to_bytes()
        );
        let proof = &response.dleq_proofs[0];
        let challenge = decode_scalar_b64(
            "contact_discovery_proof_challenge_scalar",
            &proof.challenge_scalar_base64,
        )
        .expect("decode challenge");
        let response_scalar = decode_scalar_b64(
            "contact_discovery_proof_response_scalar",
            &proof.response_scalar_base64,
        )
        .expect("decode response");
        let commitment_base = CompressedRistretto(
            B64.decode(proof.commitment_base_base64.as_bytes())
                .expect("decode commitment base")
                .as_slice()
                .try_into()
                .expect("commitment base size"),
        )
        .decompress()
        .expect("decompress commitment base");
        let commitment_blinded = CompressedRistretto(
            B64.decode(proof.commitment_blinded_base64.as_bytes())
                .expect("decode commitment blinded")
                .as_slice()
                .try_into()
                .expect("commitment blinded size"),
        )
        .decompress()
        .expect("decompress commitment blinded");
        let public_key = RISTRETTO_BASEPOINT_POINT * oprf_scalar;
        let expected_challenge = discovery_evaluation_challenge(
            &public_key,
            &(handle_point * blind_scalar),
            &evaluated_point,
            &commitment_base,
            &commitment_blinded,
        );
        assert_eq!(challenge, expected_challenge);
        assert_eq!(
            RISTRETTO_BASEPOINT_POINT * response_scalar,
            commitment_base + public_key * challenge
        );
        assert_eq!(
            (handle_point * blind_scalar) * response_scalar,
            commitment_blinded + evaluated_point * challenge
        );
    }

    #[tokio::test]
    async fn evaluate_endpoint_rejects_ticket_after_max_uses() {
        let ticket_signing_key = SigningKey::from_bytes(&[41u8; 32]);
        let oprf_scalar = Scalar::from_bytes_mod_order([42u8; 32]);
        let state = AppState {
            ticket_issuer_verifying_key: Arc::new(ticket_signing_key.verifying_key()),
            manifest_signing_key: Arc::new(SigningKey::from_bytes(&[43u8; 32])),
            attestation_mode: DEFAULT_ATTESTATION_MODE.to_string(),
            attestation_verifier: None,
            enclave_measurement_hex: None,
            attestation_pcrs_sha384: None,
            attestation_document_base64: None,
            attestation_document_sha256: None,
            registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
            oprf_secret_scalar: Arc::new(oprf_scalar),
            oprf_public_key_ristretto255_b64: B64.encode(
                (RISTRETTO_BASEPOINT_POINT * oprf_scalar)
                    .compress()
                    .to_bytes(),
            ),
            host_release_id: DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID.to_string(),
            enclave_release_id: DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID.to_string(),
        };
        let issued_at = Utc::now() - chrono::Duration::minutes(1);
        let expires_at = issued_at + chrono::Duration::minutes(5);
        let manifest_contract_sha256 = current_manifest_contract_sha256(&state);
        let (ticket, _) = signed_ticket(
            &ticket_signing_key,
            &issued_at.to_rfc3339(),
            &expires_at.to_rfc3339(),
            "match",
            &manifest_contract_sha256,
        );
        let (blinded_b64, _) =
            blind_handle_hash(&"11".repeat(32), Scalar::from_bytes_mod_order([44u8; 32]));
        for _ in 0..CONTACT_DISCOVERY_TICKET_MATCH_MAX_USES {
            let _ = evaluate_blinded_elements(
                State(state.clone()),
                Json(DiscoveryEvaluateRequest {
                    ticket: ticket.clone(),
                    blinded_elements_base64: vec![blinded_b64.clone()],
                }),
            )
            .await
            .expect("evaluate within ticket budget");
        }
        let error = evaluate_blinded_elements(
            State(state),
            Json(DiscoveryEvaluateRequest {
                ticket,
                blinded_elements_base64: vec![blinded_b64],
            }),
        )
        .await
        .expect_err("ticket should exceed max uses");
        assert!(error.detail.contains("exceeded max uses"));
    }

    #[tokio::test]
    async fn upload_endpoint_rejects_match_purpose_ticket() {
        let ticket_signing_key = SigningKey::from_bytes(&[46u8; 32]);
        let oprf_scalar = Scalar::from_bytes_mod_order([47u8; 32]);
        let state = AppState {
            ticket_issuer_verifying_key: Arc::new(ticket_signing_key.verifying_key()),
            manifest_signing_key: Arc::new(SigningKey::from_bytes(&[48u8; 32])),
            attestation_mode: DEFAULT_ATTESTATION_MODE.to_string(),
            attestation_verifier: None,
            enclave_measurement_hex: None,
            attestation_pcrs_sha384: None,
            attestation_document_base64: None,
            attestation_document_sha256: None,
            registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
            oprf_secret_scalar: Arc::new(oprf_scalar),
            oprf_public_key_ristretto255_b64: B64.encode(
                (RISTRETTO_BASEPOINT_POINT * oprf_scalar)
                    .compress()
                    .to_bytes(),
            ),
            host_release_id: DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID.to_string(),
            enclave_release_id: DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID.to_string(),
        };
        let issued_at = Utc::now() - chrono::Duration::minutes(1);
        let expires_at = issued_at + chrono::Duration::minutes(5);
        let manifest_contract_sha256 = current_manifest_contract_sha256(&state);
        let (ticket, _) = signed_ticket(
            &ticket_signing_key,
            &issued_at.to_rfc3339(),
            &expires_at.to_rfc3339(),
            "match",
            &manifest_contract_sha256,
        );
        let error = upload_handles(
            State(state),
            Json(DiscoveryHandlesUploadRequest {
                ticket,
                phone_tokens_sha256: vec!["11".repeat(32)],
                email_tokens_sha256: vec![],
            }),
        )
        .await
        .expect_err("match-purpose ticket should not upload");
        assert!(error.detail.contains("purpose"));
    }

    #[tokio::test]
    async fn match_endpoint_rejects_upload_purpose_ticket() {
        let ticket_signing_key = SigningKey::from_bytes(&[49u8; 32]);
        let oprf_scalar = Scalar::from_bytes_mod_order([50u8; 32]);
        let state = AppState {
            ticket_issuer_verifying_key: Arc::new(ticket_signing_key.verifying_key()),
            manifest_signing_key: Arc::new(SigningKey::from_bytes(&[51u8; 32])),
            attestation_mode: DEFAULT_ATTESTATION_MODE.to_string(),
            attestation_verifier: None,
            enclave_measurement_hex: None,
            attestation_pcrs_sha384: None,
            attestation_document_base64: None,
            attestation_document_sha256: None,
            registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
            oprf_secret_scalar: Arc::new(oprf_scalar),
            oprf_public_key_ristretto255_b64: B64.encode(
                (RISTRETTO_BASEPOINT_POINT * oprf_scalar)
                    .compress()
                    .to_bytes(),
            ),
            host_release_id: DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID.to_string(),
            enclave_release_id: DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID.to_string(),
        };
        let issued_at = Utc::now() - chrono::Duration::minutes(1);
        let expires_at = issued_at + chrono::Duration::minutes(5);
        let manifest_contract_sha256 = current_manifest_contract_sha256(&state);
        let (ticket, _) = signed_ticket(
            &ticket_signing_key,
            &issued_at.to_rfc3339(),
            &expires_at.to_rfc3339(),
            "upload",
            &manifest_contract_sha256,
        );
        let error = match_handles(
            State(state),
            Json(DiscoveryMatchRequest {
                ticket,
                tokens_sha256: vec!["22".repeat(32)],
            }),
        )
        .await
        .expect_err("upload-purpose ticket should not match");
        assert!(error.detail.contains("purpose"));
    }

    #[tokio::test]
    async fn attestation_endpoint_returns_configured_document() {
        let ticket_signing_key = SigningKey::from_bytes(&[31u8; 32]);
        let manifest_signing_key = Arc::new(SigningKey::from_bytes(&[32u8; 32]));
        let oprf_scalar = Scalar::from_bytes_mod_order([33u8; 32]);
        let oprf_public_key_ristretto255_b64 = B64.encode(
            (RISTRETTO_BASEPOINT_POINT * oprf_scalar)
                .compress()
                .to_bytes(),
        );
        let document_bytes = b"{\"tee\":\"sgx\",\"svn\":1}".to_vec();
        let document_b64 = B64.encode(&document_bytes);
        let attestation_pcrs_sha384 = BTreeMap::from([
            ("pcr0".to_string(), "ef".repeat(48)),
            ("pcr8".to_string(), "12".repeat(48)),
        ]);
        let state = AppState {
            ticket_issuer_verifying_key: Arc::new(ticket_signing_key.verifying_key()),
            manifest_signing_key: manifest_signing_key.clone(),
            attestation_mode: "attested_enclave_v1".to_string(),
            attestation_verifier: Some("aws-nitro-root-v1".to_string()),
            enclave_measurement_hex: Some("cd".repeat(32)),
            attestation_pcrs_sha384: Some(attestation_pcrs_sha384.clone()),
            attestation_document_base64: Some(document_b64.clone()),
            attestation_document_sha256: Some(bytes_to_hex(&Sha256::digest(&document_bytes))),
            registry: Arc::new(RwLock::new(DiscoveryRegistry::default())),
            oprf_secret_scalar: Arc::new(oprf_scalar),
            oprf_public_key_ristretto255_b64: oprf_public_key_ristretto255_b64.clone(),
            host_release_id: DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID.to_string(),
            enclave_release_id: DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID.to_string(),
        };
        let nonce_b64 = B64.encode([7u8; 16]);

        let response = attestation(
            State(state),
            Query(AttestationQuery {
                nonce_b64: nonce_b64.clone(),
            }),
        )
        .await
        .expect("attestation response")
        .0;
        assert_eq!(response.payload.attestation_mode, "attested_enclave_v1");
        assert_eq!(response.payload.attestation_verifier, "aws-nitro-root-v1");
        assert_eq!(response.payload.enclave_measurement_hex, "cd".repeat(32));
        assert_eq!(
            response.payload.attested_pcrs_sha384,
            Some(attestation_pcrs_sha384.clone())
        );
        assert_eq!(
            response.payload.directory_backend,
            CONTACT_DISCOVERY_DIRECTORY_BACKEND
        );
        assert_eq!(
            response.payload.host_enclave_protocol_version,
            CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION
        );
        assert_eq!(
            response.payload.host_release_id,
            DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID
        );
        assert_eq!(
            response.payload.enclave_release_id,
            DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID
        );
        let manifest_payload = ManifestPayload {
            service: "pqmsg-discovery",
            protocol_version: 1,
            attestation_mode: "attested_enclave_v1".to_string(),
            attestation_verifier: Some("aws-nitro-root-v1".to_string()),
            enclave_measurement_hex: Some("cd".repeat(32)),
            attestation_pcrs_sha384: Some(attestation_pcrs_sha384.clone()),
            attestation_document_format: Some(
                CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_FORMAT.to_string(),
            ),
            attestation_document_sha256: Some(bytes_to_hex(&Sha256::digest(&document_bytes))),
            attestation_challenge_mode: Some(
                CONTACT_DISCOVERY_ATTESTATION_CHALLENGE_MODE.to_string(),
            ),
            ticket_format: "base64(json-payload).base64(ed25519-signature)",
            ticket_issuer_ed25519_pub: B64.encode(ticket_signing_key.verifying_key().as_bytes()),
            ticket_max_ttl_seconds: CONTACT_DISCOVERY_TICKET_MAX_TTL_SECONDS,
            lookup_protocol: CONTACT_DISCOVERY_LOOKUP_PROTOCOL,
            privacy_mode: CONTACT_DISCOVERY_PRIVACY_MODE,
            directory_backend: CONTACT_DISCOVERY_DIRECTORY_BACKEND,
            host_enclave_protocol_version: CONTACT_DISCOVERY_HOST_ENCLAVE_PROTOCOL_VERSION,
            host_release_id: DEFAULT_CONTACT_DISCOVERY_HOST_RELEASE_ID.to_string(),
            enclave_release_id: DEFAULT_CONTACT_DISCOVERY_ENCLAVE_RELEASE_ID.to_string(),
            match_result_format: CONTACT_DISCOVERY_MATCH_RESULT_FORMAT,
            oprf_suite: CONTACT_DISCOVERY_OPRF_SUITE,
            evaluation_proof_mode: CONTACT_DISCOVERY_EVALUATION_PROOF_MODE,
            oprf_public_key_ristretto255: oprf_public_key_ristretto255_b64.clone(),
            signed_at: "unused".to_string(),
            expires_at: "unused".to_string(),
        };
        assert_eq!(
            response.payload.manifest_contract_sha256,
            manifest_contract_sha256_hex(&manifest_payload)
        );
        assert_eq!(
            response.payload.attested_oprf_public_key_ristretto255,
            oprf_public_key_ristretto255_b64
        );
        assert_eq!(
            response.payload.document_format,
            CONTACT_DISCOVERY_ATTESTATION_DOCUMENT_FORMAT
        );
        assert_eq!(response.payload.document_base64, document_b64);
        assert_eq!(
            response.payload.document_sha256,
            bytes_to_hex(&Sha256::digest(&document_bytes))
        );
        assert_eq!(response.payload.challenge_nonce_base64, nonce_b64);

        let payload_bytes =
            serde_json::to_vec(&response.payload).expect("serialize attestation payload");
        let signature_bytes = B64
            .decode(response.attestation_signature_ed25519.as_bytes())
            .expect("decode attestation signature");
        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .expect("signature is 64 bytes");
        let signature = Signature::from_bytes(&signature_array);
        manifest_signing_key
            .verifying_key()
            .verify(&payload_bytes, &signature)
            .expect("verify attestation signature");
    }

    #[test]
    fn registry_replaces_tokens_and_matches_other_users() {
        let mut registry = DiscoveryRegistry::default();
        registry.replace_tokens(
            "alice",
            "invite-alice",
            "2026-03-27T12:00:00Z",
            &["11".repeat(32)],
            &["22".repeat(32)],
        );
        registry.replace_tokens(
            "bob",
            "invite-bob",
            "2026-03-27T12:00:00Z",
            &["33".repeat(32)],
            &["44".repeat(32), "11".repeat(32)],
        );
        let matches = registry.match_tokens(
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
        registry.replace_tokens(
            "bob",
            "invite-bob",
            "2026-03-13T11:59:00Z",
            &["11".repeat(32)],
            &[],
        );
        let matches = registry.match_tokens(
            "alice",
            &["11".repeat(32)],
            DateTime::parse_from_rfc3339("2026-03-13T12:01:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn registry_purges_expired_bootstrap_invites() {
        let mut registry = DiscoveryRegistry::default();
        registry.replace_tokens(
            "bob",
            "invite-bob",
            "2026-03-13T11:59:00Z",
            &["11".repeat(32)],
            &[],
        );
        assert_eq!(registry.user_handles.len(), 1);
        registry.purge_expired_handles(
            DateTime::parse_from_rfc3339("2026-03-13T12:01:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        );
        assert!(registry.user_handles.is_empty());
    }

    #[test]
    fn verify_contact_discovery_ticket_rejects_invalid_purpose() {
        let signing_key = SigningKey::from_bytes(&[45u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let mut claims = signed_ticket(
            &signing_key,
            "2026-03-13T12:00:00Z",
            "2026-03-13T12:05:00Z",
            "match",
            &"11".repeat(32),
        )
        .1;
        claims.purpose = "weird".to_string();
        let payload = serde_json::to_vec(&claims).expect("serialize claims");
        let signature = signing_key.sign(&payload).to_bytes();
        let ticket = format!("{}.{}", B64.encode(payload), B64.encode(signature));
        let error = verify_contact_discovery_ticket(
            &verifying_key,
            &ticket,
            DateTime::parse_from_rfc3339("2026-03-13T12:01:00Z")
                .expect("parse time")
                .with_timezone(&Utc),
        )
        .expect_err("purpose should be rejected");
        assert!(error.to_string().contains("purpose"));
    }
}
