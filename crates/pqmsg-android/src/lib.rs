#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqmsg_core::ad::conversation_associated_data;
use pqmsg_core::alg::{
    runtime_crypto_profile, AlgorithmSuite, KemAlgorithm,
    SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use pqmsg_core::dh::{DhKeyPair, DhPublicKey};
use pqmsg_core::groups::{
    PrivateGroupAttributes, PrivateGroupEncryptedSnapshot, PrivateGroupEpochTransition,
    PrivateGroupInvitePackage, PrivateGroupJoinPackage, PrivateGroupMember,
    PrivateGroupMemberCredential, PrivateGroupRole, PrivateGroupState,
};
use pqmsg_core::handshake::{
    alice_initiate, bob_receive, pq_signed_prekey_signature_message,
    signed_prekey_signature_message, validate_hybrid_prekey_bundle_signatures, InitialMessage,
    SignatureVerifier,
};
use pqmsg_core::kem::MlKem768;
use pqmsg_core::key_transparency::{
    verify_consistency_proof, verify_inclusion_proof, ConsistencyProof, InclusionProof,
    SignedTreeHead, TransparencyLeaf,
};
use pqmsg_core::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
use pqmsg_core::pq_sig::{MlDsa65, PqSignatureProvider};
use pqmsg_core::ratchet::pq::{
    PqRatchetState, DEFAULT_PQ_RATCHET_INTERVAL, DEFAULT_PQ_RATCHET_KEY_HISTORY,
};
use pqmsg_core::safety_number::compute_safety_number;
use pqmsg_core::sealed::{open_message_with_cert, seal_message_with_cert, SenderCertificate};
use pqmsg_core::session::{SessionRole, SessionSnapshot, SessionState};
use pqmsg_core::storage::{
    unwrap_bytes as unwrap_wrapped_bytes, wrap_bytes as wrap_wrapped_bytes, WrappedSecret,
};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_core::CoreError;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ONE_TIME_PREKEYS: u32 = 256;
const SECONDARY_DEVICE_PACKAGE_VERSION: u16 = 1;
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
const AUTH_TAG_ROTATE_NEW_PQ_SIG_HASH: u16 = critical_type(0x3230);
const AUTH_TAG_ROTATE_PQ_SIG_CURRENT_HASH: u16 = critical_type(0x3231);
const AUTH_TAG_ROTATE_PQ_SIG_NEW_HASH: u16 = critical_type(0x3232);
const AUTH_TAG_PUSH_DEVICE_ID: u16 = critical_type(0x3210);
const AUTH_TAG_PUSH_TOKEN_HASH: u16 = critical_type(0x3211);
const AUTH_TAG_LINK_DEVICE_ID: u16 = critical_type(0x3212);
const AUTH_TAG_REVOKE_DEVICE_ID: u16 = critical_type(0x3213);
const AUTH_TAG_CONTACT_USER_ID: u16 = critical_type(0x3219);
const AUTH_TAG_CONTACT_ALIAS_HASH: u16 = critical_type(0x321A);
const AUTH_TAG_CONTACT_VERIFIED_FLAG: u16 = critical_type(0x321B);
const AUTH_TAG_CONTACT_FINGERPRINT: u16 = critical_type(0x321C);
const AUTH_TAG_GROUP_ID: u16 = critical_type(0x321D);
const AUTH_TAG_GROUP_MEMBER_USER_ID: u16 = critical_type(0x321E);
const AUTH_TAG_GROUP_MEMBERS_HASH: u16 = critical_type(0x321F);
const AUTH_TAG_GROUP_SENDER_USER_ID: u16 = critical_type(0x3220);
const AUTH_TAG_PROFILE_DISPLAY_NAME_HASH: u16 = critical_type(0x3226);
const AUTH_TAG_PROFILE_AVATAR_HASH: u16 = critical_type(0x3227);
const AUTH_TAG_PROFILE_AVATAR_MIME_HASH: u16 = critical_type(0x3228);
const AUTH_TAG_PRESENCE_STATUS: u16 = critical_type(0x3229);
const AUTH_TAG_TYPING_PEER_ID: u16 = critical_type(0x322A);
const AUTH_TAG_TYPING_STATE_FLAG: u16 = critical_type(0x322B);
const AUTH_TAG_GROUP_RECIPIENTS_HASH: u16 = critical_type(0x322C);
const AUTH_TAG_PROFILE_USERNAME_HASH: u16 = critical_type(0x322D);
const AUTH_TAG_PROFILE_USERNAME_LOOKUP_ENABLED: u16 = critical_type(0x322E);
const ROTATE_SIG_TAG_USER_ID: u16 = critical_type(0x3101);
const ROTATE_SIG_TAG_CHALLENGE_ID: u16 = critical_type(0x3102);
const ROTATE_SIG_TAG_CHALLENGE_NONCE: u16 = critical_type(0x3103);
const ROTATE_SIG_TAG_NEW_IDENTITY_X25519: u16 = critical_type(0x3104);
const ROTATE_SIG_TAG_NEW_IDENTITY_SIG: u16 = critical_type(0x3105);
const ROTATE_SIG_TAG_NEW_DEVICE_ID: u16 = critical_type(0x3106);
const ROTATE_SIG_TAG_NEW_IDENTITY_PQ_SIG: u16 = critical_type(0x3107);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, uniffi::Enum)]
pub enum Suite {
    MlKem768,
    Kyber768,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OneTimeKeyRecord {
    key_id: String,
    public_b64: String,
    secret_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserKeysFile {
    version: u16,
    user_id: String,
    device_id: String,
    suite: Suite,
    identity_x25519_pub_b64: String,
    identity_x25519_secret_b64: String,
    identity_sig_pub_b64: String,
    identity_sig_secret_b64: String,
    identity_pq_sig_pub_b64: String,
    identity_pq_sig_secret_b64: String,
    signed_prekey_x25519_pub_b64: String,
    signed_prekey_x25519_secret_b64: String,
    pq_signed_prekey_pub_b64: String,
    pq_signed_prekey_secret_b64: String,
    one_time_prekeys_x25519: Vec<OneTimeKeyRecord>,
    one_time_prekeys_mlkem768: Vec<OneTimeKeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionFile {
    version: u16,
    user_id: String,
    peer_user_id: String,
    suite: Suite,
    snapshot: SessionSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateGroupRestoreResult {
    state: PrivateGroupState,
    member_credential: PrivateGroupMemberCredential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateGroupCredentialMaterial {
    membership_handle_sha256: String,
    member_commitment_sha256: String,
    fetch_key_base64: String,
    fetch_key_sha256: String,
    publish_key_base64: Option<String>,
    publish_key_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecondaryDeviceOnboardingPayload {
    version: u16,
    server_url: String,
    keys_json: String,
    exported_at_unix: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct BundleResponse {
    user_id: String,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    identity_pq_sig_pub: String,
    signed_prekey_x25519_pub: String,
    sig_over_spk: String,
    pq_signed_prekey_pub_mlkem768: String,
    sig_over_pqspk: String,
    pq_sig_over_spk: String,
    pq_sig_over_pqspk: String,
    one_time_prekey_x25519: Option<String>,
    one_time_prekey_mlkem768: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct UserProfile {
    pub user_id: String,
    pub device_id: String,
    pub suite: Suite,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RegisterPayload {
    pub user_id: String,
    pub identity_x25519_pub: String,
    pub identity_sig_pub: String,
    pub identity_pq_sig_pub: String,
    pub device_id: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PublishPrekeysPayload {
    pub signed_prekey_x25519_pub: String,
    pub sig_over_spk: String,
    pub pq_signed_prekey_pub_mlkem768: String,
    pub sig_over_pqspk: String,
    pub pq_sig_over_spk: String,
    pub pq_sig_over_pqspk: String,
    pub one_time_prekeys_x25519: Vec<String>,
    pub one_time_prekeys_mlkem768: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RequestAuthHeaders {
    pub auth_user: String,
    pub auth_device: String,
    pub auth_timestamp: String,
    pub auth_nonce: String,
    pub auth_signature: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct GroupRelayAuthRecipient {
    pub recipient_user_id: String,
    pub message_bytes_base64: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SecondaryDeviceOnboardingPackage {
    pub server_url: String,
    pub user_id: String,
    pub device_id: String,
    pub suite: Suite,
    pub keys_json: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RotateInitPayload {
    pub new_identity_x25519_pub: String,
    pub new_identity_sig_pub: String,
    pub new_identity_pq_sig_pub: String,
    pub new_device_id: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RotateConfirmPayload {
    pub challenge_id: String,
    pub sig_by_current_identity: String,
    pub sig_by_new_identity: String,
    pub pq_sig_by_current_identity: String,
    pub pq_sig_by_new_identity: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TransparencyLeafRecord {
    user_id: String,
    version: u64,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    identity_pq_sig_pub: Option<String>,
    timestamp: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct TransparencyPathItem {
    hash: String,
    is_left: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct TransparencyInclusionProofRecord {
    leaf_index: u64,
    path: Vec<TransparencyPathItem>,
}

#[derive(Debug, Clone, Deserialize)]
struct TransparencyConsistencyProofRecord {
    old_size: u64,
    new_size: u64,
    proof_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct TransparencySignedTreeHeadRecord {
    pub epoch: u64,
    pub tree_size: u64,
    pub root_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TransparencyProofDocument {
    leaf: TransparencyLeafRecord,
    inclusion_proof: TransparencyInclusionProofRecord,
    signed_tree_head: TransparencySignedTreeHeadRecord,
    consistency_proof: Option<TransparencyConsistencyProofRecord>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TransparencyVerificationResult {
    pub verified: bool,
    pub consistency_verified: bool,
    pub leaf_user_id: String,
    pub leaf_version: u64,
    pub tree_size: u64,
    pub epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct ServerBundle {
    pub user_id: String,
    pub identity_x25519_pub: String,
    pub identity_sig_pub: String,
    pub identity_pq_sig_pub: String,
    pub signed_prekey_x25519_pub: String,
    pub sig_over_spk: String,
    pub pq_signed_prekey_pub_mlkem768: String,
    pub sig_over_pqspk: String,
    pub pq_sig_over_spk: String,
    pub pq_sig_over_pqspk: String,
    pub one_time_prekey_x25519: Option<String>,
    pub one_time_prekey_mlkem768: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SendResult {
    pub message_bytes_base64: String,
    pub session_json: String,
    pub used_handshake: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DecryptResult {
    pub plaintext_utf8: String,
    pub plaintext_base64: String,
    pub session_json: String,
    pub used_handshake: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct OpenedCertifiedSealedMessage {
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub payload_message_bytes_base64: String,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PqmsgAndroidError {
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    #[error("operation failed: {reason}")]
    OperationFailed { reason: String },
}

struct Ed25519SignatureVerifier;

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CoreError::InvalidLength {
                field: "signature.public_key",
                expected: 32,
                actual: public_key.len(),
            })?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| CoreError::InvalidLength {
            field: "signature.signature",
            expected: 64,
            actual: signature.len(),
        })?;
        let verifier = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CoreError::SignatureVerificationFailed)?;
        let signature = Signature::from_bytes(&signature);
        verifier
            .verify(message, &signature)
            .map_err(|_| CoreError::SignatureVerificationFailed)
    }
}

struct AndroidKemKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

fn kem_keypair(kem: &MlKem768) -> Result<AndroidKemKeyPair, PqmsgAndroidError> {
    let pair = kem.keypair()?;
    Ok(AndroidKemKeyPair {
        public_key: pair.public_key,
        secret_key: pair.secret_key.as_slice().to_vec(),
    })
}

fn suite_to_kem_algorithm(suite: Suite) -> KemAlgorithm {
    match suite {
        Suite::MlKem768 => KemAlgorithm::MlKem768,
        Suite::Kyber768 => KemAlgorithm::Kyber768Alias,
    }
}

fn suite_from_suite_id(suite_id: u16) -> Result<Suite, PqmsgAndroidError> {
    match suite_id {
        SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok(Suite::MlKem768),
        SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok(Suite::Kyber768),
        _ => Err(operation_failed(format!(
            "unsupported suite_id '{}'",
            suite_id
        ))),
    }
}

fn suite_id_for_user_keys(suite: Suite) -> u16 {
    match suite {
        Suite::MlKem768 => SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
        Suite::Kyber768 => SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    }
}

fn build_kem_for_suite(suite: Suite) -> Result<MlKem768, PqmsgAndroidError> {
    MlKem768::new(suite_to_kem_algorithm(suite))
        .map_err(|_| operation_failed("pq-oqs backend is disabled"))
}

fn mandatory_pq_ratchet_state(
    local_pq_prekey: &KEMPreKey,
    remote_public_key: Vec<u8>,
) -> PqRatchetState {
    PqRatchetState {
        interval: DEFAULT_PQ_RATCHET_INTERVAL,
        local_public_key: local_pq_prekey.public_key.clone(),
        local_secret_key: local_pq_prekey.secret_key.clone(),
        remote_public_key,
        local_key_history: Vec::new(),
        max_key_history: DEFAULT_PQ_RATCHET_KEY_HISTORY,
        last_remote_update_msg_num: 0,
    }
}

fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> SigningKey {
    SigningKey::generate(rng)
}

fn decode_signing_key_b64(
    field: &'static str,
    value: &str,
) -> Result<SigningKey, PqmsgAndroidError> {
    let bytes = decode_b64(field, value)?;
    let actual_len = bytes.len();
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        invalid_input(format!(
            "field '{field}' must decode to 32 bytes (got {})",
            actual_len
        ))
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn build_signature_payload(signing_key: &SigningKey, message: &[u8]) -> String {
    B64.encode(signing_key.sign(message).to_bytes())
}

fn build_pq_signature_provider() -> Result<MlDsa65, PqmsgAndroidError> {
    MlDsa65::new().map_err(|_| operation_failed("pq signature backend is disabled"))
}

fn build_pq_signature_payload(
    secret_key: &[u8],
    message: &[u8],
) -> Result<String, PqmsgAndroidError> {
    let provider = build_pq_signature_provider()?;
    Ok(B64.encode(provider.sign(secret_key, message)?))
}

fn auth_signing_key_for_user(keys: &UserKeysFile) -> Result<SigningKey, PqmsgAndroidError> {
    let signing_key =
        decode_signing_key_b64("identity_sig_secret_b64", &keys.identity_sig_secret_b64)?;
    Ok(signing_key)
}

fn refresh_one_time_prekeys(
    keys: &mut UserKeysFile,
    one_time_count: u32,
) -> Result<(), PqmsgAndroidError> {
    if one_time_count == 0 || one_time_count > MAX_ONE_TIME_PREKEYS {
        return Err(invalid_input(format!(
            "one_time_count must be in 1..={MAX_ONE_TIME_PREKEYS}"
        )));
    }
    let mut rng = OsRng;
    let kem = build_kem_for_suite(keys.suite)?;
    let timestamp = auth_timestamp()?;
    let mut one_time_x25519 = Vec::with_capacity(one_time_count as usize);
    let mut one_time_mlkem = Vec::with_capacity(one_time_count as usize);

    for idx in 0..one_time_count {
        let key = OneTimePreKey::generate(
            format!("{}-otk-x-{}-{idx}", keys.user_id, timestamp),
            &mut rng,
        );
        one_time_x25519.push(OneTimeKeyRecord {
            key_id: key.key_id,
            public_b64: B64.encode(key.public_key.0),
            secret_b64: B64.encode(key.secret_key.as_slice()),
        });

        let pq_key = kem_keypair(&kem)?;
        one_time_mlkem.push(OneTimeKeyRecord {
            key_id: format!("{}-otk-pq-{}-{idx}", keys.user_id, timestamp),
            public_b64: B64.encode(pq_key.public_key),
            secret_b64: B64.encode(pq_key.secret_key),
        });
    }

    keys.one_time_prekeys_x25519 = one_time_x25519;
    keys.one_time_prekeys_mlkem768 = one_time_mlkem;
    Ok(())
}

fn rebind_keys_to_new_device(
    keys: &UserKeysFile,
    new_device_id: String,
    one_time_count: u32,
) -> Result<UserKeysFile, PqmsgAndroidError> {
    let normalized_device_id = new_device_id.trim();
    if normalized_device_id.is_empty() {
        return Err(invalid_input("new_device_id must not be empty"));
    }
    if normalized_device_id == keys.device_id {
        return Err(invalid_input(
            "new_device_id must differ from the current device_id",
        ));
    }
    let signing_key =
        decode_signing_key_b64("identity_sig_secret_b64", &keys.identity_sig_secret_b64)?;
    if B64.encode(signing_key.verifying_key().to_bytes()) != keys.identity_sig_pub_b64 {
        return Err(invalid_input(
            "identity_sig_pub_b64 does not match identity_sig_secret_b64",
        ));
    }

    let mut rebound = keys.clone();
    rebound.device_id = normalized_device_id.to_string();
    let mut rng = OsRng;
    let timestamp = auth_timestamp()?;
    let signed_prekey =
        OneTimePreKey::generate(format!("{}-spk-{timestamp}", rebound.user_id), &mut rng);
    let kem = build_kem_for_suite(rebound.suite)?;
    let pq_signed_prekey = kem_keypair(&kem)?;
    rebound.signed_prekey_x25519_pub_b64 = B64.encode(signed_prekey.public_key.0);
    rebound.signed_prekey_x25519_secret_b64 = B64.encode(signed_prekey.secret_key.as_slice());
    rebound.pq_signed_prekey_pub_b64 = B64.encode(pq_signed_prekey.public_key);
    rebound.pq_signed_prekey_secret_b64 = B64.encode(pq_signed_prekey.secret_key);
    refresh_one_time_prekeys(&mut rebound, one_time_count)?;
    Ok(rebound)
}

fn rotation_signature_message(
    user_id: &str,
    challenge_id: &str,
    challenge_nonce: &[u8],
    new_identity_x25519: &[u8],
    new_identity_sig: &[u8],
    new_identity_pq_sig: &[u8],
    new_device_id: &str,
) -> Result<Vec<u8>, PqmsgAndroidError> {
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
            ty: ROTATE_SIG_TAG_NEW_IDENTITY_PQ_SIG,
            value: new_identity_pq_sig.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_DEVICE_ID,
            value: new_device_id.as_bytes().to_vec(),
        },
    ])
    .map_err(|_| operation_failed("failed to encode rotation signature transcript"))
}

fn auth_timestamp() -> Result<i64, PqmsgAndroidError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| operation_failed("system time is before UNIX epoch"))?;
    i64::try_from(duration.as_secs()).map_err(|_| operation_failed("system time overflow"))
}

fn auth_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn auth_common_records(
    endpoint: &'static str,
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

fn hash_string_list_sha256(values: &[String]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_vec()
}

fn normalize_contact_alias_for_auth(alias: &str) -> String {
    alias.trim().to_string()
}

fn normalize_fingerprint_sha256_for_auth(
    fingerprint_sha256: Option<String>,
) -> Result<Option<String>, PqmsgAndroidError> {
    let Some(fingerprint_sha256) = fingerprint_sha256 else {
        return Ok(None);
    };
    let normalized = fingerprint_sha256.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.len() != 64 {
        return Err(invalid_input(
            "verified_fingerprint_sha256 must be 64 lowercase hex characters",
        ));
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(invalid_input(
            "verified_fingerprint_sha256 must be 64 lowercase hex characters",
        ));
    }
    Ok(Some(normalized))
}

fn normalize_group_members_for_auth(member_user_ids: &[String]) -> Vec<String> {
    let mut normalized_members: Vec<String> = member_user_ids
        .iter()
        .map(|member_user_id| member_user_id.trim().to_string())
        .collect();
    normalized_members.sort_unstable();
    normalized_members.dedup();
    normalized_members
}

fn normalize_presence_status_for_auth(status: &str) -> Result<String, PqmsgAndroidError> {
    let normalized = status.trim().to_ascii_lowercase();
    let valid = matches!(normalized.as_str(), "offline" | "online" | "away" | "busy");
    if valid {
        Ok(normalized)
    } else {
        Err(invalid_input(
            "status must be one of offline|online|away|busy",
        ))
    }
}

fn hash_group_recipients_sha256(
    recipients: &[GroupRelayAuthRecipient],
) -> Result<Vec<u8>, PqmsgAndroidError> {
    let mut normalized: Vec<(String, Vec<u8>)> = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let mut blob_hasher = Sha256::new();
        blob_hasher.update(decode_b64(
            "message_bytes_base64",
            &recipient.message_bytes_base64,
        )?);
        normalized.push((
            recipient.recipient_user_id.clone(),
            blob_hasher.finalize().to_vec(),
        ));
    }
    normalized.sort_by(|left, right| left.0.cmp(&right.0));

    let mut hasher = Sha256::new();
    for (recipient_user_id, message_hash) in normalized {
        hasher.update(recipient_user_id.as_bytes());
        hasher.update([0x00]);
        hasher.update(&message_hash);
        hasher.update([0x01]);
    }
    Ok(hasher.finalize().to_vec())
}

#[uniffi::export]
pub fn active_crypto_profile() -> Result<String, PqmsgAndroidError> {
    let profile = runtime_crypto_profile()?;
    serde_json::to_string_pretty(&profile).map_err(Into::into)
}

#[uniffi::export]
pub fn require_pq_backend_enabled() -> Result<(), PqmsgAndroidError> {
    let profile = runtime_crypto_profile()?;
    if profile.pq_oqs_enabled {
        Ok(())
    } else {
        Err(operation_failed("pq-oqs backend is disabled"))
    }
}

#[uniffi::export]
pub fn suite_id_from_suite(suite: Suite) -> Result<u16, PqmsgAndroidError> {
    let config = AlgorithmSuite {
        kem: suite_to_kem_algorithm(suite),
        ..AlgorithmSuite::default()
    };
    config.suite_id().map_err(Into::into)
}

#[uniffi::export]
pub fn suite_from_suite_id_json(suite_id: u16) -> Result<String, PqmsgAndroidError> {
    let suite = suite_from_suite_id(suite_id)?;
    serde_json::to_string(&suite).map_err(Into::into)
}

#[uniffi::export]
pub fn verify_identity_sig_keypair(keys_json: String) -> Result<bool, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing = decode_signing_key_b64("identity_sig_secret_b64", &keys.identity_sig_secret_b64)?;
    Ok(B64.encode(signing.verifying_key().to_bytes()) == keys.identity_sig_pub_b64)
}

#[uniffi::export]
pub fn generate_identity_keys(
    user_id: String,
    device_id: String,
    suite: Suite,
    one_time_count: u32,
) -> Result<String, PqmsgAndroidError> {
    if user_id.trim().is_empty() {
        return Err(invalid_input("user_id must not be empty"));
    }
    if device_id.trim().is_empty() {
        return Err(invalid_input("device_id must not be empty"));
    }
    if one_time_count == 0 || one_time_count > MAX_ONE_TIME_PREKEYS {
        return Err(invalid_input(format!(
            "one_time_count must be in 1..={MAX_ONE_TIME_PREKEYS}"
        )));
    }

    let mut rng = OsRng;
    let identity = IdentityKeyPair::generate(format!("{user_id}-ik"), &mut rng);
    let signed_prekey = OneTimePreKey::generate(format!("{user_id}-spk"), &mut rng);
    let identity_sig = generate_signing_key(&mut rng);
    let pq_identity_sig = build_pq_signature_provider()?.keypair()?;
    let kem = build_kem_for_suite(suite)?;
    let pq_signed_prekey = kem_keypair(&kem)?;

    let mut one_time_x25519 = Vec::with_capacity(one_time_count as usize);
    let mut one_time_mlkem = Vec::with_capacity(one_time_count as usize);

    for idx in 0..one_time_count {
        let key = OneTimePreKey::generate(format!("{user_id}-otk-x-{idx}"), &mut rng);
        one_time_x25519.push(OneTimeKeyRecord {
            key_id: key.key_id,
            public_b64: B64.encode(key.public_key.0),
            secret_b64: B64.encode(key.secret_key.as_slice()),
        });

        let pq_key = kem_keypair(&kem)?;
        one_time_mlkem.push(OneTimeKeyRecord {
            key_id: format!("{user_id}-otk-pq-{idx}"),
            public_b64: B64.encode(pq_key.public_key),
            secret_b64: B64.encode(pq_key.secret_key),
        });
    }

    let keys = UserKeysFile {
        version: 1,
        user_id,
        device_id,
        suite,
        identity_x25519_pub_b64: B64.encode(identity.public_key.0),
        identity_x25519_secret_b64: B64.encode(identity.secret_key.as_slice()),
        identity_sig_pub_b64: B64.encode(identity_sig.verifying_key().to_bytes()),
        identity_sig_secret_b64: B64.encode(identity_sig.to_bytes()),
        identity_pq_sig_pub_b64: B64.encode(&pq_identity_sig.public_key),
        identity_pq_sig_secret_b64: B64.encode(pq_identity_sig.secret_key.as_slice()),
        signed_prekey_x25519_pub_b64: B64.encode(signed_prekey.public_key.0),
        signed_prekey_x25519_secret_b64: B64.encode(signed_prekey.secret_key.as_slice()),
        pq_signed_prekey_pub_b64: B64.encode(pq_signed_prekey.public_key),
        pq_signed_prekey_secret_b64: B64.encode(pq_signed_prekey.secret_key),
        one_time_prekeys_x25519: one_time_x25519,
        one_time_prekeys_mlkem768: one_time_mlkem,
    };

    serde_json::to_string_pretty(&keys).map_err(Into::into)
}

#[uniffi::export]
pub fn load_user_profile(keys_json: String) -> Result<UserProfile, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    Ok(UserProfile {
        user_id: keys.user_id,
        device_id: keys.device_id,
        suite: keys.suite,
    })
}

#[uniffi::export]
pub fn compute_safety_number_with_peer(
    keys_json: String,
    peer_user_id: String,
    peer_identity_x25519_pub_b64: String,
    peer_identity_pq_sig_pub_b64: String,
) -> Result<String, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let local_identity_x25519 =
        decode_b64_32("identity_x25519_pub_b64", &keys.identity_x25519_pub_b64)?;
    let peer_identity_x25519 = decode_b64_32(
        "peer_identity_x25519_pub_b64",
        &peer_identity_x25519_pub_b64,
    )?;
    let local_identity_pq_sig =
        decode_b64("identity_pq_sig_pub_b64", &keys.identity_pq_sig_pub_b64)?;
    let peer_identity_pq_sig = decode_b64(
        "peer_identity_pq_sig_pub_b64",
        &peer_identity_pq_sig_pub_b64,
    )?;
    Ok(compute_safety_number(
        &keys.user_id,
        &local_identity_x25519,
        &local_identity_pq_sig,
        &peer_user_id,
        &peer_identity_x25519,
        &peer_identity_pq_sig,
    ))
}

#[uniffi::export]
pub fn build_register_payload(keys_json: String) -> Result<RegisterPayload, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    Ok(RegisterPayload {
        user_id: keys.user_id,
        identity_x25519_pub: keys.identity_x25519_pub_b64,
        identity_sig_pub: keys.identity_sig_pub_b64,
        identity_pq_sig_pub: keys.identity_pq_sig_pub_b64,
        device_id: keys.device_id,
    })
}

#[uniffi::export]
pub fn build_publish_prekeys_payload(
    keys_json: String,
) -> Result<PublishPrekeysPayload, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let spk_pub = decode_b64_32(
        "signed_prekey_x25519_pub_b64",
        &keys.signed_prekey_x25519_pub_b64,
    )?;
    let pq_spk_pub = decode_b64("pq_signed_prekey_pub_b64", &keys.pq_signed_prekey_pub_b64)?;
    let signing_key =
        decode_signing_key_b64("identity_sig_secret_b64", &keys.identity_sig_secret_b64)?;
    let pq_sig_secret_key = decode_b64(
        "identity_pq_sig_secret_b64",
        &keys.identity_pq_sig_secret_b64,
    )?;
    if B64.encode(signing_key.verifying_key().to_bytes()) != keys.identity_sig_pub_b64 {
        return Err(invalid_input(
            "identity_sig_pub_b64 does not match identity_sig_secret_b64",
        ));
    }

    let spk_msg = signed_prekey_signature_message(1, &DhPublicKey(spk_pub))?;
    let pq_msg = pq_signed_prekey_signature_message(1, &pq_spk_pub)?;

    Ok(PublishPrekeysPayload {
        signed_prekey_x25519_pub: keys.signed_prekey_x25519_pub_b64,
        sig_over_spk: build_signature_payload(&signing_key, &spk_msg),
        pq_signed_prekey_pub_mlkem768: keys.pq_signed_prekey_pub_b64,
        sig_over_pqspk: build_signature_payload(&signing_key, &pq_msg),
        pq_sig_over_spk: build_pq_signature_payload(&pq_sig_secret_key, &spk_msg)?,
        pq_sig_over_pqspk: build_pq_signature_payload(&pq_sig_secret_key, &pq_msg)?,
        one_time_prekeys_x25519: keys
            .one_time_prekeys_x25519
            .into_iter()
            .map(|item| item.public_b64)
            .collect(),
        one_time_prekeys_mlkem768: keys
            .one_time_prekeys_mlkem768
            .into_iter()
            .map(|item| item.public_b64)
            .collect(),
    })
}

#[uniffi::export]
pub fn replenish_one_time_prekeys(
    keys_json: String,
    one_time_count: u32,
) -> Result<String, PqmsgAndroidError> {
    let mut keys = read_keys_file(&keys_json)?;
    refresh_one_time_prekeys(&mut keys, one_time_count)?;
    serde_json::to_string_pretty(&keys).map_err(Into::into)
}

#[uniffi::export]
pub fn prepare_secondary_device_package(
    keys_json: String,
    new_device_id: String,
    server_url: String,
    one_time_count: u32,
    package_passphrase: String,
) -> Result<String, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let rebound = rebind_keys_to_new_device(&keys, new_device_id, one_time_count)?;
    let normalized_server_url = server_url.trim();
    if normalized_server_url.is_empty() {
        return Err(invalid_input("server_url must not be empty"));
    }
    if package_passphrase.trim().is_empty() {
        return Err(invalid_input("package_passphrase must not be empty"));
    }
    let rebound_keys_json = serde_json::to_string_pretty(&rebound)?;
    let payload = SecondaryDeviceOnboardingPayload {
        version: SECONDARY_DEVICE_PACKAGE_VERSION,
        server_url: normalized_server_url.to_string(),
        keys_json: rebound_keys_json,
        exported_at_unix: auth_timestamp()?,
    };
    let plaintext = serde_json::to_vec_pretty(&payload)?;
    let wrapped = wrap_wrapped_bytes(&SecretString::new(package_passphrase.into()), &plaintext)?;
    serde_json::to_string_pretty(&wrapped).map_err(Into::into)
}

#[uniffi::export]
pub fn open_secondary_device_package(
    package_json: String,
    package_passphrase: String,
) -> Result<SecondaryDeviceOnboardingPackage, PqmsgAndroidError> {
    if package_passphrase.trim().is_empty() {
        return Err(invalid_input("package_passphrase must not be empty"));
    }
    let wrapped: WrappedSecret = serde_json::from_str(&package_json)?;
    let plaintext = unwrap_wrapped_bytes(&SecretString::new(package_passphrase.into()), &wrapped)?;
    let payload: SecondaryDeviceOnboardingPayload = serde_json::from_slice(&plaintext)?;
    if payload.version != SECONDARY_DEVICE_PACKAGE_VERSION {
        return Err(invalid_input(format!(
            "unsupported onboarding package version '{}'",
            payload.version
        )));
    }
    let normalized_server_url = payload.server_url.trim();
    if normalized_server_url.is_empty() {
        return Err(invalid_input(
            "onboarding package server_url must not be empty",
        ));
    }
    let keys = read_keys_file(&payload.keys_json)?;
    Ok(SecondaryDeviceOnboardingPackage {
        server_url: normalized_server_url.to_string(),
        user_id: keys.user_id,
        device_id: keys.device_id,
        suite: keys.suite,
        keys_json: payload.keys_json,
    })
}

#[uniffi::export]
pub fn build_rotate_init_payload(
    keys_json: String,
) -> Result<RotateInitPayload, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    Ok(RotateInitPayload {
        new_identity_x25519_pub: keys.identity_x25519_pub_b64,
        new_identity_sig_pub: keys.identity_sig_pub_b64,
        new_identity_pq_sig_pub: keys.identity_pq_sig_pub_b64,
        new_device_id: keys.device_id,
    })
}

#[uniffi::export]
pub fn build_rotate_init_auth_headers(
    keys_json: String,
    user_id: String,
    new_identity_x25519_pub: String,
    new_identity_sig_pub: String,
    new_identity_pq_sig_pub: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("rotate-init", &user_id, &keys.device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(new_identity_x25519_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_X25519_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(new_identity_sig_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_SIG_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(new_identity_pq_sig_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_PQ_SIG_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode rotate-init auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_rotate_confirm_payload(
    current_keys_json: String,
    new_keys_json: String,
    user_id: String,
    challenge_id: String,
    challenge_nonce_base64: String,
) -> Result<RotateConfirmPayload, PqmsgAndroidError> {
    let current_keys = read_keys_file(&current_keys_json)?;
    if current_keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match current keys user '{}'",
            user_id, current_keys.user_id
        )));
    }
    let new_keys = read_keys_file(&new_keys_json)?;
    if new_keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match new keys user '{}'",
            user_id, new_keys.user_id
        )));
    }
    let current_signing_key = auth_signing_key_for_user(&current_keys)?;
    let new_signing_key = auth_signing_key_for_user(&new_keys)?;
    let current_pq_signing_key = decode_b64(
        "identity_pq_sig_secret_b64",
        &current_keys.identity_pq_sig_secret_b64,
    )?;
    let new_pq_signing_key = decode_b64(
        "identity_pq_sig_secret_b64",
        &new_keys.identity_pq_sig_secret_b64,
    )?;
    let challenge_nonce = decode_b64("challenge_nonce_base64", &challenge_nonce_base64)?;
    let new_identity_x25519 =
        decode_b64("identity_x25519_pub_b64", &new_keys.identity_x25519_pub_b64)?;
    let new_identity_sig = decode_b64("identity_sig_pub_b64", &new_keys.identity_sig_pub_b64)?;
    let new_identity_pq_sig =
        decode_b64("identity_pq_sig_pub_b64", &new_keys.identity_pq_sig_pub_b64)?;
    let message = rotation_signature_message(
        &user_id,
        &challenge_id,
        &challenge_nonce,
        &new_identity_x25519,
        &new_identity_sig,
        &new_identity_pq_sig,
        &new_keys.device_id,
    )?;
    Ok(RotateConfirmPayload {
        challenge_id,
        sig_by_current_identity: B64.encode(current_signing_key.sign(&message).to_bytes()),
        sig_by_new_identity: B64.encode(new_signing_key.sign(&message).to_bytes()),
        pq_sig_by_current_identity: build_pq_signature_payload(&current_pq_signing_key, &message)?,
        pq_sig_by_new_identity: build_pq_signature_payload(&new_pq_signing_key, &message)?,
    })
}

#[uniffi::export]
pub fn build_rotate_confirm_auth_headers(
    keys_json: String,
    user_id: String,
    challenge_id: String,
    sig_by_current_identity: String,
    sig_by_new_identity: String,
    pq_sig_by_current_identity: String,
    pq_sig_by_new_identity: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "rotate-confirm",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_CHALLENGE_ID,
        value: challenge_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(sig_by_current_identity.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_SIG_CURRENT_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(sig_by_new_identity.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_SIG_NEW_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(pq_sig_by_current_identity.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_PQ_SIG_CURRENT_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(pq_sig_by_new_identity.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_PQ_SIG_NEW_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode rotate-confirm auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_identity_log_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("identity-log", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode identity-log auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

fn parse_transparency_leaf(
    record: TransparencyLeafRecord,
) -> Result<TransparencyLeaf, PqmsgAndroidError> {
    Ok(TransparencyLeaf {
        user_id: record.user_id,
        version: record.version,
        identity_x25519_pub: decode_b64_32(
            "transparency.leaf.identity_x25519_pub",
            &record.identity_x25519_pub,
        )?,
        identity_sig_pub: decode_b64(
            "transparency.leaf.identity_sig_pub",
            &record.identity_sig_pub,
        )?,
        identity_pq_sig_pub: record
            .identity_pq_sig_pub
            .as_ref()
            .map(|raw| decode_b64("transparency.leaf.identity_pq_sig_pub", raw))
            .transpose()?,
        timestamp: record.timestamp,
    })
}

fn parse_transparency_sth(
    record: TransparencySignedTreeHeadRecord,
) -> Result<SignedTreeHead, PqmsgAndroidError> {
    Ok(SignedTreeHead {
        epoch: record.epoch,
        tree_size: record.tree_size,
        root_hash: decode_b64_32("transparency.signed_tree_head.root_hash", &record.root_hash)?,
        signature: decode_b64("transparency.signed_tree_head.signature", &record.signature)?,
    })
}

#[uniffi::export]
pub fn verify_transparency_proof(
    proof_json: String,
    server_pub_key_b64: String,
    previous_sth_json: Option<String>,
) -> Result<TransparencyVerificationResult, PqmsgAndroidError> {
    let document: TransparencyProofDocument = serde_json::from_str(&proof_json)?;
    let leaf = parse_transparency_leaf(document.leaf)?;
    let inclusion_proof = InclusionProof {
        leaf_index: document.inclusion_proof.leaf_index,
        path: document
            .inclusion_proof
            .path
            .into_iter()
            .map(|item| {
                Ok((
                    decode_b64_32("transparency.inclusion_proof.path.hash", &item.hash)?,
                    item.is_left,
                ))
            })
            .collect::<Result<Vec<_>, PqmsgAndroidError>>()?,
    };
    let sth = parse_transparency_sth(document.signed_tree_head)?;
    let server_pub_key = VerifyingKey::from_bytes(&decode_b64_32(
        "transparency.server_pub_key",
        &server_pub_key_b64,
    )?)
    .map_err(|_| operation_failed("invalid transparency server public key"))?;
    verify_inclusion_proof(&leaf.hash(), &inclusion_proof, &sth, &server_pub_key)
        .map_err(|error| operation_failed(error.to_string()))?;

    let mut consistency_verified = false;
    if let Some(previous_sth_json) = previous_sth_json {
        let previous_sth_record: TransparencySignedTreeHeadRecord =
            serde_json::from_str(&previous_sth_json)?;
        let previous_sth = parse_transparency_sth(previous_sth_record)?;
        if let Some(consistency_record) = document.consistency_proof {
            let proof = ConsistencyProof {
                old_size: consistency_record.old_size,
                new_size: consistency_record.new_size,
                proof_hashes: consistency_record
                    .proof_hashes
                    .into_iter()
                    .map(|hash| decode_b64_32("transparency.consistency_proof.hash", &hash))
                    .collect::<Result<Vec<_>, PqmsgAndroidError>>()?,
            };
            verify_consistency_proof(&previous_sth, &sth, &proof, &server_pub_key)
                .map_err(|error| operation_failed(error.to_string()))?;
            consistency_verified = true;
        }
    }

    Ok(TransparencyVerificationResult {
        verified: true,
        consistency_verified,
        leaf_user_id: leaf.user_id,
        leaf_version: leaf.version,
        tree_size: sth.tree_size,
        epoch: sth.epoch,
    })
}

#[uniffi::export]
pub fn parse_bundle_json(bundle_json: String) -> Result<ServerBundle, PqmsgAndroidError> {
    let bundle: BundleResponse = serde_json::from_str(&bundle_json)?;
    Ok(ServerBundle {
        user_id: bundle.user_id,
        identity_x25519_pub: bundle.identity_x25519_pub,
        identity_sig_pub: bundle.identity_sig_pub,
        identity_pq_sig_pub: bundle.identity_pq_sig_pub,
        signed_prekey_x25519_pub: bundle.signed_prekey_x25519_pub,
        sig_over_spk: bundle.sig_over_spk,
        pq_signed_prekey_pub_mlkem768: bundle.pq_signed_prekey_pub_mlkem768,
        sig_over_pqspk: bundle.sig_over_pqspk,
        pq_sig_over_spk: bundle.pq_sig_over_spk,
        pq_sig_over_pqspk: bundle.pq_sig_over_pqspk,
        one_time_prekey_x25519: bundle.one_time_prekey_x25519,
        one_time_prekey_mlkem768: bundle.one_time_prekey_mlkem768,
    })
}

#[uniffi::export]
pub fn private_group_create_state(
    owner_user_id: String,
    attributes_json: String,
    initial_members_json: String,
    created_at_unix_seconds: u64,
) -> Result<String, PqmsgAndroidError> {
    let attributes: PrivateGroupAttributes = serde_json::from_str(&attributes_json)?;
    let initial_members: Vec<PrivateGroupMember> = serde_json::from_str(&initial_members_json)?;
    let state = PrivateGroupState::new(
        owner_user_id,
        attributes,
        initial_members,
        created_at_unix_seconds,
    )?;
    serde_json::to_string_pretty(&state).map_err(Into::into)
}

#[uniffi::export]
pub fn private_group_encrypt_snapshot(
    state_json: String,
) -> Result<String, PqmsgAndroidError> {
    let state: PrivateGroupState = serde_json::from_str(&state_json)?;
    let snapshot: PrivateGroupEncryptedSnapshot = state.encrypted_snapshot()?;
    serde_json::to_string_pretty(&snapshot).map_err(Into::into)
}

#[uniffi::export]
pub fn private_group_export_invite_package(
    state_json: String,
) -> Result<String, PqmsgAndroidError> {
    let state: PrivateGroupState = serde_json::from_str(&state_json)?;
    let invite: PrivateGroupInvitePackage = state.export_invite_package()?;
    serde_json::to_string_pretty(&invite).map_err(Into::into)
}

#[uniffi::export]
pub fn private_group_export_join_package_for_member(
    state_json: String,
    member_user_id: String,
) -> Result<String, PqmsgAndroidError> {
    let state: PrivateGroupState = serde_json::from_str(&state_json)?;
    let join_package: PrivateGroupJoinPackage =
        state.export_join_package_for_member(&member_user_id)?;
    serde_json::to_string_pretty(&join_package).map_err(Into::into)
}

#[uniffi::export]
pub fn private_group_restore_join_package(
    join_package_json: String,
) -> Result<String, PqmsgAndroidError> {
    let join_package: PrivateGroupJoinPackage = serde_json::from_str(&join_package_json)?;
    let (state, member_credential) = join_package.restore_state_and_credential()?;
    serde_json::to_string_pretty(&PrivateGroupRestoreResult {
        state,
        member_credential,
    })
    .map_err(Into::into)
}

#[uniffi::export]
pub fn private_group_describe_member_credential(
    credential_json: String,
) -> Result<String, PqmsgAndroidError> {
    let credential: PrivateGroupMemberCredential = serde_json::from_str(&credential_json)?;
    let material = private_group_credential_material(&credential)?;
    serde_json::to_string_pretty(&material).map_err(Into::into)
}

#[uniffi::export]
pub fn private_group_prepare_add_member_transition(
    state_json: String,
    member_user_id: String,
    role: String,
    updated_at_unix_seconds: u64,
) -> Result<String, PqmsgAndroidError> {
    let state: PrivateGroupState = serde_json::from_str(&state_json)?;
    let role = parse_private_group_role(&role)?;
    let transition: PrivateGroupEpochTransition =
        state.prepare_add_member_transition(member_user_id, role, updated_at_unix_seconds)?;
    serde_json::to_string_pretty(&transition).map_err(Into::into)
}

#[uniffi::export]
pub fn private_group_prepare_remove_member_transition(
    state_json: String,
    member_user_id: String,
    updated_at_unix_seconds: u64,
) -> Result<String, PqmsgAndroidError> {
    let state: PrivateGroupState = serde_json::from_str(&state_json)?;
    let transition: PrivateGroupEpochTransition =
        state.prepare_remove_member_transition(&member_user_id, updated_at_unix_seconds)?;
    serde_json::to_string_pretty(&transition).map_err(Into::into)
}

#[uniffi::export]
pub fn build_relay_auth_headers(
    keys_json: String,
    sender_user_id: String,
    recipient_user_id: String,
    message_bytes_base64: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != sender_user_id {
        return Err(invalid_input(format!(
            "sender_user_id '{}' does not match keys user '{}'",
            sender_user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let message_blob = decode_b64("message_bytes_base64", &message_bytes_base64)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("relay", &sender_user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_MESSAGE_BLOB,
        value: message_blob,
    });
    let transcript =
        encode(&records).map_err(|_| operation_failed("failed to encode relay auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: sender_user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_inbox_auth_headers(
    keys_json: String,
    user_id: String,
    since: i64,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("inbox", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| operation_failed("failed to encode inbox auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_sealed_inbox_auth_headers(
    keys_json: String,
    user_id: String,
    since: i64,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("sealed-inbox", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode sealed-inbox auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_sender_certificate_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "sender-certificate",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode sender-certificate auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_contact_discovery_ticket_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "contact-discovery-ticket",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records).map_err(|_| {
        operation_failed("failed to encode contact-discovery-ticket auth transcript")
    })?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_contacts_list_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "contacts-list",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode contacts-list auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_contact_invite_create_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "contact-invite-create",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode contact-invite-create auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_contacts_upsert_auth_headers(
    keys_json: String,
    user_id: String,
    contact_user_id: String,
    alias: String,
    verified_by_qr: bool,
    verified_fingerprint_sha256: Option<String>,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let alias = normalize_contact_alias_for_auth(&alias);
    let verified_fingerprint_sha256 =
        normalize_fingerprint_sha256_for_auth(verified_fingerprint_sha256)?;
    let mut records = auth_common_records(
        "contacts-upsert",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    let mut alias_hasher = Sha256::new();
    alias_hasher.update(alias.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_ALIAS_HASH,
        value: alias_hasher.finalize().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_VERIFIED_FLAG,
        value: vec![if verified_by_qr { 1 } else { 0 }],
    });
    if let Some(fingerprint) = verified_fingerprint_sha256 {
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_FINGERPRINT,
            value: fingerprint.as_bytes().to_vec(),
        });
    }
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode contacts-upsert auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_contacts_remove_auth_headers(
    keys_json: String,
    user_id: String,
    contact_user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "contacts-remove",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode contacts-remove auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_group_create_auth_headers(
    keys_json: String,
    group_id: String,
    member_user_ids: Vec<String>,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let normalized_members = normalize_group_members_for_auth(&member_user_ids);
    let mut records = auth_common_records(
        "groups-create",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBERS_HASH,
        value: hash_string_list_sha256(&normalized_members),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode groups-create auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_user_groups_list_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("groups-list", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode groups-list auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_group_members_list_auth_headers(
    keys_json: String,
    group_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "groups-members-list",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode groups-members-list auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_group_members_add_auth_headers(
    keys_json: String,
    group_id: String,
    member_user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "groups-members-add",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode groups-members-add auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_group_members_remove_auth_headers(
    keys_json: String,
    group_id: String,
    member_user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "groups-members-remove",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode groups-members-remove auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_group_relay_auth_headers(
    keys_json: String,
    group_id: String,
    sender_user_id: String,
    recipients: Vec<GroupRelayAuthRecipient>,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != sender_user_id {
        return Err(invalid_input(format!(
            "sender_user_id '{}' does not match keys user '{}'",
            sender_user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "groups-relay",
        &sender_user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_SENDER_USER_ID,
        value: sender_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_RECIPIENTS_HASH,
        value: hash_group_recipients_sha256(&recipients)?,
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode groups-relay auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: sender_user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_profile_get_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "profile-get",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode profile-get auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_profile_upsert_auth_headers(
    keys_json: String,
    user_id: String,
    display_name: String,
    username: String,
    username_lookup_enabled: bool,
    avatar_mime: String,
    avatar_blob: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "profile-upsert",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(display_name.trim().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_DISPLAY_NAME_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    let normalized_username = username.trim().trim_start_matches('@').to_ascii_lowercase();
    hasher.update(normalized_username.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_USERNAME_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_USERNAME_LOOKUP_ENABLED,
        value: vec![if username_lookup_enabled { 1 } else { 0 }],
    });
    hasher.update(avatar_blob.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_AVATAR_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(avatar_mime.trim().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_AVATAR_MIME_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode profile-upsert auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_presence_update_auth_headers(
    keys_json: String,
    user_id: String,
    status: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let status = normalize_presence_status_for_auth(&status)?;
    let mut records = auth_common_records(
        "presence-update",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PRESENCE_STATUS,
        value: status.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode presence-update auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_presence_get_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "presence-get",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode presence-get auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_typing_update_auth_headers(
    keys_json: String,
    peer_user_id: String,
    is_typing: bool,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "typing-update",
        &keys.user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_TYPING_PEER_ID,
        value: peer_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_TYPING_STATE_FLAG,
        value: vec![if is_typing { 1 } else { 0 }],
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode typing-update auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_typing_get_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("typing-get", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode typing-get auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_send_receipt_auth_headers(
    keys_json: String,
    user_id: String,
    message_id: i64,
    receipt_type: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    build_format_string_auth_headers(
        keys_json,
        format!(
            "receipt:{}:{}:{}:{}",
            user_id, keys.device_id, message_id, receipt_type
        ),
    )
}

#[uniffi::export]
pub fn build_get_receipts_auth_headers(
    keys_json: String,
    user_id: String,
    since_id: i64,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    build_format_string_auth_headers(
        keys_json,
        format!("get-receipts:{}:{}:{}", user_id, keys.device_id, since_id),
    )
}

#[uniffi::export]
pub fn build_list_devices_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("devices-list", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode devices-list auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_link_device_auth_headers(
    keys_json: String,
    user_id: String,
    new_device_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    if new_device_id.trim().is_empty() {
        return Err(invalid_input("new_device_id must not be empty"));
    }
    if keys.device_id == new_device_id {
        return Err(invalid_input(
            "new_device_id must differ from the authenticated device_id",
        ));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("devices-link", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_LINK_DEVICE_ID,
        value: new_device_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode devices-link auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_revoke_device_auth_headers(
    keys_json: String,
    user_id: String,
    target_device_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    if target_device_id.trim().is_empty() {
        return Err(invalid_input("target_device_id must not be empty"));
    }
    if keys.device_id == target_device_id {
        return Err(invalid_input(
            "target_device_id must differ from the authenticated device_id",
        ));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "devices-revoke",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_REVOKE_DEVICE_ID,
        value: target_device_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode devices-revoke auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_prekeys_status_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "prekeys-status",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode prekeys-status auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_prekeys_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("prekeys", &user_id, &keys.device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(keys.signed_prekey_x25519_pub_b64.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_SPK_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(keys.pq_signed_prekey_pub_b64.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_PQSPK_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode prekeys auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_push_token_auth_headers(
    keys_json: String,
    user_id: String,
    fcm_token: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    if fcm_token.trim().is_empty() {
        return Err(invalid_input("fcm_token must not be empty"));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("push-token", &user_id, &keys.device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PUSH_DEVICE_ID,
        value: keys.device_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(fcm_token.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PUSH_TOKEN_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode push-token auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_retire_device_auth_headers(
    keys_json: String,
    user_id: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != user_id {
        return Err(invalid_input(format!(
            "user_id '{}' does not match keys user '{}'",
            user_id, keys.user_id
        )));
    }
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "devices-retire",
        &user_id,
        &keys.device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_REVOKE_DEVICE_ID,
        value: keys.device_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| operation_failed("failed to encode devices-retire auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn build_format_string_auth_headers(
    keys_json: String,
    message: String,
) -> Result<RequestAuthHeaders, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let signing_key = auth_signing_key_for_user(&keys)?;
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let signature = signing_key.sign(message.as_bytes()).to_bytes();
    Ok(RequestAuthHeaders {
        auth_user: keys.user_id,
        auth_device: keys.device_id,
        auth_timestamp: timestamp.to_string(),
        auth_nonce: nonce,
        auth_signature: B64.encode(signature),
    })
}

#[uniffi::export]
pub fn initiate_session_and_encrypt(
    keys_json: String,
    from_user_id: String,
    peer_user_id: String,
    peer_bundle: ServerBundle,
    plaintext_utf8: String,
    suite_override: Option<Suite>,
) -> Result<SendResult, PqmsgAndroidError> {
    let mut keys = read_keys_file(&keys_json)?;
    if keys.user_id != from_user_id {
        return Err(invalid_input(format!(
            "from_user_id '{}' does not match keys user '{}'",
            from_user_id, keys.user_id
        )));
    }
    if let Some(suite) = suite_override {
        keys.suite = suite;
    }

    let prekey_bundle = bundle_to_core(&peer_bundle, keys.suite)?;
    let identity = to_identity_keypair(&keys)?;
    let local_pq_signed_prekey = to_pq_signed_prekey(&keys)?;
    let kem = build_kem_for_suite(keys.suite)?;
    let verifier = Ed25519SignatureVerifier;
    let pq_verifier = build_pq_signature_provider()?;
    validate_hybrid_prekey_bundle_signatures(&prekey_bundle, &verifier, &pq_verifier)?;
    let initiator = alice_initiate(
        &mut OsRng,
        &verifier,
        &kem,
        &from_user_id,
        &peer_user_id,
        &identity,
        &local_pq_signed_prekey.public_key,
        &prekey_bundle,
        plaintext_utf8.as_bytes(),
    )?;

    let initial_encoded = initiator.initial_message.encode()?;
    let local_dh = DhKeyPair {
        public: identity.public_key,
        secret: identity.require_secret_key()?,
    };
    let session = SessionState::from_handshake_with_suite_with_pq_ratchet(
        SessionRole::Initiator,
        *initiator.session_key.as_bytes(),
        local_dh,
        prekey_bundle.signed_prekey,
        prekey_bundle.suite.suite_id()?,
        512,
        mandatory_pq_ratchet_state(
            &local_pq_signed_prekey,
            prekey_bundle.pq_signed_prekey.clone(),
        ),
        Box::new(kem),
    )?;
    let session_file = SessionFile {
        version: 1,
        user_id: from_user_id,
        peer_user_id,
        suite: keys.suite,
        snapshot: session.snapshot(),
    };

    Ok(SendResult {
        message_bytes_base64: B64.encode(initial_encoded),
        session_json: serde_json::to_string_pretty(&session_file)?,
        used_handshake: true,
    })
}

#[uniffi::export]
pub fn normalize_session_json(session_json: String) -> Result<String, PqmsgAndroidError> {
    let session = read_session_file(&session_json)?;
    serde_json::to_string_pretty(&session).map_err(Into::into)
}

#[uniffi::export]
pub fn encrypt_with_session(
    session_json: String,
    sender_user_id: String,
    peer_user_id: String,
    plaintext_utf8: String,
) -> Result<SendResult, PqmsgAndroidError> {
    let mut session_file = read_session_file(&session_json)?;
    if session_file.user_id != sender_user_id {
        return Err(invalid_input(format!(
            "sender_user_id '{}' does not match session user '{}'",
            sender_user_id, session_file.user_id
        )));
    }
    if session_file.peer_user_id != peer_user_id {
        return Err(invalid_input(format!(
            "peer_user_id '{}' does not match session peer '{}'",
            peer_user_id, session_file.peer_user_id
        )));
    }

    let mut session = restore_session(&session_file)?;
    let ad = make_ad(&sender_user_id, &peer_user_id)?;
    let wire = session.encrypt(plaintext_utf8.as_bytes(), &ad)?;
    session_file.snapshot = session.snapshot();

    Ok(SendResult {
        message_bytes_base64: B64.encode(wire),
        session_json: serde_json::to_string_pretty(&session_file)?,
        used_handshake: false,
    })
}

#[uniffi::export]
pub fn decrypt_message(
    keys_json: String,
    recipient_user_id: String,
    sender_user_id: String,
    message_bytes_base64: String,
    existing_session_json: Option<String>,
) -> Result<DecryptResult, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != recipient_user_id {
        return Err(invalid_input(format!(
            "recipient_user_id '{}' does not match keys user '{}'",
            recipient_user_id, keys.user_id
        )));
    }

    let message_bytes = decode_b64("message_bytes_base64", &message_bytes_base64)?;
    if let Ok(initial) = InitialMessage::decode(&message_bytes) {
        if initial.sender_id != sender_user_id {
            return Err(invalid_input(format!(
                "sender_user_id '{}' does not match handshake sender '{}'",
                sender_user_id, initial.sender_id
            )));
        }
        if initial.recipient_id != recipient_user_id {
            return Err(invalid_input(format!(
                "recipient_user_id '{}' does not match handshake recipient '{}'",
                recipient_user_id, initial.recipient_id
            )));
        }

        let suite = suite_from_suite_id(initial.suite_id)?;
        let kem = build_kem_for_suite(suite)?;
        let identity = to_identity_keypair(&keys)?;
        let signed_prekey = to_signed_prekey(&keys)?;
        let pq_signed_prekey = to_pq_signed_prekey(&keys)?;
        let responder = bob_receive(
            &kem,
            &identity,
            &signed_prekey,
            &pq_signed_prekey,
            None,
            &initial,
        )?;
        let local_dh = DhKeyPair {
            public: signed_prekey.public_key,
            secret: signed_prekey.require_secret_key()?,
        };
        let session = SessionState::from_handshake_with_suite_with_pq_ratchet(
            SessionRole::Responder,
            *responder.session_key.as_bytes(),
            local_dh,
            initial.ik_a_pub,
            initial.suite_id,
            512,
            mandatory_pq_ratchet_state(&pq_signed_prekey, initial.pq_ratchet_pub_a.clone()),
            Box::new(kem),
        )?;
        let session_file = SessionFile {
            version: 1,
            user_id: recipient_user_id,
            peer_user_id: sender_user_id,
            suite,
            snapshot: session.snapshot(),
        };
        let plaintext_base64 = B64.encode(&responder.plaintext);
        let plaintext_utf8 = String::from_utf8_lossy(&responder.plaintext).to_string();

        return Ok(DecryptResult {
            plaintext_utf8,
            plaintext_base64,
            session_json: serde_json::to_string_pretty(&session_file)?,
            used_handshake: true,
        });
    }

    let Some(session_json) = existing_session_json else {
        return Err(invalid_input(
            "existing_session_json is required for non-handshake messages",
        ));
    };
    let mut session_file = read_session_file(&session_json)?;
    if session_file.user_id != recipient_user_id {
        return Err(invalid_input(format!(
            "recipient_user_id '{}' does not match session user '{}'",
            recipient_user_id, session_file.user_id
        )));
    }
    if session_file.peer_user_id != sender_user_id {
        return Err(invalid_input(format!(
            "sender_user_id '{}' does not match session peer '{}'",
            sender_user_id, session_file.peer_user_id
        )));
    }

    let mut session = restore_session(&session_file)?;
    let ad = make_ad(&sender_user_id, &recipient_user_id)?;
    let plaintext = session.decrypt(&message_bytes, &ad)?;
    session_file.snapshot = session.snapshot();
    let plaintext_base64 = B64.encode(&plaintext);
    let plaintext_utf8 = String::from_utf8_lossy(&plaintext).to_string();

    Ok(DecryptResult {
        plaintext_utf8,
        plaintext_base64,
        session_json: serde_json::to_string_pretty(&session_file)?,
        used_handshake: false,
    })
}

#[uniffi::export]
pub fn seal_message_with_sender_cert(
    keys_json: String,
    recipient_user_id: String,
    recipient_identity_x25519_pub: String,
    payload_message_bytes_base64: String,
    sender_certificate_base64: String,
) -> Result<String, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let identity = to_identity_keypair(&keys)?;
    let local_secret = identity.require_secret_key()?;
    let recipient_identity_pub = DhPublicKey(decode_b64_32(
        "recipient_identity_x25519_pub",
        &recipient_identity_x25519_pub,
    )?);
    let suite_id = suite_id_for_user_keys(keys.suite);
    let payload = decode_b64(
        "payload_message_bytes_base64",
        &payload_message_bytes_base64,
    )?;
    let sender_certificate = SenderCertificate::decode(&decode_b64(
        "sender_certificate_base64",
        &sender_certificate_base64,
    )?)
    .map_err(|error| operation_failed(error.to_string()))?;
    let sealed = seal_message_with_cert(
        &local_secret,
        &recipient_identity_pub,
        suite_id,
        &recipient_user_id,
        &keys.user_id,
        &keys.device_id,
        &payload,
        &sender_certificate,
    )?;
    Ok(B64.encode(sealed))
}

#[uniffi::export]
pub fn open_sealed_message_with_sender_cert(
    keys_json: String,
    sender_identity_x25519_pub: Option<String>,
    sealed_message_bytes_base64: String,
    server_issuer_ed25519_pub: String,
) -> Result<OpenedCertifiedSealedMessage, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let identity = to_identity_keypair(&keys)?;
    let local_secret = identity.require_secret_key()?;
    let suite_id = suite_id_for_user_keys(keys.suite);
    let legacy_sender_identity_pub = sender_identity_x25519_pub
        .as_deref()
        .map(|value| decode_b64_32("sender_identity_x25519_pub", value))
        .transpose()?
        .map(DhPublicKey);
    let server_pub_key = VerifyingKey::from_bytes(&decode_b64_32(
        "server_issuer_ed25519_pub",
        &server_issuer_ed25519_pub,
    )?)
    .map_err(|_| operation_failed("invalid server issuer ed25519 public key"))?;
    let now_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| operation_failed("system clock before unix epoch"))?
        .as_secs();
    let opened = open_message_with_cert(
        &local_secret,
        &decode_b64("sealed_message_bytes_base64", &sealed_message_bytes_base64)?,
        suite_id,
        &keys.user_id,
        Some(&server_pub_key),
        now_unix_secs,
        legacy_sender_identity_pub.as_ref(),
    )?;
    if opened.sender_cert.is_none() {
        return Err(operation_failed(
            "sealed sender certificate missing from transport envelope",
        ));
    }
    Ok(OpenedCertifiedSealedMessage {
        sender_user_id: opened.sender_user_id,
        sender_device_id: opened.sender_device_id,
        payload_message_bytes_base64: B64.encode(opened.payload),
    })
}

fn read_keys_file(keys_json: &str) -> Result<UserKeysFile, PqmsgAndroidError> {
    serde_json::from_str(keys_json).map_err(Into::into)
}

fn read_session_file(session_json: &str) -> Result<SessionFile, PqmsgAndroidError> {
    serde_json::from_str(session_json).map_err(Into::into)
}

fn restore_session(session_file: &SessionFile) -> Result<SessionState, PqmsgAndroidError> {
    let kem = build_kem_for_suite(session_file.suite)?;
    Ok(SessionState::from_snapshot_with_kem(
        session_file.snapshot.clone(),
        Some(Box::new(kem)),
    ))
}

fn to_identity_keypair(keys: &UserKeysFile) -> Result<IdentityKeyPair, PqmsgAndroidError> {
    Ok(IdentityKeyPair {
        key_id: format!("{}-ik", keys.user_id),
        public_key: DhPublicKey(decode_b64_32(
            "identity_x25519_pub_b64",
            &keys.identity_x25519_pub_b64,
        )?),
        secret_key: SecretBytes::from(decode_b64(
            "identity_x25519_secret_b64",
            &keys.identity_x25519_secret_b64,
        )?),
        pq_sig_public_key: Some(decode_b64(
            "identity_pq_sig_pub_b64",
            &keys.identity_pq_sig_pub_b64,
        )?),
        pq_sig_secret_key: Some(SecretBytes::from(decode_b64(
            "identity_pq_sig_secret_b64",
            &keys.identity_pq_sig_secret_b64,
        )?)),
    })
}

fn to_signed_prekey(keys: &UserKeysFile) -> Result<OneTimePreKey, PqmsgAndroidError> {
    Ok(OneTimePreKey {
        key_id: format!("{}-spk", keys.user_id),
        public_key: DhPublicKey(decode_b64_32(
            "signed_prekey_x25519_pub_b64",
            &keys.signed_prekey_x25519_pub_b64,
        )?),
        secret_key: SecretBytes::from(decode_b64(
            "signed_prekey_x25519_secret_b64",
            &keys.signed_prekey_x25519_secret_b64,
        )?),
    })
}

fn to_pq_signed_prekey(keys: &UserKeysFile) -> Result<KEMPreKey, PqmsgAndroidError> {
    Ok(KEMPreKey {
        key_id: format!("{}-pqspk", keys.user_id),
        public_key: decode_b64("pq_signed_prekey_pub_b64", &keys.pq_signed_prekey_pub_b64)?,
        secret_key: SecretBytes::from(decode_b64(
            "pq_signed_prekey_secret_b64",
            &keys.pq_signed_prekey_secret_b64,
        )?),
    })
}

fn bundle_to_core(bundle: &ServerBundle, suite: Suite) -> Result<PreKeyBundle, PqmsgAndroidError> {
    let core_suite = AlgorithmSuite {
        kem: suite_to_kem_algorithm(suite),
        ..AlgorithmSuite::default()
    };

    let mut out = PreKeyBundle::new(
        bundle.user_id.clone(),
        DhPublicKey(decode_b64_32(
            "identity_x25519_pub",
            &bundle.identity_x25519_pub,
        )?),
        DhPublicKey(decode_b64_32(
            "signed_prekey_x25519_pub",
            &bundle.signed_prekey_x25519_pub,
        )?),
        decode_b64(
            "pq_signed_prekey_pub_mlkem768",
            &bundle.pq_signed_prekey_pub_mlkem768,
        )?,
        decode_b64("sig_over_spk", &bundle.sig_over_spk)?,
        decode_b64("sig_over_pqspk", &bundle.sig_over_pqspk)?,
        decode_b64("identity_sig_pub", &bundle.identity_sig_pub)?,
    );
    out.suite = core_suite;
    out.pq_sig_public_key = Some(decode_b64(
        "identity_pq_sig_pub",
        &bundle.identity_pq_sig_pub,
    )?);
    out.pq_spk_signature = Some(decode_b64("pq_sig_over_spk", &bundle.pq_sig_over_spk)?);
    out.pq_pqspk_signature = Some(decode_b64("pq_sig_over_pqspk", &bundle.pq_sig_over_pqspk)?);
    out.one_time_prekey = bundle
        .one_time_prekey_x25519
        .as_ref()
        .map(|value| decode_b64_32("one_time_prekey_x25519", value))
        .transpose()?
        .map(DhPublicKey);
    out.one_time_pq_prekey = bundle
        .one_time_prekey_mlkem768
        .as_ref()
        .map(|value| decode_b64("one_time_prekey_mlkem768", value))
        .transpose()?;
    Ok(out)
}

fn make_ad(sender: &str, recipient: &str) -> Result<Vec<u8>, PqmsgAndroidError> {
    conversation_associated_data(sender, recipient).map_err(Into::into)
}

fn parse_private_group_role(role: &str) -> Result<PrivateGroupRole, PqmsgAndroidError> {
    match role.trim().to_ascii_lowercase().as_str() {
        "owner" => Ok(PrivateGroupRole::Owner),
        "admin" => Ok(PrivateGroupRole::Admin),
        "member" => Ok(PrivateGroupRole::Member),
        _ => Err(invalid_input("invalid private group role")),
    }
}

fn private_group_credential_material(
    credential: &PrivateGroupMemberCredential,
) -> Result<PrivateGroupCredentialMaterial, PqmsgAndroidError> {
    let fetch_key = credential.state_fetch_key()?;
    let publish_key = credential.state_publish_key()?;
    Ok(PrivateGroupCredentialMaterial {
        membership_handle_sha256: hex_string(&credential.membership_handle_sha256()),
        member_commitment_sha256: hex_string(&credential.member_commitment_sha256()),
        fetch_key_base64: B64.encode(fetch_key),
        fetch_key_sha256: hex_string(&Sha256::digest(fetch_key)),
        publish_key_base64: publish_key.map(|value| B64.encode(value)),
        publish_key_sha256: publish_key
            .map(|value| hex_string(&Sha256::digest(value))),
    })
}

fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>, PqmsgAndroidError> {
    B64.decode(value.as_bytes())
        .map_err(|_| invalid_input(format!("invalid base64 for field '{field}'")))
}

fn decode_b64_32(field: &'static str, value: &str) -> Result<[u8; 32], PqmsgAndroidError> {
    let bytes = decode_b64(field, value)?;
    if bytes.len() != 32 {
        return Err(invalid_input(format!(
            "field '{field}' must decode to 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn invalid_input(message: impl Into<String>) -> PqmsgAndroidError {
    PqmsgAndroidError::InvalidInput {
        reason: message.into(),
    }
}

fn operation_failed(message: impl Into<String>) -> PqmsgAndroidError {
    PqmsgAndroidError::OperationFailed {
        reason: message.into(),
    }
}

impl From<CoreError> for PqmsgAndroidError {
    fn from(value: CoreError) -> Self {
        operation_failed(value.to_string())
    }
}

impl From<serde_json::Error> for PqmsgAndroidError {
    fn from(value: serde_json::Error) -> Self {
        invalid_input(value.to_string())
    }
}

impl From<base64::DecodeError> for PqmsgAndroidError {
    fn from(value: base64::DecodeError) -> Self {
        invalid_input(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_signature(signature_base64: &str) -> Signature {
        let signature = B64.decode(signature_base64).expect("decode signature");
        let signature: [u8; 64] = signature.try_into().expect("signature length");
        Signature::from_bytes(&signature)
    }

    fn verify_auth_signature(
        keys_json: &str,
        headers: &RequestAuthHeaders,
        transcript: &[u8],
    ) -> VerifyingKey {
        let keys = read_keys_file(keys_json).expect("read keys");
        let signing_key = auth_signing_key_for_user(&keys).expect("auth signing key");
        let verifying_key = signing_key.verifying_key();
        let signature = decode_signature(&headers.auth_signature);
        verifying_key
            .verify(transcript, &signature)
            .expect("verify auth signature");
        verifying_key
    }

    fn auth_timestamp_from_headers(headers: &RequestAuthHeaders) -> i64 {
        headers
            .auth_timestamp
            .parse::<i64>()
            .expect("parse auth timestamp")
    }

    fn tlv_transcript_from_records(records: Vec<TlvRecord>) -> Vec<u8> {
        encode(&records).expect("encode tlv transcript")
    }

    #[test]
    fn compute_safety_number_with_peer_returns_numeric_groups() {
        let keys_json = generate_identity_keys(
            "alice".to_string(),
            "alice-android-1".to_string(),
            Suite::MlKem768,
            8,
        )
        .expect("generate keys");
        let safety_number = compute_safety_number_with_peer(
            keys_json,
            "bob".to_string(),
            B64.encode([0x44; 32]),
            B64.encode(vec![0x55; 1952]),
        )
        .expect("compute safety number");
        assert_eq!(safety_number.split(' ').count(), 12);
        assert!(safety_number
            .chars()
            .all(|c| c.is_ascii_digit() || c == ' '));
    }

    #[test]
    fn secondary_device_package_roundtrip_preserves_identity_and_rebinds_device_material() {
        let source_keys_json = generate_identity_keys(
            "alice".to_string(),
            "alice-android-1".to_string(),
            Suite::MlKem768,
            8,
        )
        .expect("generate keys");
        let source_keys = read_keys_file(&source_keys_json).expect("read source keys");

        let package_json = prepare_secondary_device_package(
            source_keys_json,
            "alice-android-2".to_string(),
            "https://relay.example.test".to_string(),
            8,
            "device-package-passphrase".to_string(),
        )
        .expect("prepare package");
        let package =
            open_secondary_device_package(package_json, "device-package-passphrase".to_string())
                .expect("open package");
        let imported_keys = read_keys_file(&package.keys_json).expect("read imported keys");

        assert_eq!(package.server_url, "https://relay.example.test");
        assert_eq!(package.user_id, "alice");
        assert_eq!(package.device_id, "alice-android-2");
        assert_eq!(package.suite, Suite::MlKem768);
        assert_eq!(imported_keys.user_id, source_keys.user_id);
        assert_eq!(imported_keys.device_id, "alice-android-2");
        assert_eq!(
            imported_keys.identity_x25519_pub_b64,
            source_keys.identity_x25519_pub_b64
        );
        assert_eq!(
            imported_keys.identity_x25519_secret_b64,
            source_keys.identity_x25519_secret_b64
        );
        assert_eq!(
            imported_keys.identity_sig_pub_b64,
            source_keys.identity_sig_pub_b64
        );
        assert_eq!(
            imported_keys.identity_sig_secret_b64,
            source_keys.identity_sig_secret_b64
        );
        assert_ne!(
            imported_keys.signed_prekey_x25519_pub_b64,
            source_keys.signed_prekey_x25519_pub_b64
        );
        assert_ne!(
            imported_keys.pq_signed_prekey_pub_b64,
            source_keys.pq_signed_prekey_pub_b64
        );
        assert_eq!(imported_keys.one_time_prekeys_x25519.len(), 8);
        assert_eq!(imported_keys.one_time_prekeys_mlkem768.len(), 8);
    }

    #[test]
    fn rotate_confirm_payload_and_identity_log_headers_use_expected_identities() {
        let current_keys_json = generate_identity_keys(
            "bob".to_string(),
            "bob-android-1".to_string(),
            Suite::MlKem768,
            8,
        )
        .expect("generate current keys");
        let new_keys_json = generate_identity_keys(
            "bob".to_string(),
            "bob-android-2".to_string(),
            Suite::MlKem768,
            8,
        )
        .expect("generate new keys");

        let init_payload = build_rotate_init_payload(new_keys_json.clone()).expect("init payload");
        assert_eq!(init_payload.new_device_id, "bob-android-2");
        assert!(!init_payload.new_identity_pq_sig_pub.is_empty());

        let confirm_payload = build_rotate_confirm_payload(
            current_keys_json.clone(),
            new_keys_json,
            "bob".to_string(),
            "challenge-123".to_string(),
            B64.encode([7u8; 32]),
        )
        .expect("confirm payload");
        assert_eq!(confirm_payload.challenge_id, "challenge-123");
        assert_ne!(
            confirm_payload.sig_by_current_identity,
            confirm_payload.sig_by_new_identity
        );
        assert!(!confirm_payload.pq_sig_by_current_identity.is_empty());
        assert!(!confirm_payload.pq_sig_by_new_identity.is_empty());

        let headers = build_identity_log_auth_headers(current_keys_json, "bob".to_string())
            .expect("identity log headers");
        assert_eq!(headers.auth_user, "bob");
        assert_eq!(headers.auth_device, "bob-android-1");
        assert!(!headers.auth_signature.is_empty());
    }

    #[test]
    fn contacts_upsert_auth_headers_follow_server_normalization_rules() {
        let keys_json = generate_identity_keys(
            "alice".to_string(),
            "alice-android-1".to_string(),
            Suite::MlKem768,
            8,
        )
        .expect("generate keys");

        let headers = build_contacts_upsert_auth_headers(
            keys_json.clone(),
            "alice".to_string(),
            "bob".to_string(),
            "  Bob Alias  ".to_string(),
            true,
            Some("AA".repeat(32)),
        )
        .expect("contacts upsert headers");

        let timestamp = auth_timestamp_from_headers(&headers);
        let mut records = auth_common_records(
            "contacts-upsert",
            "alice",
            "alice-android-1",
            timestamp,
            &headers.auth_nonce,
        );
        records.push(TlvRecord {
            ty: AUTH_TAG_RECIPIENT_ID,
            value: b"alice".to_vec(),
        });
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_USER_ID,
            value: b"bob".to_vec(),
        });
        let mut alias_hasher = Sha256::new();
        alias_hasher.update(b"Bob Alias");
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_ALIAS_HASH,
            value: alias_hasher.finalize().to_vec(),
        });
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_VERIFIED_FLAG,
            value: vec![1],
        });
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_FINGERPRINT,
            value: b"aa".repeat(32),
        });
        let transcript = tlv_transcript_from_records(records);
        verify_auth_signature(&keys_json, &headers, &transcript);
    }

    #[test]
    fn group_create_auth_headers_hash_trimmed_sorted_unique_members() {
        let keys_json = generate_identity_keys(
            "alice".to_string(),
            "alice-android-1".to_string(),
            Suite::MlKem768,
            8,
        )
        .expect("generate keys");

        let headers = build_group_create_auth_headers(
            keys_json.clone(),
            "group-1".to_string(),
            vec![
                "  carol ".to_string(),
                "bob".to_string(),
                "carol".to_string(),
                " alice ".to_string(),
            ],
        )
        .expect("group create headers");

        let timestamp = auth_timestamp_from_headers(&headers);
        let mut records = auth_common_records(
            "groups-create",
            "alice",
            "alice-android-1",
            timestamp,
            &headers.auth_nonce,
        );
        records.push(TlvRecord {
            ty: AUTH_TAG_GROUP_ID,
            value: b"group-1".to_vec(),
        });
        records.push(TlvRecord {
            ty: AUTH_TAG_GROUP_MEMBERS_HASH,
            value: hash_string_list_sha256(&[
                "alice".to_string(),
                "bob".to_string(),
                "carol".to_string(),
            ]),
        });
        let transcript = tlv_transcript_from_records(records);
        verify_auth_signature(&keys_json, &headers, &transcript);
    }

    #[test]
    fn private_group_exports_roundtrip_join_package_and_credential_material() {
        let attributes_json = serde_json::json!({
            "title": "Ops",
            "description": "Private group",
            "avatar_hash_sha256": serde_json::Value::Null,
            "disappearing_message_timer_seconds": 3600,
        })
        .to_string();
        let members_json = serde_json::json!([
            { "user_id": "alice", "role": "Owner" },
            { "user_id": "bob", "role": "Admin" },
        ])
        .to_string();

        let state_json = private_group_create_state(
            "alice".to_string(),
            attributes_json,
            members_json,
            1_710_000_000,
        )
        .expect("create private group state");
        let join_package_json = private_group_export_join_package_for_member(
            state_json,
            "bob".to_string(),
        )
        .expect("export join package");
        let restored_json =
            private_group_restore_join_package(join_package_json).expect("restore join package");
        let restored: PrivateGroupRestoreResult =
            serde_json::from_str(&restored_json).expect("parse restored join package");

        assert_eq!(restored.state.group_id, restored.member_credential.group_id);
        assert_eq!(restored.member_credential.member_user_id, "bob");

        let material_json = private_group_describe_member_credential(
            serde_json::to_string(&restored.member_credential).expect("serialize credential"),
        )
        .expect("describe member credential");
        let material: PrivateGroupCredentialMaterial =
            serde_json::from_str(&material_json).expect("parse member credential material");

        assert_eq!(material.membership_handle_sha256.len(), 64);
        assert_eq!(material.member_commitment_sha256.len(), 64);
        assert!(!material.fetch_key_base64.is_empty());
        assert!(!material.fetch_key_sha256.is_empty());
        assert!(material.publish_key_base64.is_some());
        assert!(material.publish_key_sha256.is_some());
    }

    #[test]
    fn presence_and_receipts_auth_headers_match_server_transcripts() {
        let keys_json = generate_identity_keys(
            "alice".to_string(),
            "alice-android-1".to_string(),
            Suite::MlKem768,
            8,
        )
        .expect("generate keys");

        let presence_headers = build_presence_update_auth_headers(
            keys_json.clone(),
            "alice".to_string(),
            "  ONline ".to_string(),
        )
        .expect("presence update headers");
        let presence_timestamp = auth_timestamp_from_headers(&presence_headers);
        let mut presence_records = auth_common_records(
            "presence-update",
            "alice",
            "alice-android-1",
            presence_timestamp,
            &presence_headers.auth_nonce,
        );
        presence_records.push(TlvRecord {
            ty: AUTH_TAG_RECIPIENT_ID,
            value: b"alice".to_vec(),
        });
        presence_records.push(TlvRecord {
            ty: AUTH_TAG_PRESENCE_STATUS,
            value: b"online".to_vec(),
        });
        let presence_transcript = tlv_transcript_from_records(presence_records);
        verify_auth_signature(&keys_json, &presence_headers, &presence_transcript);

        let profile_headers = build_profile_get_auth_headers(keys_json.clone(), "bob".to_string())
            .expect("profile get headers");
        let profile_timestamp = auth_timestamp_from_headers(&profile_headers);
        let mut profile_records = auth_common_records(
            "profile-get",
            "alice",
            "alice-android-1",
            profile_timestamp,
            &profile_headers.auth_nonce,
        );
        profile_records.push(TlvRecord {
            ty: AUTH_TAG_RECIPIENT_ID,
            value: b"bob".to_vec(),
        });
        let profile_transcript = tlv_transcript_from_records(profile_records);
        verify_auth_signature(&keys_json, &profile_headers, &profile_transcript);

        let receipt_headers = build_send_receipt_auth_headers(
            keys_json.clone(),
            "alice".to_string(),
            42,
            "delivered".to_string(),
        )
        .expect("send receipt headers");
        let receipt_transcript = b"receipt:alice:alice-android-1:42:delivered".to_vec();
        let verifying_key =
            verify_auth_signature(&keys_json, &receipt_headers, &receipt_transcript);

        let wrong_receipt_transcript = b"receipt:alice:alice-android-1:42:read".to_vec();
        let signature = decode_signature(&receipt_headers.auth_signature);
        assert!(verifying_key
            .verify(&wrong_receipt_transcript, &signature)
            .is_err());
    }
}

uniffi::setup_scaffolding!();
