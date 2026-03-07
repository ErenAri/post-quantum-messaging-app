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
use pqmsg_core::handshake::{
    alice_initiate, bob_receive, pq_signed_prekey_signature_message,
    signed_prekey_signature_message, InitialMessage, SignatureVerifier,
};
use pqmsg_core::kem::MlKem768;
use pqmsg_core::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
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
const AUTH_TAG_PUSH_DEVICE_ID: u16 = critical_type(0x3210);
const AUTH_TAG_PUSH_TOKEN_HASH: u16 = critical_type(0x3211);
const AUTH_TAG_LINK_DEVICE_ID: u16 = critical_type(0x3212);
const AUTH_TAG_REVOKE_DEVICE_ID: u16 = critical_type(0x3213);
const ROTATE_SIG_TAG_USER_ID: u16 = critical_type(0x3101);
const ROTATE_SIG_TAG_CHALLENGE_ID: u16 = critical_type(0x3102);
const ROTATE_SIG_TAG_CHALLENGE_NONCE: u16 = critical_type(0x3103);
const ROTATE_SIG_TAG_NEW_IDENTITY_X25519: u16 = critical_type(0x3104);
const ROTATE_SIG_TAG_NEW_IDENTITY_SIG: u16 = critical_type(0x3105);
const ROTATE_SIG_TAG_NEW_DEVICE_ID: u16 = critical_type(0x3106);

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
    signed_prekey_x25519_pub: String,
    sig_over_spk: String,
    pq_signed_prekey_pub_mlkem768: String,
    sig_over_pqspk: String,
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
    pub device_id: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PublishPrekeysPayload {
    pub signed_prekey_x25519_pub: String,
    pub sig_over_spk: String,
    pub pq_signed_prekey_pub_mlkem768: String,
    pub sig_over_pqspk: String,
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
    pub new_device_id: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RotateConfirmPayload {
    pub challenge_id: String,
    pub sig_by_current_identity: String,
    pub sig_by_new_identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct ServerBundle {
    pub user_id: String,
    pub identity_x25519_pub: String,
    pub identity_sig_pub: String,
    pub signed_prekey_x25519_pub: String,
    pub sig_over_spk: String,
    pub pq_signed_prekey_pub_mlkem768: String,
    pub sig_over_pqspk: String,
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

fn build_kem_for_suite(suite: Suite) -> Result<MlKem768, PqmsgAndroidError> {
    MlKem768::new(suite_to_kem_algorithm(suite))
        .map_err(|_| operation_failed("pq-oqs backend is disabled"))
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
pub fn build_register_payload(keys_json: String) -> Result<RegisterPayload, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    Ok(RegisterPayload {
        user_id: keys.user_id,
        identity_x25519_pub: keys.identity_x25519_pub_b64,
        identity_sig_pub: keys.identity_sig_pub_b64,
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
    let wrapped = wrap_wrapped_bytes(
        &SecretString::new(package_passphrase.into()),
        &plaintext,
    )?;
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
    let plaintext = unwrap_wrapped_bytes(
        &SecretString::new(package_passphrase.into()),
        &wrapped,
    )?;
    let payload: SecondaryDeviceOnboardingPayload = serde_json::from_slice(&plaintext)?;
    if payload.version != SECONDARY_DEVICE_PACKAGE_VERSION {
        return Err(invalid_input(format!(
            "unsupported onboarding package version '{}'",
            payload.version
        )));
    }
    let normalized_server_url = payload.server_url.trim();
    if normalized_server_url.is_empty() {
        return Err(invalid_input("onboarding package server_url must not be empty"));
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
pub fn build_rotate_init_payload(keys_json: String) -> Result<RotateInitPayload, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    Ok(RotateInitPayload {
        new_identity_x25519_pub: keys.identity_x25519_pub_b64,
        new_identity_sig_pub: keys.identity_sig_pub_b64,
        new_device_id: keys.device_id,
    })
}

#[uniffi::export]
pub fn build_rotate_init_auth_headers(
    keys_json: String,
    user_id: String,
    new_identity_x25519_pub: String,
    new_identity_sig_pub: String,
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
    let mut records = auth_common_records("rotate-init", &user_id, &keys.device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(new_identity_x25519_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_X25519_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(new_identity_sig_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_SIG_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| operation_failed("failed to encode rotate-init auth transcript"))?;
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
    let challenge_nonce = decode_b64("challenge_nonce_base64", &challenge_nonce_base64)?;
    let new_identity_x25519 =
        decode_b64("identity_x25519_pub_b64", &new_keys.identity_x25519_pub_b64)?;
    let new_identity_sig = decode_b64("identity_sig_pub_b64", &new_keys.identity_sig_pub_b64)?;
    let message = rotation_signature_message(
        &user_id,
        &challenge_id,
        &challenge_nonce,
        &new_identity_x25519,
        &new_identity_sig,
        &new_keys.device_id,
    )?;
    Ok(RotateConfirmPayload {
        challenge_id,
        sig_by_current_identity: B64.encode(current_signing_key.sign(&message).to_bytes()),
        sig_by_new_identity: B64.encode(new_signing_key.sign(&message).to_bytes()),
    })
}

#[uniffi::export]
pub fn build_rotate_confirm_auth_headers(
    keys_json: String,
    user_id: String,
    challenge_id: String,
    sig_by_current_identity: String,
    sig_by_new_identity: String,
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
        auth_common_records("rotate-confirm", &user_id, &keys.device_id, timestamp, &nonce);
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
    let transcript =
        encode(&records).map_err(|_| operation_failed("failed to encode identity-log auth transcript"))?;
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
pub fn parse_bundle_json(bundle_json: String) -> Result<ServerBundle, PqmsgAndroidError> {
    let bundle: BundleResponse = serde_json::from_str(&bundle_json)?;
    Ok(ServerBundle {
        user_id: bundle.user_id,
        identity_x25519_pub: bundle.identity_x25519_pub,
        identity_sig_pub: bundle.identity_sig_pub,
        signed_prekey_x25519_pub: bundle.signed_prekey_x25519_pub,
        sig_over_spk: bundle.sig_over_spk,
        pq_signed_prekey_pub_mlkem768: bundle.pq_signed_prekey_pub_mlkem768,
        sig_over_pqspk: bundle.sig_over_pqspk,
        one_time_prekey_x25519: bundle.one_time_prekey_x25519,
        one_time_prekey_mlkem768: bundle.one_time_prekey_mlkem768,
    })
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
    let kem = build_kem_for_suite(keys.suite)?;
    let verifier = Ed25519SignatureVerifier;
    let initiator = alice_initiate(
        &mut OsRng,
        &verifier,
        &kem,
        &from_user_id,
        &peer_user_id,
        &identity,
        &prekey_bundle,
        plaintext_utf8.as_bytes(),
    )?;

    let initial_encoded = initiator.initial_message.encode()?;
    let local_dh = DhKeyPair {
        public: identity.public_key,
        secret: identity.require_secret_key()?,
    };
    let session = SessionState::from_handshake_with_suite(
        SessionRole::Initiator,
        *initiator.session_key.as_bytes(),
        local_dh,
        prekey_bundle.signed_prekey,
        prekey_bundle.suite.suite_id()?,
        512,
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
        let responder = bob_receive(&kem, &identity, &signed_prekey, &pq_signed_prekey, &initial)?;
        let local_dh = DhKeyPair {
            public: signed_prekey.public_key,
            secret: signed_prekey.require_secret_key()?,
        };
        let session = SessionState::from_handshake_with_suite(
            SessionRole::Responder,
            *responder.session_key.as_bytes(),
            local_dh,
            initial.ik_a_pub,
            initial.suite_id,
            512,
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
        let package = open_secondary_device_package(
            package_json,
            "device-package-passphrase".to_string(),
        )
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
        assert_eq!(imported_keys.identity_sig_pub_b64, source_keys.identity_sig_pub_b64);
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

        let headers = build_identity_log_auth_headers(current_keys_json, "bob".to_string())
            .expect("identity log headers");
        assert_eq!(headers.auth_user, "bob");
        assert_eq!(headers.auth_device, "bob-android-1");
        assert!(!headers.auth_signature.is_empty());
    }
}

uniffi::setup_scaffolding!();
