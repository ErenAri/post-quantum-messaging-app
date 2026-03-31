//! WASM bindings for pqmsg-core.
//!
//! Exposes key generation, AEAD, KDF, DH, and storage wrapping
//! to JavaScript via wasm-bindgen.
//!
//! Compiled with `wasm-pack build --features wasm --no-default-features`.

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn wasm_init() {
    console_error_panic_hook::set_once();
}

use crate::ad::conversation_associated_data;
use crate::aead;
use crate::dh;
use crate::kdf;
use crate::keys::{IdentityKeyPair, OneTimePreKey};
use crate::storage;

use rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::alg::{
    AlgorithmSuite, KemAlgorithm, SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::dh::{DhKeyPair, DhPublicKey};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::groups::{
    PrivateGroupAttributes, PrivateGroupDecryptedMessage, PrivateGroupEncryptedMessage,
    PrivateGroupEncryptedSnapshot, PrivateGroupEpochTransition, PrivateGroupInvitePackage,
    PrivateGroupJoinPackage, PrivateGroupLinkInviteEnvelope, PrivateGroupLinkInviteMaterial,
    PrivateGroupMember, PrivateGroupMemberCredential, PrivateGroupRole, PrivateGroupState,
};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::handshake::{
    alice_initiate, bob_receive, validate_hybrid_prekey_bundle_signatures, InitialMessage,
    SignatureVerifier,
};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::kem::MlKem768;
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::key_transparency::{
    verify_consistency_proof, verify_inclusion_proof, ConsistencyProof, InclusionProof,
    SignedTreeHead, TransparencyLeaf,
};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::keys::{KEMPreKey, PreKeyBundle, SecretBytes};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::pq_sig::MlDsa65;
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::ratchet::pq::{
    PqRatchetState, DEFAULT_PQ_RATCHET_INTERVAL, DEFAULT_PQ_RATCHET_KEY_HISTORY,
};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::safety_number::compute_safety_number;
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::sealed::{open_message_with_cert, seal_message_with_cert, SenderCertificate};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::session::{SessionRole, SessionSnapshot, SessionState};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use crate::CoreError;
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use base64::Engine;
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use sha2::Digest;
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
use js_sys::Date;

// ---------------------------------------------------------------------------
// Types (serialized to/from JS via serde-wasm-bindgen)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct WasmIdentityKeys {
    pub user_id: String,
    pub device_id: String,
    pub identity_key_id: String,
    pub identity_pub: Vec<u8>,
    pub identity_secret: Vec<u8>,
    pub signed_prekey_id: String,
    pub signed_prekey_pub: Vec<u8>,
    pub signed_prekey_secret: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Generate a new identity keypair + signed prekey for a user/device.
#[wasm_bindgen]
pub fn wasm_generate_identity_keys(user_id: &str, device_id: &str) -> Result<JsValue, JsValue> {
    let mut rng = OsRng;

    let identity = IdentityKeyPair::generate("ik-0", &mut rng);
    let signed_prekey = IdentityKeyPair::generate("spk-0", &mut rng);

    let keys = WasmIdentityKeys {
        user_id: user_id.to_string(),
        device_id: device_id.to_string(),
        identity_key_id: "ik-0".to_string(),
        identity_pub: identity.public_key.0.to_vec(),
        identity_secret: identity.secret_key.as_slice().to_vec(),
        signed_prekey_id: "spk-0".to_string(),
        signed_prekey_pub: signed_prekey.public_key.0.to_vec(),
        signed_prekey_secret: signed_prekey.secret_key.as_slice().to_vec(),
    };

    serde_wasm_bindgen::to_value(&keys).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate a one-time prekey.
#[wasm_bindgen]
pub fn wasm_generate_one_time_prekey(key_id: &str) -> Result<JsValue, JsValue> {
    let mut rng = OsRng;
    let otpk = OneTimePreKey::generate(key_id, &mut rng);

    #[derive(Serialize)]
    struct OtpkResult {
        key_id: String,
        public: Vec<u8>,
        secret: Vec<u8>,
    }

    let result = OtpkResult {
        key_id: key_id.to_string(),
        public: otpk.public_key.0.to_vec(),
        secret: otpk.secret_key.as_slice().to_vec(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// AEAD encrypt a plaintext message.
#[wasm_bindgen]
pub fn wasm_encrypt(key: &[u8], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("key must be 32 bytes"));
    }
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("key must be exactly 32 bytes"))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let envelope = aead::encrypt(&key_arr, plaintext, ad, nonce)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    // Concatenate nonce + ciphertext for wire transport
    let mut out = Vec::with_capacity(12 + envelope.ciphertext.len());
    out.extend_from_slice(&envelope.nonce);
    out.extend_from_slice(&envelope.ciphertext);
    Ok(out)
}

/// AEAD decrypt a ciphertext.
#[wasm_bindgen]
pub fn wasm_decrypt(
    key: &[u8],
    ciphertext_with_nonce: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if key.len() != 32 {
        return Err(JsValue::from_str("key must be 32 bytes"));
    }
    if ciphertext_with_nonce.len() < 12 {
        return Err(JsValue::from_str("ciphertext too short"));
    }
    let key_arr: [u8; 32] = key
        .try_into()
        .map_err(|_| JsValue::from_str("key must be exactly 32 bytes"))?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&ciphertext_with_nonce[..12]);
    let ciphertext = ciphertext_with_nonce[12..].to_vec();
    let envelope = aead::CiphertextEnvelope {
        nonce,
        ciphertext,
        aad: ad.to_vec(),
    };
    aead::decrypt(&key_arr, &envelope).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Derive a key using HKDF-SHA256.
#[wasm_bindgen]
pub fn wasm_hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, JsValue> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    kdf::hkdf_sha256(ikm, salt_opt, info, out_len)
        .map(|z| z.to_vec())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// X25519 Diffie-Hellman key agreement.
#[wasm_bindgen]
pub fn wasm_x25519_dh(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret_key.len() != 32 || public_key.len() != 32 {
        return Err(JsValue::from_str("keys must be 32 bytes"));
    }
    let sk = dh::DhSecretKey(
        secret_key
            .try_into()
            .map_err(|_| JsValue::from_str("secret_key must be exactly 32 bytes"))?,
    );
    let pk = dh::DhPublicKey(
        public_key
            .try_into()
            .map_err(|_| JsValue::from_str("public_key must be exactly 32 bytes"))?,
    );
    Ok(dh::diffie_hellman(&sk, &pk).to_vec())
}

/// Generate an X25519 keypair.
#[wasm_bindgen]
pub fn wasm_x25519_keypair() -> Result<Vec<u8>, JsValue> {
    let mut rng = OsRng;
    let kp = dh::generate_keypair(&mut rng);
    // Return secret || public (32 + 32 = 64 bytes)
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&kp.secret.0);
    out.extend_from_slice(&kp.public.0);
    Ok(out)
}

/// Wrap secret bytes for at-rest storage (Argon2id + AEAD).
#[wasm_bindgen]
pub fn wasm_wrap_secret(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = SecretString::from(passphrase.to_string());
    let wrapped =
        storage::wrap_bytes(&secret, plaintext).map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_vec(&wrapped).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Unwrap secret bytes from at-rest storage.
#[wasm_bindgen]
pub fn wasm_unwrap_secret(passphrase: &str, wrapped_json: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = SecretString::from(passphrase.to_string());
    let wrapped: storage::WrappedSecret =
        serde_json::from_slice(wrapped_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    storage::unwrap_bytes(&secret, &wrapped).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build conversation associated data for AEAD binding.
#[wasm_bindgen]
pub fn wasm_conversation_ad(sender: &str, recipient: &str) -> Result<Vec<u8>, JsValue> {
    conversation_associated_data(sender, recipient).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ---------------------------------------------------------------------------
// KEM operations (ML-KEM-768) — only available with `wasm-pq` feature
// ---------------------------------------------------------------------------

/// Generate an ML-KEM-768 keypair. Returns JSON: {public_key: number[], secret_key: number[]}.
#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_compute_safety_number(
    local_user_id: &str,
    local_identity_x25519_pub_b64: &str,
    local_identity_pq_sig_pub_b64: &str,
    peer_user_id: &str,
    peer_identity_x25519_pub_b64: &str,
    peer_identity_pq_sig_pub_b64: &str,
) -> Result<String, JsValue> {
    let local_identity_x25519 = decode_b64_32(
        "local_identity_x25519_pub_b64",
        local_identity_x25519_pub_b64,
    )?;
    let peer_identity_x25519 =
        decode_b64_32("peer_identity_x25519_pub_b64", peer_identity_x25519_pub_b64)?;
    let local_identity_pq_sig = decode_b64(
        "local_identity_pq_sig_pub_b64",
        local_identity_pq_sig_pub_b64,
    )?;
    let peer_identity_pq_sig =
        decode_b64("peer_identity_pq_sig_pub_b64", peer_identity_pq_sig_pub_b64)?;
    Ok(compute_safety_number(
        local_user_id,
        &local_identity_x25519,
        &local_identity_pq_sig,
        peer_user_id,
        &peer_identity_x25519,
        &peer_identity_pq_sig,
    ))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Deserialize)]
struct WasmTransparencyLeafRecord {
    user_id: String,
    version: u64,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    identity_pq_sig_pub: Option<String>,
    timestamp: u64,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Deserialize)]
struct WasmTransparencyPathItem {
    hash: String,
    is_left: bool,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Deserialize)]
struct WasmTransparencyInclusionProof {
    leaf_index: u64,
    path: Vec<WasmTransparencyPathItem>,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Deserialize)]
struct WasmTransparencyConsistencyProof {
    old_size: u64,
    new_size: u64,
    proof_hashes: Vec<String>,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Deserialize)]
struct WasmTransparencySignedTreeHead {
    epoch: u64,
    tree_size: u64,
    root_hash: String,
    signature: String,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Deserialize)]
struct WasmTransparencyProofDocument {
    leaf: WasmTransparencyLeafRecord,
    inclusion_proof: WasmTransparencyInclusionProof,
    signed_tree_head: WasmTransparencySignedTreeHead,
    consistency_proof: Option<WasmTransparencyConsistencyProof>,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Serialize)]
struct WasmTransparencyVerificationResult {
    verified: bool,
    consistency_verified: bool,
    leaf_user_id: String,
    leaf_version: u64,
    tree_size: u64,
    epoch: u64,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn parse_transparency_leaf(value: WasmTransparencyLeafRecord) -> Result<TransparencyLeaf, JsValue> {
    Ok(TransparencyLeaf {
        user_id: value.user_id,
        version: value.version,
        identity_x25519_pub: decode_b64_32(
            "transparency.leaf.identity_x25519_pub",
            &value.identity_x25519_pub,
        )?,
        identity_sig_pub: decode_b64(
            "transparency.leaf.identity_sig_pub",
            &value.identity_sig_pub,
        )?,
        identity_pq_sig_pub: value
            .identity_pq_sig_pub
            .as_ref()
            .map(|raw| decode_b64("transparency.leaf.identity_pq_sig_pub", raw))
            .transpose()?,
        timestamp: value.timestamp,
    })
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn parse_transparency_sth(
    value: WasmTransparencySignedTreeHead,
) -> Result<SignedTreeHead, JsValue> {
    Ok(SignedTreeHead {
        epoch: value.epoch,
        tree_size: value.tree_size,
        root_hash: decode_b64_32("transparency.signed_tree_head.root_hash", &value.root_hash)?,
        signature: decode_b64("transparency.signed_tree_head.signature", &value.signature)?,
    })
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[wasm_bindgen]
pub fn wasm_verify_transparency_proof(
    proof_json: &str,
    server_pub_key_b64: &str,
    previous_sth_json: Option<String>,
) -> Result<JsValue, JsValue> {
    let document: WasmTransparencyProofDocument =
        serde_json::from_str(proof_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
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
            .collect::<Result<Vec<_>, JsValue>>()?,
    };
    let sth = parse_transparency_sth(document.signed_tree_head)?;
    let server_pub_key = VerifyingKey::from_bytes(&decode_b64_32(
        "transparency.server_pub_key",
        server_pub_key_b64,
    )?)
    .map_err(|_| JsValue::from_str("invalid transparency server public key"))?;
    verify_inclusion_proof(&leaf.hash(), &inclusion_proof, &sth, &server_pub_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut consistency_verified = false;
    if let Some(previous_sth_json) = previous_sth_json {
        let previous_sth_value: WasmTransparencySignedTreeHead =
            serde_json::from_str(&previous_sth_json)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let previous_sth = parse_transparency_sth(previous_sth_value)?;
        if let Some(consistency) = document.consistency_proof {
            let proof = ConsistencyProof {
                old_size: consistency.old_size,
                new_size: consistency.new_size,
                proof_hashes: consistency
                    .proof_hashes
                    .into_iter()
                    .map(|hash| decode_b64_32("transparency.consistency_proof.hash", &hash))
                    .collect::<Result<Vec<_>, JsValue>>()?,
            };
            verify_consistency_proof(&previous_sth, &sth, &proof, &server_pub_key)
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            consistency_verified = true;
        }
    }

    serde_wasm_bindgen::to_value(&WasmTransparencyVerificationResult {
        verified: true,
        consistency_verified,
        leaf_user_id: leaf.user_id,
        leaf_version: leaf.version,
        tree_size: sth.tree_size,
        epoch: sth.epoch,
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Generate an ML-KEM-768 keypair. Returns JSON: {public_key: number[], secret_key: number[]}.
#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_kem_keypair() -> Result<JsValue, JsValue> {
    use crate::alg::KemAlgorithm;
    use crate::kem::MlKem768;

    let kem =
        MlKem768::new(KemAlgorithm::MlKem768).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let kp = kem
        .keypair()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    #[derive(Serialize)]
    struct KemKeyPairResult {
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    }

    let result = KemKeyPairResult {
        public_key: kp.public_key,
        secret_key: kp.secret_key.as_slice().to_vec(),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Encapsulate a shared secret using an ML-KEM-768 public key.
/// Returns JSON: {ciphertext: number[], shared_secret: number[]}.
#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_kem_encapsulate(recipient_public_key: &[u8]) -> Result<JsValue, JsValue> {
    use crate::alg::KemAlgorithm;
    use crate::kem::{KemProvider, MlKem768};

    let kem =
        MlKem768::new(KemAlgorithm::MlKem768).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let enc = kem
        .encapsulate(recipient_public_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    #[derive(Serialize)]
    struct KemEncapsulateResult {
        ciphertext: Vec<u8>,
        shared_secret: Vec<u8>,
    }

    let result = KemEncapsulateResult {
        ciphertext: enc.ciphertext,
        shared_secret: enc.shared_secret.to_vec(),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Decapsulate a shared secret from a ciphertext using an ML-KEM-768 secret key.
/// Returns the shared secret bytes.
#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_kem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::alg::KemAlgorithm;
    use crate::kem::{KemProvider, MlKem768};

    let kem =
        MlKem768::new(KemAlgorithm::MlKem768).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let shared_secret = kem
        .decapsulate(secret_key, ciphertext)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(shared_secret.to_vec())
}

// ---------------------------------------------------------------------------
// PQ Signature operations (ML-DSA-65) — only available with `pq-oqs` feature
// ---------------------------------------------------------------------------

/// Generate an ML-DSA-65 keypair. Returns JSON: {public_key: number[], secret_key: number[]}.
#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_ml_dsa_keypair() -> Result<JsValue, JsValue> {
    use crate::pq_sig::{MlDsa65, PqSignatureProvider};

    let provider = MlDsa65::new().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let kp = provider
        .keypair()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    #[derive(Serialize)]
    struct PqSigKeyPairResult {
        public_key: Vec<u8>,
        secret_key: Vec<u8>,
    }

    let result = PqSigKeyPairResult {
        public_key: kp.public_key,
        secret_key: kp.secret_key.as_slice().to_vec(),
    };
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Sign a message using an ML-DSA-65 secret key.
#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_ml_dsa_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::pq_sig::{MlDsa65, PqSignatureProvider};

    let provider = MlDsa65::new().map_err(|e| JsValue::from_str(&e.to_string()))?;
    provider
        .sign(secret_key, message)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify an ML-DSA-65 signature.
#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_ml_dsa_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), JsValue> {
    use crate::pq_sig::{MlDsa65, PqSignatureProvider};

    let provider = MlDsa65::new().map_err(|e| JsValue::from_str(&e.to_string()))?;
    provider
        .verify(public_key, message, signature)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Session messaging exports (real hybrid PQ messaging for web)
// ---------------------------------------------------------------------------

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WasmGeneratedKeysFile {
    user_id: String,
    device_id: String,
    suite: String,
    identity_x25519_pub: String,
    identity_x25519_secret: String,
    identity_sig_pub: String,
    identity_sig_secret: String,
    identity_pq_sig_pub: String,
    identity_pq_sig_secret: String,
    signed_prekey_x25519_pub: String,
    signed_prekey_x25519_secret: String,
    pq_signed_prekey_pub_mlkem768: String,
    pq_signed_prekey_secret_mlkem768: String,
    one_time_prekeys_x25519: Vec<String>,
    one_time_prekeys_x25519_secret: Vec<String>,
    one_time_prekeys_mlkem768: Vec<String>,
    one_time_prekeys_mlkem768_secret: Vec<String>,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct WasmPrivateGroupRestoreResult {
    state: PrivateGroupState,
    member_credential: PrivateGroupMemberCredential,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct WasmPrivateGroupCredentialMaterial {
    membership_handle_sha256: String,
    member_commitment_sha256: String,
    fetch_key_base64: String,
    fetch_key_sha256: String,
    publish_key_base64: Option<String>,
    publish_key_sha256: Option<String>,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct WasmPrivateGroupMemberJoinPackage {
    member_user_id: String,
    join_package: PrivateGroupJoinPackage,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct WasmPrivateGroupBootstrapMaterial {
    snapshot: PrivateGroupEncryptedSnapshot,
    authorizing_member_credential: PrivateGroupMemberCredential,
    member_credentials: Vec<PrivateGroupMemberCredential>,
    member_join_packages: Vec<WasmPrivateGroupMemberJoinPackage>,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Deserialize)]
struct WasmServerBundle {
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

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn parse_private_group_role(role: &str) -> Result<PrivateGroupRole, JsValue> {
    match role.trim().to_ascii_lowercase().as_str() {
        "owner" => Ok(PrivateGroupRole::Owner),
        "admin" => Ok(PrivateGroupRole::Admin),
        "member" => Ok(PrivateGroupRole::Member),
        _ => Err(JsValue::from_str("invalid private group role")),
    }
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn parse_json<T: serde::de::DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    serde_json::from_str(json).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn to_json<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string_pretty(value).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn private_group_credential_material(
    credential: &PrivateGroupMemberCredential,
) -> Result<WasmPrivateGroupCredentialMaterial, JsValue> {
    let fetch_key = credential
        .state_fetch_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let publish_key = credential
        .state_publish_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(WasmPrivateGroupCredentialMaterial {
        membership_handle_sha256: hex_string(&credential.membership_handle_sha256()),
        member_commitment_sha256: hex_string(&credential.member_commitment_sha256()),
        fetch_key_base64: B64.encode(fetch_key),
        fetch_key_sha256: hex_string(&sha2::Sha256::digest(fetch_key)),
        publish_key_base64: publish_key.map(|value| B64.encode(value)),
        publish_key_sha256: publish_key.map(|value| hex_string(&sha2::Sha256::digest(value))),
    })
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_create_state(
    owner_user_id: &str,
    attributes_json: &str,
    initial_members_json: &str,
    created_at_unix_seconds: u64,
) -> Result<String, JsValue> {
    let attributes: PrivateGroupAttributes = parse_json(attributes_json)?;
    let initial_members: Vec<PrivateGroupMember> = parse_json(initial_members_json)?;
    let state = PrivateGroupState::new(
        owner_user_id.to_string(),
        attributes,
        initial_members,
        created_at_unix_seconds,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&state)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_encrypt_snapshot(state_json: &str) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let snapshot: PrivateGroupEncryptedSnapshot = state
        .encrypted_snapshot()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&snapshot)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_export_invite_package(state_json: &str) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let invite: PrivateGroupInvitePackage = state
        .export_invite_package()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&invite)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_export_join_package_for_member(
    state_json: &str,
    member_user_id: &str,
) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let join_package: PrivateGroupJoinPackage = state
        .export_join_package_for_member(member_user_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&join_package)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_restore_join_package(join_package_json: &str) -> Result<String, JsValue> {
    let join_package: PrivateGroupJoinPackage = parse_json(join_package_json)?;
    let (state, member_credential) = join_package
        .restore_state_and_credential()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&WasmPrivateGroupRestoreResult {
        state,
        member_credential,
    })
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_describe_member_credential(
    credential_json: &str,
) -> Result<String, JsValue> {
    let credential: PrivateGroupMemberCredential = parse_json(credential_json)?;
    let material = private_group_credential_material(&credential)?;
    to_json(&material)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_issue_member_credentials(state_json: &str) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let credentials = state
        .issue_member_credentials_for_all_members()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&credentials)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_prepare_bootstrap_material(
    state_json: &str,
    authorizing_user_id: &str,
) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let snapshot = state
        .encrypted_snapshot()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let member_credentials = state
        .issue_member_credentials_for_all_members()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let authorizing_member_credential = member_credentials
        .iter()
        .find(|credential| credential.member_user_id == authorizing_user_id)
        .cloned()
        .ok_or_else(|| JsValue::from_str("authorizing private group member missing from state"))?;
    let member_join_packages = member_credentials
        .iter()
        .cloned()
        .map(|credential| {
            let member_user_id = credential.member_user_id.clone();
            state
                .export_join_package_for_member_credential(credential)
                .map(|join_package| WasmPrivateGroupMemberJoinPackage {
                    member_user_id,
                    join_package,
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&WasmPrivateGroupBootstrapMaterial {
        snapshot,
        authorizing_member_credential,
        member_credentials,
        member_join_packages,
    })
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_encrypt_join_package_for_share_link(
    join_package_json: &str,
) -> Result<String, JsValue> {
    let join_package: PrivateGroupJoinPackage = parse_json(join_package_json)?;
    let material: PrivateGroupLinkInviteMaterial = join_package
        .encrypt_for_share_link()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&material)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_open_share_link_invite(
    envelope_json: &str,
    invite_secret_base64: &str,
) -> Result<String, JsValue> {
    let envelope: PrivateGroupLinkInviteEnvelope = parse_json(envelope_json)?;
    let invite_secret = B64
        .decode(invite_secret_base64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    if invite_secret.len() != 32 {
        return Err(JsValue::from_str(
            "private group invite secret must decode to 32 bytes",
        ));
    }
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&invite_secret);
    let join_package = envelope
        .open_join_package(&secret_bytes)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&join_package)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_prepare_add_member_transition(
    state_json: &str,
    member_user_id: &str,
    role: &str,
    updated_at_unix_seconds: u64,
) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let next_role = parse_private_group_role(role)?;
    let transition: PrivateGroupEpochTransition = state
        .prepare_add_member_transition(
            member_user_id.to_string(),
            next_role,
            updated_at_unix_seconds,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&transition)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_prepare_remove_member_transition(
    state_json: &str,
    member_user_id: &str,
    updated_at_unix_seconds: u64,
) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let transition: PrivateGroupEpochTransition = state
        .prepare_remove_member_transition(member_user_id, updated_at_unix_seconds)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&transition)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_encrypt_message(
    state_json: &str,
    sender_user_id: &str,
    sender_identity_sig_secret_base64: &str,
    sender_identity_pq_sig_secret_base64: &str,
    body: &str,
    sent_at_unix_ms: u64,
) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let sender_identity_sig_secret = decode_b64(
        "private_group.sender_identity_sig_secret_base64",
        sender_identity_sig_secret_base64,
    )?;
    let sender_identity_pq_sig_secret = decode_b64(
        "private_group.sender_identity_pq_sig_secret_base64",
        sender_identity_pq_sig_secret_base64,
    )?;
    let pq_provider = MlDsa65::new().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let message: PrivateGroupEncryptedMessage = state
        .encrypt_message(
            sender_user_id,
            &sender_identity_sig_secret,
            &sender_identity_pq_sig_secret,
            body,
            sent_at_unix_ms,
            &pq_provider,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&message)
}

#[wasm_bindgen]
#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
pub fn wasm_private_group_open_message(
    state_json: &str,
    message_json: &str,
    sender_identity_sig_pub_base64: &str,
    sender_identity_pq_sig_pub_base64: &str,
) -> Result<String, JsValue> {
    let state: PrivateGroupState = parse_json(state_json)?;
    let message: PrivateGroupEncryptedMessage = parse_json(message_json)?;
    let sender_identity_sig_pub = decode_b64(
        "private_group.sender_identity_sig_pub_base64",
        sender_identity_sig_pub_base64,
    )?;
    let sender_identity_pq_sig_pub = decode_b64(
        "private_group.sender_identity_pq_sig_pub_base64",
        sender_identity_pq_sig_pub_base64,
    )?;
    let pq_provider = MlDsa65::new().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let decrypted: PrivateGroupDecryptedMessage = state
        .decrypt_message(
            &message,
            &sender_identity_sig_pub,
            &sender_identity_pq_sig_pub,
            &pq_provider,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    to_json(&decrypted)
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WasmSessionFile {
    version: u16,
    user_id: String,
    peer_user_id: String,
    suite: String,
    snapshot: SessionSnapshot,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Serialize)]
struct WasmSendResult {
    message_bytes_base64: String,
    session_json: String,
    used_handshake: bool,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Serialize)]
struct WasmDecryptResult {
    plaintext_utf8: String,
    plaintext_base64: String,
    session_json: String,
    used_handshake: bool,
    updated_keys: WasmGeneratedKeysFile,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[derive(Clone, Debug, Serialize)]
struct WasmOpenedCertifiedSealedMessage {
    sender_user_id: String,
    sender_device_id: String,
    payload_message_bytes_base64: String,
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
struct WasmEd25519SignatureVerifier;

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
impl SignatureVerifier for WasmEd25519SignatureVerifier {
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

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn suite_to_kem_algorithm(suite: &str) -> Result<KemAlgorithm, JsValue> {
    match suite.trim().to_ascii_lowercase().as_str() {
        "ml-kem-768" => Ok(KemAlgorithm::MlKem768),
        "kyber768" => Ok(KemAlgorithm::Kyber768Alias),
        other => Err(JsValue::from_str(&format!("unsupported suite '{other}'"))),
    }
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn suite_id_to_label(suite_id: u16) -> Result<&'static str, JsValue> {
    match suite_id {
        SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok("ml-kem-768"),
        SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok("kyber768"),
        _ => Err(JsValue::from_str(&format!(
            "unsupported suite id '{suite_id}'"
        ))),
    }
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn build_kem_for_suite(suite: &str) -> Result<MlKem768, JsValue> {
    MlKem768::new(suite_to_kem_algorithm(suite)?).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn suite_label_to_id(suite: &str) -> Result<u16, JsValue> {
    match suite.trim().to_ascii_lowercase().as_str() {
        "ml-kem-768" => Ok(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305),
        "kyber768" => Ok(SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305),
        other => Err(JsValue::from_str(&format!("unsupported suite '{other}'"))),
    }
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
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

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>, JsValue> {
    B64.decode(value.as_bytes())
        .map_err(|_| JsValue::from_str(&format!("invalid base64 for field '{field}'")))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn decode_b64_32(field: &'static str, value: &str) -> Result<[u8; 32], JsValue> {
    let bytes = decode_b64(field, value)?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str(&format!(
            "field '{field}' must decode to 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn to_identity_keypair(keys: &WasmGeneratedKeysFile) -> Result<IdentityKeyPair, JsValue> {
    Ok(IdentityKeyPair {
        key_id: format!("{}-ik", keys.user_id),
        public_key: DhPublicKey(decode_b64_32(
            "identityX25519Pub",
            &keys.identity_x25519_pub,
        )?),
        secret_key: SecretBytes::from(decode_b64(
            "identityX25519Secret",
            &keys.identity_x25519_secret,
        )?),
        pq_sig_public_key: Some(decode_b64("identityPqSigPub", &keys.identity_pq_sig_pub)?),
        pq_sig_secret_key: Some(SecretBytes::from(decode_b64(
            "identityPqSigSecret",
            &keys.identity_pq_sig_secret,
        )?)),
    })
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn to_signed_prekey(keys: &WasmGeneratedKeysFile) -> Result<OneTimePreKey, JsValue> {
    Ok(OneTimePreKey {
        key_id: format!("{}-spk", keys.user_id),
        public_key: DhPublicKey(decode_b64_32(
            "signedPrekeyX25519Pub",
            &keys.signed_prekey_x25519_pub,
        )?),
        secret_key: SecretBytes::from(decode_b64(
            "signedPrekeyX25519Secret",
            &keys.signed_prekey_x25519_secret,
        )?),
    })
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn to_pq_signed_prekey(keys: &WasmGeneratedKeysFile) -> Result<KEMPreKey, JsValue> {
    Ok(KEMPreKey {
        key_id: format!("{}-pqspk", keys.user_id),
        public_key: decode_b64(
            "pqSignedPrekeyPubMlkem768",
            &keys.pq_signed_prekey_pub_mlkem768,
        )?,
        secret_key: SecretBytes::from(decode_b64(
            "pqSignedPrekeySecretMlkem768",
            &keys.pq_signed_prekey_secret_mlkem768,
        )?),
    })
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn candidate_one_time_prekey(
    keys: &WasmGeneratedKeysFile,
    index: usize,
) -> Result<Option<OneTimePreKey>, JsValue> {
    if index >= keys.one_time_prekeys_x25519.len()
        || index >= keys.one_time_prekeys_x25519_secret.len()
    {
        return Ok(None);
    }
    Ok(Some(OneTimePreKey {
        key_id: format!("{}-otk-x-{index}", keys.user_id),
        public_key: DhPublicKey(decode_b64_32(
            "oneTimePrekeysX25519[]",
            &keys.one_time_prekeys_x25519[index],
        )?),
        secret_key: SecretBytes::from(decode_b64(
            "oneTimePrekeysX25519Secret[]",
            &keys.one_time_prekeys_x25519_secret[index],
        )?),
    }))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn bundle_to_core(bundle: &WasmServerBundle, suite: &str) -> Result<PreKeyBundle, JsValue> {
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
    out.suite = AlgorithmSuite {
        kem: suite_to_kem_algorithm(suite)?,
        ..AlgorithmSuite::default()
    };
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

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn read_session_file(session_json: &str) -> Result<WasmSessionFile, JsValue> {
    serde_json::from_str(session_json).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn restore_session(session_file: &WasmSessionFile) -> Result<SessionState, JsValue> {
    let kem = build_kem_for_suite(&session_file.suite)?;
    Ok(SessionState::from_snapshot_with_kem(
        session_file.snapshot.clone(),
        Some(Box::new(kem)),
    ))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
fn remove_consumed_one_time_keys(keys: &mut WasmGeneratedKeysFile, index: usize) {
    if index < keys.one_time_prekeys_x25519.len() {
        keys.one_time_prekeys_x25519.remove(index);
    }
    if index < keys.one_time_prekeys_x25519_secret.len() {
        keys.one_time_prekeys_x25519_secret.remove(index);
    }
    if index < keys.one_time_prekeys_mlkem768.len() {
        keys.one_time_prekeys_mlkem768.remove(index);
    }
    if index < keys.one_time_prekeys_mlkem768_secret.len() {
        keys.one_time_prekeys_mlkem768_secret.remove(index);
    }
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[wasm_bindgen]
pub fn wasm_seal_message_with_sender_cert(
    keys: JsValue,
    recipient_user_id: &str,
    recipient_identity_x25519_pub: &str,
    payload_message_bytes_base64: &str,
    sender_certificate_base64: &str,
) -> Result<String, JsValue> {
    let keys: WasmGeneratedKeysFile =
        serde_wasm_bindgen::from_value(keys).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let identity = to_identity_keypair(&keys)?;
    let local_secret = identity
        .require_secret_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let recipient_identity_pub = DhPublicKey(decode_b64_32(
        "recipient_identity_x25519_pub",
        recipient_identity_x25519_pub,
    )?);
    let suite_id = suite_label_to_id(&keys.suite)?;
    let payload = decode_b64("payload_message_bytes_base64", payload_message_bytes_base64)?;
    let sender_certificate = SenderCertificate::decode(&decode_b64(
        "sender_certificate_base64",
        sender_certificate_base64,
    )?)
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sealed = seal_message_with_cert(
        &local_secret,
        &recipient_identity_pub,
        suite_id,
        recipient_user_id,
        &keys.user_id,
        &keys.device_id,
        &payload,
        &sender_certificate,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(B64.encode(sealed))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[wasm_bindgen]
pub fn wasm_open_sealed_message_with_sender_cert(
    keys: JsValue,
    sender_identity_x25519_pub: Option<String>,
    sealed_message_bytes_base64: &str,
    server_issuer_ed25519_pub: &str,
) -> Result<JsValue, JsValue> {
    let keys: WasmGeneratedKeysFile =
        serde_wasm_bindgen::from_value(keys).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let identity = to_identity_keypair(&keys)?;
    let local_secret = identity
        .require_secret_key()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let suite_id = suite_label_to_id(&keys.suite)?;
    let legacy_sender_identity_pub = sender_identity_x25519_pub
        .as_deref()
        .map(|value| decode_b64_32("sender_identity_x25519_pub", value))
        .transpose()?
        .map(DhPublicKey);
    let server_pub_key = VerifyingKey::from_bytes(&decode_b64_32(
        "server_issuer_ed25519_pub",
        server_issuer_ed25519_pub,
    )?)
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let now_unix_secs = (Date::now() / 1000.0).floor() as u64;
    let opened = open_message_with_cert(
        &local_secret,
        &decode_b64("sealed_message_bytes_base64", sealed_message_bytes_base64)?,
        suite_id,
        &keys.user_id,
        Some(&server_pub_key),
        now_unix_secs,
        legacy_sender_identity_pub.as_ref(),
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    if opened.sender_cert.is_none() {
        return Err(JsValue::from_str(
            "sealed sender certificate missing from transport envelope",
        ));
    }
    serde_wasm_bindgen::to_value(&WasmOpenedCertifiedSealedMessage {
        sender_user_id: opened.sender_user_id,
        sender_device_id: opened.sender_device_id,
        payload_message_bytes_base64: B64.encode(opened.payload),
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[wasm_bindgen]
pub fn wasm_initiate_session_and_encrypt(
    keys: JsValue,
    from_user_id: &str,
    peer_user_id: &str,
    peer_bundle: JsValue,
    plaintext_utf8: &str,
) -> Result<JsValue, JsValue> {
    let keys: WasmGeneratedKeysFile =
        serde_wasm_bindgen::from_value(keys).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if keys.user_id != from_user_id {
        return Err(JsValue::from_str(&format!(
            "from_user_id '{from_user_id}' does not match keys user '{}'",
            keys.user_id
        )));
    }
    let peer_bundle: WasmServerBundle = serde_wasm_bindgen::from_value(peer_bundle)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let prekey_bundle = bundle_to_core(&peer_bundle, &keys.suite)?;
    let identity = to_identity_keypair(&keys)?;
    let local_pq_signed_prekey = to_pq_signed_prekey(&keys)?;
    let kem = build_kem_for_suite(&keys.suite)?;
    let verifier = WasmEd25519SignatureVerifier;
    let pq_verifier = MlDsa65::new().map_err(|e| JsValue::from_str(&e.to_string()))?;
    validate_hybrid_prekey_bundle_signatures(&prekey_bundle, &verifier, &pq_verifier)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let initiator = alice_initiate(
        &mut OsRng,
        &verifier,
        &kem,
        from_user_id,
        peer_user_id,
        &identity,
        &local_pq_signed_prekey.public_key,
        &prekey_bundle,
        plaintext_utf8.as_bytes(),
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let initial_encoded = initiator
        .initial_message
        .encode()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let local_dh = DhKeyPair {
        public: identity.public_key,
        secret: identity
            .require_secret_key()
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
    };
    let session = SessionState::from_handshake_with_suite_with_pq_ratchet(
        SessionRole::Initiator,
        *initiator.session_key.as_bytes(),
        local_dh,
        prekey_bundle.signed_prekey,
        prekey_bundle
            .suite
            .suite_id()
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        512,
        mandatory_pq_ratchet_state(
            &local_pq_signed_prekey,
            prekey_bundle.pq_signed_prekey.clone(),
        ),
        Box::new(kem),
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let session_file = WasmSessionFile {
        version: 1,
        user_id: from_user_id.to_string(),
        peer_user_id: peer_user_id.to_string(),
        suite: keys.suite.clone(),
        snapshot: session.snapshot(),
    };

    serde_wasm_bindgen::to_value(&WasmSendResult {
        message_bytes_base64: B64.encode(initial_encoded),
        session_json: serde_json::to_string_pretty(&session_file)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        used_handshake: true,
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[wasm_bindgen]
pub fn wasm_encrypt_with_session(
    session_json: &str,
    sender_user_id: &str,
    peer_user_id: &str,
    plaintext_utf8: &str,
) -> Result<JsValue, JsValue> {
    let mut session_file = read_session_file(session_json)?;
    if session_file.user_id != sender_user_id {
        return Err(JsValue::from_str(&format!(
            "sender_user_id '{sender_user_id}' does not match session user '{}'",
            session_file.user_id
        )));
    }
    if session_file.peer_user_id != peer_user_id {
        return Err(JsValue::from_str(&format!(
            "peer_user_id '{peer_user_id}' does not match session peer '{}'",
            session_file.peer_user_id
        )));
    }

    let mut session = restore_session(&session_file)?;
    let ad = conversation_associated_data(sender_user_id, peer_user_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let wire = session
        .encrypt(plaintext_utf8.as_bytes(), &ad)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    session_file.snapshot = session.snapshot();

    serde_wasm_bindgen::to_value(&WasmSendResult {
        message_bytes_base64: B64.encode(wire),
        session_json: serde_json::to_string_pretty(&session_file)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        used_handshake: false,
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
#[wasm_bindgen]
pub fn wasm_decrypt_message(
    keys: JsValue,
    recipient_user_id: &str,
    sender_user_id: &str,
    message_bytes_base64: &str,
    existing_session_json: Option<String>,
) -> Result<JsValue, JsValue> {
    let mut keys: WasmGeneratedKeysFile =
        serde_wasm_bindgen::from_value(keys).map_err(|e| JsValue::from_str(&e.to_string()))?;
    if keys.user_id != recipient_user_id {
        return Err(JsValue::from_str(&format!(
            "recipient_user_id '{recipient_user_id}' does not match keys user '{}'",
            keys.user_id
        )));
    }

    let message_bytes = decode_b64("message_bytes_base64", message_bytes_base64)?;
    if let Ok(initial) = InitialMessage::decode(&message_bytes) {
        if initial.sender_id != sender_user_id {
            return Err(JsValue::from_str(&format!(
                "sender_user_id '{sender_user_id}' does not match handshake sender '{}'",
                initial.sender_id
            )));
        }
        if initial.recipient_id != recipient_user_id {
            return Err(JsValue::from_str(&format!(
                "recipient_user_id '{recipient_user_id}' does not match handshake recipient '{}'",
                initial.recipient_id
            )));
        }

        let suite_label = suite_id_to_label(initial.suite_id)?;
        let kem = build_kem_for_suite(suite_label)?;
        let identity = to_identity_keypair(&keys)?;
        let signed_prekey = to_signed_prekey(&keys)?;
        let pq_signed_prekey = to_pq_signed_prekey(&keys)?;

        let mut responder = bob_receive(
            &kem,
            &identity,
            &signed_prekey,
            &pq_signed_prekey,
            None,
            &initial,
        );
        let mut consumed_otpk_index: Option<usize> = None;
        if responder.is_err() {
            let candidate_count = keys
                .one_time_prekeys_x25519
                .len()
                .min(keys.one_time_prekeys_x25519_secret.len());
            for idx in 0..candidate_count {
                let Some(candidate) = candidate_one_time_prekey(&keys, idx)? else {
                    continue;
                };
                if let Ok(next) = bob_receive(
                    &kem,
                    &identity,
                    &signed_prekey,
                    &pq_signed_prekey,
                    Some(&candidate),
                    &initial,
                ) {
                    responder = Ok(next);
                    consumed_otpk_index = Some(idx);
                    break;
                }
            }
        }

        let responder = responder.map_err(|e| JsValue::from_str(&e.to_string()))?;
        if let Some(index) = consumed_otpk_index {
            remove_consumed_one_time_keys(&mut keys, index);
        }

        let local_dh = DhKeyPair {
            public: signed_prekey.public_key,
            secret: signed_prekey
                .require_secret_key()
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
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
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let session_file = WasmSessionFile {
            version: 1,
            user_id: recipient_user_id.to_string(),
            peer_user_id: sender_user_id.to_string(),
            suite: suite_label.to_string(),
            snapshot: session.snapshot(),
        };
        let plaintext_base64 = B64.encode(&responder.plaintext);
        let plaintext_utf8 = String::from_utf8_lossy(&responder.plaintext).to_string();

        return serde_wasm_bindgen::to_value(&WasmDecryptResult {
            plaintext_utf8,
            plaintext_base64,
            session_json: serde_json::to_string_pretty(&session_file)
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
            used_handshake: true,
            updated_keys: keys,
        })
        .map_err(|e| JsValue::from_str(&e.to_string()));
    }

    let Some(session_json) = existing_session_json else {
        return Err(JsValue::from_str(
            "existing_session_json is required for non-handshake messages",
        ));
    };
    let mut session_file = read_session_file(&session_json)?;
    if session_file.user_id != recipient_user_id {
        return Err(JsValue::from_str(&format!(
            "recipient_user_id '{recipient_user_id}' does not match session user '{}'",
            session_file.user_id
        )));
    }
    if session_file.peer_user_id != sender_user_id {
        return Err(JsValue::from_str(&format!(
            "sender_user_id '{sender_user_id}' does not match session peer '{}'",
            session_file.peer_user_id
        )));
    }

    let mut session = restore_session(&session_file)?;
    let ad = conversation_associated_data(sender_user_id, recipient_user_id)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let plaintext = session
        .decrypt(&message_bytes, &ad)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    session_file.snapshot = session.snapshot();
    let plaintext_base64 = B64.encode(&plaintext);
    let plaintext_utf8 = String::from_utf8_lossy(&plaintext).to_string();

    serde_wasm_bindgen::to_value(&WasmDecryptResult {
        plaintext_utf8,
        plaintext_base64,
        session_json: serde_json::to_string_pretty(&session_file)
            .map_err(|e| JsValue::from_str(&e.to_string()))?,
        used_handshake: false,
        updated_keys: keys,
    })
    .map_err(|e| JsValue::from_str(&e.to_string()))
}
