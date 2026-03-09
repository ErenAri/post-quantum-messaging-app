//! WASM bindings for pqmsg-core.
//!
//! Exposes key generation, AEAD, KDF, DH, and storage wrapping
//! to JavaScript via wasm-bindgen.
//!
//! Compiled with `wasm-pack build --features wasm --no-default-features`.

use wasm_bindgen::prelude::*;

use crate::ad::conversation_associated_data;
use crate::aead;
use crate::dh;
use crate::kdf;
use crate::keys::{IdentityKeyPair, OneTimePreKey};
use crate::storage;

use rand_core::{OsRng, RngCore};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

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
    let key_arr: [u8; 32] = key.try_into().unwrap();
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
    let key_arr: [u8; 32] = key.try_into().unwrap();
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
    kdf::hkdf_sha256(ikm, salt_opt, info, out_len).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// X25519 Diffie-Hellman key agreement.
#[wasm_bindgen]
pub fn wasm_x25519_dh(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    if secret_key.len() != 32 || public_key.len() != 32 {
        return Err(JsValue::from_str("keys must be 32 bytes"));
    }
    let sk = dh::DhSecretKey(secret_key.try_into().unwrap());
    let pk = dh::DhPublicKey(public_key.try_into().unwrap());
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
#[cfg(feature = "pq-oqs")]
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
#[cfg(feature = "pq-oqs")]
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
#[cfg(feature = "pq-oqs")]
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
#[cfg(feature = "pq-oqs")]
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
#[cfg(feature = "pq-oqs")]
pub fn wasm_ml_dsa_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsValue> {
    use crate::pq_sig::{MlDsa65, PqSignatureProvider};

    let provider = MlDsa65::new().map_err(|e| JsValue::from_str(&e.to_string()))?;
    provider
        .sign(secret_key, message)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify an ML-DSA-65 signature.
#[wasm_bindgen]
#[cfg(feature = "pq-oqs")]
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
