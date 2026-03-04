use crate::CoreError;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const WRAPPED_KIND: &str = "pqmsg-sealed";
const WRAPPED_KDF: &str = "argon2id";
const WRAPPED_AEAD: &str = "aes-256-gcm";
const STORAGE_AAD: &[u8] = b"pqmsg-storage-v1";
pub const WRAPPED_VERSION: u16 = 1;
pub const WRAPPED_SALT_BYTES: usize = 16;
pub const WRAPPED_NONCE_BYTES: usize = 12;
const WRAPPED_KEY_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2idParams {
    fn default() -> Self {
        Self {
            m_cost_kib: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedSecret {
    pub kind: String,
    pub version: u16,
    pub kdf: String,
    pub aead: String,
    pub kdf_params: Argon2idParams,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn wrap_bytes(passphrase: &SecretString, plaintext: &[u8]) -> Result<WrappedSecret, CoreError> {
    wrap_bytes_with_params(passphrase, plaintext, Argon2idParams::default())
}

pub fn wrap_bytes_with_params(
    passphrase: &SecretString,
    plaintext: &[u8],
    params: Argon2idParams,
) -> Result<WrappedSecret, CoreError> {
    let mut salt = [0u8; WRAPPED_SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; WRAPPED_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let mut key = derive_key(passphrase, &salt, params)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CoreError::AeadOperation)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: STORAGE_AAD,
            },
        )
        .map_err(|_| CoreError::AeadOperation)?;
    key.zeroize();

    Ok(WrappedSecret {
        kind: WRAPPED_KIND.to_string(),
        version: WRAPPED_VERSION,
        kdf: WRAPPED_KDF.to_string(),
        aead: WRAPPED_AEAD.to_string(),
        kdf_params: params,
        salt_b64: B64.encode(salt),
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
    })
}

pub fn unwrap_bytes(
    passphrase: &SecretString,
    wrapped: &WrappedSecret,
) -> Result<Vec<u8>, CoreError> {
    if wrapped.kind != WRAPPED_KIND {
        return Err(CoreError::InvalidStorageFormat("kind"));
    }
    if wrapped.version != WRAPPED_VERSION {
        return Err(CoreError::InvalidStorageFormat("version"));
    }
    if wrapped.kdf != WRAPPED_KDF {
        return Err(CoreError::InvalidStorageFormat("kdf"));
    }
    if wrapped.aead != WRAPPED_AEAD {
        return Err(CoreError::InvalidStorageFormat("aead"));
    }

    let salt = decode_base64_exact(
        "salt_b64",
        &wrapped.salt_b64,
        WRAPPED_SALT_BYTES,
        WRAPPED_SALT_BYTES,
    )?;
    let nonce = decode_base64_exact(
        "nonce_b64",
        &wrapped.nonce_b64,
        WRAPPED_NONCE_BYTES,
        WRAPPED_NONCE_BYTES,
    )?;
    let ciphertext = decode_base64_exact("ciphertext_b64", &wrapped.ciphertext_b64, 16, 1 << 30)?;

    let mut key = derive_key(passphrase, &salt, wrapped.kdf_params)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| CoreError::AeadOperation)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: STORAGE_AAD,
            },
        )
        .map_err(|_| CoreError::StorageDecryptionFailed)?;
    key.zeroize();
    Ok(plaintext)
}

fn decode_base64_exact(
    field: &'static str,
    value: &str,
    min_len: usize,
    max_len: usize,
) -> Result<Vec<u8>, CoreError> {
    let decoded = B64
        .decode(value.as_bytes())
        .map_err(|_| CoreError::InvalidStorageBase64(field))?;
    if decoded.len() < min_len || decoded.len() > max_len {
        return Err(CoreError::InvalidLength {
            field,
            expected: min_len,
            actual: decoded.len(),
        });
    }
    Ok(decoded)
}

fn derive_key(
    passphrase: &SecretString,
    salt: &[u8],
    params: Argon2idParams,
) -> Result<[u8; WRAPPED_KEY_BYTES], CoreError> {
    let params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(WRAPPED_KEY_BYTES),
    )
    .map_err(|_| CoreError::KdfOperation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut passphrase_bytes = passphrase.expose_secret().as_bytes().to_vec();
    let mut key = [0u8; WRAPPED_KEY_BYTES];
    let result = argon2.hash_password_into(&passphrase_bytes, salt, &mut key);
    passphrase_bytes.zeroize();
    if result.is_err() {
        key.zeroize();
        return Err(CoreError::KdfOperation);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_secret_roundtrip() {
        let passphrase = SecretString::new("passphrase".to_string().into());
        let plaintext = b"hello";
        let wrapped = wrap_bytes(&passphrase, plaintext).expect("wrap");
        let out = unwrap_bytes(&passphrase, &wrapped).expect("unwrap");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrapped_secret_rejects_wrong_passphrase() {
        let passphrase = SecretString::new("passphrase".to_string().into());
        let wrong = SecretString::new("wrong".to_string().into());
        let wrapped = wrap_bytes(&passphrase, b"hello").expect("wrap");
        assert!(unwrap_bytes(&wrong, &wrapped).is_err());
    }

    #[test]
    fn wrapped_secret_rejects_tampered_ciphertext() {
        let passphrase = SecretString::new("passphrase".to_string().into());
        let mut wrapped = wrap_bytes(&passphrase, b"hello").expect("wrap");
        let mut ciphertext = B64
            .decode(wrapped.ciphertext_b64.as_bytes())
            .expect("decode");
        ciphertext.push(0x42);
        wrapped.ciphertext_b64 = B64.encode(ciphertext);
        assert!(unwrap_bytes(&passphrase, &wrapped).is_err());
    }
}
