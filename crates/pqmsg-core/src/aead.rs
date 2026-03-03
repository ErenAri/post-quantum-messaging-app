use crate::CoreError;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CiphertextEnvelope {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    nonce: [u8; 12],
) -> Result<CiphertextEnvelope, CoreError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreError::AeadOperation)?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| CoreError::AeadOperation)?;
    Ok(CiphertextEnvelope {
        nonce,
        ciphertext,
        aad: aad.to_vec(),
    })
}

pub fn encrypt_with_rng<R: RngCore + CryptoRng>(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> Result<CiphertextEnvelope, CoreError> {
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    encrypt(key, plaintext, aad, nonce)
}

pub fn decrypt(key: &[u8; 32], envelope: &CiphertextEnvelope) -> Result<Vec<u8>, CoreError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CoreError::AeadOperation)?;
    let payload = Payload {
        msg: &envelope.ciphertext,
        aad: &envelope.aad,
    };
    cipher
        .decrypt(Nonce::from_slice(&envelope.nonce), payload)
        .map_err(|_| CoreError::AeadOperation)
}
