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

/// Default padding block size in bytes (ISO 7816-4).
pub const PADDING_BLOCK_SIZE: usize = 256;

/// Pads plaintext using ISO 7816-4 scheme: append 0x80, then zeros to the next
/// multiple of `block_size`. The padded output is always at least `block_size`
/// bytes and always strictly longer than the input.
pub fn pad_plaintext(plaintext: &[u8], block_size: usize) -> Vec<u8> {
    assert!(block_size > 0, "block_size must be positive");
    // padded_len = next multiple of block_size that is > plaintext.len()
    let padded_len = ((plaintext.len() / block_size) + 1) * block_size;
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(padded_len, 0x00);
    out
}

/// Removes ISO 7816-4 padding. Scans from the end for the 0x80 delimiter byte,
/// verifying that only zero bytes follow it. Returns a slice of the original
/// plaintext. The scan is *not* constant-time (padding is inside the AEAD
/// boundary so timing is not exploitable).
pub fn unpad_plaintext(padded: &[u8]) -> Result<&[u8], CoreError> {
    // Scan backwards for the 0x80 delimiter
    for i in (0..padded.len()).rev() {
        match padded[i] {
            0x80 => return Ok(&padded[..i]),
            0x00 => continue,
            _ => return Err(CoreError::MessageParsing("invalid ISO 7816-4 padding")),
        }
    }
    Err(CoreError::MessageParsing("no padding delimiter found"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_hello_256() {
        let padded = pad_plaintext(b"hello", 256);
        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..5], b"hello");
        assert_eq!(padded[5], 0x80);
        assert!(padded[6..].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn unpad_recovers_hello() {
        let padded = pad_plaintext(b"hello", 256);
        let recovered = unpad_plaintext(&padded).expect("unpad");
        assert_eq!(recovered, b"hello");
    }

    #[test]
    fn pad_empty_input() {
        let padded = pad_plaintext(b"", 256);
        assert_eq!(padded.len(), 256);
        assert_eq!(padded[0], 0x80);
        assert!(padded[1..].iter().all(|&b| b == 0x00));
        let recovered = unpad_plaintext(&padded).expect("unpad empty");
        assert!(recovered.is_empty());
    }

    #[test]
    fn pad_exact_block_size_input() {
        // Input that exactly fills one block should still produce a second block
        let input = vec![0x41u8; 256];
        let padded = pad_plaintext(&input, 256);
        assert_eq!(padded.len(), 512);
        assert_eq!(&padded[..256], &input[..]);
        assert_eq!(padded[256], 0x80);
        let recovered = unpad_plaintext(&padded).expect("unpad exact block");
        assert_eq!(recovered, &input[..]);
    }

    #[test]
    fn pad_one_byte_over_block() {
        let input = vec![0x42u8; 257];
        let padded = pad_plaintext(&input, 256);
        assert_eq!(padded.len(), 512);
        let recovered = unpad_plaintext(&padded).expect("unpad one-over");
        assert_eq!(recovered, &input[..]);
    }

    #[test]
    fn pad_small_block_size() {
        let padded = pad_plaintext(b"ab", 4);
        assert_eq!(padded.len(), 4);
        assert_eq!(&padded[..2], b"ab");
        assert_eq!(padded[2], 0x80);
        assert_eq!(padded[3], 0x00);
        let recovered = unpad_plaintext(&padded).expect("unpad small");
        assert_eq!(recovered, b"ab");
    }

    #[test]
    fn unpad_rejects_corrupt_padding() {
        let mut padded = pad_plaintext(b"test", 256);
        // Replace a trailing zero with a non-zero byte
        padded[200] = 0x42;
        assert!(unpad_plaintext(&padded).is_err());
    }

    #[test]
    fn unpad_rejects_no_delimiter() {
        let data = vec![0x00u8; 256];
        assert!(unpad_plaintext(&data).is_err());
    }

    #[test]
    fn roundtrip_property_various_sizes() {
        for size in [0, 1, 2, 127, 255, 256, 257, 511, 512, 1000] {
            let input: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let padded = pad_plaintext(&input, 256);
            assert_eq!(
                padded.len() % 256,
                0,
                "padded size not block-aligned for input size {size}"
            );
            assert!(
                padded.len() > input.len(),
                "padded not longer than input for size {size}"
            );
            let recovered = unpad_plaintext(&padded).expect("unpad roundtrip");
            assert_eq!(
                recovered,
                &input[..],
                "roundtrip failed for input size {size}"
            );
        }
    }

    #[test]
    fn aead_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"test message";
        let aad = b"associated data";
        let envelope = encrypt(&key, plaintext, aad, nonce).expect("encrypt");
        let decrypted = decrypt(&key, &envelope).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }
}
