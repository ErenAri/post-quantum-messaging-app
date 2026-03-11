//! Post-quantum digital signatures (ML-DSA-65 / Dilithium3).
//!
//! Provides a [`PqSignatureProvider`] trait with native liboqs and pure-Rust
//! backends. The hybrid scheme pairs ML-DSA-65 with an external Ed25519
//! signature so that security holds if either algorithm remains unbroken.

use crate::keys::SecretBytes;
use crate::CoreError;

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
use fips204::traits::{KeyGen as _, SerDes as _, Signer as _, Verifier as _};
#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
use rand_core::OsRng;

pub const ML_DSA_65_PK_LEN: usize = 1952;
pub const ML_DSA_65_SK_LEN: usize = 4032;
pub const ML_DSA_65_SIG_LEN: usize = 3309;

pub struct PqSigKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: SecretBytes,
}

pub trait PqSignatureProvider {
    fn keypair(&self) -> Result<PqSigKeyPair, CoreError>;
    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CoreError>;
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError>;
}

#[cfg(feature = "pq-oqs")]
pub struct MlDsa65 {
    sig: oqs::sig::Sig,
}

#[cfg(feature = "pq-oqs")]
impl MlDsa65 {
    pub fn new() -> Result<Self, CoreError> {
        oqs::init();
        let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65)
            .map_err(|_| CoreError::PqSigOperation("MlDsa65 init failed"))?;
        Ok(Self { sig })
    }

    pub fn public_key_len(&self) -> usize {
        self.sig.length_public_key()
    }

    pub fn secret_key_len(&self) -> usize {
        self.sig.length_secret_key()
    }

    pub fn signature_len(&self) -> usize {
        self.sig.length_signature()
    }
}

#[cfg(feature = "pq-oqs")]
impl PqSignatureProvider for MlDsa65 {
    fn keypair(&self) -> Result<PqSigKeyPair, CoreError> {
        let (pk, sk) = self
            .sig
            .keypair()
            .map_err(|_| CoreError::PqSigOperation("keypair generation failed"))?;
        Ok(PqSigKeyPair {
            public_key: pk.into_vec(),
            secret_key: SecretBytes::new(sk.into_vec()),
        })
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let Some(sk_ref) = self.sig.secret_key_from_bytes(secret_key) else {
            return Err(CoreError::InvalidLength {
                field: "pq_sig.secret_key",
                expected: self.secret_key_len(),
                actual: secret_key.len(),
            });
        };
        let sig = self
            .sig
            .sign(message, sk_ref)
            .map_err(|_| CoreError::PqSigOperation("signing failed"))?;
        Ok(sig.into_vec())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        let Some(pk_ref) = self.sig.public_key_from_bytes(public_key) else {
            return Err(CoreError::InvalidLength {
                field: "pq_sig.public_key",
                expected: self.public_key_len(),
                actual: public_key.len(),
            });
        };
        let Some(sig_ref) = self.sig.signature_from_bytes(signature) else {
            return Err(CoreError::InvalidLength {
                field: "pq_sig.signature",
                expected: self.signature_len(),
                actual: signature.len(),
            });
        };
        self.sig
            .verify(message, sig_ref, pk_ref)
            .map_err(|_| CoreError::SignatureVerificationFailed)
    }
}

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
pub struct MlDsa65;

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
impl MlDsa65 {
    pub fn new() -> Result<Self, CoreError> {
        Ok(Self)
    }

    pub fn public_key_len(&self) -> usize {
        fips204::ml_dsa_65::PK_LEN
    }

    pub fn secret_key_len(&self) -> usize {
        fips204::ml_dsa_65::SK_LEN
    }

    pub fn signature_len(&self) -> usize {
        fips204::ml_dsa_65::SIG_LEN
    }
}

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
impl PqSignatureProvider for MlDsa65 {
    fn keypair(&self) -> Result<PqSigKeyPair, CoreError> {
        let (public_key, secret_key) = fips204::ml_dsa_65::KG::try_keygen_with_rng(&mut OsRng)
            .map_err(|_| CoreError::PqSigOperation("keypair generation failed"))?;
        Ok(PqSigKeyPair {
            public_key: public_key.into_bytes().to_vec(),
            secret_key: SecretBytes::new(secret_key.into_bytes().to_vec()),
        })
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let secret_key =
            to_fixed_array::<{ fips204::ml_dsa_65::SK_LEN }>("pq_sig.secret_key", secret_key)?;
        let secret_key = fips204::ml_dsa_65::PrivateKey::try_from_bytes(secret_key)
            .map_err(|_| CoreError::PqSigOperation("secret key deserialization failed"))?;
        let signature = secret_key
            .try_sign_with_rng(&mut OsRng, message, &[0])
            .map_err(|_| CoreError::PqSigOperation("signing failed"))?;
        Ok(signature.to_vec())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        let public_key =
            to_fixed_array::<{ fips204::ml_dsa_65::PK_LEN }>("pq_sig.public_key", public_key)?;
        let signature =
            to_fixed_array::<{ fips204::ml_dsa_65::SIG_LEN }>("pq_sig.signature", signature)?;
        let public_key = fips204::ml_dsa_65::PublicKey::try_from_bytes(public_key)
            .map_err(|_| CoreError::PqSigOperation("public key deserialization failed"))?;
        if public_key.verify(message, &signature, &[0]) {
            Ok(())
        } else {
            Err(CoreError::SignatureVerificationFailed)
        }
    }
}

#[cfg(all(not(feature = "pq-oqs"), not(feature = "pq-rust")))]
pub struct MlDsa65;

#[cfg(all(not(feature = "pq-oqs"), not(feature = "pq-rust")))]
impl MlDsa65 {
    pub fn new() -> Result<Self, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }
}

#[cfg(all(not(feature = "pq-oqs"), not(feature = "pq-rust")))]
impl PqSignatureProvider for MlDsa65 {
    fn keypair(&self) -> Result<PqSigKeyPair, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }

    fn sign(&self, _secret_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }

    fn verify(
        &self,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }
}

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
fn to_fixed_array<const N: usize>(field: &'static str, value: &[u8]) -> Result<[u8; N], CoreError> {
    value.try_into().map_err(|_| CoreError::InvalidLength {
        field,
        expected: N,
        actual: value.len(),
    })
}

pub struct HybridSignature {
    pub ed25519_sig: Vec<u8>,
    pub pq_sig: Vec<u8>,
}

impl HybridSignature {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ed25519_sig.len() + self.pq_sig.len());
        out.extend_from_slice(&self.ed25519_sig);
        out.extend_from_slice(&self.pq_sig);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() <= 64 {
            return Err(CoreError::InvalidLength {
                field: "hybrid_signature",
                expected: 65,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            ed25519_sig: bytes[..64].to_vec(),
            pq_sig: bytes[64..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn ml_dsa_65_keypair_expected_lengths() {
        let provider = MlDsa65::new().expect("init");
        assert_eq!(provider.public_key_len(), ML_DSA_65_PK_LEN);
        assert_eq!(provider.secret_key_len(), ML_DSA_65_SK_LEN);
        let kp = provider.keypair().expect("keypair");
        assert_eq!(kp.public_key.len(), ML_DSA_65_PK_LEN);
        assert_eq!(kp.secret_key.as_slice().len(), ML_DSA_65_SK_LEN);
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn ml_dsa_65_sign_verify_roundtrip() {
        let provider = MlDsa65::new().expect("init");
        let kp = provider.keypair().expect("keypair");
        let message = b"post-quantum authentication test";
        let sig = provider
            .sign(kp.secret_key.as_slice(), message)
            .expect("sign");
        provider
            .verify(&kp.public_key, message, &sig)
            .expect("verify");
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn ml_dsa_65_verify_rejects_tampered_message() {
        let provider = MlDsa65::new().expect("init");
        let kp = provider.keypair().expect("keypair");
        let sig = provider
            .sign(kp.secret_key.as_slice(), b"original")
            .expect("sign");
        let result = provider.verify(&kp.public_key, b"tampered", &sig);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn ml_dsa_65_verify_rejects_wrong_key() {
        let provider = MlDsa65::new().expect("init");
        let kp1 = provider.keypair().expect("keypair1");
        let kp2 = provider.keypair().expect("keypair2");
        let sig = provider
            .sign(kp1.secret_key.as_slice(), b"msg")
            .expect("sign");
        let result = provider.verify(&kp2.public_key, b"msg", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn hybrid_signature_encode_decode_roundtrip() {
        let hybrid = HybridSignature {
            ed25519_sig: vec![0xAA; 64],
            pq_sig: vec![0xBB; 100],
        };
        let encoded = hybrid.encode();
        assert_eq!(encoded.len(), 164);
        let decoded = HybridSignature::decode(&encoded).expect("decode");
        assert_eq!(decoded.ed25519_sig, vec![0xAA; 64]);
        assert_eq!(decoded.pq_sig, vec![0xBB; 100]);
    }

    #[test]
    fn hybrid_signature_decode_rejects_short() {
        let result = HybridSignature::decode(&[0u8; 64]);
        assert!(result.is_err());
    }
}
