use crate::alg::{AlgorithmSuite, PROTOCOL_VERSION_V1};
use crate::dh::{generate_keypair, DhPublicKey, DhSecretKey};
use crate::CoreError;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Default, Eq, PartialEq, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn require_32(&self, field: &'static str) -> Result<[u8; 32], CoreError> {
        if self.0.len() != 32 {
            return Err(CoreError::InvalidLength {
                field,
                expected: 32,
                actual: self.0.len(),
            });
        }
        let mut output = [0u8; 32];
        output.copy_from_slice(&self.0);
        Ok(output)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretBytes").field(&"[REDACTED]").finish()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityKeyPair {
    pub key_id: String,
    pub public_key: DhPublicKey,
    #[serde(default, skip_serializing)]
    pub secret_key: SecretBytes,
}

impl IdentityKeyPair {
    pub fn generate<R: RngCore + CryptoRng>(key_id: impl Into<String>, rng: &mut R) -> Self {
        let keypair = generate_keypair(rng);
        Self {
            key_id: key_id.into(),
            public_key: keypair.public,
            secret_key: SecretBytes::new(keypair.secret.0.to_vec()),
        }
    }

    pub fn require_secret_key(&self) -> Result<DhSecretKey, CoreError> {
        Ok(DhSecretKey(
            self.secret_key.require_32("identity_key_pair.secret_key")?,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneTimePreKey {
    pub key_id: String,
    pub public_key: DhPublicKey,
    #[serde(default, skip_serializing)]
    pub secret_key: SecretBytes,
}

impl OneTimePreKey {
    pub fn generate<R: RngCore + CryptoRng>(key_id: impl Into<String>, rng: &mut R) -> Self {
        let keypair = generate_keypair(rng);
        Self {
            key_id: key_id.into(),
            public_key: keypair.public,
            secret_key: SecretBytes::new(keypair.secret.0.to_vec()),
        }
    }

    pub fn require_secret_key(&self) -> Result<DhSecretKey, CoreError> {
        Ok(DhSecretKey(
            self.secret_key.require_32("one_time_prekey.secret_key")?,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KEMPreKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
    #[serde(default, skip_serializing)]
    pub secret_key: SecretBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub protocol_version: u16,
    pub suite: AlgorithmSuite,
    pub owner_id: String,
    pub identity_key: DhPublicKey,
    pub signed_prekey: DhPublicKey,
    pub pq_signed_prekey: Vec<u8>,
    pub spk_signature: Vec<u8>,
    pub pqspk_signature: Vec<u8>,
    pub signature_public_key: Vec<u8>,
    pub one_time_prekey: Option<DhPublicKey>,
    pub one_time_pq_prekey: Option<Vec<u8>>,
}

impl PreKeyBundle {
    pub fn new(
        owner_id: impl Into<String>,
        identity_key: DhPublicKey,
        signed_prekey: DhPublicKey,
        pq_signed_prekey: Vec<u8>,
        spk_signature: Vec<u8>,
        pqspk_signature: Vec<u8>,
        signature_public_key: Vec<u8>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION_V1,
            suite: AlgorithmSuite::default(),
            owner_id: owner_id.into(),
            identity_key,
            signed_prekey,
            pq_signed_prekey,
            spk_signature,
            pqspk_signature,
            signature_public_key,
            one_time_prekey: None,
            one_time_pq_prekey: None,
        }
    }
}
