use crate::CoreError;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION_V1: u16 = 1;
pub const ALGORITHM_REGISTRY_V1: u16 = 1;
pub const SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305: u16 = 1;
pub const SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct VersionedAlgorithmId {
    pub registry_version: u16,
    pub id: u16,
}

impl VersionedAlgorithmId {
    pub const fn new(registry_version: u16, id: u16) -> Self {
        Self {
            registry_version,
            id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub enum KemAlgorithm {
    #[default]
    MlKem768,
    Kyber768Alias,
}

impl KemAlgorithm {
    pub const fn as_id(self) -> VersionedAlgorithmId {
        match self {
            Self::MlKem768 => VersionedAlgorithmId::new(ALGORITHM_REGISTRY_V1, 0x0001),
            Self::Kyber768Alias => VersionedAlgorithmId::new(ALGORITHM_REGISTRY_V1, 0x0002),
        }
    }

    pub fn from_id(id: VersionedAlgorithmId) -> Result<Self, CoreError> {
        if id.registry_version != ALGORITHM_REGISTRY_V1 {
            return Err(CoreError::UnsupportedAlgorithm("kem.registry_version"));
        }
        match id.id {
            0x0001 => Ok(Self::MlKem768),
            0x0002 => Ok(Self::Kyber768Alias),
            _ => Err(CoreError::UnsupportedAlgorithm("kem.id")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub enum DhAlgorithm {
    #[default]
    X25519,
}

impl DhAlgorithm {
    pub const fn as_id(self) -> VersionedAlgorithmId {
        match self {
            Self::X25519 => VersionedAlgorithmId::new(ALGORITHM_REGISTRY_V1, 0x0101),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub enum KdfAlgorithm {
    #[default]
    HkdfSha256,
}

impl KdfAlgorithm {
    pub const fn as_id(self) -> VersionedAlgorithmId {
        match self {
            Self::HkdfSha256 => VersionedAlgorithmId::new(ALGORITHM_REGISTRY_V1, 0x0201),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub enum AeadAlgorithm {
    #[default]
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    pub const fn as_id(self) -> VersionedAlgorithmId {
        match self {
            Self::ChaCha20Poly1305 => VersionedAlgorithmId::new(ALGORITHM_REGISTRY_V1, 0x0301),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub enum SignatureAlgorithm {
    #[default]
    External,
}

impl SignatureAlgorithm {
    pub const fn as_id(self) -> VersionedAlgorithmId {
        match self {
            Self::External => VersionedAlgorithmId::new(ALGORITHM_REGISTRY_V1, 0x0401),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
pub struct AlgorithmSuite {
    pub kem: KemAlgorithm,
    pub dh: DhAlgorithm,
    pub kdf: KdfAlgorithm,
    pub aead: AeadAlgorithm,
    pub signature: SignatureAlgorithm,
}

impl AlgorithmSuite {
    pub fn suite_id(self) -> Result<u16, CoreError> {
        match (self.kem, self.dh, self.kdf, self.aead, self.signature) {
            (
                KemAlgorithm::MlKem768,
                DhAlgorithm::X25519,
                KdfAlgorithm::HkdfSha256,
                AeadAlgorithm::ChaCha20Poly1305,
                SignatureAlgorithm::External,
            ) => Ok(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305),
            (
                KemAlgorithm::Kyber768Alias,
                DhAlgorithm::X25519,
                KdfAlgorithm::HkdfSha256,
                AeadAlgorithm::ChaCha20Poly1305,
                SignatureAlgorithm::External,
            ) => Ok(SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305),
        }
    }

    pub fn from_suite_id(suite_id: u16) -> Result<Self, CoreError> {
        match suite_id {
            SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok(Self {
                kem: KemAlgorithm::MlKem768,
                dh: DhAlgorithm::X25519,
                kdf: KdfAlgorithm::HkdfSha256,
                aead: AeadAlgorithm::ChaCha20Poly1305,
                signature: SignatureAlgorithm::External,
            }),
            SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok(Self {
                kem: KemAlgorithm::Kyber768Alias,
                dh: DhAlgorithm::X25519,
                kdf: KdfAlgorithm::HkdfSha256,
                aead: AeadAlgorithm::ChaCha20Poly1305,
                signature: SignatureAlgorithm::External,
            }),
            _ => Err(CoreError::UnsupportedAlgorithm("suite.id")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct RuntimeCryptoProfile {
    pub protocol_version: u16,
    pub suite_id: u16,
    pub kem: KemAlgorithm,
    pub dh: DhAlgorithm,
    pub kdf: KdfAlgorithm,
    pub aead: AeadAlgorithm,
    pub signature: SignatureAlgorithm,
    pub pq_oqs_enabled: bool,
}

pub fn runtime_crypto_profile() -> Result<RuntimeCryptoProfile, CoreError> {
    let suite = AlgorithmSuite::default();
    Ok(RuntimeCryptoProfile {
        protocol_version: PROTOCOL_VERSION_V1,
        suite_id: suite.suite_id()?,
        kem: suite.kem,
        dh: suite.dh,
        kdf: suite.kdf,
        aead: suite.aead,
        signature: suite.signature,
        pq_oqs_enabled: cfg!(feature = "pq-oqs"),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CryptoAgilityRegistry {
    pub protocol_version: u16,
    pub registry_version: u16,
}

impl Default for CryptoAgilityRegistry {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION_V1,
            registry_version: ALGORITHM_REGISTRY_V1,
        }
    }
}

impl CryptoAgilityRegistry {
    pub fn supports_suite(&self, suite: AlgorithmSuite) -> bool {
        self.protocol_version == PROTOCOL_VERSION_V1
            && suite.kem.as_id().registry_version == self.registry_version
            && suite.dh == DhAlgorithm::X25519
            && suite.kdf == KdfAlgorithm::HkdfSha256
            && suite.aead == AeadAlgorithm::ChaCha20Poly1305
    }
}
