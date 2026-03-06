use crate::CoreError;
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION_V1: u16 = 1;
pub const ALGORITHM_REGISTRY_V1: u16 = 1;
pub const SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305: u16 = 1;
pub const SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SecurityProfile {
    Research,
    #[default]
    HighAssurance,
    NssAligned,
}

impl SecurityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Research => "research",
            Self::HighAssurance => "high_assurance",
            Self::NssAligned => "nss_aligned",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "research" => Ok(Self::Research),
            "high_assurance" | "high-assurance" => Ok(Self::HighAssurance),
            "nss_aligned" | "nss-aligned" => Ok(Self::NssAligned),
            _ => Err(CoreError::InvalidSecurityProfile("profile")),
        }
    }

    pub const fn requires_tls(self) -> bool {
        !matches!(self, Self::Research)
    }

    pub const fn requires_pq_backend(self) -> bool {
        if cfg!(feature = "classical-only-INSECURE") {
            false
        } else {
            !matches!(self, Self::Research)
        }
    }

    pub fn allows_suite_id(self, suite_id: u16) -> bool {
        match self {
            Self::Research => AlgorithmSuite::from_suite_id(suite_id).is_ok(),
            Self::HighAssurance => matches!(
                suite_id,
                SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305
                    | SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305
            ),
            Self::NssAligned => suite_id == SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
        }
    }

    pub fn enforce_suite_id(self, suite_id: u16) -> Result<(), CoreError> {
        if self.allows_suite_id(suite_id) {
            Ok(())
        } else {
            Err(CoreError::PolicyViolation("security_profile.suite_id"))
        }
    }

    pub fn enforce_runtime_profile(self, runtime: &RuntimeCryptoProfile) -> Result<(), CoreError> {
        if self.requires_pq_backend() && !runtime.pq_oqs_enabled {
            return Err(CoreError::PolicyViolation("security_profile.pq_backend"));
        }
        self.enforce_suite_id(runtime.suite_id)
    }
}

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

pub fn enforce_runtime_security_profile(
    security_profile: SecurityProfile,
    suite_id: Option<u16>,
) -> Result<RuntimeCryptoProfile, CoreError> {
    let runtime = runtime_crypto_profile()?;
    security_profile.enforce_runtime_profile(&runtime)?;
    if let Some(suite_id) = suite_id {
        security_profile.enforce_suite_id(suite_id)?;
    }
    Ok(runtime)
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

#[cfg(test)]
mod tests {
    use super::{
        enforce_runtime_security_profile, runtime_crypto_profile, SecurityProfile,
        SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
        SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    };

    #[test]
    fn parse_security_profile_variants() {
        assert_eq!(
            SecurityProfile::parse("research").expect("parse research"),
            SecurityProfile::Research
        );
        assert_eq!(
            SecurityProfile::parse("high-assurance").expect("parse high assurance"),
            SecurityProfile::HighAssurance
        );
        assert_eq!(
            SecurityProfile::parse("nss_aligned").expect("parse nss aligned"),
            SecurityProfile::NssAligned
        );
        assert!(SecurityProfile::parse("unknown").is_err());
    }

    #[test]
    fn nss_profile_rejects_kyber_alias_suite() {
        let result = SecurityProfile::NssAligned
            .enforce_suite_id(SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305);
        assert!(result.is_err());
    }

    #[test]
    fn high_assurance_accepts_supported_suites() {
        SecurityProfile::HighAssurance
            .enforce_suite_id(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305)
            .expect("mlkem suite allowed");
        SecurityProfile::HighAssurance
            .enforce_suite_id(SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305)
            .expect("kyber alias suite allowed");
    }

    #[test]
    fn runtime_enforcement_matches_runtime_profile() {
        let runtime = runtime_crypto_profile().expect("runtime profile");
        if runtime.pq_oqs_enabled {
            let checked = enforce_runtime_security_profile(SecurityProfile::HighAssurance, None)
                .expect("runtime enforcement");
            assert_eq!(checked.suite_id, runtime.suite_id);
        } else {
            assert!(
                enforce_runtime_security_profile(SecurityProfile::HighAssurance, None).is_err()
            );
        }
    }
}
