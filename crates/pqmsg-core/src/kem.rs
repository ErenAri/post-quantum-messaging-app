use crate::alg::KemAlgorithm;
use crate::keys::SecretBytes;
use crate::CoreError;
use zeroize::Zeroizing;

pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: SecretBytes,
}

pub struct KemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Zeroizing<Vec<u8>>,
}

pub trait KemProvider {
    fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError>;
    fn decapsulate(
        &self,
        recipient_secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError>;
}

#[cfg(feature = "pq-oqs")]
pub struct MlKem768 {
    kem: oqs::kem::Kem,
    algorithm: KemAlgorithm,
}

#[cfg(feature = "pq-oqs")]
impl MlKem768 {
    pub fn new(algorithm: KemAlgorithm) -> Result<Self, CoreError> {
        oqs::init();
        let oqs_alg = match algorithm {
            KemAlgorithm::MlKem768 => oqs::kem::Algorithm::MlKem768,
            KemAlgorithm::Kyber768Alias => oqs::kem::Algorithm::Kyber768,
        };
        let kem = oqs::kem::Kem::new(oqs_alg).map_err(|_| CoreError::KemOperation)?;
        Ok(Self { kem, algorithm })
    }

    pub fn new_preferred() -> Result<Self, CoreError> {
        Self::new(KemAlgorithm::MlKem768).or_else(|_| Self::new(KemAlgorithm::Kyber768Alias))
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    pub fn public_key_len(&self) -> usize {
        self.kem.length_public_key()
    }

    pub fn secret_key_len(&self) -> usize {
        self.kem.length_secret_key()
    }

    pub fn ciphertext_len(&self) -> usize {
        self.kem.length_ciphertext()
    }

    pub fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        let (public_key, secret_key) = self.kem.keypair().map_err(|_| CoreError::KemOperation)?;
        Ok(KemKeyPair {
            public_key: public_key.into_vec(),
            secret_key: SecretBytes::from(secret_key.into_vec()),
        })
    }
}

#[cfg(feature = "pq-oqs")]
impl KemProvider for MlKem768 {
    fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError> {
        let Some(public_key_ref) = self.kem.public_key_from_bytes(recipient_public_key) else {
            return Err(CoreError::InvalidLength {
                field: "kem.public_key",
                expected: self.public_key_len(),
                actual: recipient_public_key.len(),
            });
        };
        let (ciphertext, shared_secret) = self
            .kem
            .encapsulate(public_key_ref)
            .map_err(|_| CoreError::KemOperation)?;
        Ok(KemEncapsulation {
            ciphertext: ciphertext.into_vec(),
            shared_secret: Zeroizing::new(shared_secret.into_vec()),
        })
    }

    fn decapsulate(
        &self,
        recipient_secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let Some(secret_key_ref) = self.kem.secret_key_from_bytes(recipient_secret_key) else {
            return Err(CoreError::InvalidLength {
                field: "kem.secret_key",
                expected: self.secret_key_len(),
                actual: recipient_secret_key.len(),
            });
        };
        let Some(ciphertext_ref) = self.kem.ciphertext_from_bytes(ciphertext) else {
            return Err(CoreError::InvalidLength {
                field: "kem.ciphertext",
                expected: self.ciphertext_len(),
                actual: ciphertext.len(),
            });
        };
        let shared_secret = self
            .kem
            .decapsulate(secret_key_ref, ciphertext_ref)
            .map_err(|_| CoreError::KemOperation)?;
        Ok(Zeroizing::new(shared_secret.into_vec()))
    }
}

#[cfg(not(feature = "pq-oqs"))]
pub struct MlKem768;

#[cfg(not(feature = "pq-oqs"))]
impl MlKem768 {
    pub fn new(_algorithm: KemAlgorithm) -> Result<Self, CoreError> {
        Err(CoreError::UnsupportedAlgorithm("pq-oqs feature disabled"))
    }

    pub fn new_preferred() -> Result<Self, CoreError> {
        Err(CoreError::UnsupportedAlgorithm("pq-oqs feature disabled"))
    }

    pub fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        Err(CoreError::UnsupportedAlgorithm("pq-oqs feature disabled"))
    }
}

#[cfg(not(feature = "pq-oqs"))]
impl KemProvider for MlKem768 {
    fn encapsulate(&self, _recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError> {
        Err(CoreError::UnsupportedAlgorithm("pq-oqs feature disabled"))
    }

    fn decapsulate(
        &self,
        _recipient_secret_key: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        Err(CoreError::UnsupportedAlgorithm("pq-oqs feature disabled"))
    }
}
