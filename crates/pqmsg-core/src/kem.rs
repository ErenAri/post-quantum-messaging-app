#[cfg(not(any(
    feature = "pq-oqs",
    feature = "pq-rust",
    feature = "classical-only-INSECURE"
)))]
compile_error!(
    "pqmsg-core requires an explicit PQ backend choice: enable `pq-oqs` \
     (liboqs-backed) or `pq-rust` (pure Rust browser-safe PQ backend), \
     or the explicit `classical-only-INSECURE` opt-in. \
     Do not build without post-quantum support unless you know what you are doing."
);

#[cfg(all(feature = "fips", feature = "classical-only-INSECURE"))]
compile_error!(
    "The `fips` and `classical-only-INSECURE` features are mutually exclusive. \
     FIPS mode requires post-quantum cryptography."
);

use crate::alg::KemAlgorithm;
use crate::keys::SecretBytes;
use crate::CoreError;
use zeroize::Zeroizing;

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
use rand_core::OsRng;

pub struct KemKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: SecretBytes,
}

pub struct KemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Zeroizing<Vec<u8>>,
}

pub trait KemProvider {
    fn keypair(&self) -> Result<KemKeyPair, CoreError>;
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
        #[cfg(feature = "fips")]
        if algorithm == KemAlgorithm::Kyber768Alias {
            return Err(CoreError::PolicyViolation(
                "fips: Kyber768Alias not permitted; use MlKem768",
            ));
        }
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

    pub fn validate_public_key(&self, public_key: &[u8]) -> Result<(), CoreError> {
        if self.kem.public_key_from_bytes(public_key).is_none() {
            return Err(CoreError::InvalidLength {
                field: "kem.public_key",
                expected: self.public_key_len(),
                actual: public_key.len(),
            });
        }
        Ok(())
    }
}

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
pub struct MlKem768 {
    algorithm: KemAlgorithm,
}

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
impl MlKem768 {
    pub fn new(algorithm: KemAlgorithm) -> Result<Self, CoreError> {
        #[cfg(feature = "fips")]
        if algorithm == KemAlgorithm::Kyber768Alias {
            return Err(CoreError::PolicyViolation(
                "fips: Kyber768Alias not permitted; use MlKem768",
            ));
        }
        Ok(Self { algorithm })
    }

    pub fn new_preferred() -> Result<Self, CoreError> {
        Self::new(KemAlgorithm::MlKem768)
    }

    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }

    pub fn public_key_len(&self) -> usize {
        fips203::ml_kem_768::EK_LEN
    }

    pub fn secret_key_len(&self) -> usize {
        fips203::ml_kem_768::DK_LEN
    }

    pub fn ciphertext_len(&self) -> usize {
        fips203::ml_kem_768::CT_LEN
    }

    pub fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        let (public_key, secret_key) = fips203::ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
            .map_err(|_| CoreError::KemOperation)?;
        Ok(KemKeyPair {
            public_key: public_key.into_bytes().to_vec(),
            secret_key: SecretBytes::from(secret_key.into_bytes().to_vec()),
        })
    }

    pub fn validate_public_key(&self, public_key: &[u8]) -> Result<(), CoreError> {
        let public_key =
            to_fixed_array::<{ fips203::ml_kem_768::EK_LEN }>("kem.public_key", public_key)?;
        fips203::ml_kem_768::EncapsKey::try_from_bytes(public_key)
            .map(|_| ())
            .map_err(|_| CoreError::KemOperation)
    }
}

#[cfg(feature = "fips")]
pub struct FipsKemWrapper {
    inner: MlKem768,
}

#[cfg(feature = "fips")]
impl FipsKemWrapper {
    pub fn new() -> Result<Self, CoreError> {
        let inner = MlKem768::new(KemAlgorithm::MlKem768)?;
        Ok(Self { inner })
    }

    pub fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        let kp = self.inner.keypair()?;
        self.inner.validate_public_key(&kp.public_key)?;
        Ok(kp)
    }
}

#[cfg(feature = "fips")]
impl KemProvider for FipsKemWrapper {
    fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        FipsKemWrapper::keypair(self)
    }

    fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError> {
        self.inner.validate_public_key(recipient_public_key)?;
        self.inner.encapsulate(recipient_public_key)
    }

    fn decapsulate(
        &self,
        recipient_secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        self.inner.decapsulate(recipient_secret_key, ciphertext)
    }
}

#[cfg(feature = "pq-oqs")]
impl KemProvider for MlKem768 {
    fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        MlKem768::keypair(self)
    }

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

#[cfg(all(feature = "pq-rust", not(feature = "pq-oqs")))]
impl KemProvider for MlKem768 {
    fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        MlKem768::keypair(self)
    }

    fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError> {
        let public_key = to_fixed_array::<{ fips203::ml_kem_768::EK_LEN }>(
            "kem.public_key",
            recipient_public_key,
        )?;
        let public_key = fips203::ml_kem_768::EncapsKey::try_from_bytes(public_key)
            .map_err(|_| CoreError::KemOperation)?;
        let (shared_secret, ciphertext) = public_key
            .try_encaps_with_rng(&mut OsRng)
            .map_err(|_| CoreError::KemOperation)?;
        Ok(KemEncapsulation {
            ciphertext: ciphertext.into_bytes().to_vec(),
            shared_secret: Zeroizing::new(shared_secret.into_bytes().to_vec()),
        })
    }

    fn decapsulate(
        &self,
        recipient_secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        let recipient_secret_key = to_fixed_array::<{ fips203::ml_kem_768::DK_LEN }>(
            "kem.secret_key",
            recipient_secret_key,
        )?;
        let ciphertext =
            to_fixed_array::<{ fips203::ml_kem_768::CT_LEN }>("kem.ciphertext", ciphertext)?;
        let secret_key = fips203::ml_kem_768::DecapsKey::try_from_bytes(recipient_secret_key)
            .map_err(|_| CoreError::KemOperation)?;
        let ciphertext = fips203::ml_kem_768::CipherText::try_from_bytes(ciphertext)
            .map_err(|_| CoreError::KemOperation)?;
        let shared_secret = secret_key
            .try_decaps(&ciphertext)
            .map_err(|_| CoreError::KemOperation)?;
        Ok(Zeroizing::new(shared_secret.into_bytes().to_vec()))
    }
}

#[cfg(all(not(feature = "pq-oqs"), not(feature = "pq-rust")))]
pub struct MlKem768;

#[cfg(all(not(feature = "pq-oqs"), not(feature = "pq-rust")))]
impl MlKem768 {
    pub fn new(_algorithm: KemAlgorithm) -> Result<Self, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }

    pub fn new_preferred() -> Result<Self, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }

    pub fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }
}

#[cfg(all(not(feature = "pq-oqs"), not(feature = "pq-rust")))]
impl KemProvider for MlKem768 {
    fn keypair(&self) -> Result<KemKeyPair, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }

    fn encapsulate(&self, _recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError> {
        Err(CoreError::UnsupportedAlgorithm(
            "PQ backend feature disabled",
        ))
    }

    fn decapsulate(
        &self,
        _recipient_secret_key: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::KemAlgorithm;

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn mlkem768_keypair_has_expected_lengths() {
        let kem = MlKem768::new(KemAlgorithm::MlKem768).expect("kem init");
        assert_eq!(kem.public_key_len(), 1184);
        assert_eq!(kem.secret_key_len(), 2400);
        assert_eq!(kem.ciphertext_len(), 1088);
        let kp = kem.keypair().expect("keypair");
        assert_eq!(kp.public_key.len(), 1184);
        assert_eq!(kp.secret_key.as_slice().len(), 2400);
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn mlkem768_rejects_short_public_key() {
        let kem = MlKem768::new(KemAlgorithm::MlKem768).expect("kem init");
        let short_key = vec![0u8; 32];
        let result = kem.encapsulate(&short_key);
        assert!(matches!(result, Err(CoreError::InvalidLength { .. })));
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn mlkem768_validate_public_key_rejects_wrong_length() {
        let kem = MlKem768::new(KemAlgorithm::MlKem768).expect("kem init");
        assert!(kem.validate_public_key(&[0u8; 32]).is_err());
        assert!(kem.validate_public_key(&[]).is_err());
        assert!(kem.validate_public_key(&[0u8; 1183]).is_err());
        assert!(kem.validate_public_key(&[0u8; 1185]).is_err());
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn mlkem768_validate_public_key_accepts_valid_key() {
        let kem = MlKem768::new(KemAlgorithm::MlKem768).expect("kem init");
        let kp = kem.keypair().expect("keypair");
        assert!(kem.validate_public_key(&kp.public_key).is_ok());
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn mlkem768_encapsulate_decapsulate_roundtrip() {
        let kem = MlKem768::new(KemAlgorithm::MlKem768).expect("kem init");
        let kp = kem.keypair().expect("keypair");
        let encap = kem.encapsulate(&kp.public_key).expect("encapsulate");
        assert_eq!(encap.ciphertext.len(), 1088);
        let ss = kem
            .decapsulate(kp.secret_key.as_slice(), &encap.ciphertext)
            .expect("decapsulate");
        assert_eq!(*encap.shared_secret, *ss);
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn mlkem768_decapsulate_rejects_short_ciphertext() {
        let kem = MlKem768::new(KemAlgorithm::MlKem768).expect("kem init");
        let kp = kem.keypair().expect("keypair");
        let result = kem.decapsulate(kp.secret_key.as_slice(), &[0u8; 32]);
        assert!(matches!(result, Err(CoreError::InvalidLength { .. })));
    }

    #[test]
    #[cfg(feature = "fips")]
    fn fips_kem_wrapper_roundtrip() {
        let fips_kem = FipsKemWrapper::new().expect("fips kem init");
        let kp = fips_kem.keypair().expect("keypair");
        let encap = fips_kem.encapsulate(&kp.public_key).expect("encapsulate");
        let ss = fips_kem
            .decapsulate(kp.secret_key.as_slice(), &encap.ciphertext)
            .expect("decapsulate");
        assert_eq!(*encap.shared_secret, *ss);
    }

    #[test]
    #[cfg(feature = "fips")]
    fn fips_rejects_kyber768_alias() {
        let result = MlKem768::new(KemAlgorithm::Kyber768Alias);
        assert!(matches!(result, Err(CoreError::PolicyViolation(_))));
    }

    #[test]
    #[cfg(feature = "fips")]
    fn fips_kem_wrapper_rejects_invalid_public_key() {
        let fips_kem = FipsKemWrapper::new().expect("fips kem init");
        let result = fips_kem.encapsulate(&[0u8; 32]);
        assert!(result.is_err());
    }
}
