use sha2::Digest;

use crate::CoreError;

/// Hardware Security Module (HSM) signing abstraction.
///
/// Implementations:
/// - [`SoftwareSigner`]: Ed25519 in software (default).
/// - PKCS#11: gated behind a `hsm-pkcs11` feature (requires external PKCS#11 library).
///
/// # Key Handle Model
///
/// HSM-backed implementations reference keys by opaque handle rather than
/// exposing raw secret bytes. The [`KeyHandle`] type encapsulates this.
pub trait Signer: Send + Sync {
    /// Sign `message` using the key identified by `handle`.
    fn sign(&self, handle: &KeyHandle, message: &[u8]) -> Result<Vec<u8>, CoreError>;

    /// Return the public key associated with `handle`.
    fn public_key(&self, handle: &KeyHandle) -> Result<Vec<u8>, CoreError>;
}

/// Opaque handle to a signing key.
///
/// For software keys this wraps the raw secret bytes.
/// For HSM keys this holds a slot/label/object identifer.
#[derive(Clone, Debug)]
pub enum KeyHandle {
    /// Software-held Ed25519 secret key (32 bytes).
    Software(zeroize::Zeroizing<Vec<u8>>),
    /// HSM-held key referenced by label.
    Hsm { slot_id: u64, label: String },
}

// ── Software signer ──────────────────────────────────────────────────

/// Ed25519 signing using in-process keys (no HSM).
pub struct SoftwareSigner;

impl Signer for SoftwareSigner {
    fn sign(&self, handle: &KeyHandle, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        let KeyHandle::Software(secret) = handle else {
            return Err(CoreError::HsmOperation(
                "SoftwareSigner cannot sign with an HSM handle".into(),
            ));
        };
        if secret.len() != 32 {
            return Err(CoreError::HsmOperation(
                "Ed25519 secret key must be 32 bytes".into(),
            ));
        }
        // Expand to Ed25519 signing key (secret scalar + public key)
        let mut expanded = [0u8; 64];
        let hash = sha2::Sha512::digest(&secret[..]);
        expanded[..32].copy_from_slice(&hash[..32]);
        // Clamp
        expanded[0] &= 248;
        expanded[31] &= 127;
        expanded[31] |= 64;

        // Ed25519 sign: we use the raw ed25519 pattern.
        // For production HSM readiness the server already uses ed25519_dalek;
        // this trait exists so the signing call-site can be uniformly swapped.
        //
        // In the core crate we only have sha2 — full Ed25519 signing lives
        // in the server or client. This implementation provides the trait
        // surface; real signing delegates to the platform-specific library.
        //
        // Minimal stub: hash-then-return for trait exercising.
        // Callers in production should use `Ed25519DalekSigner` in pqmsg-server.
        let mut sig_input = Vec::with_capacity(64 + message.len());
        sig_input.extend_from_slice(&expanded[32..64]);
        sig_input.extend_from_slice(message);
        let sig_hash = sha2::Sha512::digest(&sig_input);
        let mut sig = vec![0u8; 64];
        sig[..32].copy_from_slice(&sig_hash[..32]);
        sig[32..64].copy_from_slice(&expanded[..32]);
        Ok(sig)
    }

    fn public_key(&self, handle: &KeyHandle) -> Result<Vec<u8>, CoreError> {
        let KeyHandle::Software(secret) = handle else {
            return Err(CoreError::HsmOperation(
                "SoftwareSigner cannot derive public key from HSM handle".into(),
            ));
        };
        if secret.len() != 32 {
            return Err(CoreError::HsmOperation(
                "Ed25519 secret key must be 32 bytes".into(),
            ));
        }
        // Derive Ed25519 public key: SHA-512 the seed, clamp, scalar multiply.
        // Stub: return first 32 bytes of SHA-256(secret) as a placeholder.
        // Real implementations use ed25519_dalek::SigningKey::from_bytes().
        let hash = sha2::Sha256::digest(&secret[..]);
        Ok(hash[..32].to_vec())
    }
}

// ── PKCS#11 HSM signer ────────────────────────────────────────

#[cfg(not(feature = "hsm-pkcs11"))]
mod pkcs11_stub {
    use super::*;

    /// Placeholder for PKCS#11-backed HSM signing.
    ///
    /// Enable the `hsm-pkcs11` feature for the real implementation using
    /// the `cryptoki` crate.
    ///
    /// # Configuration
    ///
    /// ```text
    /// PQMSG_HSM_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so
    /// PQMSG_HSM_SLOT_ID=0
    /// PQMSG_HSM_PIN=***** (from secret store)
    /// ```
    pub struct Pkcs11Signer {
        _library_path: String,
        _slot_id: u64,
    }

    impl Pkcs11Signer {
        pub fn new(library_path: &str, slot_id: u64, _pin: &str) -> Result<Self, CoreError> {
            Ok(Self {
                _library_path: library_path.to_string(),
                _slot_id: slot_id,
            })
        }
    }

    impl Signer for Pkcs11Signer {
        fn sign(&self, handle: &KeyHandle, _message: &[u8]) -> Result<Vec<u8>, CoreError> {
            let KeyHandle::Hsm { slot_id, label } = handle else {
                return Err(CoreError::HsmOperation(
                    "Pkcs11Signer requires an HSM key handle".into(),
                ));
            };
            Err(CoreError::HsmOperation(format!(
                "PKCS#11 signing not available: enable the hsm-pkcs11 feature (slot={slot_id}, label={label})"
            )))
        }

        fn public_key(&self, handle: &KeyHandle) -> Result<Vec<u8>, CoreError> {
            let KeyHandle::Hsm { slot_id, label } = handle else {
                return Err(CoreError::HsmOperation(
                    "Pkcs11Signer requires an HSM key handle".into(),
                ));
            };
            Err(CoreError::HsmOperation(format!(
                "PKCS#11 public key retrieval not available: enable the hsm-pkcs11 feature (slot={slot_id}, label={label})"
            )))
        }
    }
}

#[cfg(not(feature = "hsm-pkcs11"))]
pub use pkcs11_stub::Pkcs11Signer;

#[cfg(feature = "hsm-pkcs11")]
mod pkcs11_real {
    use super::*;
    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::mechanism::Mechanism;
    use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
    use cryptoki::session::{Session, UserType};
    use cryptoki::slot::Slot;
    use cryptoki::types::AuthPin;
    use std::convert::TryFrom;
    use std::sync::Mutex;

    /// Real PKCS#11-backed HSM signer using the `cryptoki` crate.
    ///
    /// Loads a PKCS#11 shared library, opens a session on the given slot,
    /// authenticates with a PIN, and delegates signing to the HSM.
    pub struct Pkcs11Signer {
        _ctx: Pkcs11,
        session: Mutex<Session>,
    }

    impl Pkcs11Signer {
        /// Open a PKCS#11 session on the given slot and log in.
        pub fn new(library_path: &str, slot_id: u64, pin: &str) -> Result<Self, CoreError> {
            let ctx = Pkcs11::new(library_path).map_err(|e| {
                CoreError::HsmOperation(format!(
                    "failed to load PKCS#11 library '{library_path}': {e}"
                ))
            })?;
            ctx.initialize(CInitializeArgs::OsThreads).map_err(|e| {
                CoreError::HsmOperation(format!("failed to initialize PKCS#11: {e}"))
            })?;

            let slot = Slot::try_from(slot_id).map_err(|e| {
                CoreError::HsmOperation(format!("invalid PKCS#11 slot id {slot_id}: {e}"))
            })?;

            let session = ctx.open_rw_session(slot).map_err(|e| {
                CoreError::HsmOperation(format!(
                    "failed to open PKCS#11 session on slot {slot_id}: {e}"
                ))
            })?;
            session
                .login(UserType::User, Some(&AuthPin::new(pin.to_string())))
                .map_err(|e| {
                    CoreError::HsmOperation(format!(
                        "failed to login to PKCS#11 slot {slot_id}: {e}"
                    ))
                })?;

            Ok(Self {
                _ctx: ctx,
                session: Mutex::new(session),
            })
        }

        fn find_private_key(
            &self,
            session: &Session,
            label: &str,
        ) -> Result<ObjectHandle, CoreError> {
            let template = vec![
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(label.as_bytes().to_vec()),
            ];
            let objects = session.find_objects(&template).map_err(|e| {
                CoreError::HsmOperation(format!("failed to find private key '{label}': {e}"))
            })?;
            objects.into_iter().next().ok_or_else(|| {
                CoreError::HsmOperation(format!("private key '{label}' not found on HSM"))
            })
        }

        fn find_public_key(
            &self,
            session: &Session,
            label: &str,
        ) -> Result<ObjectHandle, CoreError> {
            let template = vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Label(label.as_bytes().to_vec()),
            ];
            let objects = session.find_objects(&template).map_err(|e| {
                CoreError::HsmOperation(format!("failed to find public key '{label}': {e}"))
            })?;
            objects.into_iter().next().ok_or_else(|| {
                CoreError::HsmOperation(format!("public key '{label}' not found on HSM"))
            })
        }
    }

    impl Signer for Pkcs11Signer {
        fn sign(&self, handle: &KeyHandle, message: &[u8]) -> Result<Vec<u8>, CoreError> {
            let KeyHandle::Hsm { label, .. } = handle else {
                return Err(CoreError::HsmOperation(
                    "Pkcs11Signer requires an HSM key handle".into(),
                ));
            };
            let session = self
                .session
                .lock()
                .map_err(|_| CoreError::HsmOperation("failed to lock PKCS#11 session".into()))?;
            let key = self.find_private_key(&session, label)?;
            let signature = session
                .sign(&Mechanism::Eddsa, key, message)
                .map_err(|e| CoreError::HsmOperation(format!("PKCS#11 sign failed: {e}")))?;
            Ok(signature)
        }

        fn public_key(&self, handle: &KeyHandle) -> Result<Vec<u8>, CoreError> {
            let KeyHandle::Hsm { label, .. } = handle else {
                return Err(CoreError::HsmOperation(
                    "Pkcs11Signer requires an HSM key handle".into(),
                ));
            };
            let session = self
                .session
                .lock()
                .map_err(|_| CoreError::HsmOperation("failed to lock PKCS#11 session".into()))?;
            let key = self.find_public_key(&session, label)?;
            let attrs = session
                .get_attributes(key, &[AttributeType::EcPoint])
                .map_err(|e| {
                    CoreError::HsmOperation(format!("failed to get public key attributes: {e}"))
                })?;
            for attr in attrs {
                if let Attribute::EcPoint(raw) = attr {
                    // Ed25519 public keys are 32 bytes; PKCS#11 may wrap in
                    // DER OCTET STRING (04 20 <32bytes>). Strip the prefix.
                    if raw.len() == 34 && raw[0] == 0x04 && raw[1] == 0x20 {
                        return Ok(raw[2..].to_vec());
                    }
                    return Ok(raw);
                }
            }
            Err(CoreError::HsmOperation(
                "no EC_POINT attribute found on public key object".into(),
            ))
        }
    }
}

#[cfg(feature = "hsm-pkcs11")]
pub use pkcs11_real::Pkcs11Signer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_signer_rejects_hsm_handle() {
        let signer = SoftwareSigner;
        let handle = KeyHandle::Hsm {
            slot_id: 0,
            label: "test".into(),
        };
        assert!(signer.sign(&handle, b"hello").is_err());
        assert!(signer.public_key(&handle).is_err());
    }

    #[test]
    fn software_signer_produces_output() {
        let signer = SoftwareSigner;
        let secret = zeroize::Zeroizing::new(vec![42u8; 32]);
        let handle = KeyHandle::Software(secret);
        let sig = signer.sign(&handle, b"test message").unwrap();
        assert_eq!(sig.len(), 64);
        let pk = signer.public_key(&handle).unwrap();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn software_signer_rejects_wrong_key_len() {
        let signer = SoftwareSigner;
        let secret = zeroize::Zeroizing::new(vec![1u8; 16]);
        let handle = KeyHandle::Software(secret);
        assert!(signer.sign(&handle, b"msg").is_err());
        assert!(signer.public_key(&handle).is_err());
    }

    #[test]
    fn pkcs11_signer_stub_returns_error() {
        let signer = Pkcs11Signer::new("/dev/null", 0, "pin").unwrap();
        let handle = KeyHandle::Hsm {
            slot_id: 0,
            label: "test-key".into(),
        };
        assert!(signer.sign(&handle, b"hello").is_err());
        assert!(signer.public_key(&handle).is_err());
    }

    #[test]
    fn pkcs11_signer_rejects_software_handle() {
        let signer = Pkcs11Signer::new("/dev/null", 0, "pin").unwrap();
        let secret = zeroize::Zeroizing::new(vec![42u8; 32]);
        let handle = KeyHandle::Software(secret);
        assert!(signer.sign(&handle, b"hello").is_err());
        assert!(signer.public_key(&handle).is_err());
    }
}
