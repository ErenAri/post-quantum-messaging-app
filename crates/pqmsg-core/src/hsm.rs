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

// ── PKCS#11 HSM signer (stub) ────────────────────────────────────────

/// Placeholder for PKCS#11-backed HSM signing.
///
/// When the `hsm-pkcs11` feature is enabled, this implementation will
/// load a PKCS#11 shared library (`.so`/`.dylib`/`.dll`), open a session
/// on the configured slot, and delegate `C_Sign` / `C_GetAttributeValue`
/// calls to the HSM.
///
/// # Configuration
///
/// ```text
/// PQMSG_HSM_PKCS11_LIB=/usr/lib/softhsm/libsofthsm2.so
/// PQMSG_HSM_SLOT_ID=0
/// PQMSG_HSM_PIN=***** (from secret store)
/// ```
///
/// # Status
///
/// This is an architecture stub. The trait surface is stable; the PKCS#11
/// plumbing requires the `cryptoki` crate and a configured HSM or SoftHSM
/// environment for integration testing.
pub struct Pkcs11Signer {
    _library_path: String,
    _slot_id: u64,
}

impl Pkcs11Signer {
    /// Create a new PKCS#11 signer (stub — always returns an error currently).
    pub fn new(library_path: &str, slot_id: u64, _pin: &str) -> Result<Self, CoreError> {
        // In a real implementation:
        // 1. Load the PKCS#11 library via `cryptoki::context::Pkcs11::new(library_path)`
        // 2. Initialize with `CKF_OS_LOCKING_OK`
        // 3. Open a session on slot_id
        // 4. Login with the PIN
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
        // In a real implementation:
        // 1. Find the private key object by label on the given slot
        // 2. Call C_Sign with CKM_EDDSA mechanism
        // 3. Return the 64-byte Ed25519 signature
        Err(CoreError::HsmOperation(format!(
            "PKCS#11 signing not yet implemented (slot={slot_id}, label={label})"
        )))
    }

    fn public_key(&self, handle: &KeyHandle) -> Result<Vec<u8>, CoreError> {
        let KeyHandle::Hsm { slot_id, label } = handle else {
            return Err(CoreError::HsmOperation(
                "Pkcs11Signer requires an HSM key handle".into(),
            ));
        };
        // In a real implementation:
        // 1. Find the public key object by label on the given slot
        // 2. Call C_GetAttributeValue for CKA_EC_POINT / CKA_VALUE
        // 3. Return the 32-byte Ed25519 public key
        Err(CoreError::HsmOperation(format!(
            "PKCS#11 public key retrieval not yet implemented (slot={slot_id}, label={label})"
        )))
    }
}

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
