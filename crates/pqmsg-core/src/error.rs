use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid length for {field}: expected {expected}, got {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid TLV: {0}")]
    InvalidTlv(&'static str),
    #[error("unknown critical TLV type: 0x{0:04x}")]
    UnknownCriticalTlv(u16),
    #[error("duplicate TLV type: 0x{0:04x}")]
    DuplicateTlv(u16),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid UTF-8 field: {0}")]
    InvalidUtf8(&'static str),
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("AEAD operation failed")]
    AeadOperation,
    #[error("KDF operation failed")]
    KdfOperation,
    #[error("DH operation failed")]
    DhOperation,
    #[error("KEM operation failed")]
    KemOperation,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(&'static str),
    #[error("message parsing failed: {0}")]
    MessageParsing(&'static str),
    #[error("message key unavailable")]
    MessageKeyUnavailable,
    #[error("pq ratchet is not enabled")]
    PqRatchetDisabled,
    #[error("security policy violation: {0}")]
    PolicyViolation(&'static str),
    #[error("invalid security profile: {0}")]
    InvalidSecurityProfile(&'static str),
}
