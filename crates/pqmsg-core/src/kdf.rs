use crate::CoreError;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Derive key material using HKDF-SHA256.
///
/// Returns `Zeroizing<Vec<u8>>` to ensure derived key material is automatically
/// zeroized on drop, preventing secrets from lingering in memory.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = Zeroizing::new(vec![0u8; output_len]);
    hkdf.expand(info, &mut output)
        .map_err(|_| CoreError::KdfOperation)?;
    Ok(output)
}

pub fn hkdf_sha256_32(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<[u8; 32], CoreError> {
    let mut output = [0u8; 32];
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    hkdf.expand(info, &mut output)
        .map_err(|_| CoreError::KdfOperation)?;
    Ok(output)
}
