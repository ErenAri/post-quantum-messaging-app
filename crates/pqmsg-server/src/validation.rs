use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pqmsg_core::alg::PROTOCOL_VERSION_V1;
use pqmsg_core::dh::DhPublicKey;
use pqmsg_core::handshake::{pq_signed_prekey_signature_message, signed_prekey_signature_message};
use pqmsg_core::pq_sig::{MlDsa65, PqSignatureProvider};
use pqmsg_core::tlv::{encode, TlvRecord};
use sha2::{Digest, Sha256};

use crate::error::AppError;
use crate::types::RegisterPushTokenRequest;
use crate::{
    PushProvider, MAX_CONTACT_ALIAS_LEN, MAX_DEVICE_ID_LEN, MAX_DISCOVERY_HASHES, MAX_FILE_ID_LEN,
    MAX_GROUP_MEMBERS, MAX_MIME_TYPE_LEN, MAX_ONE_TIME_KEYS, MAX_PROFILE_DISPLAY_NAME_LEN,
    MAX_PUSH_TOKEN_LEN, MAX_ROTATION_CHALLENGE_ID_LEN, MAX_USERNAME_LEN, MAX_USER_ID_LEN,
    PQ_SIG_LEN, PQ_SIG_PUB_KEY_LEN, PREKEY_LOW_WATERMARK, ROTATE_SIG_TAG_CHALLENGE_ID,
    ROTATE_SIG_TAG_CHALLENGE_NONCE, ROTATE_SIG_TAG_NEW_DEVICE_ID,
    ROTATE_SIG_TAG_NEW_IDENTITY_PQ_SIG, ROTATE_SIG_TAG_NEW_IDENTITY_SIG,
    ROTATE_SIG_TAG_NEW_IDENTITY_X25519, ROTATE_SIG_TAG_USER_ID, SHA256_HEX_LEN, SIG_LEN,
    SIG_PUB_KEY_LEN, X25519_KEY_LEN,
};

pub(crate) fn is_prekey_inventory_low(remaining_x: i64, remaining_pq: i64) -> bool {
    remaining_x <= PREKEY_LOW_WATERMARK || remaining_pq <= PREKEY_LOW_WATERMARK
}

pub(crate) fn normalize_group_members(raw_members: &[String]) -> Result<Vec<String>, AppError> {
    let mut members = Vec::with_capacity(raw_members.len() + 1);
    for member in raw_members {
        validate_id("member_user_ids[]", member)?;
        members.push(member.trim().to_string());
    }
    members.sort_unstable();
    members.dedup();
    if members.len() > MAX_GROUP_MEMBERS {
        return Err(AppError::bad_request(format!(
            "member_user_ids cannot exceed {MAX_GROUP_MEMBERS}"
        )));
    }
    Ok(members)
}

pub(crate) fn normalize_message_ids(message_ids: &[i64]) -> Vec<i64> {
    let mut ids = message_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub(crate) fn hash_string_list_sha256(values: &[String]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_vec()
}

pub(crate) fn validate_id(field: &'static str, value: &str) -> Result<(), AppError> {
    let len = value.trim().len();
    if len == 0 || len > MAX_USER_ID_LEN || len > MAX_DEVICE_ID_LEN {
        return Err(AppError::bad_request(format!(
            "{field} must be 1..128 non-whitespace characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_rotation_challenge_id(value: &str) -> Result<(), AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ROTATION_CHALLENGE_ID_LEN {
        return Err(AppError::bad_request(format!(
            "challenge_id must be 1..{MAX_ROTATION_CHALLENGE_ID_LEN} characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_one_time_count(field: &'static str, count: usize) -> Result<(), AppError> {
    if count > MAX_ONE_TIME_KEYS {
        return Err(AppError::bad_request(format!(
            "{field} cannot contain more than {MAX_ONE_TIME_KEYS} items"
        )));
    }
    Ok(())
}

pub(crate) fn resolve_push_token_payload(
    request: &RegisterPushTokenRequest,
) -> Result<(PushProvider, String), AppError> {
    let provider = if let Some(raw) = request.provider.as_deref() {
        PushProvider::parse(raw)
            .ok_or_else(|| AppError::bad_request("provider must be one of: fcm, apns"))?
    } else {
        PushProvider::Fcm
    };
    let token = request
        .token
        .as_deref()
        .or(request.fcm_token.as_deref())
        .ok_or_else(|| AppError::bad_request("push token is required"))?;
    Ok((provider, token.to_string()))
}

pub(crate) fn validate_push_token(provider: PushProvider, value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_PUSH_TOKEN_LEN {
        return Err(AppError::bad_request(format!(
            "token must be 1..={MAX_PUSH_TOKEN_LEN} characters"
        )));
    }
    match provider {
        PushProvider::Fcm => Ok(trimmed.to_string()),
        PushProvider::Apns => {
            if !trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(AppError::bad_request(
                    "apns token must contain only hexadecimal characters",
                ));
            }
            if trimmed.len() < 64 || trimmed.len() > 512 {
                return Err(AppError::bad_request(
                    "apns token must be 64..=512 hexadecimal characters",
                ));
            }
            Ok(trimmed.to_string())
        }
    }
}

pub(crate) fn validate_file_id(value: &str) -> Result<(), AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_FILE_ID_LEN {
        return Err(AppError::bad_request(format!(
            "file_id must be 1..={MAX_FILE_ID_LEN} characters"
        )));
    }
    if !trimmed
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AppError::bad_request(
            "file_id must contain only [A-Za-z0-9_-]",
        ));
    }
    Ok(())
}

pub(crate) fn validate_mime_type(field: &'static str, value: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_MIME_TYPE_LEN {
        return Err(AppError::bad_request(format!(
            "{field} must be 1..={MAX_MIME_TYPE_LEN} characters"
        )));
    }
    if !trimmed.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || byte == b'/' || byte == b'-' || byte == b'+' || byte == b'.'
    }) {
        return Err(AppError::bad_request(format!(
            "{field} contains invalid characters"
        )));
    }
    if !trimmed.contains('/') {
        return Err(AppError::bad_request(format!(
            "{field} must include type/subtype"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

pub(crate) fn validate_optional_mime_type(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(validate_mime_type(field, trimmed)?))
}

pub(crate) fn validate_optional_profile_display_name(
    value: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_PROFILE_DISPLAY_NAME_LEN {
        return Err(AppError::bad_request(format!(
            "display_name must be <= {MAX_PROFILE_DISPLAY_NAME_LEN} characters"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

pub(crate) fn validate_optional_username(value: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(validate_username(trimmed)?))
}

pub(crate) fn validate_username(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    if normalized.len() < 3 || normalized.len() > MAX_USERNAME_LEN {
        return Err(AppError::bad_request(format!(
            "username must be 3..={MAX_USERNAME_LEN} characters"
        )));
    }
    let bytes = normalized.as_bytes();
    let is_valid_core = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let is_valid_punct = |byte: u8| byte == b'.' || byte == b'_';
    if !is_valid_core(bytes[0]) || !is_valid_core(*bytes.last().expect("username len checked")) {
        return Err(AppError::bad_request(
            "username must start and end with a letter or digit",
        ));
    }
    let mut previous_was_punct = false;
    for &byte in bytes {
        if is_valid_core(byte) {
            previous_was_punct = false;
            continue;
        }
        if !is_valid_punct(byte) {
            return Err(AppError::bad_request(
                "username must contain only lowercase letters, digits, '.' or '_'",
            ));
        }
        if previous_was_punct {
            return Err(AppError::bad_request(
                "username cannot contain consecutive punctuation",
            ));
        }
        previous_was_punct = true;
    }
    Ok(normalized)
}

pub(crate) fn validate_presence_status(value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    let valid = matches!(normalized.as_str(), "offline" | "online" | "away" | "busy");
    if !valid {
        return Err(AppError::bad_request(
            "status must be one of offline|online|away|busy",
        ));
    }
    Ok(normalized)
}

pub(crate) fn validate_optional_contact_alias(
    value: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(alias) = value else {
        return Ok(None);
    };
    let trimmed = alias.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_CONTACT_ALIAS_LEN {
        return Err(AppError::bad_request(format!(
            "alias must be <= {MAX_CONTACT_ALIAS_LEN} characters"
        )));
    }
    Ok(Some(trimmed.to_string()))
}

pub(crate) fn normalize_sha256_hashes(
    field: &'static str,
    values: &[String],
) -> Result<Vec<String>, AppError> {
    if values.len() > MAX_DISCOVERY_HASHES {
        return Err(AppError::bad_request(format!(
            "{field} cannot exceed {MAX_DISCOVERY_HASHES} items"
        )));
    }
    let mut hashes = Vec::with_capacity(values.len());
    for value in values {
        hashes.push(validate_sha256_hex(field, value)?);
    }
    hashes.sort_unstable();
    hashes.dedup();
    Ok(hashes)
}

pub(crate) fn validate_sha256_hex(field: &'static str, value: &str) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != SHA256_HEX_LEN {
        return Err(AppError::bad_request(format!(
            "{field} value must be {SHA256_HEX_LEN} hex characters"
        )));
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(AppError::bad_request(format!(
            "{field} value must be lowercase hex"
        )));
    }
    Ok(normalized)
}

pub(crate) fn validate_optional_fingerprint_sha256(
    value: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let normalized = validate_sha256_hex("verified_fingerprint_sha256", raw)?;
    Ok(Some(normalized))
}

pub(crate) fn decode_base64_exact(
    field: &'static str,
    value: &str,
    expected_len: usize,
) -> Result<Vec<u8>, AppError> {
    let decoded = decode_base64_range(field, value, expected_len, expected_len)?;
    Ok(decoded)
}

pub(crate) fn decode_base64_range(
    field: &'static str,
    value: &str,
    min_len: usize,
    max_len: usize,
) -> Result<Vec<u8>, AppError> {
    if value.is_empty() {
        return Err(AppError::bad_request(format!("{field} cannot be empty")));
    }
    let max_encoded = max_len.div_ceil(3) * 4 + 8;
    if value.len() > max_encoded {
        return Err(AppError::bad_request(format!("{field} is too large")));
    }
    let decoded = B64
        .decode(value.as_bytes())
        .map_err(|_| AppError::bad_request(format!("{field} is not valid base64")))?;
    if decoded.len() < min_len || decoded.len() > max_len {
        return Err(AppError::bad_request(format!(
            "{field} decoded length must be between {min_len} and {max_len}"
        )));
    }
    Ok(decoded)
}

pub(crate) fn decode_base64_max(
    field: &'static str,
    value: &str,
    max_len: usize,
) -> Result<Vec<u8>, AppError> {
    decode_base64_range(field, value, 1, max_len)
}

pub(crate) fn verify_ed25519_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    field: &'static str,
) -> Result<(), AppError> {
    let public_key: [u8; SIG_PUB_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| AppError::bad_request("identity_sig_pub must be 32 bytes"))?;
    let verifier = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AppError::bad_request("identity_sig_pub is not a valid Ed25519 public key"))?;
    let signature: [u8; SIG_LEN] = signature
        .try_into()
        .map_err(|_| AppError::bad_request(format!("{field} must be 64 bytes")))?;
    let signature = Signature::from_bytes(&signature);
    verifier
        .verify(message, &signature)
        .map_err(|_| AppError::bad_request(format!("{field} verification failed")))?;
    Ok(())
}

pub(crate) fn validate_ed25519_public_key(identity_sig_pub: &[u8]) -> Result<(), AppError> {
    let key_bytes: [u8; SIG_PUB_KEY_LEN] = identity_sig_pub
        .try_into()
        .map_err(|_| AppError::bad_request("identity_sig_pub must be 32 bytes"))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| AppError::bad_request("identity_sig_pub is not a valid Ed25519 public key"))?;
    Ok(())
}

pub(crate) fn validate_ml_dsa_public_key(identity_pq_sig_pub: &[u8]) -> Result<(), AppError> {
    if identity_pq_sig_pub.len() != PQ_SIG_PUB_KEY_LEN {
        return Err(AppError::bad_request(format!(
            "identity_pq_sig_pub must be {PQ_SIG_PUB_KEY_LEN} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn verify_ml_dsa_signature(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    field: &'static str,
) -> Result<(), AppError> {
    validate_ml_dsa_public_key(public_key)?;
    if signature.len() != PQ_SIG_LEN {
        return Err(AppError::bad_request(format!(
            "{field} must be {PQ_SIG_LEN} bytes"
        )));
    }
    let provider =
        MlDsa65::new().map_err(|_| AppError::internal("pq signature backend unavailable"))?;
    provider
        .verify(public_key, message, signature)
        .map_err(|_| AppError::bad_request(format!("{field} verification failed")))?;
    Ok(())
}

pub(crate) fn rotation_signature_message(
    user_id: &str,
    challenge_id: &str,
    challenge_nonce: &[u8],
    new_identity_x25519: &[u8],
    new_identity_sig: &[u8],
    new_identity_pq_sig: &[u8],
    new_device_id: &str,
) -> Result<Vec<u8>, AppError> {
    encode(&[
        TlvRecord {
            ty: ROTATE_SIG_TAG_USER_ID,
            value: user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_CHALLENGE_ID,
            value: challenge_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_CHALLENGE_NONCE,
            value: challenge_nonce.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_IDENTITY_X25519,
            value: new_identity_x25519.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_IDENTITY_SIG,
            value: new_identity_sig.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_IDENTITY_PQ_SIG,
            value: new_identity_pq_sig.to_vec(),
        },
        TlvRecord {
            ty: ROTATE_SIG_TAG_NEW_DEVICE_ID,
            value: new_device_id.as_bytes().to_vec(),
        },
    ])
    .map_err(|_| AppError::internal("rotation signature transcript encoding failed"))
}

pub(crate) fn identity_fingerprint_sha256(
    identity_key: &[u8],
    identity_pq_sig_pub: Option<&[u8]>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(identity_key);
    if let Some(identity_pq_sig_pub) = identity_pq_sig_pub {
        hasher.update(identity_pq_sig_pub);
    }
    hex::encode(hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_hybrid_prekey_signatures(
    identity_sig_pub: &[u8],
    identity_pq_sig_pub: &[u8],
    signed_prekey_x25519_pub: &[u8],
    sig_over_spk: &[u8],
    pq_signed_prekey_pub_mlkem768: &[u8],
    sig_over_pqspk: &[u8],
    pq_sig_over_spk: &[u8],
    pq_sig_over_pqspk: &[u8],
) -> Result<(), AppError> {
    let identity_sig_pub: [u8; SIG_PUB_KEY_LEN] = identity_sig_pub
        .try_into()
        .map_err(|_| AppError::bad_request("identity_sig_pub must be 32 bytes"))?;
    let verifier = VerifyingKey::from_bytes(&identity_sig_pub)
        .map_err(|_| AppError::bad_request("identity_sig_pub is not a valid Ed25519 public key"))?;

    let spk_pub: [u8; X25519_KEY_LEN] = signed_prekey_x25519_pub
        .try_into()
        .map_err(|_| AppError::bad_request("signed_prekey_x25519_pub must be 32 bytes"))?;
    let spk_signature: [u8; SIG_LEN] = sig_over_spk
        .try_into()
        .map_err(|_| AppError::bad_request("sig_over_spk must be 64 bytes"))?;
    let spk_message =
        signed_prekey_signature_message(PROTOCOL_VERSION_V1, &DhPublicKey(spk_pub))
            .map_err(|_| AppError::bad_request("failed to build SPK signature transcript"))?;
    let spk_signature = Signature::from_bytes(&spk_signature);
    verifier
        .verify(&spk_message, &spk_signature)
        .map_err(|_| AppError::bad_request("sig_over_spk verification failed"))?;

    let pq_signature: [u8; SIG_LEN] = sig_over_pqspk
        .try_into()
        .map_err(|_| AppError::bad_request("sig_over_pqspk must be 64 bytes"))?;
    let pq_message =
        pq_signed_prekey_signature_message(PROTOCOL_VERSION_V1, pq_signed_prekey_pub_mlkem768)
            .map_err(|_| AppError::bad_request("failed to build PQSPK signature transcript"))?;
    let pq_signature = Signature::from_bytes(&pq_signature);
    verifier
        .verify(&pq_message, &pq_signature)
        .map_err(|_| AppError::bad_request("sig_over_pqspk verification failed"))?;

    validate_ml_dsa_public_key(identity_pq_sig_pub)?;
    if pq_sig_over_spk.len() != PQ_SIG_LEN {
        return Err(AppError::bad_request(format!(
            "pq_sig_over_spk must be {PQ_SIG_LEN} bytes"
        )));
    }
    if pq_sig_over_pqspk.len() != PQ_SIG_LEN {
        return Err(AppError::bad_request(format!(
            "pq_sig_over_pqspk must be {PQ_SIG_LEN} bytes"
        )));
    }
    let pq_verifier =
        MlDsa65::new().map_err(|_| AppError::internal("failed to initialize ML-DSA verifier"))?;
    pq_verifier
        .verify(identity_pq_sig_pub, &spk_message, pq_sig_over_spk)
        .map_err(|_| AppError::bad_request("pq_sig_over_spk verification failed"))?;
    pq_verifier
        .verify(identity_pq_sig_pub, &pq_message, pq_sig_over_pqspk)
        .map_err(|_| AppError::bad_request("pq_sig_over_pqspk verification failed"))?;

    Ok(())
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // --- validate_id must never panic on arbitrary strings ---
    proptest! {
        #[test]
        fn validate_id_never_panics(s in "\\PC{0,256}") {
            let _ = validate_id("user_id", &s);
        }
    }

    // --- validate_mime_type must never panic ---
    proptest! {
        #[test]
        fn validate_mime_type_never_panics(s in "\\PC{0,256}") {
            let _ = validate_mime_type("content_type", &s);
        }
    }

    // --- validate_file_id must never panic ---
    proptest! {
        #[test]
        fn validate_file_id_never_panics(s in "\\PC{0,256}") {
            let _ = validate_file_id(&s);
        }
    }

    // --- validate_sha256_hex must never panic ---
    proptest! {
        #[test]
        fn validate_sha256_hex_never_panics(s in "\\PC{0,128}") {
            let _ = validate_sha256_hex("hash", &s);
        }
    }

    // --- decode_base64_range must never panic on arbitrary strings ---
    proptest! {
        #[test]
        fn decode_base64_range_never_panics(
            s in "\\PC{0,512}",
            min_len in 0usize..256,
            max_len in 0usize..512,
        ) {
            let min = min_len.min(max_len);
            let max = min_len.max(max_len).max(1);
            let _ = decode_base64_range("field", &s, min, max);
        }
    }

    // --- decode_base64_exact must never panic ---
    proptest! {
        #[test]
        fn decode_base64_exact_never_panics(s in "\\PC{0,512}", expected in 1usize..256) {
            let _ = decode_base64_exact("field", &s, expected);
        }
    }

    // --- validate_push_token must never panic for both providers ---
    proptest! {
        #[test]
        fn validate_push_token_fcm_never_panics(s in "\\PC{0,8192}") {
            let _ = validate_push_token(PushProvider::Fcm, &s);
        }

        #[test]
        fn validate_push_token_apns_never_panics(s in "\\PC{0,1024}") {
            let _ = validate_push_token(PushProvider::Apns, &s);
        }
    }

    // --- validate_presence_status must never panic ---
    proptest! {
        #[test]
        fn validate_presence_status_never_panics(s in "\\PC{0,64}") {
            let _ = validate_presence_status(&s);
        }
    }

    // --- verify_ed25519_signature must never panic on arbitrary bytes ---
    proptest! {
        #[test]
        fn verify_ed25519_never_panics(
            pk in proptest::collection::vec(any::<u8>(), 0..64),
            sig in proptest::collection::vec(any::<u8>(), 0..128),
            msg in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let _ = verify_ed25519_signature(&pk, &sig, &msg, "sig");
        }
    }

    // --- validate_ed25519_public_key must never panic on arbitrary bytes ---
    proptest! {
        #[test]
        fn validate_ed25519_public_key_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let _ = validate_ed25519_public_key(&data);
        }
    }
}
