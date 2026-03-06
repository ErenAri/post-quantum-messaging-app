use axum::http::HeaderMap;
use chrono::Utc;
use pqmsg_core::tlv::{encode, TlvRecord};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::error::AppError;
use crate::types::{DeleteInboxRequest, PublishPrekeysRequest, RotateConfirmRequest, RotateInitRequest};
use crate::{
    AppState, record_security_event, validate_id, decode_base64_exact,
    verify_ed25519_signature, hash_string_list_sha256, normalize_message_ids,
    AUTH_HEADER_USER, AUTH_HEADER_DEVICE, AUTH_HEADER_TIMESTAMP,
    AUTH_HEADER_NONCE, AUTH_HEADER_SIGNATURE, REQUEST_ID_HEADER,
    AUTH_MAX_NONCE_LEN, MAX_REQUEST_ID_LEN, AUTH_MAX_CLOCK_SKEW_SECONDS,
    MAX_USER_ID_LEN, MAX_DEVICE_ID_LEN, SIG_LEN,
    AUTH_TAG_ENDPOINT, AUTH_TAG_USER_ID, AUTH_TAG_DEVICE_ID,
    AUTH_TAG_TIMESTAMP, AUTH_TAG_NONCE, AUTH_TAG_RECIPIENT_ID,
    AUTH_TAG_SINCE, AUTH_TAG_MESSAGE_BLOB,
    AUTH_TAG_PREKEY_SPK_HASH, AUTH_TAG_PREKEY_PQSPK_HASH,
    AUTH_TAG_ROTATE_NEW_X25519_HASH, AUTH_TAG_ROTATE_NEW_SIG_HASH,
    AUTH_TAG_ROTATE_CHALLENGE_ID, AUTH_TAG_ROTATE_SIG_CURRENT_HASH,
    AUTH_TAG_ROTATE_SIG_NEW_HASH,
    AUTH_TAG_PUSH_DEVICE_ID, AUTH_TAG_PUSH_TOKEN_HASH,
    AUTH_TAG_LINK_DEVICE_ID, AUTH_TAG_REVOKE_DEVICE_ID,
    AUTH_TAG_DELETE_IDS_HASH, AUTH_TAG_DELETE_BEFORE_ID,
    AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH, AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH,
    AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH,
    AUTH_TAG_CONTACT_USER_ID, AUTH_TAG_CONTACT_ALIAS_HASH,
    AUTH_TAG_CONTACT_VERIFIED_FLAG, AUTH_TAG_CONTACT_FINGERPRINT,
    AUTH_TAG_GROUP_ID, AUTH_TAG_GROUP_MEMBER_USER_ID,
    AUTH_TAG_GROUP_MEMBERS_HASH, AUTH_TAG_GROUP_SENDER_USER_ID,
    AUTH_TAG_GROUP_MESSAGE_BLOB_HASH,
    AUTH_TAG_FILE_ID, AUTH_TAG_FILE_RECIPIENT_ID,
    AUTH_TAG_FILE_BLOB_HASH, AUTH_TAG_FILE_MIME_HASH,
    AUTH_TAG_PROFILE_DISPLAY_NAME_HASH, AUTH_TAG_PROFILE_AVATAR_HASH,
    AUTH_TAG_PROFILE_AVATAR_MIME_HASH,
    AUTH_TAG_PRESENCE_STATUS,
    AUTH_TAG_TYPING_PEER_ID, AUTH_TAG_TYPING_STATE_FLAG,
};

#[derive(Debug)]
pub(crate) struct RequestAuth {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) timestamp: i64,
    pub(crate) nonce: String,
    pub(crate) signature: Vec<u8>,
}

pub(crate) fn parse_request_auth(headers: &HeaderMap) -> Result<RequestAuth, AppError> {
    let user_id = require_header_value(headers, AUTH_HEADER_USER, MAX_USER_ID_LEN)?;
    let device_id = require_header_value(headers, AUTH_HEADER_DEVICE, MAX_DEVICE_ID_LEN)?;
    validate_id("auth.user_id", &user_id)?;
    validate_id("auth.device_id", &device_id)?;

    let timestamp_raw = require_header_value(headers, AUTH_HEADER_TIMESTAMP, 32)?;
    let timestamp = timestamp_raw
        .parse::<i64>()
        .map_err(|_| AppError::bad_request("x-pqmsg-auth-timestamp must be an integer"))?;

    let nonce = require_header_value(headers, AUTH_HEADER_NONCE, AUTH_MAX_NONCE_LEN)?;
    let signature_b64 = require_header_value(headers, AUTH_HEADER_SIGNATURE, 256)?;
    let signature = decode_base64_exact(AUTH_HEADER_SIGNATURE, &signature_b64, SIG_LEN)?;

    Ok(RequestAuth {
        user_id,
        device_id,
        timestamp,
        nonce,
        signature,
    })
}

pub(crate) fn require_header_value(
    headers: &HeaderMap,
    name: &'static str,
    max_len: usize,
) -> Result<String, AppError> {
    let value = headers
        .get(name)
        .ok_or_else(|| AppError::bad_request(format!("missing header '{name}'")))?;
    let value = value
        .to_str()
        .map_err(|_| AppError::bad_request(format!("header '{name}' must be ASCII")))?;
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > max_len {
        return Err(AppError::bad_request(format!(
            "header '{name}' must be 1..={max_len} characters"
        )));
    }
    Ok(trimmed.to_string())
}

pub(crate) async fn verify_request_auth(
    state: &AppState,
    auth: &RequestAuth,
    message: &[u8],
) -> Result<(), AppError> {
    let now = Utc::now().timestamp();
    if (now - auth.timestamp).abs() > AUTH_MAX_CLOCK_SKEW_SECONDS {
        record_security_event(
            state,
            "auth_timestamp_skew",
            "reject",
            None,
            Some(&auth.user_id),
            Some(&auth.device_id),
            Some("request timestamp outside allowed skew".to_string()),
        );
        return Err(AppError::bad_request(
            "request timestamp outside allowed skew",
        ));
    }
    if !state.auth_replay().observe(&auth.user_id, &auth.nonce) {
        record_security_event(
            state,
            "auth_nonce_replay",
            "reject",
            None,
            Some(&auth.user_id),
            Some(&auth.device_id),
            Some("request nonce replayed".to_string()),
        );
        return Err(AppError::conflict("request nonce replayed"));
    }

    let user_row = sqlx::query("SELECT identity_sig_pub FROM users WHERE user_id = $1")
        .bind(&auth.user_id)
        .fetch_optional(state.pool())
        .await?;
    let Some(user_row) = user_row else {
        record_security_event(
            state,
            "auth_unknown_user",
            "reject",
            None,
            Some(&auth.user_id),
            Some(&auth.device_id),
            Some("auth user not found".to_string()),
        );
        return Err(AppError::not_found("auth user not found"));
    };
    let active_device = sqlx::query(
        "SELECT 1
         FROM user_devices
         WHERE user_id = $1 AND device_id = $2 AND active = 1",
    )
    .bind(&auth.user_id)
    .bind(&auth.device_id)
    .fetch_optional(state.pool())
    .await?;
    if active_device.is_none() {
        record_security_event(
            state,
            "auth_device_mismatch",
            "reject",
            None,
            Some(&auth.user_id),
            Some(&auth.device_id),
            Some("auth device mismatch for user or device revoked".to_string()),
        );
        return Err(AppError::bad_request(
            "auth device mismatch for user or device revoked",
        ));
    }
    let identity_sig_pub: Vec<u8> = user_row.try_get("identity_sig_pub")?;
    let verification = verify_ed25519_signature(
        &identity_sig_pub,
        &auth.signature,
        message,
        AUTH_HEADER_SIGNATURE,
    );
    if verification.is_err() {
        record_security_event(
            state,
            "auth_signature_invalid",
            "reject",
            None,
            Some(&auth.user_id),
            Some(&auth.device_id),
            Some("x-pqmsg-auth-signature verification failed".to_string()),
        );
    }
    verification
}

pub(crate) fn auth_common_records(auth: &RequestAuth, endpoint: &'static str) -> Vec<TlvRecord> {
    vec![
        TlvRecord {
            ty: AUTH_TAG_ENDPOINT,
            value: endpoint.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_USER_ID,
            value: auth.user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_DEVICE_ID,
            value: auth.device_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_TIMESTAMP,
            value: auth.timestamp.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_NONCE,
            value: auth.nonce.as_bytes().to_vec(),
        },
    ]
}

pub(crate) fn relay_auth_message(
    auth: &RequestAuth,
    recipient_user_id: &str,
    message_blob: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "relay");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_MESSAGE_BLOB,
        value: message_blob.to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode relay auth transcript"))
}

pub(crate) fn inbox_auth_message(auth: &RequestAuth, user_id: &str, since: i64) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "inbox");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode inbox auth transcript"))
}

pub(crate) fn sealed_inbox_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    since: i64,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "sealed-inbox");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode sealed-inbox auth transcript"))
}

pub(crate) fn inbox_delete_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    request: &DeleteInboxRequest,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "inbox-delete");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let normalized_ids = normalize_message_ids(&request.message_ids);
    let mut hasher = Sha256::new();
    for message_id in &normalized_ids {
        hasher.update(message_id.to_be_bytes());
    }
    records.push(TlvRecord {
        ty: AUTH_TAG_DELETE_IDS_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    if let Some(delete_before_id) = request.delete_before_id {
        records.push(TlvRecord {
            ty: AUTH_TAG_DELETE_BEFORE_ID,
            value: delete_before_id.to_be_bytes().to_vec(),
        });
    }
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode inbox-delete auth transcript"))
}

pub(crate) fn ws_inbox_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    since: i64,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "ws-inbox");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode ws-inbox auth transcript"))
}

pub(crate) fn list_devices_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "devices-list");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode devices-list auth transcript"))
}

pub(crate) fn link_device_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    new_device_id: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "devices-link");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_LINK_DEVICE_ID,
        value: new_device_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode devices-link auth transcript"))
}

pub(crate) fn revoke_device_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    target_device_id: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "devices-revoke");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_REVOKE_DEVICE_ID,
        value: target_device_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode devices-revoke auth transcript"))
}

pub(crate) fn discovery_handles_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    phone_hashes: &[String],
    email_hashes: &[String],
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "discovery-handles");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH,
        value: hash_string_list_sha256(phone_hashes),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH,
        value: hash_string_list_sha256(email_hashes),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode discovery-handles auth transcript"))
}

pub(crate) fn discovery_match_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    query_hashes: &[String],
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "discovery-match");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH,
        value: hash_string_list_sha256(query_hashes),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode discovery-match auth transcript"))
}

pub(crate) fn contacts_list_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "contacts-list");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode contacts-list auth transcript"))
}

pub(crate) fn contacts_upsert_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    contact_user_id: &str,
    alias: Option<&str>,
    verified_by_qr: bool,
    verified_fingerprint_sha256: Option<&str>,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "contacts-upsert");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    let mut alias_hasher = Sha256::new();
    alias_hasher.update(alias.unwrap_or_default().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_ALIAS_HASH,
        value: alias_hasher.finalize().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_VERIFIED_FLAG,
        value: vec![if verified_by_qr { 1 } else { 0 }],
    });
    if let Some(fingerprint) = verified_fingerprint_sha256 {
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_FINGERPRINT,
            value: fingerprint.as_bytes().to_vec(),
        });
    }
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode contacts-upsert auth transcript"))
}

pub(crate) fn contacts_remove_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    contact_user_id: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "contacts-remove");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode contacts-remove auth transcript"))
}

pub(crate) fn group_create_auth_message(
    auth: &RequestAuth,
    group_id: &str,
    member_user_ids: &[String],
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "groups-create");
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBERS_HASH,
        value: hash_string_list_sha256(member_user_ids),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode groups-create auth transcript"))
}

pub(crate) fn group_members_list_auth_message(
    auth: &RequestAuth,
    group_id: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "groups-members-list");
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode groups-members-list auth transcript"))
}

pub(crate) fn group_members_add_auth_message(
    auth: &RequestAuth,
    group_id: &str,
    member_user_id: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "groups-members-add");
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode groups-members-add auth transcript"))
}

pub(crate) fn group_members_remove_auth_message(
    auth: &RequestAuth,
    group_id: &str,
    member_user_id: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "groups-members-remove");
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode groups-members-remove auth transcript"))
}

pub(crate) fn group_relay_auth_message(
    auth: &RequestAuth,
    group_id: &str,
    sender_user_id: &str,
    message_blob: &[u8],
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "groups-relay");
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_SENDER_USER_ID,
        value: sender_user_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(message_blob);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MESSAGE_BLOB_HASH,
        value: hasher.finalize().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode groups-relay auth transcript"))
}

pub(crate) fn identity_log_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "identity-log");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode identity-log auth transcript"))
}

pub(crate) fn prekeys_status_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "prekeys-status");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode prekeys-status auth transcript"))
}

pub(crate) fn prekeys_auth_message(
    auth: &RequestAuth,
    request: &PublishPrekeysRequest,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "prekeys");
    let mut hasher = Sha256::new();
    hasher.update(request.signed_prekey_x25519_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_SPK_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(request.pq_signed_prekey_pub_mlkem768.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_PQSPK_HASH,
        value: hasher.finalize().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode prekeys auth transcript"))
}

pub(crate) fn push_token_auth_message(
    auth: &RequestAuth,
    device_id: &str,
    push_token: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "push-token");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: auth.user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PUSH_DEVICE_ID,
        value: device_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(push_token.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PUSH_TOKEN_HASH,
        value: hasher.finalize().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode push-token auth transcript"))
}

pub(crate) fn file_upload_auth_message(
    auth: &RequestAuth,
    recipient_user_id: &str,
    file_blob: &[u8],
    mime_type: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "files-upload");
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(file_blob);
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_BLOB_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(mime_type.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_MIME_HASH,
        value: hasher.finalize().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode files-upload auth transcript"))
}

pub(crate) fn file_download_auth_message(auth: &RequestAuth, file_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "files-download");
    records.push(TlvRecord {
        ty: AUTH_TAG_FILE_ID,
        value: file_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode files-download auth transcript"))
}

pub(crate) fn profile_upsert_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    display_name: Option<&str>,
    avatar_mime: Option<&str>,
    avatar_blob: Option<&[u8]>,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "profile-upsert");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(display_name.unwrap_or_default().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_DISPLAY_NAME_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(avatar_blob.unwrap_or_default());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_AVATAR_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(avatar_mime.unwrap_or_default().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PROFILE_AVATAR_MIME_HASH,
        value: hasher.finalize().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode profile-upsert auth transcript"))
}

pub(crate) fn profile_get_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "profile-get");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode profile-get auth transcript"))
}

pub(crate) fn presence_update_auth_message(
    auth: &RequestAuth,
    user_id: &str,
    status: &str,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "presence-update");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_PRESENCE_STATUS,
        value: status.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode presence-update auth transcript"))
}

pub(crate) fn presence_get_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "presence-get");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode presence-get auth transcript"))
}

pub(crate) fn typing_update_auth_message(
    auth: &RequestAuth,
    peer_user_id: &str,
    is_typing: bool,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "typing-update");
    records.push(TlvRecord {
        ty: AUTH_TAG_TYPING_PEER_ID,
        value: peer_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_TYPING_STATE_FLAG,
        value: vec![if is_typing { 1 } else { 0 }],
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode typing-update auth transcript"))
}

pub(crate) fn typing_get_auth_message(auth: &RequestAuth, user_id: &str) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "typing-get");
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode typing-get auth transcript"))
}

pub(crate) fn rotate_init_auth_message(
    auth: &RequestAuth,
    request: &RotateInitRequest,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "rotate-init");
    let mut hasher = Sha256::new();
    hasher.update(request.new_identity_x25519_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_X25519_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(request.new_identity_sig_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_NEW_SIG_HASH,
        value: hasher.finalize().to_vec(),
    });
    encode(&records).map_err(|_| AppError::internal("failed to encode rotate-init auth transcript"))
}

pub(crate) fn rotate_confirm_auth_message(
    auth: &RequestAuth,
    request: &RotateConfirmRequest,
) -> Result<Vec<u8>, AppError> {
    let mut records = auth_common_records(auth, "rotate-confirm");
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_CHALLENGE_ID,
        value: request.challenge_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(request.sig_by_current_identity.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_SIG_CURRENT_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(request.sig_by_new_identity.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_ROTATE_SIG_NEW_HASH,
        value: hasher.finalize().to_vec(),
    });
    encode(&records)
        .map_err(|_| AppError::internal("failed to encode rotate-confirm auth transcript"))
}

pub(crate) fn request_id_from_header(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(REQUEST_ID_HEADER)?;
    let value = value.to_str().ok()?.trim();
    if value.is_empty() || value.len() > MAX_REQUEST_ID_LEN {
        return None;
    }
    Some(value.to_string())
}
