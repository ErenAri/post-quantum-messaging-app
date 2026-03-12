use pqmsg_core::alg::RuntimeCryptoProfile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterUserRequest {
    pub(crate) user_id: String,
    pub(crate) identity_x25519_pub: String,
    pub(crate) identity_sig_pub: String,
    pub(crate) identity_pq_sig_pub: String,
    pub(crate) device_id: String,
    #[serde(default)]
    pub(crate) pow_nonce: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegisterUserResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) registered_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LinkDeviceRequest {
    pub(crate) new_device_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct LinkDeviceResponse {
    pub(crate) user_id: String,
    pub(crate) linked_device_id: String,
    pub(crate) linked_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RevokeDeviceResponse {
    pub(crate) user_id: String,
    pub(crate) revoked_device_id: String,
    pub(crate) revoked_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RetireCurrentDeviceResponse {
    pub(crate) user_id: String,
    pub(crate) retired_device_id: String,
    pub(crate) retired_at: String,
    pub(crate) remaining_active_devices: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceRecord {
    pub(crate) device_id: String,
    pub(crate) active: bool,
    pub(crate) linked_at: String,
    pub(crate) revoked_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeviceListResponse {
    pub(crate) user_id: String,
    pub(crate) devices: Vec<DeviceRecord>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DiscoveryHandlesUploadRequest {
    pub(crate) phone_hashes_sha256: Vec<String>,
    pub(crate) email_hashes_sha256: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DiscoveryHandlesUploadResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) uploaded_phone_hashes: usize,
    pub(crate) uploaded_email_hashes: usize,
    pub(crate) updated_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DiscoveryMatchRequest {
    pub(crate) hashes_sha256: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DiscoveryMatchItem {
    pub(crate) hash_sha256: String,
    pub(crate) matched_user_id: String,
    pub(crate) handle_kind: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct DiscoveryMatchResponse {
    pub(crate) user_id: String,
    pub(crate) matches: Vec<DiscoveryMatchItem>,
    pub(crate) checked_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpsertContactRequest {
    pub(crate) contact_user_id: String,
    pub(crate) alias: Option<String>,
    pub(crate) verified_by_qr: Option<bool>,
    pub(crate) verified_fingerprint_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct UpsertContactResponse {
    pub(crate) user_id: String,
    pub(crate) contact_user_id: String,
    pub(crate) alias: Option<String>,
    pub(crate) verified_by_qr: bool,
    pub(crate) verified_fingerprint_sha256: Option<String>,
    pub(crate) updated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ContactListItem {
    pub(crate) contact_user_id: String,
    pub(crate) alias: Option<String>,
    pub(crate) verified_by_qr: bool,
    pub(crate) verified_fingerprint_sha256: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ContactListResponse {
    pub(crate) user_id: String,
    pub(crate) contacts: Vec<ContactListItem>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemoveContactRequest {
    pub(crate) contact_user_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RemoveContactResponse {
    pub(crate) user_id: String,
    pub(crate) removed_contact_user_id: String,
    pub(crate) removed: bool,
    pub(crate) removed_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateGroupRequest {
    pub(crate) group_id: String,
    pub(crate) member_user_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateGroupResponse {
    pub(crate) group_id: String,
    pub(crate) owner_user_id: String,
    pub(crate) member_count: usize,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GroupMembershipRecord {
    pub(crate) group_id: String,
    pub(crate) owner_user_id: String,
    pub(crate) joined_at: String,
    pub(crate) updated_at: String,
    pub(crate) member_count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserGroupsResponse {
    pub(crate) user_id: String,
    pub(crate) groups: Vec<GroupMembershipRecord>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AddGroupMemberRequest {
    pub(crate) member_user_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemoveGroupMemberRequest {
    pub(crate) member_user_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GroupMemberRecord {
    pub(crate) user_id: String,
    pub(crate) joined_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GroupMembersResponse {
    pub(crate) group_id: String,
    pub(crate) members: Vec<GroupMemberRecord>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GroupMemberMutationResponse {
    pub(crate) group_id: String,
    pub(crate) member_user_id: String,
    pub(crate) owner_user_id: String,
    pub(crate) changed: bool,
    pub(crate) updated_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GroupRelayRequest {
    pub(crate) sender_user_id: String,
    pub(crate) device_id: String,
    pub(crate) recipients: Vec<GroupRelayRecipient>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct GroupRelayRecipient {
    pub(crate) recipient_user_id: String,
    pub(crate) message_bytes_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct GroupRelayResponse {
    pub(crate) group_id: String,
    pub(crate) delivered_message_count: usize,
    pub(crate) delivered_user_count: usize,
    pub(crate) first_message_id: Option<i64>,
    pub(crate) received_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SealedRelayRequest {
    pub(crate) delivery_token: String,
    pub(crate) message_bytes_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SealedRelayResponse {
    pub(crate) delivered_device_count: usize,
    pub(crate) first_message_id: Option<i64>,
    pub(crate) received_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SenderCertificateResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) certificate_base64: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SealedInboxItem {
    pub(crate) message_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sender_identity_x25519_pub: Option<String>,
    pub(crate) message_bytes_base64: String,
    pub(crate) received_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct SealedInboxResponse {
    pub(crate) user_id: String,
    pub(crate) messages: Vec<SealedInboxItem>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PublishPrekeysRequest {
    pub(crate) signed_prekey_x25519_pub: String,
    pub(crate) sig_over_spk: String,
    pub(crate) pq_signed_prekey_pub_mlkem768: String,
    pub(crate) sig_over_pqspk: String,
    pub(crate) pq_sig_over_spk: String,
    pub(crate) pq_sig_over_pqspk: String,
    pub(crate) one_time_prekeys_x25519: Vec<String>,
    pub(crate) one_time_prekeys_mlkem768: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PublishPrekeysResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) uploaded_one_time_prekeys_x25519: usize,
    pub(crate) uploaded_one_time_prekeys_mlkem768: usize,
    pub(crate) remaining_one_time_prekeys_x25519: usize,
    pub(crate) remaining_one_time_prekeys_mlkem768: usize,
    pub(crate) low_one_time_prekeys: bool,
    pub(crate) minimum_recommended_one_time_prekeys: usize,
    pub(crate) updated_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RotateInitRequest {
    pub(crate) new_identity_x25519_pub: String,
    pub(crate) new_identity_sig_pub: String,
    pub(crate) new_identity_pq_sig_pub: String,
    pub(crate) new_device_id: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RotateInitResponse {
    pub(crate) user_id: String,
    pub(crate) challenge_id: String,
    pub(crate) challenge_nonce: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RotateConfirmRequest {
    pub(crate) challenge_id: String,
    pub(crate) sig_by_current_identity: String,
    pub(crate) sig_by_new_identity: String,
    pub(crate) pq_sig_by_current_identity: String,
    pub(crate) pq_sig_by_new_identity: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RotateConfirmResponse {
    pub(crate) user_id: String,
    pub(crate) identity_key_version: u32,
    pub(crate) identity_fingerprint_sha256: String,
    pub(crate) rotated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct IdentityLogItem {
    pub(crate) version: u32,
    pub(crate) identity_x25519_pub: String,
    pub(crate) identity_sig_pub: String,
    pub(crate) identity_pq_sig_pub: Option<String>,
    pub(crate) device_id: String,
    pub(crate) event_type: String,
    pub(crate) changed_at: String,
    pub(crate) identity_fingerprint_sha256: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct IdentityLogResponse {
    pub(crate) user_id: String,
    pub(crate) events: Vec<IdentityLogItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct BundleResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) identity_x25519_pub: String,
    pub(crate) identity_sig_pub: String,
    pub(crate) identity_pq_sig_pub: String,
    pub(crate) signed_prekey_x25519_pub: String,
    pub(crate) sig_over_spk: String,
    pub(crate) pq_signed_prekey_pub_mlkem768: String,
    pub(crate) sig_over_pqspk: String,
    pub(crate) pq_sig_over_spk: String,
    pub(crate) pq_sig_over_pqspk: String,
    pub(crate) one_time_prekey_x25519: Option<String>,
    pub(crate) one_time_prekey_mlkem768: Option<String>,
    pub(crate) remaining_one_time_prekeys_x25519: usize,
    pub(crate) remaining_one_time_prekeys_mlkem768: usize,
    pub(crate) low_one_time_prekeys: bool,
    pub(crate) minimum_recommended_one_time_prekeys: usize,
    pub(crate) last_resort_prekey_only: bool,
    pub(crate) identity_key_version: u32,
    pub(crate) identity_fingerprint_sha256: String,
    pub(crate) bundle_generated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PrekeysStatusResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) remaining_one_time_prekeys_x25519: usize,
    pub(crate) remaining_one_time_prekeys_mlkem768: usize,
    pub(crate) low_one_time_prekeys: bool,
    pub(crate) minimum_recommended_one_time_prekeys: usize,
    pub(crate) checked_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RelayRequest {
    pub(crate) sender_user_id: String,
    pub(crate) device_id: String,
    pub(crate) message_bytes_base64: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RegisterPushTokenRequest {
    pub(crate) device_id: String,
    pub(crate) provider: Option<String>,
    pub(crate) token: Option<String>,
    pub(crate) fcm_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RegisterPushTokenResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) provider: String,
    pub(crate) registered_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FileUploadRequest {
    pub(crate) recipient_user_id: String,
    pub(crate) device_id: String,
    pub(crate) mime_type: String,
    pub(crate) file_bytes_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct FileUploadResponse {
    pub(crate) file_id: String,
    pub(crate) owner_user_id: String,
    pub(crate) recipient_user_id: String,
    pub(crate) mime_type: String,
    pub(crate) byte_len: usize,
    pub(crate) uploaded_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct FileDownloadResponse {
    pub(crate) file_id: String,
    pub(crate) owner_user_id: String,
    pub(crate) recipient_user_id: String,
    pub(crate) mime_type: String,
    pub(crate) file_bytes_base64: String,
    pub(crate) uploaded_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpsertProfileRequest {
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_mime: Option<String>,
    pub(crate) avatar_bytes_base64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BackupUploadRequest {
    pub(crate) device_id: String,
    pub(crate) backup_version: i64,
    pub(crate) recovery_hint: Option<String>,
    pub(crate) encrypted_backup_bytes_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackupUploadResponse {
    pub(crate) backup_id: String,
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) backup_version: i64,
    pub(crate) byte_len: usize,
    pub(crate) uploaded_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct BackupDownloadResponse {
    pub(crate) backup_id: String,
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) backup_version: i64,
    pub(crate) recovery_hint: Option<String>,
    pub(crate) encrypted_backup_bytes_base64: String,
    pub(crate) uploaded_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct UserProfileResponse {
    pub(crate) user_id: String,
    pub(crate) display_name: Option<String>,
    pub(crate) avatar_mime: Option<String>,
    pub(crate) avatar_bytes_base64: Option<String>,
    pub(crate) sealed_delivery_token: Option<String>,
    pub(crate) updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PresenceUpdateRequest {
    pub(crate) status: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PresenceResponse {
    pub(crate) user_id: String,
    pub(crate) status: String,
    pub(crate) active: bool,
    pub(crate) updated_at: Option<String>,
    pub(crate) expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TypingUpdateRequest {
    pub(crate) is_typing: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct TypingUpdateResponse {
    pub(crate) recipient_user_id: String,
    pub(crate) sender_user_id: String,
    pub(crate) sender_device_id: String,
    pub(crate) is_typing: bool,
    pub(crate) updated_at: String,
    pub(crate) expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TypingIndicator {
    pub(crate) sender_user_id: String,
    pub(crate) sender_device_id: String,
    pub(crate) updated_at: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct TypingInboxResponse {
    pub(crate) user_id: String,
    pub(crate) typing: Vec<TypingIndicator>,
    pub(crate) checked_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RelayResponse {
    pub(crate) message_id: i64,
    pub(crate) delivered_device_count: usize,
    pub(crate) received_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InboxQuery {
    pub(crate) since: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WsInboxQuery {
    pub(crate) since: Option<i64>,
    pub(crate) ticket: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct BundleQuery {
    pub(crate) device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct InboxItem {
    pub(crate) message_id: i64,
    pub(crate) sender_user_id: String,
    pub(crate) message_bytes_base64: String,
    pub(crate) received_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct InboxResponse {
    pub(crate) user_id: String,
    pub(crate) messages: Vec<InboxItem>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DeleteInboxRequest {
    pub(crate) message_ids: Vec<i64>,
    pub(crate) delete_before_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeleteInboxResponse {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) deleted_count: u64,
    pub(crate) deleted_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct WsInboxEnvelope {
    pub(crate) event: &'static str,
    pub(crate) user_id: String,
    pub(crate) messages: Vec<InboxItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WsSealedInboxEnvelope {
    pub(crate) event: &'static str,
    pub(crate) user_id: String,
    pub(crate) messages: Vec<SealedInboxItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WsInboxTicketResponse {
    pub(crate) ticket: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct StatusResponse {
    pub(crate) status: &'static str,
    pub(crate) security_profile: String,
    pub(crate) deployment_mode: String,
    pub(crate) db_backend: String,
    pub(crate) db_ready: bool,
    pub(crate) db_pool_size: u32,
    pub(crate) db_pool_idle: usize,
    pub(crate) push_enabled: bool,
    pub(crate) push_providers: Vec<&'static str>,
    pub(crate) audit_logger_enabled: bool,
    pub(crate) tls_enabled: bool,
    pub(crate) rate_limiter_mode: &'static str,
    pub(crate) replay_cache_mode: &'static str,
    pub(crate) realtime_mode: &'static str,
    pub(crate) supported_suite_ids: Vec<u16>,
    pub(crate) runtime_crypto_profile: RuntimeCryptoProfile,
    pub(crate) production_baseline_met: bool,
    pub(crate) registration_pow_bits: u8,
    pub(crate) prekey_publish_min_interval_seconds: i64,
    pub(crate) prekey_bundle_reserve_count: i64,
    pub(crate) pq_ratchet_interval: u32,
}

#[derive(Debug, Serialize)]
pub(crate) struct ServerCapabilitiesResponse {
    pub(crate) capability_schema_version: u16,
    pub(crate) security_profile: String,
    pub(crate) deployment_mode: String,
    pub(crate) tls_required: bool,
    pub(crate) tls_enabled: bool,
    pub(crate) supported_suite_ids: Vec<u16>,
    pub(crate) runtime_crypto_profile: RuntimeCryptoProfile,
    pub(crate) production_baseline_met: bool,
    pub(crate) registration_pow_bits: u8,
    pub(crate) prekey_bundle_reserve_count: i64,
    pub(crate) pq_ratchet_interval: u32,
    pub(crate) contact_discovery_supported: bool,
    pub(crate) presence_supported: bool,
    pub(crate) typing_indicators_supported: bool,
    pub(crate) read_receipts_supported: bool,
    pub(crate) calling_supported: bool,
    pub(crate) stories_supported: bool,
    pub(crate) channels_supported: bool,
    pub(crate) group_messaging_supported: bool,
    pub(crate) sealed_sender_required: bool,
    pub(crate) sender_certificate_supported: bool,
    pub(crate) sealed_delivery_tokens_supported: bool,
    pub(crate) sender_certificate_issuer_ed25519_pub: String,
    pub(crate) authenticated_direct_messaging_supported: bool,
    pub(crate) ephemeral_messaging_supported: bool,
    pub(crate) web_client_policy: &'static str,
}

// ── Delivery receipts ──

#[derive(Debug, Deserialize)]
pub(crate) struct SendReceiptRequest {
    pub(crate) message_id: i64,
    pub(crate) receipt_type: String, // "delivered" or "read"
}

#[derive(Debug, Serialize)]
pub(crate) struct SendReceiptResponse {
    pub(crate) message_id: i64,
    pub(crate) receipt_type: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReceiptItem {
    pub(crate) message_id: i64,
    pub(crate) recipient_user_id: String,
    pub(crate) recipient_device_id: String,
    pub(crate) receipt_type: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReceiptsResponse {
    pub(crate) sender_user_id: String,
    pub(crate) receipts: Vec<ReceiptItem>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReceiptsQuery {
    pub(crate) since_id: Option<i64>,
}

// ── Disappearing messages ──

#[derive(Debug, Deserialize)]
pub(crate) struct RelayEphemeralRequest {
    pub(crate) sender_user_id: String,
    pub(crate) device_id: String,
    pub(crate) message_bytes_base64: String,
    pub(crate) ttl_seconds: u64,
}

// ── Call Signaling ──

#[derive(Debug, Deserialize)]
pub(crate) struct CallOfferRequest {
    pub(crate) caller_user_id: String,
    pub(crate) device_id: String,
    pub(crate) sdp_offer_base64: String,
    pub(crate) call_type: String, // "audio" | "video"
}

#[derive(Debug, Serialize)]
pub(crate) struct CallOfferResponse {
    pub(crate) call_id: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallAnswerRequest {
    pub(crate) callee_user_id: String,
    pub(crate) device_id: String,
    pub(crate) sdp_answer_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CallAnswerResponse {
    pub(crate) call_id: String,
    pub(crate) answered_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IceCandidateRequest {
    pub(crate) sender_user_id: String,
    pub(crate) device_id: String,
    pub(crate) candidate_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct IceCandidateResponse {
    pub(crate) call_id: String,
    pub(crate) queued_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallHangupRequest {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CallHangupResponse {
    pub(crate) call_id: String,
    pub(crate) ended_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CallSignal {
    pub(crate) signal_id: i64,
    pub(crate) signal_type: String,
    pub(crate) from_user_id: String,
    pub(crate) payload_base64: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PollCallSignalsResponse {
    pub(crate) call_id: String,
    pub(crate) signals: Vec<CallSignal>,
}

// ── Stories ──

#[derive(Debug, Deserialize)]
pub(crate) struct CreateStoryRequest {
    pub(crate) author_user_id: String,
    pub(crate) device_id: String,
    pub(crate) content_base64: String,
    pub(crate) media_type: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateStoryResponse {
    pub(crate) story_id: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct StoryItem {
    pub(crate) story_id: String,
    pub(crate) author_user_id: String,
    pub(crate) content_base64: String,
    pub(crate) media_type: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: String,
    pub(crate) view_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct StoriesFeedResponse {
    pub(crate) stories: Vec<StoryItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ViewStoryResponse {
    pub(crate) story_id: String,
    pub(crate) viewed_at: String,
}

// ── Channels ──

#[derive(Debug, Deserialize)]
pub(crate) struct CreateChannelRequest {
    pub(crate) owner_user_id: String,
    pub(crate) device_id: String,
    pub(crate) display_name: String,
    pub(crate) description: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateChannelResponse {
    pub(crate) channel_id: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChannelMessageRequest {
    pub(crate) owner_user_id: String,
    pub(crate) device_id: String,
    pub(crate) content_base64: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChannelMessageResponse {
    pub(crate) message_id: i64,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChannelMessageItem {
    pub(crate) message_id: i64,
    pub(crate) content_base64: String,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChannelMessagesResponse {
    pub(crate) channel_id: String,
    pub(crate) messages: Vec<ChannelMessageItem>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChannelInfo {
    pub(crate) channel_id: String,
    pub(crate) owner_user_id: String,
    pub(crate) display_name: String,
    pub(crate) description: String,
    pub(crate) subscriber_count: i64,
    pub(crate) created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ChannelListResponse {
    pub(crate) channels: Vec<ChannelInfo>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SubscribeChannelResponse {
    pub(crate) channel_id: String,
    pub(crate) subscribed_at: String,
}
