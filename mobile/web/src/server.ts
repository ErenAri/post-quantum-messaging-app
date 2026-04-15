import { RequestAuthHeaders } from "./crypto";
import { validateWebServerUrl } from "./webEnvironment";

export class PqmsgApiError extends Error {
  readonly status: number;
  readonly detail: string;

  constructor(status: number, detail: string) {
    const normalizedDetail = normalizeApiErrorDetail(detail);
    super(normalizedDetail ? `HTTP ${status}: ${normalizedDetail}` : `HTTP ${status}`);
    this.name = "PqmsgApiError";
    this.status = status;
    this.detail = normalizedDetail;
  }
}

export type RegisterUserRequest = {
  user_id: string;
  identity_x25519_pub: string;
  identity_sig_pub: string;
  identity_pq_sig_pub: string;
  device_id: string;
  pow_nonce?: string;
};

export type RegisterUserResponse = {
  user_id: string;
  device_id: string;
  registered_at: string;
};

export type PublishPrekeysRequest = {
  signed_prekey_x25519_pub: string;
  sig_over_spk: string;
  pq_signed_prekey_pub_mlkem768: string;
  sig_over_pqspk: string;
  pq_sig_over_spk: string;
  pq_sig_over_pqspk: string;
  one_time_prekeys_x25519: string[];
  one_time_prekeys_mlkem768: string[];
};

export type PublishPrekeysResponse = {
  user_id: string;
  device_id: string;
  uploaded_one_time_prekeys_x25519: number;
  uploaded_one_time_prekeys_mlkem768: number;
  remaining_one_time_prekeys_x25519: number;
  remaining_one_time_prekeys_mlkem768: number;
  low_one_time_prekeys: boolean;
  minimum_recommended_one_time_prekeys: number;
  updated_at: string;
};

export type BundleResponse = {
  user_id: string;
  device_id: string;
  identity_x25519_pub: string;
  identity_sig_pub: string;
  identity_pq_sig_pub: string;
  signed_prekey_x25519_pub: string;
  sig_over_spk: string;
  pq_signed_prekey_pub_mlkem768: string;
  sig_over_pqspk: string;
  pq_sig_over_spk: string;
  pq_sig_over_pqspk: string;
  one_time_prekey_x25519: string | null;
  one_time_prekey_mlkem768: string | null;
  identity_fingerprint_sha256: string | null;
  identity_key_version: number;
  bundle_generated_at: string;
};

export type RelayRequest = {
  sender_user_id: string;
  device_id: string;
  message_bytes_base64: string;
};

export type RelayResponse = {
  message_id: number;
  received_at: string;
};

export type InboxMessage = {
  message_id: number;
  sender_user_id: string;
  message_bytes_base64: string;
  received_at: string;
};

export type InboxResponse = {
  user_id: string;
  messages: InboxMessage[];
};

export type RetireCurrentDeviceResponse = {
  user_id: string;
  retired_device_id: string;
  retired_at: string;
  remaining_active_devices: number;
};

export type DeviceRecord = {
  device_id: string;
  active: boolean;
  linked_at: string;
  revoked_at: string | null;
};

export type DeviceListResponse = {
  user_id: string;
  devices: DeviceRecord[];
};

export type LinkDeviceResponse = {
  user_id: string;
  linked_device_id: string;
  linked_at: string;
};

export type BackupUploadRequest = {
  device_id: string;
  backup_version: number;
  recovery_hint?: string;
  encrypted_backup_bytes_base64: string;
};

export type BackupUploadResponse = {
  backup_id: string;
  user_id: string;
  device_id: string;
  backup_version: number;
  byte_len: number;
  uploaded_at: string;
};

export type BackupDownloadResponse = {
  backup_id: string;
  user_id: string;
  device_id: string;
  backup_version: number;
  recovery_hint: string | null;
  encrypted_backup_bytes_base64: string;
  uploaded_at: string;
};

export type RevokeDeviceResponse = {
  user_id: string;
  revoked_device_id: string;
  revoked_at: string;
};

// --- Phase 2 types ---

export type ProfileResponse = {
  user_id: string;
  display_name: string | null;
  username: string | null;
  username_lookup_enabled?: boolean | null;
  avatar_mime: string | null;
  avatar_bytes_base64: string | null;
  sealed_delivery_token: string | null;
  updated_at: string | null;
};

export type UpsertProfileRequest = {
  display_name?: string;
  username?: string;
  username_lookup_enabled?: boolean;
  avatar_mime?: string;
  avatar_bytes_base64?: string;
};

export type UsernameResolveResponse = {
  username: string;
  user_id: string;
};

export type PresenceResponse = {
  user_id: string;
  status: "online" | "away" | "offline";
  active: boolean;
  updated_at: string | null;
  expires_at: string | null;
};

export type UpdatePresenceRequest = {
  status: "online" | "away" | "offline";
};

export type TypingEntry = {
  user_id: string;
  is_typing: boolean;
  updated_at: string;
};

export type TypingResponse = {
  typing: TypingEntry[];
};

export type UpdateTypingRequest = {
  is_typing: boolean;
};

export type SendReceiptRequest = {
  message_id: number;
  receipt_type: "delivered" | "read";
};

export type ReceiptEntry = {
  receipt_id: number;
  message_id: number;
  from_user_id: string;
  receipt_type: string;
  received_at: string;
};

export type ReceiptsResponse = {
  receipts: ReceiptEntry[];
};

export type WsInboxTicketResponse = {
  ticket: string;
  expires_at: string;
};

export type ContactDiscoveryTicketResponse = {
  user_id: string;
  device_id: string;
  service_origin: string;
  ticket: string;
  ticket_nonce: string;
  expires_at: string;
};

export type ContactDiscoveryTicketRequest = {
  purpose: "upload" | "match";
};

export type ContactDiscoveryManifestResponse = {
  service: string;
  protocol_version: number;
  attestation_mode: string;
  attestation_verifier?: string | null;
  enclave_measurement_hex?: string | null;
  attestation_pcrs_sha384?: Record<string, string> | null;
  attestation_document_format?: string | null;
  attestation_document_sha256?: string | null;
  attestation_challenge_mode?: string | null;
  ticket_format: string;
  ticket_issuer_ed25519_pub: string;
  ticket_max_ttl_seconds: number;
  lookup_protocol: string;
  privacy_mode: string;
  directory_backend: string;
  host_enclave_protocol_version: number;
  host_release_id: string;
  enclave_release_id: string;
  match_result_format: string;
  oprf_suite: string;
  evaluation_proof_mode: string;
  oprf_public_key_ristretto255: string;
  signed_at: string;
  expires_at: string;
  manifest_issuer_ed25519_pub: string;
  manifest_signature_ed25519: string;
};

export type ContactDiscoveryAttestationResponse = {
  attestation_mode: string;
  attestation_verifier: string;
  enclave_measurement_hex: string;
  attested_pcrs_sha384?: Record<string, string> | null;
  directory_backend: string;
  host_enclave_protocol_version: number;
  host_release_id: string;
  enclave_release_id: string;
  manifest_contract_sha256: string;
  attested_oprf_public_key_ristretto255: string;
  document_format: string;
  document_base64: string;
  document_sha256: string;
  published_at: string;
  challenge_nonce_base64: string;
  attestation_signature_ed25519: string;
};

export type ContactEntry = {
  contact_user_id: string;
  username?: string | null;
  alias: string | null;
  verified_by_qr: boolean;
  verified_fingerprint_sha256: string | null;
  created_at: string;
  updated_at: string;
};

export type ContactsListResponse = {
  contacts: ContactEntry[];
};

export type UpsertContactRequest = {
  contact_user_id: string;
  alias?: string;
  verified_by_qr?: boolean;
  verified_fingerprint_sha256?: string;
};

export type RemoveContactRequest = {
  contact_user_id: string;
};

export type ContactInviteCreateResponse = {
  user_id: string;
  invite_token: string;
  expires_at: string;
};

export type ContactInviteResolveResponse = {
  invite_token: string;
  user_id: string;
  expires_at: string;
};

// --- Phase 3 types ---

export type CreateGroupRequest = {
  group_id: string;
  member_user_ids: string[];
};

export type CreateGroupResponse = {
  group_id: string;
  owner_user_id: string;
  member_count: number;
  created_at: string;
};

export type GroupMembershipRecord = {
  group_id: string;
  owner_user_id: string;
  joined_at: string;
  updated_at: string;
  member_count: number;
};

export type UserGroupsResponse = {
  user_id: string;
  groups: GroupMembershipRecord[];
};

export type GroupMemberRecord = {
  user_id: string;
  joined_at: string;
};

export type GroupMembersResponse = {
  group_id: string;
  members: GroupMemberRecord[];
};

export type AddGroupMemberRequest = {
  member_user_id: string;
};

export type RemoveGroupMemberRequest = {
  member_user_id: string;
};

export type GroupMemberMutationResponse = {
  group_id: string;
  member_user_id: string;
  owner_user_id: string;
  changed: boolean;
  updated_at: string;
};

export type GroupRelayRequest = {
  sender_user_id: string;
  device_id: string;
  message_bytes_base64: string;
};

export type GroupRelayResponse = {
  group_id: string;
  delivered_message_count: number;
  delivered_user_count: number;
  first_message_id: number | null;
  received_at: string;
};

export type PrivateGroupMemberCredentialRecord = {
  membership_handle_sha256: string;
  member_commitment_sha256: string;
  fetch_key_sha256: string;
  publish_key_sha256: string | null;
};

export type PublishPrivateGroupStateRequest = {
  group_id: string;
  epoch: number;
  state_commitment_sha256: string;
  ciphertext_nonce_base64: string;
  ciphertext_base64: string;
  ciphertext_aad_base64: string;
  authorizing_membership_handle_sha256: string;
  authorizing_publish_key_base64: string;
  members: PrivateGroupMemberCredentialRecord[];
};

export type PublishPrivateGroupStateResponse = {
  group_id: string;
  epoch: number;
  stored_member_count: number;
  published_at: string;
};

export type FetchPrivateGroupStateRequest = {
  membership_handle_sha256: string;
  fetch_key_base64: string;
};

export type FetchPrivateGroupStateResponse = {
  group_id: string;
  epoch: number;
  state_commitment_sha256: string;
  ciphertext_nonce_base64: string;
  ciphertext_base64: string;
  ciphertext_aad_base64: string;
  published_at: string;
};

export type CreatePrivateGroupInviteRequest = {
  group_id: string;
  epoch: number;
  invite_commitment_sha256: string;
  invite_ciphertext_nonce_base64: string;
  invite_ciphertext_base64: string;
  invite_ciphertext_aad_base64: string;
  authorizing_membership_handle_sha256: string;
  authorizing_publish_key_base64: string;
  expires_in_seconds?: number;
};

export type CreatePrivateGroupInviteResponse = {
  invite_token: string;
  group_id: string;
  epoch: number;
  expires_at: string;
  created_at: string;
};

export type ResolvePrivateGroupInviteResponse = {
  invite_token: string;
  group_id: string;
  epoch: number;
  invite_commitment_sha256: string;
  invite_ciphertext_nonce_base64: string;
  invite_ciphertext_base64: string;
  invite_ciphertext_aad_base64: string;
  created_at: string;
  expires_at: string;
};

export type ConsumePrivateGroupInviteResponse = {
  invite_token: string;
  consumed: boolean;
  revoked_at: string;
};

export type PublishPrivateGroupMessageRequest = {
  group_id: string;
  epoch: number;
  sent_at_unix_ms: number;
  ciphertext_nonce_base64: string;
  ciphertext_base64: string;
  ciphertext_aad_base64: string;
  sender_hybrid_signature_base64: string;
  authorizing_membership_handle_sha256: string;
  authorizing_fetch_key_base64: string;
};

export type PublishPrivateGroupMessageResponse = {
  message_id: number;
  group_id: string;
  epoch: number;
  received_at: string;
};

export type FetchPrivateGroupMessagesRequest = {
  membership_handle_sha256: string;
  fetch_key_base64: string;
  since_message_id?: number;
};

export type PrivateGroupMessageItem = {
  message_id: number;
  group_id: string;
  epoch: number;
  sent_at_unix_ms: number;
  ciphertext_nonce_base64: string;
  ciphertext_base64: string;
  ciphertext_aad_base64: string;
  sender_hybrid_signature_base64: string;
  received_at: string;
};

export type FetchPrivateGroupMessagesResponse = {
  group_id: string;
  epoch: number;
  messages: PrivateGroupMessageItem[];
  fetched_at: string;
};

export type FileUploadRequest = {
  recipient_user_id: string;
  device_id: string;
  mime_type: string;
  file_bytes_base64: string;
};

export type FileUploadResponse = {
  file_id: string;
  owner_user_id: string;
  recipient_user_id: string;
  mime_type: string;
  byte_len: number;
  uploaded_at: string;
};

export type FileDownloadResponse = {
  file_id: string;
  owner_user_id: string;
  recipient_user_id: string;
  mime_type: string;
  file_bytes_base64: string;
  uploaded_at: string;
};

export type DeleteInboxRequest = {
  message_ids: number[];
  delete_before_id?: number;
};

export type DeleteInboxResponse = {
  user_id: string;
  device_id: string;
  deleted_count: number;
  deleted_at: string;
};

export type PrekeysStatusResponse = {
  user_id: string;
  device_id: string;
  remaining_one_time_prekeys_x25519: number;
  remaining_one_time_prekeys_mlkem768: number;
  low_one_time_prekeys: boolean;
  minimum_recommended_one_time_prekeys: number;
  checked_at: string;
};

// --- Phase 4 types ---

export type RotateInitRequest = {
  new_identity_x25519_pub: string;
  new_identity_sig_pub: string;
  new_identity_pq_sig_pub: string;
  new_device_id: string;
};

export type RotateInitResponse = {
  user_id: string;
  challenge_id: string;
  challenge_nonce: string;
  expires_at: string;
};

export type RotateConfirmRequest = {
  challenge_id: string;
  sig_by_current_identity: string;
  sig_by_new_identity: string;
  pq_sig_by_current_identity: string;
  pq_sig_by_new_identity: string;
};

export type RotateConfirmResponse = {
  user_id: string;
  identity_key_version: number;
  identity_fingerprint_sha256: string;
  rotated_at: string;
};

export type IdentityLogItem = {
  version: number;
  identity_x25519_pub: string;
  identity_sig_pub: string;
  identity_pq_sig_pub?: string | null;
  device_id: string;
  event_type: string;
  changed_at: string;
  identity_fingerprint_sha256: string;
};

export type IdentityLogResponse = {
  user_id: string;
  events: IdentityLogItem[];
};

export type TransparencyLeafRecord = {
  user_id: string;
  version: number;
  identity_x25519_pub: string;
  identity_sig_pub: string;
  identity_pq_sig_pub: string | null;
  timestamp: number;
};

export type TransparencyPathItem = {
  hash: string;
  is_left: boolean;
};

export type TransparencyInclusionProofResponse = {
  leaf_index: number;
  path: TransparencyPathItem[];
};

export type TransparencyConsistencyProofResponse = {
  old_size: number;
  new_size: number;
  proof_hashes: string[];
};

export type TransparencySignedTreeHeadResponse = {
  epoch: number;
  tree_size: number;
  root_hash: string;
  signature: string;
};

export type TransparencyProofResponse = {
  user_id: string;
  leaf: TransparencyLeafRecord;
  inclusion_proof: TransparencyInclusionProofResponse;
  signed_tree_head: TransparencySignedTreeHeadResponse;
  consistency_proof: TransparencyConsistencyProofResponse | null;
};

export type SealedRelayRequest = {
  delivery_token: string;
  message_bytes_base64: string;
};

export type SealedRelayResponse = {
  delivered_device_count: number;
  first_message_id: number | null;
  received_at: string;
};

export type SenderCertificateResponse = {
  user_id: string;
  device_id: string;
  certificate_base64: string;
  expires_at: string;
};

export type SealedInboxItem = {
  message_id: number;
  sender_identity_x25519_pub?: string | null;
  message_bytes_base64: string;
  received_at: string;
};

export type SealedInboxResponse = {
  user_id: string;
  messages: SealedInboxItem[];
};

export type RelayEphemeralRequest = {
  sender_user_id: string;
  device_id: string;
  message_bytes_base64: string;
  ttl_seconds: number;
};

export type RelayEphemeralResponse = {
  message_id: number;
  delivered_device_count: number;
  received_at: string;
};

// --- Call signaling types ---

export type CallOfferRequest = {
  caller_user_id: string;
  device_id: string;
  sdp_offer_base64: string;
  call_type: "audio" | "video";
};

export type CallOfferResponse = {
  call_id: string;
  created_at: string;
};

export type CallAnswerRequest = {
  callee_user_id: string;
  device_id: string;
  sdp_answer_base64: string;
};

export type CallAnswerResponse = {
  call_id: string;
  answered_at: string;
};

export type IceCandidateRequest = {
  sender_user_id: string;
  device_id: string;
  candidate_base64: string;
};

export type IceCandidateResponse = {
  call_id: string;
  queued_at: string;
};

export type CallHangupRequest = {
  user_id: string;
  device_id: string;
  reason: string;
};

export type CallHangupResponse = {
  call_id: string;
  ended_at: string;
};

export type CallSignal = {
  signal_id: number;
  signal_type: string;
  from_user_id: string;
  payload_base64: string;
  created_at: string;
};

export type PollCallSignalsResponse = {
  call_id: string;
  signals: CallSignal[];
};

// Phase 5: Discovery
export type DiscoveryHandlesUploadRequest = {
  phone_hashes_sha256: string[];
  email_hashes_sha256: string[];
};

export type DiscoveryHandlesUploadResponse = {
  user_id: string;
  device_id: string;
  uploaded_phone_hashes: number;
  uploaded_email_hashes: number;
  updated_at: string;
};

export type DiscoveryMatchRequest = {
  hashes_sha256: string[];
};

export type DiscoveryMatchItem = {
  hash_sha256: string;
  contact_invite_token: string;
  handle_kind: string;
};

export type DiscoveryMatchResponse = {
  user_id: string;
  matches: DiscoveryMatchItem[];
  checked_at: string;
};

export type PrivateDiscoveryEvaluateRequest = {
  ticket: string;
  blinded_elements_base64: string[];
};

export type PrivateDiscoveryEvaluateResponse = {
  user_id: string;
  device_id: string;
  ticket_nonce: string;
  manifest_contract_sha256: string;
  evaluation_proof_mode: string;
  evaluated_elements_base64: string[];
  dleq_proofs: Array<{
    challenge_scalar_base64: string;
    response_scalar_base64: string;
    commitment_base_base64: string;
    commitment_blinded_base64: string;
  }>;
  evaluated_at: string;
};

export type PrivateDiscoveryHandlesUploadRequest = {
  ticket: string;
  phone_tokens_sha256: string[];
  email_tokens_sha256: string[];
};

export type PrivateDiscoveryHandlesUploadResponse = {
  user_id: string;
  device_id: string;
  ticket_nonce: string;
  manifest_contract_sha256: string;
  uploaded_phone_tokens: number;
  uploaded_email_tokens: number;
  updated_at: string;
};

export type PrivateDiscoveryMatchRequest = {
  ticket: string;
  tokens_sha256: string[];
};

export type PrivateDiscoveryMatchItem = {
  token_sha256: string;
  contact_invite_token: string;
  handle_kind: string;
};

export type PrivateDiscoveryMatchResponse = {
  user_id: string;
  ticket_nonce: string;
  manifest_contract_sha256: string;
  matches: PrivateDiscoveryMatchItem[];
  checked_at: string;
};

// Phase 5: Push Token
export type RegisterPushTokenRequest = {
  device_id: string;
  provider?: string | null;
  token?: string | null;
  fcm_token?: string | null;
};

export type RegisterPushTokenResponse = {
  user_id: string;
  device_id: string;
  provider: string;
  registered_at: string;
};

// Phase 5: Health
export type HealthStatusResponse = {
  status: string;
  security_profile: string;
  deployment_mode: string;
  db_backend: string;
  db_ready: boolean;
  db_pool_size: number;
  db_pool_idle: number;
  push_enabled: boolean;
  push_providers: string[];
  audit_logger_enabled: boolean;
  tls_enabled: boolean;
  rate_limiter_mode: string;
  replay_cache_mode: string;
  realtime_mode: string;
  supported_suite_ids: number[];
  runtime_crypto_profile: RuntimeCryptoProfileResponse;
  production_baseline_met: boolean;
  registration_pow_bits: number;
  prekey_publish_min_interval_seconds: number;
  prekey_bundle_reserve_count: number;
  pq_ratchet_interval: number;
};

export type RuntimeCryptoProfileResponse = {
  protocol_version: number;
  suite_id: number;
  kem: string;
  dh: string;
  kdf: string;
  aead: string;
  signature: string;
  pq_oqs_enabled: boolean;
  fips_mode: boolean;
};

export type ServerCapabilitiesResponse = {
  capability_schema_version: number;
  security_profile: string;
  deployment_mode: string;
  tls_required: boolean;
  tls_enabled: boolean;
  supported_beta_clients: string[];
  supported_suite_ids: number[];
  runtime_crypto_profile: RuntimeCryptoProfileResponse;
  production_baseline_met: boolean;
  registration_pow_bits: number;
  prekey_bundle_reserve_count: number;
  pq_ratchet_interval: number;
  contact_discovery_supported: boolean;
  contact_discovery_mode: string;
  contact_discovery_ticket_supported: boolean;
  contact_discovery_service_origin: string | null;
  contact_discovery_manifest_issuer_ed25519_pub: string | null;
  contact_discovery_directory_backend: string | null;
  contact_discovery_host_enclave_protocol_version: number | null;
  contact_discovery_host_release_id: string | null;
  contact_discovery_enclave_release_id: string | null;
  contact_discovery_expected_manifest_contract_sha256?: string | null;
  contact_discovery_attestation_verifier: string | null;
  contact_discovery_expected_measurement_hex: string | null;
  contact_discovery_expected_pcrs_sha384: Record<string, string> | null;
  contact_discovery_attestation_document_sha256: string | null;
  contact_discovery_attestation_max_age_seconds: number | null;
  presence_supported: boolean;
  typing_indicators_supported: boolean;
  read_receipts_supported: boolean;
  calling_supported: boolean;
  stories_supported: boolean;
  channels_supported: boolean;
  group_messaging_supported: boolean;
  private_group_state_supported: boolean;
  private_group_messaging_supported: boolean;
  sealed_sender_required: boolean;
  sender_certificate_supported: boolean;
  key_transparency_supported: boolean;
  sealed_delivery_tokens_supported: boolean;
  contact_discovery_ticket_issuer_ed25519_pub: string;
  sender_certificate_issuer_ed25519_pub: string;
  transparency_log_issuer_ed25519_pub: string;
  authenticated_direct_messaging_supported: boolean;
  ephemeral_messaging_supported: boolean;
  web_client_policy: string;
};

export class PqmsgApi {
  private readonly baseUrl: string;

  constructor(serverUrl: string) {
    const normalized = serverUrl.trim().replace(/\/+$/, "");
    if (!normalized) {
      throw new Error("server URL is empty");
    }
    validateWebServerUrl(normalized);
    this.baseUrl = normalized;
  }

  async pingRoot(): Promise<void> {
    await this.request<void>("GET", "/", undefined, {});
  }

  async getCapabilities(): Promise<ServerCapabilitiesResponse> {
    return this.request<ServerCapabilitiesResponse>("GET", "/v1/capabilities", undefined, {});
  }

  async getTransparencyProof(
    userId: string,
    previousTreeSize?: number,
  ): Promise<TransparencyProofResponse> {
    const query = previousTreeSize && previousTreeSize > 0
      ? `?previous_tree_size=${encodeURIComponent(String(previousTreeSize))}`
      : "";
    return this.request<TransparencyProofResponse>(
      "GET",
      `/v1/transparency/users/${encodeURIComponent(userId)}/proof${query}`,
      undefined,
      {},
    );
  }

  async registerUser(payload: RegisterUserRequest): Promise<RegisterUserResponse> {
    return this.request<RegisterUserResponse>("POST", "/v1/users/register", payload, {});
  }

  async resetDevUserIdentity(userId: string): Promise<void> {
    await this.request<void>(
      "POST",
      `/v1/dev/users/${encodeURIComponent(userId)}/reset`,
      undefined,
      {}
    );
  }

  async publishPrekeys(
    userId: string,
    payload: PublishPrekeysRequest,
    headers: RequestAuthHeaders
  ): Promise<PublishPrekeysResponse> {
    return this.request<PublishPrekeysResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/prekeys`,
      payload,
      headers
    );
  }

  async getBundle(userId: string): Promise<BundleResponse> {
    return this.request<BundleResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/bundle`,
      undefined,
      {}
    );
  }

  async relay(
    recipientUserId: string,
    payload: RelayRequest,
    headers: RequestAuthHeaders
  ): Promise<RelayResponse> {
    return this.request<RelayResponse>(
      "POST",
      `/v1/relay/${encodeURIComponent(recipientUserId)}`,
      payload,
      headers
    );
  }

  async inbox(
    userId: string,
    since: number,
    headers: RequestAuthHeaders
  ): Promise<InboxResponse> {
    return this.request<InboxResponse>(
      "GET",
      `/v1/inbox/${encodeURIComponent(userId)}?since=${encodeURIComponent(String(since))}`,
      undefined,
      headers
    );
  }

  async listDevices(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<DeviceListResponse> {
    return this.request<DeviceListResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/devices`,
      undefined,
      headers
    );
  }

  async linkDevice(
    userId: string,
    newDeviceId: string,
    headers: RequestAuthHeaders
  ): Promise<LinkDeviceResponse> {
    return this.request<LinkDeviceResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/devices/link`,
      { new_device_id: newDeviceId },
      headers
    );
  }

  async uploadBackup(
    userId: string,
    payload: BackupUploadRequest,
    headers: RequestAuthHeaders
  ): Promise<BackupUploadResponse> {
    return this.request<BackupUploadResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/backups`,
      payload,
      headers
    );
  }

  async downloadRecoveryBackup(userId: string): Promise<BackupDownloadResponse> {
    return this.request<BackupDownloadResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/backups/recovery`,
      undefined,
      {}
    );
  }

  async revokeDevice(
    userId: string,
    targetDeviceId: string,
    headers: RequestAuthHeaders
  ): Promise<RevokeDeviceResponse> {
    return this.request<RevokeDeviceResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/devices/${encodeURIComponent(targetDeviceId)}/revoke`,
      undefined,
      headers
    );
  }

  async retireCurrentDevice(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<RetireCurrentDeviceResponse> {
    return this.request<RetireCurrentDeviceResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/devices/current/retire`,
      undefined,
      headers
    );
  }

  // --- Phase 2 API methods ---

  async getProfile(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<ProfileResponse> {
    return this.request<ProfileResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/profile`,
      undefined,
      headers
    );
  }

  async upsertProfile(
    userId: string,
    payload: UpsertProfileRequest,
    headers: RequestAuthHeaders
  ): Promise<ProfileResponse> {
    return this.request<ProfileResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/profile`,
      payload,
      headers
    );
  }

  async resolveUsername(
    username: string
  ): Promise<UsernameResolveResponse> {
    const normalized = username.trim().replace(/^@/, "");
    return this.request<UsernameResolveResponse>(
      "GET",
      `/v1/usernames/${encodeURIComponent(normalized)}`,
      undefined,
      {}
    );
  }

  async getUsernameBundle(
    username: string
  ): Promise<BundleResponse> {
    const normalized = username.trim().replace(/^@/, "");
    return this.request<BundleResponse>(
      "GET",
      `/v1/usernames/${encodeURIComponent(normalized)}/bundle`,
      undefined,
      {}
    );
  }

  async getPresence(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<PresenceResponse> {
    return this.request<PresenceResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/presence`,
      undefined,
      headers
    );
  }

  async updatePresence(
    userId: string,
    payload: UpdatePresenceRequest,
    headers: RequestAuthHeaders
  ): Promise<PresenceResponse> {
    return this.request<PresenceResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/presence`,
      payload,
      headers
    );
  }

  async getTyping(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<TypingResponse> {
    return this.request<TypingResponse>(
      "GET",
      `/v1/typing/${encodeURIComponent(userId)}`,
      undefined,
      headers
    );
  }

  async updateTyping(
    peerUserId: string,
    payload: UpdateTypingRequest,
    headers: RequestAuthHeaders
  ): Promise<void> {
    await this.request<void>(
      "POST",
      `/v1/typing/${encodeURIComponent(peerUserId)}`,
      payload,
      headers
    );
  }

  async sendReceipt(
    userId: string,
    payload: SendReceiptRequest,
    headers: RequestAuthHeaders
  ): Promise<void> {
    await this.request<void>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/receipts`,
      payload,
      headers
    );
  }

  async getReceipts(
    userId: string,
    sinceId: number,
    headers: RequestAuthHeaders
  ): Promise<ReceiptsResponse> {
    return this.request<ReceiptsResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/receipts/poll?since_id=${encodeURIComponent(String(sinceId))}`,
      undefined,
      headers
    );
  }

  async createInboxWsTicket(
    userId: string,
    since: number,
    headers: RequestAuthHeaders
  ): Promise<WsInboxTicketResponse> {
    return this.request<WsInboxTicketResponse>(
      "POST",
      `/v1/ws/inbox/${encodeURIComponent(userId)}/ticket?since=${encodeURIComponent(String(since))}`,
      undefined,
      headers
    );
  }

  async createSealedInboxWsTicket(
    userId: string,
    since: number,
    headers: RequestAuthHeaders
  ): Promise<WsInboxTicketResponse> {
    return this.request<WsInboxTicketResponse>(
      "POST",
      `/v1/ws/sealed-inbox/${encodeURIComponent(userId)}/ticket?since=${encodeURIComponent(String(since))}`,
      undefined,
      headers
    );
  }

  async listContacts(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<ContactsListResponse> {
    return this.request<ContactsListResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/contacts`,
      undefined,
      headers
    );
  }

  async upsertContact(
    userId: string,
    payload: UpsertContactRequest,
    headers: RequestAuthHeaders
  ): Promise<void> {
    await this.request<void>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/contacts`,
      payload,
      headers
    );
  }

  async removeContact(
    userId: string,
    payload: RemoveContactRequest,
    headers: RequestAuthHeaders
  ): Promise<void> {
    await this.request<void>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/contacts/remove`,
      payload,
      headers
    );
  }

  async createContactInvite(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<ContactInviteCreateResponse> {
    return this.request<ContactInviteCreateResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/contact-invites`,
      undefined,
      headers
    );
  }

  async resolveContactInvite(
    inviteToken: string
  ): Promise<ContactInviteResolveResponse> {
    return this.request<ContactInviteResolveResponse>(
      "GET",
      `/v1/contact-invites/${encodeURIComponent(inviteToken)}`,
      undefined,
      {}
    );
  }

  async getContactInviteBundle(
    inviteToken: string
  ): Promise<BundleResponse> {
    return this.request<BundleResponse>(
      "GET",
      `/v1/contact-invites/${encodeURIComponent(inviteToken)}/bundle`,
      undefined,
      {}
    );
  }

  // --- Phase 3 API methods ---

  async publishPrivateGroupState(
    payload: PublishPrivateGroupStateRequest
  ): Promise<PublishPrivateGroupStateResponse> {
    return this.request<PublishPrivateGroupStateResponse>(
      "POST",
      "/v1/private-groups/state/publish",
      payload,
      {}
    );
  }

  async fetchPrivateGroupState(
    payload: FetchPrivateGroupStateRequest
  ): Promise<FetchPrivateGroupStateResponse> {
    return this.request<FetchPrivateGroupStateResponse>(
      "POST",
      "/v1/private-groups/state/fetch",
      payload,
      {}
    );
  }

  async createPrivateGroupInvite(
    payload: CreatePrivateGroupInviteRequest
  ): Promise<CreatePrivateGroupInviteResponse> {
    return this.request<CreatePrivateGroupInviteResponse>(
      "POST",
      "/v1/private-groups/invites",
      payload,
      {}
    );
  }

  async resolvePrivateGroupInvite(
    inviteToken: string
  ): Promise<ResolvePrivateGroupInviteResponse> {
    return this.request<ResolvePrivateGroupInviteResponse>(
      "GET",
      `/v1/private-groups/invites/${encodeURIComponent(inviteToken)}`,
      undefined,
      {}
    );
  }

  async consumePrivateGroupInvite(
    inviteToken: string
  ): Promise<ConsumePrivateGroupInviteResponse> {
    return this.request<ConsumePrivateGroupInviteResponse>(
      "POST",
      `/v1/private-groups/invites/${encodeURIComponent(inviteToken)}`,
      undefined,
      {}
    );
  }

  async publishPrivateGroupMessage(
    payload: PublishPrivateGroupMessageRequest
  ): Promise<PublishPrivateGroupMessageResponse> {
    return this.request<PublishPrivateGroupMessageResponse>(
      "POST",
      "/v1/private-groups/messages/publish",
      payload,
      {}
    );
  }

  async fetchPrivateGroupMessages(
    payload: FetchPrivateGroupMessagesRequest
  ): Promise<FetchPrivateGroupMessagesResponse> {
    return this.request<FetchPrivateGroupMessagesResponse>(
      "POST",
      "/v1/private-groups/messages/fetch",
      payload,
      {}
    );
  }

  async createGroup(
    payload: CreateGroupRequest,
    headers: RequestAuthHeaders
  ): Promise<CreateGroupResponse> {
    return this.request<CreateGroupResponse>(
      "POST",
      "/v1/groups",
      payload,
      headers
    );
  }

  async listUserGroups(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<UserGroupsResponse> {
    return this.request<UserGroupsResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/groups`,
      undefined,
      headers
    );
  }

  async listGroupMembers(
    groupId: string,
    headers: RequestAuthHeaders
  ): Promise<GroupMembersResponse> {
    return this.request<GroupMembersResponse>(
      "GET",
      `/v1/groups/${encodeURIComponent(groupId)}/members`,
      undefined,
      headers
    );
  }

  async addGroupMember(
    groupId: string,
    payload: AddGroupMemberRequest,
    headers: RequestAuthHeaders
  ): Promise<GroupMemberMutationResponse> {
    return this.request<GroupMemberMutationResponse>(
      "POST",
      `/v1/groups/${encodeURIComponent(groupId)}/members/add`,
      payload,
      headers
    );
  }

  async removeGroupMember(
    groupId: string,
    payload: RemoveGroupMemberRequest,
    headers: RequestAuthHeaders
  ): Promise<GroupMemberMutationResponse> {
    return this.request<GroupMemberMutationResponse>(
      "POST",
      `/v1/groups/${encodeURIComponent(groupId)}/members/remove`,
      payload,
      headers
    );
  }

  async relayGroupMessage(
    groupId: string,
    payload: GroupRelayRequest,
    headers: RequestAuthHeaders
  ): Promise<GroupRelayResponse> {
    return this.request<GroupRelayResponse>(
      "POST",
      `/v1/groups/${encodeURIComponent(groupId)}/relay`,
      payload,
      headers
    );
  }

  async uploadFile(
    payload: FileUploadRequest,
    headers: RequestAuthHeaders
  ): Promise<FileUploadResponse> {
    return this.request<FileUploadResponse>(
      "POST",
      "/v1/files/upload",
      payload,
      headers
    );
  }

  async downloadFile(
    fileId: string,
    headers: RequestAuthHeaders
  ): Promise<FileDownloadResponse> {
    return this.request<FileDownloadResponse>(
      "GET",
      `/v1/files/${encodeURIComponent(fileId)}`,
      undefined,
      headers
    );
  }

  async deleteInboxMessages(
    userId: string,
    payload: DeleteInboxRequest,
    headers: RequestAuthHeaders
  ): Promise<DeleteInboxResponse> {
    return this.request<DeleteInboxResponse>(
      "POST",
      `/v1/inbox/${encodeURIComponent(userId)}/delete`,
      payload,
      headers
    );
  }

  async getPrekeysStatus(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<PrekeysStatusResponse> {
    return this.request<PrekeysStatusResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/prekeys/status`,
      undefined,
      headers
    );
  }

  // --- Phase 4 API methods ---

  async rotateInit(
    userId: string,
    payload: RotateInitRequest,
    headers: RequestAuthHeaders
  ): Promise<RotateInitResponse> {
    return this.request<RotateInitResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/rotate/init`,
      payload,
      headers
    );
  }

  async rotateConfirm(
    userId: string,
    payload: RotateConfirmRequest,
    headers: RequestAuthHeaders
  ): Promise<RotateConfirmResponse> {
    return this.request<RotateConfirmResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/rotate/confirm`,
      payload,
      headers
    );
  }

  async getIdentityLog(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<IdentityLogResponse> {
    return this.request<IdentityLogResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/identity-log`,
      undefined,
      headers
    );
  }

  async sealedRelay(
    recipientUserId: string,
    payload: SealedRelayRequest
  ): Promise<SealedRelayResponse> {
    return this.request<SealedRelayResponse>(
      "POST",
      `/v1/sealed-relay/${encodeURIComponent(recipientUserId)}`,
      payload,
      {}
    );
  }

  async sealedInbox(
    userId: string,
    since: number,
    headers: RequestAuthHeaders
  ): Promise<SealedInboxResponse> {
    return this.request<SealedInboxResponse>(
      "GET",
      `/v1/sealed-inbox/${encodeURIComponent(userId)}?since=${encodeURIComponent(String(since))}`,
      undefined,
      headers
    );
  }

  async getSenderCertificate(
    userId: string,
    headers: RequestAuthHeaders
  ): Promise<SenderCertificateResponse> {
    return this.request<SenderCertificateResponse>(
      "GET",
      `/v1/users/${encodeURIComponent(userId)}/sender-certificate`,
      undefined,
      headers
    );
  }

  async anonBundle(userId: string): Promise<BundleResponse> {
    return this.request<BundleResponse>(
      "GET",
      `/v1/anon/users/${encodeURIComponent(userId)}/bundle`,
      undefined,
      {}
    );
  }

  async relayEphemeral(
    recipientUserId: string,
    payload: RelayEphemeralRequest,
    headers: RequestAuthHeaders
  ): Promise<RelayEphemeralResponse> {
    return this.request<RelayEphemeralResponse>(
      "POST",
      `/v1/ephemeral-relay/${encodeURIComponent(recipientUserId)}`,
      payload,
      headers
    );
  }

  async uploadDiscoveryHandles(
    userId: string,
    payload: DiscoveryHandlesUploadRequest,
    headers: RequestAuthHeaders
  ): Promise<DiscoveryHandlesUploadResponse> {
    return this.request<DiscoveryHandlesUploadResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/discovery/handles`,
      payload,
      headers
    );
  }

  async discoveryMatch(
    userId: string,
    payload: DiscoveryMatchRequest,
    headers: RequestAuthHeaders
  ): Promise<DiscoveryMatchResponse> {
    return this.request<DiscoveryMatchResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/discovery/match`,
      payload,
      headers
    );
  }

  async issueContactDiscoveryTicket(
    userId: string,
    headers: RequestAuthHeaders,
    request: ContactDiscoveryTicketRequest,
  ): Promise<ContactDiscoveryTicketResponse> {
    return this.request<ContactDiscoveryTicketResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/contact-discovery/ticket`,
      request,
      headers
    );
  }

  async getContactDiscoveryManifest(serviceOrigin: string): Promise<ContactDiscoveryManifestResponse> {
    const parsed = validateWebServerUrl(serviceOrigin);
    const normalized = `${parsed.origin}`;
    const response = await fetch(`${normalized}/v1/manifest`, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new PqmsgApiError(response.status, await response.text());
    }
    return response.json() as Promise<ContactDiscoveryManifestResponse>;
  }

  async getContactDiscoveryAttestation(
    serviceOrigin: string,
    challengeNonceB64: string,
  ): Promise<ContactDiscoveryAttestationResponse> {
    const parsed = validateWebServerUrl(serviceOrigin);
    const normalized = `${parsed.origin}`;
    const url = new URL(`${normalized}/v1/attestation`);
    url.searchParams.set("nonce_b64", challengeNonceB64);
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new PqmsgApiError(response.status, await response.text());
    }
    return response.json() as Promise<ContactDiscoveryAttestationResponse>;
  }

  async evaluateDiscoveryElementsAtService(
    serviceOrigin: string,
    payload: PrivateDiscoveryEvaluateRequest,
  ): Promise<PrivateDiscoveryEvaluateResponse> {
    const parsed = validateWebServerUrl(serviceOrigin);
    const normalized = `${parsed.origin}`;
    const response = await fetch(`${normalized}/v1/discovery/evaluate`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new PqmsgApiError(response.status, await response.text());
    }
    return response.json() as Promise<PrivateDiscoveryEvaluateResponse>;
  }

  async uploadDiscoveryHandlesToService(
    serviceOrigin: string,
    payload: PrivateDiscoveryHandlesUploadRequest
  ): Promise<PrivateDiscoveryHandlesUploadResponse> {
    const parsed = validateWebServerUrl(serviceOrigin);
    const normalized = `${parsed.origin}`;
    const response = await fetch(`${normalized}/v1/discovery/handles`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new PqmsgApiError(response.status, await response.text());
    }
    return response.json() as Promise<PrivateDiscoveryHandlesUploadResponse>;
  }

  async matchDiscoveryHashesAtService(
    serviceOrigin: string,
    payload: PrivateDiscoveryMatchRequest
  ): Promise<PrivateDiscoveryMatchResponse> {
    const parsed = validateWebServerUrl(serviceOrigin);
    const normalized = `${parsed.origin}`;
    const response = await fetch(`${normalized}/v1/discovery/match`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new PqmsgApiError(response.status, await response.text());
    }
    return response.json() as Promise<PrivateDiscoveryMatchResponse>;
  }

  async registerPushToken(
    userId: string,
    payload: RegisterPushTokenRequest,
    headers: RequestAuthHeaders
  ): Promise<RegisterPushTokenResponse> {
    return this.request<RegisterPushTokenResponse>(
      "POST",
      `/v1/users/${encodeURIComponent(userId)}/push-token`,
      payload,
      headers
    );
  }

  // --- Call signaling API methods ---

  async callOffer(
    calleeUserId: string,
    payload: CallOfferRequest,
    headers: RequestAuthHeaders
  ): Promise<CallOfferResponse> {
    return this.request<CallOfferResponse>(
      "POST",
      `/v1/calls/${encodeURIComponent(calleeUserId)}/offer`,
      payload,
      headers
    );
  }

  async callAnswer(
    callId: string,
    payload: CallAnswerRequest,
    headers: RequestAuthHeaders
  ): Promise<CallAnswerResponse> {
    return this.request<CallAnswerResponse>(
      "POST",
      `/v1/calls/${encodeURIComponent(callId)}/answer`,
      payload,
      headers
    );
  }

  async callIceCandidate(
    callId: string,
    payload: IceCandidateRequest,
    headers: RequestAuthHeaders
  ): Promise<IceCandidateResponse> {
    return this.request<IceCandidateResponse>(
      "POST",
      `/v1/calls/${encodeURIComponent(callId)}/ice`,
      payload,
      headers
    );
  }

  async callHangup(
    callId: string,
    payload: CallHangupRequest,
    headers: RequestAuthHeaders
  ): Promise<CallHangupResponse> {
    return this.request<CallHangupResponse>(
      "POST",
      `/v1/calls/${encodeURIComponent(callId)}/hangup`,
      payload,
      headers
    );
  }

  async pollCallSignals(
    callId: string,
    sinceSignalId: number,
    headers: RequestAuthHeaders
  ): Promise<PollCallSignalsResponse> {
    return this.request<PollCallSignalsResponse>(
      "GET",
      `/v1/calls/${encodeURIComponent(callId)}/signals?since=${encodeURIComponent(String(sinceSignalId))}`,
      undefined,
      headers
    );
  }

  async getHealth(): Promise<HealthStatusResponse> {
    return this.request<HealthStatusResponse>("GET", "/health", undefined, {});
  }

  async getMetrics(): Promise<string> {
    const endpoint = `${this.baseUrl}/metrics`;
    const response = await fetch(endpoint);
    if (!response.ok) {
      throw new PqmsgApiError(response.status, await response.text());
    }
    return response.text();
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body: unknown,
    headers: Record<string, string>
  ): Promise<T> {
    const endpoint = `${this.baseUrl}${path}`;
    const requestHeaders = new Headers(headers);
    requestHeaders.set("accept", "application/json");
    if (body !== undefined) {
      requestHeaders.set("content-type", "application/json");
    }
    const response = await fetch(endpoint, {
      method,
      headers: requestHeaders,
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (!response.ok) {
      throw new PqmsgApiError(response.status, await response.text());
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }
}

function normalizeApiErrorDetail(detail: string): string {
  return detail
    .replace(/<[^>]*>/g, " ")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 280);
}
