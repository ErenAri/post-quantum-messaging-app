package com.pqmsg.demo

import okhttp3.OkHttpClient
import okhttp3.CertificatePinner
import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.HttpUrl.Companion.toHttpUrl
import retrofit2.Retrofit
import retrofit2.Response
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.HeaderMap
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

data class RegisterUserRequest(
    val user_id: String,
    val identity_x25519_pub: String,
    val identity_sig_pub: String,
    val device_id: String,
)

data class RegisterUserResponse(
    val user_id: String,
    val device_id: String,
    val registered_at: String,
)

data class PublishPrekeysRequest(
    val signed_prekey_x25519_pub: String,
    val sig_over_spk: String,
    val pq_signed_prekey_pub_mlkem768: String,
    val sig_over_pqspk: String,
    val one_time_prekeys_x25519: List<String>,
    val one_time_prekeys_mlkem768: List<String>,
)

data class PublishPrekeysResponse(
    val user_id: String,
    val device_id: String,
    val uploaded_one_time_prekeys_x25519: Int,
    val uploaded_one_time_prekeys_mlkem768: Int,
    val remaining_one_time_prekeys_x25519: Int,
    val remaining_one_time_prekeys_mlkem768: Int,
    val low_one_time_prekeys: Boolean,
    val minimum_recommended_one_time_prekeys: Int,
    val updated_at: String,
)

data class PrekeysStatusResponse(
    val user_id: String,
    val device_id: String,
    val remaining_one_time_prekeys_x25519: Int,
    val remaining_one_time_prekeys_mlkem768: Int,
    val low_one_time_prekeys: Boolean,
    val minimum_recommended_one_time_prekeys: Int,
    val checked_at: String,
)

data class RegisterPushTokenRequest(
    val device_id: String,
    val provider: String? = null,
    val token: String? = null,
    val fcm_token: String? = null,
)

data class RegisterPushTokenResponse(
    val user_id: String,
    val device_id: String,
    val provider: String,
    val registered_at: String,
)

data class RetireCurrentDeviceResponse(
    val user_id: String,
    val retired_device_id: String,
    val retired_at: String,
    val remaining_active_devices: Int,
)

data class LinkDeviceRequest(
    val new_device_id: String,
)

data class LinkDeviceResponse(
    val user_id: String,
    val linked_device_id: String,
    val linked_at: String,
)

data class RevokeDeviceResponse(
    val user_id: String,
    val revoked_device_id: String,
    val revoked_at: String,
)

data class DeviceRecord(
    val device_id: String,
    val active: Boolean,
    val linked_at: String,
    val revoked_at: String?,
)

data class DeviceListResponse(
    val user_id: String,
    val devices: List<DeviceRecord>,
)

data class RotateInitRequest(
    val new_identity_x25519_pub: String,
    val new_identity_sig_pub: String,
    val new_device_id: String,
)

data class RotateInitResponse(
    val user_id: String,
    val challenge_id: String,
    val challenge_nonce: String,
    val expires_at: String,
)

data class RotateConfirmRequest(
    val challenge_id: String,
    val sig_by_current_identity: String,
    val sig_by_new_identity: String,
)

data class RotateConfirmResponse(
    val user_id: String,
    val identity_key_version: Int,
    val identity_fingerprint_sha256: String,
    val rotated_at: String,
)

data class IdentityLogItem(
    val version: Int,
    val identity_x25519_pub: String,
    val identity_sig_pub: String,
    val device_id: String,
    val event_type: String,
    val changed_at: String,
    val identity_fingerprint_sha256: String,
)

data class IdentityLogResponse(
    val user_id: String,
    val events: List<IdentityLogItem>,
)

data class BundleResponse(
    val user_id: String,
    val device_id: String,
    val identity_x25519_pub: String,
    val identity_sig_pub: String,
    val signed_prekey_x25519_pub: String,
    val sig_over_spk: String,
    val pq_signed_prekey_pub_mlkem768: String,
    val sig_over_pqspk: String,
    val one_time_prekey_x25519: String?,
    val one_time_prekey_mlkem768: String?,
    val remaining_one_time_prekeys_x25519: Int?,
    val remaining_one_time_prekeys_mlkem768: Int?,
    val low_one_time_prekeys: Boolean?,
    val minimum_recommended_one_time_prekeys: Int?,
    val last_resort_prekey_only: Boolean?,
    val identity_key_version: Int?,
    val identity_fingerprint_sha256: String?,
    val bundle_generated_at: String,
)

data class RelayRequest(
    val sender_user_id: String,
    val device_id: String,
    val message_bytes_base64: String,
)

data class RelayResponse(
    val message_id: Long,
    val received_at: String,
)

data class InboxMessage(
    val message_id: Long,
    val sender_user_id: String,
    val message_bytes_base64: String,
    val received_at: String,
)

data class InboxResponse(
    val user_id: String,
    val messages: List<InboxMessage>,
)

data class DeleteInboxRequest(
    val message_ids: List<Long>,
    val delete_before_id: Long?,
)

data class DeleteInboxResponse(
    val user_id: String,
    val device_id: String,
    val deleted_count: Long,
    val deleted_at: String,
)

// Groups

data class CreateGroupRequest(
    val group_id: String,
    val member_user_ids: List<String>,
)

data class CreateGroupResponse(
    val group_id: String,
    val owner_user_id: String,
    val member_count: Int,
    val created_at: String,
)

data class GroupMembershipRecord(
    val group_id: String,
    val owner_user_id: String,
    val joined_at: String,
    val updated_at: String,
    val member_count: Int,
)

data class UserGroupsResponse(
    val user_id: String,
    val groups: List<GroupMembershipRecord>,
)

data class AddGroupMemberRequest(
    val member_user_id: String,
)

data class RemoveGroupMemberRequest(
    val member_user_id: String,
)

data class GroupMemberRecord(
    val user_id: String,
    val joined_at: String,
)

data class GroupMembersResponse(
    val group_id: String,
    val members: List<GroupMemberRecord>,
)

data class GroupMemberMutationResponse(
    val group_id: String,
    val member_user_id: String,
    val owner_user_id: String,
    val changed: Boolean,
    val updated_at: String,
)

data class GroupRelayRequest(
    val sender_user_id: String,
    val device_id: String,
    val message_bytes_base64: String,
)

data class GroupRelayResponse(
    val group_id: String,
    val delivered_message_count: Int,
    val delivered_user_count: Int,
    val first_message_id: Long?,
    val received_at: String,
)

// Sealed Sender

data class SealedRelayRequest(
    val message_bytes_base64: String,
)

data class SealedRelayResponse(
    val delivered_device_count: Int,
    val first_message_id: Long?,
    val received_at: String,
)

data class SealedInboxItem(
    val message_id: Long,
    val message_bytes_base64: String,
    val received_at: String,
)

data class SealedInboxResponse(
    val user_id: String,
    val messages: List<SealedInboxItem>,
)

// Discovery & Contacts

data class DiscoveryHandlesUploadRequest(
    val phone_hashes_sha256: List<String>,
    val email_hashes_sha256: List<String>,
)

data class DiscoveryHandlesUploadResponse(
    val user_id: String,
    val device_id: String,
    val uploaded_phone_hashes: Int,
    val uploaded_email_hashes: Int,
    val updated_at: String,
)

data class DiscoveryMatchRequest(
    val hashes_sha256: List<String>,
)

data class DiscoveryMatchItem(
    val hash_sha256: String,
    val matched_user_id: String,
    val handle_kind: String,
)

data class DiscoveryMatchResponse(
    val user_id: String,
    val matches: List<DiscoveryMatchItem>,
    val checked_at: String,
)

data class UpsertContactRequest(
    val contact_user_id: String,
    val alias: String?,
    val verified_by_qr: Boolean?,
    val verified_fingerprint_sha256: String?,
)

data class UpsertContactResponse(
    val user_id: String,
    val contact_user_id: String,
    val alias: String?,
    val verified_by_qr: Boolean,
    val verified_fingerprint_sha256: String?,
    val updated_at: String,
)

data class ContactListItem(
    val contact_user_id: String,
    val alias: String?,
    val verified_by_qr: Boolean,
    val verified_fingerprint_sha256: String?,
    val created_at: String,
    val updated_at: String,
)

data class ContactListResponse(
    val user_id: String,
    val contacts: List<ContactListItem>,
)

data class RemoveContactRequest(
    val contact_user_id: String,
)

data class RemoveContactResponse(
    val user_id: String,
    val removed_contact_user_id: String,
    val removed: Boolean,
    val removed_at: String,
)

// Profile & Presence & Typing

data class UpsertProfileRequest(
    val display_name: String?,
    val avatar_mime: String?,
    val avatar_bytes_base64: String?,
)

data class UserProfileResponse(
    val user_id: String,
    val display_name: String?,
    val avatar_mime: String?,
    val avatar_bytes_base64: String?,
    val updated_at: String?,
)

data class PresenceUpdateRequest(
    val status: String,
)

data class PresenceResponse(
    val user_id: String,
    val status: String,
    val active: Boolean,
    val updated_at: String?,
    val expires_at: String?,
)

data class TypingUpdateRequest(
    val is_typing: Boolean,
)

data class TypingUpdateResponse(
    val recipient_user_id: String,
    val sender_user_id: String,
    val sender_device_id: String,
    val is_typing: Boolean,
    val updated_at: String,
    val expires_at: String?,
)

data class TypingIndicator(
    val sender_user_id: String,
    val sender_device_id: String,
    val updated_at: String,
    val expires_at: String,
)

data class TypingInboxResponse(
    val user_id: String,
    val typing: List<TypingIndicator>,
    val checked_at: String,
)

// Receipts

data class SendReceiptRequest(
    val message_id: Long,
    val receipt_type: String,
)

data class SendReceiptResponse(
    val message_id: Long,
    val receipt_type: String,
    val created_at: String,
)

data class ReceiptItem(
    val message_id: Long,
    val recipient_user_id: String,
    val recipient_device_id: String,
    val receipt_type: String,
    val created_at: String,
)

data class ReceiptsResponse(
    val sender_user_id: String,
    val receipts: List<ReceiptItem>,
)

// Ephemeral Messages

data class RelayEphemeralRequest(
    val sender_user_id: String,
    val device_id: String,
    val message_bytes_base64: String,
    val ttl_seconds: Long,
)

// File Upload/Download

data class FileUploadRequest(
    val recipient_user_id: String,
    val device_id: String,
    val mime_type: String,
    val file_bytes_base64: String,
)

data class FileUploadResponse(
    val file_id: String,
    val owner_user_id: String,
    val recipient_user_id: String,
    val mime_type: String,
    val byte_len: Int,
    val uploaded_at: String,
)

data class FileDownloadResponse(
    val file_id: String,
    val owner_user_id: String,
    val recipient_user_id: String,
    val mime_type: String,
    val file_bytes_base64: String,
    val uploaded_at: String,
)

data class RuntimeCryptoProfileResponse(
    val protocol_version: Int,
    val suite_id: Int,
    val kem: String,
    val dh: String,
    val kdf: String,
    val aead: String,
    val signature: String,
    val pq_oqs_enabled: Boolean,
    val fips_mode: Boolean,
)

data class ServerCapabilitiesResponse(
    val capability_schema_version: Int,
    val security_profile: String,
    val deployment_mode: String,
    val tls_required: Boolean,
    val tls_enabled: Boolean,
    val supported_suite_ids: List<Int>,
    val runtime_crypto_profile: RuntimeCryptoProfileResponse,
    val production_baseline_met: Boolean,
    val registration_pow_bits: Int,
    val prekey_bundle_reserve_count: Int,
    val pq_ratchet_interval: Int,
    val web_client_policy: String,
)

// Call Signaling

data class CallOfferRequest(
    val caller_user_id: String,
    val device_id: String,
    val sdp_offer_base64: String,
    val call_type: String,
)

data class CallOfferResponse(
    val call_id: String,
    val created_at: String,
)

data class CallAnswerRequest(
    val callee_user_id: String,
    val device_id: String,
    val sdp_answer_base64: String,
)

data class CallAnswerResponse(
    val call_id: String,
    val answered_at: String,
)

data class IceCandidateRequest(
    val sender_user_id: String,
    val device_id: String,
    val candidate_base64: String,
)

data class IceCandidateResponse(
    val call_id: String,
    val queued_at: String,
)

data class CallHangupRequest(
    val user_id: String,
    val device_id: String,
    val reason: String,
)

data class CallHangupResponse(
    val call_id: String,
    val ended_at: String,
)

data class CallSignal(
    val signal_type: String,
    val from_user_id: String,
    val payload_base64: String,
    val created_at: String,
)

data class PollCallSignalsResponse(
    val call_id: String,
    val signals: List<CallSignal>,
)

interface PqmsgApi {
    @GET("/")
    suspend fun pingRoot(): Response<Unit>

    @GET("/v1/capabilities")
    suspend fun getCapabilities(): ServerCapabilitiesResponse

    @POST("/v1/users/register")
    suspend fun registerUser(@Body request: RegisterUserRequest): RegisterUserResponse

    @POST("/v1/users/{user_id}/prekeys")
    suspend fun publishPrekeys(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: PublishPrekeysRequest,
    ): PublishPrekeysResponse

    @GET("/v1/users/{user_id}/prekeys/status")
    suspend fun prekeysStatus(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): PrekeysStatusResponse

    @POST("/v1/users/{user_id}/push-token")
    suspend fun registerPushToken(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RegisterPushTokenRequest,
    ): RegisterPushTokenResponse

    @POST("/v1/users/{user_id}/devices/current/retire")
    suspend fun retireCurrentDevice(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): RetireCurrentDeviceResponse

    @GET("/v1/users/{user_id}/devices")
    suspend fun listDevices(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): DeviceListResponse

    @POST("/v1/users/{user_id}/devices/link")
    suspend fun linkDevice(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: LinkDeviceRequest,
    ): LinkDeviceResponse

    @POST("/v1/users/{user_id}/devices/{target_device_id}/revoke")
    suspend fun revokeDevice(
        @Path("user_id") userId: String,
        @Path("target_device_id") targetDeviceId: String,
        @HeaderMap headers: Map<String, String>,
    ): RevokeDeviceResponse

    @POST("/v1/users/{user_id}/rotate/init")
    suspend fun rotateInit(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RotateInitRequest,
    ): RotateInitResponse

    @POST("/v1/users/{user_id}/rotate/confirm")
    suspend fun rotateConfirm(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RotateConfirmRequest,
    ): RotateConfirmResponse

    @GET("/v1/users/{user_id}/identity-log")
    suspend fun identityLog(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): IdentityLogResponse

    @GET("/v1/users/{user_id}/bundle")
    suspend fun getBundle(@Path("user_id") userId: String): BundleResponse

    @POST("/v1/relay/{recipient_user_id}")
    suspend fun relay(
        @Path("recipient_user_id") recipientUserId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RelayRequest,
    ): RelayResponse

    @GET("/v1/inbox/{user_id}")
    suspend fun inbox(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Query("since") since: Long,
    ): InboxResponse

    @POST("/v1/inbox/{user_id}/delete")
    suspend fun deleteInbox(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: DeleteInboxRequest,
    ): DeleteInboxResponse

    // Groups

    @POST("/v1/groups")
    suspend fun createGroup(
        @HeaderMap headers: Map<String, String>,
        @Body request: CreateGroupRequest,
    ): CreateGroupResponse

    @GET("/v1/users/{user_id}/groups")
    suspend fun listUserGroups(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): UserGroupsResponse

    @GET("/v1/groups/{group_id}/members")
    suspend fun listGroupMembers(
        @Path("group_id") groupId: String,
        @HeaderMap headers: Map<String, String>,
    ): GroupMembersResponse

    @POST("/v1/groups/{group_id}/members/add")
    suspend fun addGroupMember(
        @Path("group_id") groupId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: AddGroupMemberRequest,
    ): GroupMemberMutationResponse

    @POST("/v1/groups/{group_id}/members/remove")
    suspend fun removeGroupMember(
        @Path("group_id") groupId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RemoveGroupMemberRequest,
    ): GroupMemberMutationResponse

    @POST("/v1/groups/{group_id}/relay")
    suspend fun relayGroupMessage(
        @Path("group_id") groupId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: GroupRelayRequest,
    ): GroupRelayResponse

    // Sealed sender

    @POST("/v1/sealed-relay/{recipient_user_id}")
    suspend fun sealedRelay(
        @Path("recipient_user_id") recipientUserId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: SealedRelayRequest,
    ): SealedRelayResponse

    @GET("/v1/sealed-inbox/{user_id}")
    suspend fun sealedInbox(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Query("since") since: Long,
    ): SealedInboxResponse

    // Contact discovery

    @POST("/v1/users/{user_id}/discovery/handles")
    suspend fun uploadDiscoveryHandles(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: DiscoveryHandlesUploadRequest,
    ): DiscoveryHandlesUploadResponse

    @POST("/v1/users/{user_id}/discovery/match")
    suspend fun matchDiscoveryHashes(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: DiscoveryMatchRequest,
    ): DiscoveryMatchResponse

    @GET("/v1/users/{user_id}/contacts")
    suspend fun listContacts(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): ContactListResponse

    @POST("/v1/users/{user_id}/contacts")
    suspend fun upsertContact(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: UpsertContactRequest,
    ): UpsertContactResponse

    @POST("/v1/users/{user_id}/contacts/remove")
    suspend fun removeContact(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RemoveContactRequest,
    ): RemoveContactResponse

    // Profile & Presence

    @GET("/v1/users/{user_id}/profile")
    suspend fun getUserProfile(
        @Path("user_id") userId: String,
    ): UserProfileResponse

    @POST("/v1/users/{user_id}/profile")
    suspend fun upsertUserProfile(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: UpsertProfileRequest,
    ): UserProfileResponse

    @GET("/v1/users/{user_id}/presence")
    suspend fun getPresence(
        @Path("user_id") userId: String,
    ): PresenceResponse

    @POST("/v1/users/{user_id}/presence")
    suspend fun updatePresence(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: PresenceUpdateRequest,
    ): PresenceResponse

    // Typing indicators

    @GET("/v1/typing/{user_id}")
    suspend fun getTyping(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
    ): TypingInboxResponse

    @POST("/v1/typing/{peer_user_id}")
    suspend fun updateTyping(
        @Path("peer_user_id") peerUserId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: TypingUpdateRequest,
    ): TypingUpdateResponse

    // Receipts

    @POST("/v1/users/{user_id}/receipts")
    suspend fun sendReceipt(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: SendReceiptRequest,
    ): SendReceiptResponse

    @GET("/v1/users/{user_id}/receipts/poll")
    suspend fun getReceipts(
        @Path("user_id") userId: String,
        @HeaderMap headers: Map<String, String>,
        @Query("since_id") sinceId: Long?,
    ): ReceiptsResponse

    // Ephemeral messages

    @POST("/v1/ephemeral-relay/{recipient_user_id}")
    suspend fun relayEphemeralMessage(
        @Path("recipient_user_id") recipientUserId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: RelayEphemeralRequest,
    ): RelayResponse

    // File upload/download

    @POST("/v1/files/upload")
    suspend fun uploadFile(
        @HeaderMap headers: Map<String, String>,
        @Body request: FileUploadRequest,
    ): FileUploadResponse

    @GET("/v1/files/{file_id}")
    suspend fun downloadFile(
        @Path("file_id") fileId: String,
        @HeaderMap headers: Map<String, String>,
    ): FileDownloadResponse

    // Call signaling

    @POST("/v1/calls/{callee_user_id}/offer")
    suspend fun callOffer(
        @Path("callee_user_id") calleeUserId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: CallOfferRequest,
    ): CallOfferResponse

    @POST("/v1/calls/{call_id}/answer")
    suspend fun callAnswer(
        @Path("call_id") callId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: CallAnswerRequest,
    ): CallAnswerResponse

    @POST("/v1/calls/{call_id}/ice")
    suspend fun callIceCandidate(
        @Path("call_id") callId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: IceCandidateRequest,
    ): IceCandidateResponse

    @POST("/v1/calls/{call_id}/hangup")
    suspend fun callHangup(
        @Path("call_id") callId: String,
        @HeaderMap headers: Map<String, String>,
        @Body request: CallHangupRequest,
    ): CallHangupResponse

    @GET("/v1/calls/{call_id}/signals")
    suspend fun pollCallSignals(
        @Path("call_id") callId: String,
        @HeaderMap headers: Map<String, String>,
        @Query("since") sinceSignalId: Long?,
    ): PollCallSignalsResponse
}

object ApiClientFactory {
    fun create(serverUrl: String): PqmsgApi {
        val policy = resolveTransportPolicy(
            serverUrl,
            BuildConfig.ALLOW_CLEARTEXT_DEMO,
            BuildConfig.TLS_PIN_SHA256,
        )
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BASIC
        }
        val baseUrl = policy.baseUrl.toHttpUrl()
        val clientBuilder = OkHttpClient.Builder()
            .addInterceptor(logging)
        val certificatePin = policy.certificatePin
        if (certificatePin != null) {
            clientBuilder.certificatePinner(
                CertificatePinner.Builder()
                    .add(baseUrl.host, certificatePin)
                    .build()
            )
        }
        val client = clientBuilder.build()
        return Retrofit.Builder()
            .baseUrl(policy.baseUrl)
            .addConverterFactory(GsonConverterFactory.create())
            .client(client)
            .build()
            .create(PqmsgApi::class.java)
    }

    data class TransportPolicy(
        val baseUrl: String,
        val certificatePin: String?,
    )

    internal fun resolveTransportPolicy(
        base: String,
        allowCleartextDemo: Boolean,
        tlsPinSha256: String,
    ): TransportPolicy {
        val normalized = normalizeBaseUrl(base)
        val url = normalized.toHttpUrl()
        return when (url.scheme) {
            "http" -> {
                require(allowCleartextDemo && isLocalDemoHost(url.host)) {
                    "HTTP transport is only allowed for local demo hosts in debug mode"
                }
                TransportPolicy(baseUrl = normalized, certificatePin = null)
            }

            "https" -> {
                val pin = tlsPinSha256.trim()
                require(pin.isNotBlank()) { "HTTPS requires BuildConfig.TLS_PIN_SHA256" }
                require(pin.startsWith("sha256/")) {
                    "TLS pin must start with 'sha256/'"
                }
                TransportPolicy(baseUrl = normalized, certificatePin = pin)
            }

            else -> error("unsupported URL scheme '${url.scheme}'")
        }
    }

    internal fun normalizeBaseUrl(base: String): String {
        val trimmed = base.trim()
        require(trimmed.isNotBlank()) { "server URL is empty" }
        val normalized = if (trimmed.endsWith("/")) trimmed else "$trimmed/"
        val url = normalized.toHttpUrl()
        require(url.scheme == "http" || url.scheme == "https") {
            "server URL must use http or https"
        }
        return normalized
    }

    internal fun isLocalDemoHost(host: String): Boolean {
        return host == "10.0.2.2" || host == "127.0.0.1" || host == "localhost"
    }

    internal fun suiteIdForLabel(label: String): Int {
        return if (label.trim().equals("kyber768", ignoreCase = true)) {
            2
        } else {
            1
        }
    }

    internal fun validateCapabilities(
        capabilities: ServerCapabilitiesResponse,
        suiteLabel: String,
    ) {
        require(capabilities.capability_schema_version == 1) {
            "Unsupported server capability schema ${capabilities.capability_schema_version}"
        }
        val suiteId = suiteIdForLabel(suiteLabel)
        require(capabilities.supported_suite_ids.contains(suiteId)) {
            "Server does not support suite '${suiteLabel.trim()}'"
        }
        require(!capabilities.tls_required || capabilities.tls_enabled) {
            "Server requires TLS but is not advertising an active TLS transport"
        }
        require(
            capabilities.security_profile == "research" ||
                capabilities.runtime_crypto_profile.pq_oqs_enabled
        ) {
            "Server is not running a PQ-enabled crypto backend"
        }
        require(
            capabilities.deployment_mode == "development" ||
                capabilities.production_baseline_met
        ) {
            "Server '${capabilities.deployment_mode}' deployment is missing its production baseline"
        }
    }
}
