package com.pqmsg.demo

import android.net.Uri
import com.google.gson.Gson
import uniffi.pqmsg_android.privateGroupDescribeMemberCredential
import java.util.Base64

data class PrivateGroupAttributes(
    val title: String,
    val description: String?,
    val avatar_hash_sha256: String?,
    val disappearing_message_timer_seconds: Long?,
)

data class PrivateGroupMember(
    val user_id: String,
    val role: String,
)

data class PrivateGroupState(
    val group_id: String,
    val epoch: Long,
    val root_secret: List<Int>,
    val attributes: PrivateGroupAttributes,
    val members: List<PrivateGroupMember>,
    val created_at_unix_seconds: Long,
    val updated_at_unix_seconds: Long,
)

data class PrivateGroupCiphertextEnvelope(
    val nonce: List<Int>,
    val ciphertext: List<Int>,
    val aad: List<Int>,
)

data class PrivateGroupEncryptedSnapshot(
    val group_id: String,
    val epoch: Long,
    val state_commitment_sha256: List<Int>,
    val ciphertext: PrivateGroupCiphertextEnvelope,
)

data class PrivateGroupMemberCredential(
    val group_id: String,
    val epoch: Long,
    val member_user_id: String,
    val role: String,
    val credential_secret: List<Int>,
)

data class PrivateGroupJoinPackage(
    val invite: PrivateGroupInvitePackage,
    val member_credential: PrivateGroupMemberCredential,
)

data class PrivateGroupInvitePackage(
    val group_id: String,
    val epoch: Long,
    val root_secret: List<Int>,
    val snapshot: PrivateGroupEncryptedSnapshot,
)

data class PrivateGroupLinkInviteEnvelope(
    val group_id: String,
    val epoch: Long,
    val invite_commitment_sha256: List<Int>,
    val ciphertext: PrivateGroupCiphertextEnvelope,
)

data class PrivateGroupLinkInviteMaterial(
    val invite_secret: List<Int>,
    val envelope: PrivateGroupLinkInviteEnvelope,
)

data class PrivateGroupCredentialMaterial(
    val membership_handle_sha256: String,
    val member_commitment_sha256: String,
    val fetch_key_base64: String,
    val fetch_key_sha256: String,
    val publish_key_base64: String?,
    val publish_key_sha256: String?,
)

data class PrivateGroupRestoreResult(
    val state: PrivateGroupState,
    val member_credential: PrivateGroupMemberCredential,
)

data class PrivateGroupMemberJoinPackage(
    val member_user_id: String,
    val join_package: PrivateGroupJoinPackage,
)

data class PrivateGroupBootstrapMaterial(
    val snapshot: PrivateGroupEncryptedSnapshot,
    val authorizing_member_credential: PrivateGroupMemberCredential,
    val member_credentials: List<PrivateGroupMemberCredential>,
    val member_join_packages: List<PrivateGroupMemberJoinPackage>,
)

data class PrivateGroupEpochTransition(
    val next_state: PrivateGroupState,
    val member_credentials: List<PrivateGroupMemberCredential>,
    val added_member_join_package: PrivateGroupJoinPackage?,
)

data class PrivateGroupInviteTarget(
    val serverUrl: String,
    val inviteToken: String,
    val inviteSecretBase64: String,
)

data class PrivateGroupWrappedMessage(
    val kind: String,
    val group_id: String,
    val body: String,
    val sent_at_unix_ms: Long,
)

data class DecodedPrivateGroupMessage(
    val groupId: String,
    val body: String,
)

private val privateGroupGson = Gson()
const val PRIVATE_GROUP_MESSAGE_PREFIX = "pqmsg-private-group-message-v1:"
private const val GROUP_INVITE_SECRET_FRAGMENT_KEY = "group_secret"

fun parsePrivateGroupStateJson(stateJson: String): PrivateGroupState =
    privateGroupGson.fromJson(stateJson, PrivateGroupState::class.java)

fun parsePrivateGroupCredentialJson(memberCredentialJson: String): PrivateGroupMemberCredential =
    privateGroupGson.fromJson(memberCredentialJson, PrivateGroupMemberCredential::class.java)

fun parsePrivateGroupBootstrapMaterial(bootstrapJson: String): PrivateGroupBootstrapMaterial =
    privateGroupGson.fromJson(bootstrapJson, PrivateGroupBootstrapMaterial::class.java)

fun parsePrivateGroupRestoreResult(restoredJson: String): PrivateGroupRestoreResult =
    privateGroupGson.fromJson(restoredJson, PrivateGroupRestoreResult::class.java)

fun parsePrivateGroupEpochTransition(transitionJson: String): PrivateGroupEpochTransition =
    privateGroupGson.fromJson(transitionJson, PrivateGroupEpochTransition::class.java)

fun parsePrivateGroupLinkInviteMaterial(materialJson: String): PrivateGroupLinkInviteMaterial =
    privateGroupGson.fromJson(materialJson, PrivateGroupLinkInviteMaterial::class.java)

fun parsePrivateGroupJoinPackage(joinPackageJson: String): PrivateGroupJoinPackage =
    privateGroupGson.fromJson(joinPackageJson, PrivateGroupJoinPackage::class.java)

fun findPrivateGroupCredentialForUser(
    memberCredentials: List<PrivateGroupMemberCredential>,
    userId: String,
): PrivateGroupMemberCredential {
    return memberCredentials.firstOrNull { it.member_user_id == userId }
        ?: error("Private-group credential for @$userId is missing from the current epoch.")
}

fun getPrivateGroupOwnerUserId(state: PrivateGroupState): String {
    return state.members.firstOrNull { it.role.equals("Owner", ignoreCase = true) }?.user_id
        ?: state.members.firstOrNull()?.user_id
        ?: ""
}

fun getPrivateGroupTitle(state: PrivateGroupState, fallbackGroupId: String = state.group_id): String {
    return state.attributes.title.trim().ifBlank { fallbackGroupId }
}

fun isPrivateGroupMember(state: PrivateGroupState, userId: String): Boolean {
    return state.members.any { it.user_id == userId }
}

fun buildPrivateGroupInviteLink(serverUrl: String, inviteToken: String, inviteSecretBase64: String): String {
    return Uri.Builder()
        .scheme("pqmsg")
        .authority("chat")
        .appendQueryParameter("group_invite_token", inviteToken.trim())
        .appendQueryParameter("server", ApiClientFactory.normalizeBaseUrl(serverUrl).trimEnd('/'))
        .encodedFragment("$GROUP_INVITE_SECRET_FRAGMENT_KEY=${Uri.encode(inviteSecretBase64)}")
        .build()
        .toString()
}

fun extractPrivateGroupInviteTarget(rawInput: String, fallbackServerUrl: String): PrivateGroupInviteTarget? {
    val trimmed = rawInput.trim()
    if (trimmed.isBlank()) {
        return null
    }
    val parsed = runCatching { Uri.parse(trimmed) }.getOrNull() ?: return null
    val inviteToken = parsed.getQueryParameter("group_invite_token")
        ?.trim()
        .orEmpty()
        .ifBlank { parsed.getQueryParameter("group_token")?.trim().orEmpty() }
        .ifBlank { parsed.getQueryParameter("pg_invite_token")?.trim().orEmpty() }
    val inviteSecret = parseFragmentParam(parsed.fragment, GROUP_INVITE_SECRET_FRAGMENT_KEY)
        .ifBlank { parsed.getQueryParameter("group_secret")?.trim().orEmpty() }
    if (inviteToken.isBlank() || inviteSecret.isBlank()) {
        return null
    }
    val resolvedServer = parsed.getQueryParameter("server")
        ?.trim()
        .orEmpty()
        .ifBlank { fallbackServerUrl }
    return PrivateGroupInviteTarget(
        serverUrl = ApiClientFactory.normalizeBaseUrl(resolvedServer),
        inviteToken = inviteToken,
        inviteSecretBase64 = inviteSecret,
    )
}

fun encodePrivateGroupMessage(groupId: String, body: String): String {
    return PRIVATE_GROUP_MESSAGE_PREFIX + privateGroupGson.toJson(
        PrivateGroupWrappedMessage(
            kind = "pqmsg-private-group-message-v1",
            group_id = groupId,
            body = body,
            sent_at_unix_ms = System.currentTimeMillis(),
        ),
    )
}

fun decodePrivateGroupMessage(
    plaintext: String,
    senderUserId: String,
    store: LocalStateStore,
    localUserId: String,
): DecodedPrivateGroupMessage? {
    if (!plaintext.startsWith(PRIVATE_GROUP_MESSAGE_PREFIX)) {
        return null
    }
    val payload = runCatching {
        privateGroupGson.fromJson(
            plaintext.removePrefix(PRIVATE_GROUP_MESSAGE_PREFIX),
            PrivateGroupWrappedMessage::class.java,
        )
    }.getOrNull() ?: return null
    if (payload.kind != "pqmsg-private-group-message-v1" || payload.group_id.isBlank() || payload.body.isBlank()) {
        return null
    }
    val localState = store.readPrivateGroupState(localUserId, payload.group_id) ?: return null
    val state = parsePrivateGroupStateJson(localState.stateJson)
    if (!isPrivateGroupMember(state, senderUserId)) {
        return null
    }
    return DecodedPrivateGroupMessage(groupId = payload.group_id, body = payload.body)
}

fun privateGroupCredentialRecord(material: PrivateGroupCredentialMaterial): PrivateGroupMemberCredentialRecord {
    return PrivateGroupMemberCredentialRecord(
        membership_handle_sha256 = material.membership_handle_sha256,
        member_commitment_sha256 = material.member_commitment_sha256,
        fetch_key_sha256 = material.fetch_key_sha256,
        publish_key_sha256 = material.publish_key_sha256,
    )
}

suspend fun publishPrivateGroupBootstrap(
    api: PqmsgApi,
    bootstrap: PrivateGroupBootstrapMaterial,
): String {
    val authorizingMaterial = describePrivateGroupMemberCredential(bootstrap.authorizing_member_credential)
    val publishKeyBase64 = authorizingMaterial.publish_key_base64
        ?: error("Current private-group credential cannot publish state.")
    val stateCommitmentSha256 = bootstrap.snapshot.state_commitment_sha256.toByteArray().toHex()
    api.publishPrivateGroupState(
        PublishPrivateGroupStateRequest(
            group_id = bootstrap.snapshot.group_id,
            epoch = bootstrap.snapshot.epoch,
            state_commitment_sha256 = stateCommitmentSha256,
            ciphertext_nonce_base64 = bootstrap.snapshot.ciphertext.nonce.toByteArray().toBase64(),
            ciphertext_base64 = bootstrap.snapshot.ciphertext.ciphertext.toByteArray().toBase64(),
            ciphertext_aad_base64 = bootstrap.snapshot.ciphertext.aad.toByteArray().toBase64(),
            authorizing_membership_handle_sha256 = authorizingMaterial.membership_handle_sha256,
            authorizing_publish_key_base64 = publishKeyBase64,
            members = bootstrap.member_credentials.map { credential ->
                privateGroupCredentialRecord(describePrivateGroupMemberCredential(credential))
            },
        ),
    )
    return stateCommitmentSha256
}

suspend fun publishPrivateGroupTransition(
    api: PqmsgApi,
    state: PrivateGroupState,
    authorizingCredential: PrivateGroupMemberCredential,
    memberCredentials: List<PrivateGroupMemberCredential>,
    encryptedSnapshotJson: String,
): String {
    val authorizingMaterial = describePrivateGroupMemberCredential(authorizingCredential)
    val publishKeyBase64 = authorizingMaterial.publish_key_base64
        ?: error("Current private-group credential cannot publish state.")
    val snapshot = privateGroupGson.fromJson(encryptedSnapshotJson, PrivateGroupEncryptedSnapshot::class.java)
    val stateCommitmentSha256 = snapshot.state_commitment_sha256.toByteArray().toHex()
    api.publishPrivateGroupState(
        PublishPrivateGroupStateRequest(
            group_id = state.group_id,
            epoch = state.epoch,
            state_commitment_sha256 = stateCommitmentSha256,
            ciphertext_nonce_base64 = snapshot.ciphertext.nonce.toByteArray().toBase64(),
            ciphertext_base64 = snapshot.ciphertext.ciphertext.toByteArray().toBase64(),
            ciphertext_aad_base64 = snapshot.ciphertext.aad.toByteArray().toBase64(),
            authorizing_membership_handle_sha256 = authorizingMaterial.membership_handle_sha256,
            authorizing_publish_key_base64 = publishKeyBase64,
            members = memberCredentials.map { credential ->
                privateGroupCredentialRecord(describePrivateGroupMemberCredential(credential))
            },
        ),
    )
    return stateCommitmentSha256
}

suspend fun createPrivateGroupInviteLinkFromJoinPackage(
    api: PqmsgApi,
    serverUrl: String,
    state: PrivateGroupState,
    authorizingCredential: PrivateGroupMemberCredential,
    inviteMaterial: PrivateGroupLinkInviteMaterial,
): String {
    val authorizingMaterial = describePrivateGroupMemberCredential(authorizingCredential)
    val publishKeyBase64 = authorizingMaterial.publish_key_base64
        ?: error("Current private-group credential cannot issue invites.")
    val invite = api.createPrivateGroupInvite(
        CreatePrivateGroupInviteRequest(
            group_id = state.group_id,
            epoch = state.epoch,
            invite_commitment_sha256 = inviteMaterial.envelope.invite_commitment_sha256.toByteArray().toHex(),
            invite_ciphertext_nonce_base64 = inviteMaterial.envelope.ciphertext.nonce.toByteArray().toBase64(),
            invite_ciphertext_base64 = inviteMaterial.envelope.ciphertext.ciphertext.toByteArray().toBase64(),
            invite_ciphertext_aad_base64 = inviteMaterial.envelope.ciphertext.aad.toByteArray().toBase64(),
            authorizing_membership_handle_sha256 = authorizingMaterial.membership_handle_sha256,
            authorizing_publish_key_base64 = publishKeyBase64,
            expires_in_seconds = null,
        ),
    )
    return buildPrivateGroupInviteLink(
        serverUrl = serverUrl,
        inviteToken = invite.invite_token,
        inviteSecretBase64 = inviteMaterial.invite_secret.toByteArray().toBase64(),
    )
}

fun describePrivateGroupMemberCredential(credential: PrivateGroupMemberCredential): PrivateGroupCredentialMaterial {
    return privateGroupGson.fromJson(
        privateGroupDescribeMemberCredential(privateGroupGson.toJson(credential)),
        PrivateGroupCredentialMaterial::class.java,
    )
}

fun updateLocalPrivateGroupState(
    store: LocalStateStore,
    userId: String,
    state: PrivateGroupState,
    memberCredential: PrivateGroupMemberCredential,
    stateCommitmentSha256: String?,
    preview: String,
    incrementUnread: Boolean,
) {
    store.writePrivateGroupState(
        userId = userId,
        groupId = state.group_id,
        stateJson = privateGroupGson.toJson(state),
        memberCredentialJson = privateGroupGson.toJson(memberCredential),
        stateCommitmentSha256 = stateCommitmentSha256,
    )
    store.upsertGroupConversation(
        userId = userId,
        groupId = state.group_id,
        displayName = getPrivateGroupTitle(state),
        memberCount = state.members.size,
        lastPreview = preview,
        incrementUnread = incrementUnread,
    )
}

private fun parseFragmentParam(fragment: String?, key: String): String {
    val trimmed = fragment?.removePrefix("#")?.trim().orEmpty()
    if (trimmed.isBlank()) {
        return ""
    }
    return trimmed.split("&")
        .mapNotNull { part ->
            val pieces = part.split("=", limit = 2)
            if (pieces.firstOrNull() == key) {
                Uri.decode(pieces.getOrNull(1).orEmpty()).trim()
            } else {
                null
            }
        }
        .firstOrNull()
        .orEmpty()
}

private fun List<Int>.toByteArray(): ByteArray =
    ByteArray(size) { idx -> this[idx].toByte() }

private fun ByteArray.toBase64(): String =
    Base64.getEncoder().encodeToString(this)

private fun ByteArray.toHex(): String =
    joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

fun privateGroupBytesToHex(value: List<Int>): String =
    value.toByteArray().toHex()

fun privateGroupHexToIntList(value: String): List<Int> {
    val normalized = value.trim().lowercase()
    require(normalized.isNotBlank() && normalized.length % 2 == 0) { "Invalid private-group hex value." }
    return normalized.chunked(2).map { chunk -> chunk.toInt(16) }
}
