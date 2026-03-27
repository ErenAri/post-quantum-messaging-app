package com.pqmsg.demo

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.LinkedHashSet

data class SetupConfig(
    val serverUrl: String,
    val userId: String,
    val deviceId: String,
    val suiteLabel: String,
    val peerUserId: String,
)

data class IdentityPin(
    val fingerprintSha256: String,
    val identityKeyVersion: Int,
    val identityX25519Pub: String,
    val identitySigPub: String,
    val identityPqSigPub: String,
    val observedAt: String,
)

data class ConversationSummary(
    val peerUserId: String,
    val lastPreview: String,
    val updatedAtMillis: Long,
    val unreadCount: Int,
)

data class IdentityPinRecord(
    val peerUserId: String,
    val pin: IdentityPin,
)

data class MessageRequestSummary(
    val peerUserId: String,
    val lastPreview: String,
    val updatedAtMillis: Long,
    val unreadCount: Int,
)

data class ThreadMessage(
    val direction: String,
    val body: String,
    val sentAtMillis: Long,
    val transportMessageId: Long?,
    val ephemeralTtlSeconds: Long? = null,
    val expiresAtMillis: Long? = null,
    val receiptStatus: String? = null,
    val replyToId: Long? = null,
    val reactions: Map<String, String>? = null,
)

data class OutboxItem(
    val id: Long,
    val peerUserId: String,
    val plaintext: String,
    val createdAtMillis: Long,
    val ephemeralTtlSeconds: Long?,
    val sealedSender: Boolean,
)

data class GroupSummary(
    val groupId: String,
    val displayName: String,
    val memberCount: Int,
    val lastPreview: String,
    val updatedAtMillis: Long,
    val unreadCount: Int,
)

data class PrivateGroupLocalState(
    val groupId: String,
    val stateJson: String,
    val memberCredentialJson: String,
    val stateCommitmentSha256: String?,
    val updatedAtMillis: Long,
)

class LocalStateStore(context: Context) {
    private val legacyPrefs = context.getSharedPreferences("pqmsg_android_setup", Context.MODE_PRIVATE)
    private val rootDir = File(context.filesDir, "pqmsg")
    private val appContext = context.applicationContext
    private val masterKey = MasterKey.Builder(appContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    private val prefs: SharedPreferences = EncryptedSharedPreferences.create(
        appContext,
        "pqmsg_android_secure",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
    private val gson = Gson()
    private val messageStore by lazy(LazyThreadSafetyMode.NONE) {
        LocalMessageDatabase(appContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
    }

    fun loadSetup(): SetupConfig {
        return SetupConfig(
            serverUrl = getString("server_url", "http://10.0.2.2:3000"),
            userId = getString("user_id", ""),
            deviceId = getString("device_id", ""),
            suiteLabel = getString("suite_label", "ml-kem-768"),
            peerUserId = getString("peer_user_id", "bob"),
        )
    }

    fun saveSetup(config: SetupConfig) {
        prefs.edit()
            .putString("server_url", config.serverUrl)
            .putString("user_id", config.userId)
            .putString("device_id", config.deviceId)
            .putString("suite_label", config.suiteLabel)
            .putString("peer_user_id", config.peerUserId)
            .apply()
        removeLegacyKeys("server_url", "user_id", "device_id", "suite_label", "peer_user_id")
    }

    fun loadProgress(userId: String): SetupProgress {
        val sanitized = userId.ifBlank { "_" }
        return SetupProgress(
            keysGenerated = getBoolean("progress_${sanitized}_keys", false),
            userRegistered = getBoolean("progress_${sanitized}_registered", false),
            prekeysPublished = getBoolean("progress_${sanitized}_prekeys", false),
            serverVerified = getBoolean("progress_${sanitized}_verified", false),
        )
    }

    fun saveProgress(userId: String, progress: SetupProgress) {
        val sanitized = userId.ifBlank { "_" }
        prefs.edit()
            .putBoolean("progress_${sanitized}_keys", progress.keysGenerated)
            .putBoolean("progress_${sanitized}_registered", progress.userRegistered)
            .putBoolean("progress_${sanitized}_prekeys", progress.prekeysPublished)
            .putBoolean("progress_${sanitized}_verified", progress.serverVerified)
            .apply()
        removeLegacyKeys(
            "progress_${sanitized}_keys",
            "progress_${sanitized}_registered",
            "progress_${sanitized}_prekeys",
            "progress_${sanitized}_verified",
        )
    }

    fun clearProgress(userId: String) {
        saveProgress(userId, SetupProgress())
    }

    fun writeKeys(userId: String, keysJson: String) {
        val path = File(rootDir, "keys/$userId.json")
        writeProtectedFile(path, keysJson)
    }

    fun readKeys(userId: String): String? {
        val path = File(rootDir, "keys/$userId.json")
        return readProtectedFile(path)
    }

    fun writeSession(userId: String, peerUserId: String, sessionJson: String) {
        val path = File(rootDir, "sessions/$userId/$peerUserId.json")
        writeProtectedFile(path, sessionJson)
    }

    fun readSession(userId: String, peerUserId: String): String? {
        val path = File(rootDir, "sessions/$userId/$peerUserId.json")
        return readProtectedFile(path)
    }

    fun clearSession(userId: String, peerUserId: String) {
        val path = File(rootDir, "sessions/$userId/$peerUserId.json")
        if (path.exists()) {
            path.delete()
        }
    }

    private fun writeProtectedFile(path: File, content: String) {
        path.parentFile?.mkdirs()
        encryptedFile(path).openFileOutput().use { output ->
            output.write(content.toByteArray(StandardCharsets.UTF_8))
        }
    }

    private fun readProtectedFile(path: File): String? {
        if (!path.exists()) {
            return null
        }
        return try {
            encryptedFile(path).openFileInput().use { input ->
                String(input.readBytes(), StandardCharsets.UTF_8)
            }
        } catch (_: Exception) {
            val legacy = path.readText()
            runCatching {
                writeProtectedFile(path, legacy)
            }
            legacy
        }
    }

    private fun encryptedFile(path: File): EncryptedFile {
        return EncryptedFile.Builder(
            appContext,
            path,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()
    }

    fun readCursor(userId: String): Long {
        return getLong("cursor_$userId", 0L)
    }

    fun writeCursor(userId: String, cursor: Long) {
        prefs.edit().putLong("cursor_$userId", cursor).apply()
        removeLegacyKeys("cursor_$userId")
    }

    fun readSealedCursor(userId: String): Long {
        return getLong("sealed_cursor_$userId", 0L)
    }

    fun writeSealedCursor(userId: String, cursor: Long) {
        prefs.edit().putLong("sealed_cursor_$userId", cursor).apply()
        removeLegacyKeys("sealed_cursor_$userId")
    }

    fun readPrivateGroupCursor(userId: String, groupId: String): Long {
        if (userId.isBlank() || groupId.isBlank()) return 0L
        return getLong("private_group_cursor_${userId}_$groupId", 0L)
    }

    fun writePrivateGroupCursor(userId: String, groupId: String, cursor: Long) {
        if (userId.isBlank() || groupId.isBlank()) return
        val key = "private_group_cursor_${userId}_$groupId"
        prefs.edit().putLong(key, cursor).apply()
        removeLegacyKeys(key)
    }

    fun readTransparencyCheckpoint(serverUrl: String, userId: String): String? {
        return getNullableString(transparencyCheckpointKey(serverUrl, userId))
    }

    fun writeTransparencyCheckpoint(serverUrl: String, userId: String, checkpointJson: String) {
        val key = transparencyCheckpointKey(serverUrl, userId)
        prefs.edit()
            .putString(key, checkpointJson)
            .apply()
        removeLegacyKeys(key)
    }

    fun readContactDiscoveryCheckpoint(serverUrl: String, userId: String): String? {
        return getNullableString(contactDiscoveryCheckpointKey(serverUrl, userId))
    }

    fun writeContactDiscoveryCheckpoint(serverUrl: String, userId: String, checkpointJson: String) {
        val key = contactDiscoveryCheckpointKey(serverUrl, userId)
        prefs.edit()
            .putString(key, checkpointJson)
            .apply()
        removeLegacyKeys(key)
    }

    fun readPeerLastMessageId(userId: String, peerUserId: String): Long {
        return getLong("peer_last_${userId}_$peerUserId", 0L)
    }

    fun writePeerLastMessageId(userId: String, peerUserId: String, messageId: Long) {
        prefs.edit()
            .putLong("peer_last_${userId}_$peerUserId", messageId)
            .apply()
        removeLegacyKeys("peer_last_${userId}_$peerUserId")
    }

    fun readPeerSeenCipherHashes(userId: String, peerUserId: String): LinkedHashSet<String> {
        val stored = getStringSet("peer_seen_${userId}_$peerUserId")
        return LinkedHashSet(stored)
    }

    fun writePeerSeenCipherHashes(userId: String, peerUserId: String, hashes: Set<String>) {
        prefs.edit()
            .putStringSet("peer_seen_${userId}_$peerUserId", LinkedHashSet(hashes))
            .apply()
        removeLegacyKeys("peer_seen_${userId}_$peerUserId")
    }

    fun writeBundleFetchedAt(userId: String, peerUserId: String, timestamp: String) {
        prefs.edit()
            .putString("bundle_${userId}_$peerUserId", timestamp)
            .apply()
        removeLegacyKeys("bundle_${userId}_$peerUserId")
    }

    fun readBundleFetchedAt(userId: String, peerUserId: String): String? {
        return getNullableString("bundle_${userId}_$peerUserId")
    }

    fun readIdentityPin(userId: String, peerUserId: String): IdentityPin? {
        val keyBase = "pin_${userId}_$peerUserId"
        val fingerprint = getNullableString("${keyBase}_fp") ?: return null
        return IdentityPin(
            fingerprintSha256 = fingerprint,
            identityKeyVersion = getInt("${keyBase}_ver", 1),
            identityX25519Pub = getString("${keyBase}_x25519", ""),
            identitySigPub = getString("${keyBase}_sig", ""),
            identityPqSigPub = getString("${keyBase}_pq_sig", ""),
            observedAt = getString("${keyBase}_at", ""),
        )
    }

    fun writeIdentityPin(userId: String, peerUserId: String, pin: IdentityPin) {
        val keyBase = "pin_${userId}_$peerUserId"
        prefs.edit()
            .putString("${keyBase}_fp", pin.fingerprintSha256)
            .putInt("${keyBase}_ver", pin.identityKeyVersion)
            .putString("${keyBase}_x25519", pin.identityX25519Pub)
            .putString("${keyBase}_sig", pin.identitySigPub)
            .putString("${keyBase}_pq_sig", pin.identityPqSigPub)
            .putString("${keyBase}_at", pin.observedAt)
            .apply()
        removeLegacyKeys(
            "${keyBase}_fp",
            "${keyBase}_ver",
            "${keyBase}_x25519",
            "${keyBase}_sig",
            "${keyBase}_pq_sig",
            "${keyBase}_at",
        )
    }

    fun upsertConversation(
        userId: String,
        peerUserId: String,
        lastPreview: String,
        incrementUnread: Boolean,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val keyBase = "conv_${userId}_$peerUserId"
        val peers = readConversationPeers(userId)
        peers.add(peerUserId)
        val cleanPreview = lastPreview.trim().ifBlank { "(empty)" }
        val normalizedPreview = if (cleanPreview.length > 160) {
            cleanPreview.take(157) + "..."
        } else {
            cleanPreview
        }
        val nextUnread = if (incrementUnread) {
            getInt("${keyBase}_unread", 0) + 1
        } else {
            getInt("${keyBase}_unread", 0)
        }
        prefs.edit()
            .putStringSet(conversationPeersKey(userId), LinkedHashSet(peers))
            .putString("${keyBase}_preview", normalizedPreview)
            .putLong("${keyBase}_updated_ms", System.currentTimeMillis())
            .putInt("${keyBase}_unread", nextUnread)
            .apply()
        removeLegacyKeys(
            conversationPeersKey(userId),
            "${keyBase}_preview",
            "${keyBase}_updated_ms",
            "${keyBase}_unread",
        )
    }

    fun setConversationUnreadCount(userId: String, peerUserId: String, unreadCount: Int) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val keyBase = "conv_${userId}_$peerUserId"
        prefs.edit()
            .putInt("${keyBase}_unread", unreadCount.coerceAtLeast(0))
            .apply()
        removeLegacyKeys("${keyBase}_unread")
    }

    fun markConversationRead(userId: String, peerUserId: String) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val keyBase = "conv_${userId}_$peerUserId"
        prefs.edit()
            .putInt("${keyBase}_unread", 0)
            .apply()
        removeLegacyKeys("${keyBase}_unread")
    }

    fun listConversations(userId: String): List<ConversationSummary> {
        if (userId.isBlank()) {
            return emptyList()
        }
        return readConversationPeers(userId)
            .map { peer ->
                val keyBase = "conv_${userId}_$peer"
                ConversationSummary(
                    peerUserId = peer,
                    lastPreview = getString("${keyBase}_preview", "No messages yet"),
                    updatedAtMillis = getLong("${keyBase}_updated_ms", 0L),
                    unreadCount = getInt("${keyBase}_unread", 0),
                )
            }
            .sortedByDescending { it.updatedAtMillis }
    }

    fun isAcceptedPeer(userId: String, peerUserId: String): Boolean {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return false
        }
        return getStringSet(acceptedPeersKey(userId)).contains(peerUserId)
    }

    fun markPeerAccepted(userId: String, peerUserId: String) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val accepted = LinkedHashSet(getStringSet(acceptedPeersKey(userId)))
        accepted.add(peerUserId)
        prefs.edit()
            .putStringSet(acceptedPeersKey(userId), accepted)
            .apply()
        removeLegacyKeys(acceptedPeersKey(userId))
    }

    fun upsertMessageRequest(
        userId: String,
        peerUserId: String,
        lastPreview: String,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val keyBase = "request_${userId}_$peerUserId"
        val peers = readMessageRequestPeers(userId)
        peers.add(peerUserId)
        val cleanPreview = lastPreview.trim().ifBlank { "(empty)" }
        val normalizedPreview = if (cleanPreview.length > 160) {
            cleanPreview.take(157) + "..."
        } else {
            cleanPreview
        }
        val nextUnread = getInt("${keyBase}_unread", 0) + 1
        prefs.edit()
            .putStringSet(messageRequestPeersKey(userId), LinkedHashSet(peers))
            .putString("${keyBase}_preview", normalizedPreview)
            .putLong("${keyBase}_updated_ms", System.currentTimeMillis())
            .putInt("${keyBase}_unread", nextUnread)
            .apply()
        removeLegacyKeys(
            messageRequestPeersKey(userId),
            "${keyBase}_preview",
            "${keyBase}_updated_ms",
            "${keyBase}_unread",
        )
    }

    fun listMessageRequests(userId: String): List<MessageRequestSummary> {
        if (userId.isBlank()) {
            return emptyList()
        }
        return readMessageRequestPeers(userId)
            .map { peer ->
                val keyBase = "request_${userId}_$peer"
                MessageRequestSummary(
                    peerUserId = peer,
                    lastPreview = getString("${keyBase}_preview", "New message request"),
                    updatedAtMillis = getLong("${keyBase}_updated_ms", 0L),
                    unreadCount = getInt("${keyBase}_unread", 0),
                )
            }
            .sortedByDescending { it.updatedAtMillis }
    }

    fun acceptMessageRequest(userId: String, peerUserId: String) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val request = listMessageRequests(userId).firstOrNull { it.peerUserId == peerUserId }
        markPeerAccepted(userId, peerUserId)
        if (request != null) {
            upsertConversation(
                userId = userId,
                peerUserId = peerUserId,
                lastPreview = request.lastPreview,
                incrementUnread = false,
            )
            setConversationUnreadCount(userId, peerUserId, request.unreadCount)
        }
        dismissMessageRequest(userId, peerUserId)
    }

    fun dismissMessageRequest(userId: String, peerUserId: String) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val peers = readMessageRequestPeers(userId)
        if (!peers.remove(peerUserId)) {
            return
        }
        val keyBase = "request_${userId}_$peerUserId"
        prefs.edit()
            .putStringSet(messageRequestPeersKey(userId), LinkedHashSet(peers))
            .remove("${keyBase}_preview")
            .remove("${keyBase}_updated_ms")
            .remove("${keyBase}_unread")
            .apply()
        removeLegacyKeys(
            messageRequestPeersKey(userId),
            "${keyBase}_preview",
            "${keyBase}_updated_ms",
            "${keyBase}_unread",
        )
    }

    fun listIdentityPins(userId: String): List<IdentityPinRecord> {
        if (userId.isBlank()) {
            return emptyList()
        }
        val prefix = "pin_${userId}_"
        val suffix = "_fp"
        return (prefs.all.keys + legacyPrefs.all.keys)
            .asSequence()
            .filter { it.startsWith(prefix) && it.endsWith(suffix) }
            .distinct()
            .map { key ->
                key.removePrefix(prefix).removeSuffix(suffix)
            }
            .mapNotNull { peer ->
                readIdentityPin(userId, peer)?.let { pin ->
                    IdentityPinRecord(peerUserId = peer, pin = pin)
                }
            }
            .sortedBy { it.peerUserId }
            .toList()
    }

    fun listThreadMessages(userId: String, peerUserId: String): List<ThreadMessage> {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return emptyList()
        }
        migrateLegacyDirectThread(userId, peerUserId)
        return messageStore.listDirectMessages(userId, peerUserId)
    }

    fun appendThreadMessage(
        userId: String,
        peerUserId: String,
        direction: String,
        body: String,
        sentAtMillis: Long = System.currentTimeMillis(),
        transportMessageId: Long? = null,
        replyToId: Long? = null,
        reactions: Map<String, String>? = null,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val normalizedBody = body.trim().ifBlank { "(empty)" }
        migrateLegacyDirectThread(userId, peerUserId)
        messageStore.appendDirectMessage(
            userId,
            peerUserId,
            ThreadMessage(
                direction = direction,
                body = normalizedBody,
                sentAtMillis = sentAtMillis,
                transportMessageId = transportMessageId,
                replyToId = replyToId,
                reactions = reactions,
            ),
        )
    }

    fun updateThreadMessageReactions(
        userId: String,
        peerUserId: String,
        direction: String,
        sentAtMillis: Long,
        reactions: Map<String, String>?,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) return
        migrateLegacyDirectThread(userId, peerUserId)
        messageStore.updateDirectMessageReactions(userId, peerUserId, direction, sentAtMillis, reactions)
    }

    fun countSessions(userId: String): Int {
        if (userId.isBlank()) {
            return 0
        }
        val sessionsDir = File(rootDir, "sessions/$userId")
        if (!sessionsDir.exists() || !sessionsDir.isDirectory) {
            return 0
        }
        return sessionsDir.listFiles()
            ?.count { it.isFile && it.name.endsWith(".json") }
            ?: 0
    }

    // Group conversations

    fun upsertGroupConversation(
        userId: String,
        groupId: String,
        displayName: String,
        memberCount: Int,
        lastPreview: String,
        incrementUnread: Boolean,
    ) {
        if (userId.isBlank() || groupId.isBlank()) return
        val keyBase = "group_${userId}_$groupId"
        val groups = readGroupIds(userId)
        groups.add(groupId)
        val preview = lastPreview.trim().ifBlank { "(empty)" }.take(160)
        val nextUnread = if (incrementUnread) getInt("${keyBase}_unread", 0) + 1 else getInt("${keyBase}_unread", 0)
        prefs.edit()
            .putStringSet(groupIdsKey(userId), LinkedHashSet(groups))
            .putString("${keyBase}_name", displayName)
            .putInt("${keyBase}_members", memberCount)
            .putString("${keyBase}_preview", preview)
            .putLong("${keyBase}_updated_ms", System.currentTimeMillis())
            .putInt("${keyBase}_unread", nextUnread)
            .apply()
    }

    fun markGroupRead(userId: String, groupId: String) {
        if (userId.isBlank() || groupId.isBlank()) return
        prefs.edit().putInt("group_${userId}_${groupId}_unread", 0).apply()
    }

    fun listGroups(userId: String): List<GroupSummary> {
        if (userId.isBlank()) return emptyList()
        return readGroupIds(userId).map { gid ->
            val keyBase = "group_${userId}_$gid"
            GroupSummary(
                groupId = gid,
                displayName = getString("${keyBase}_name", gid),
                memberCount = getInt("${keyBase}_members", 0),
                lastPreview = getString("${keyBase}_preview", "No messages yet"),
                updatedAtMillis = getLong("${keyBase}_updated_ms", 0L),
                unreadCount = getInt("${keyBase}_unread", 0),
            )
        }.sortedByDescending { it.updatedAtMillis }
    }

    fun removeGroup(userId: String, groupId: String) {
        if (userId.isBlank() || groupId.isBlank()) return
        val groups = readGroupIds(userId)
        groups.remove(groupId)
        val keyBase = "group_${userId}_$groupId"
        prefs.edit()
            .putStringSet(groupIdsKey(userId), LinkedHashSet(groups))
            .remove("${keyBase}_name").remove("${keyBase}_members")
            .remove("${keyBase}_preview").remove("${keyBase}_updated_ms")
            .remove("${keyBase}_unread")
            .apply()
        deletePath(File(rootDir, "threads/$userId/group_$groupId.json"))
    }

    fun writePrivateGroupState(
        userId: String,
        groupId: String,
        stateJson: String,
        memberCredentialJson: String,
        stateCommitmentSha256: String? = null,
    ) {
        if (userId.isBlank() || groupId.isBlank()) return
        val groups = readPrivateGroupIds(userId)
        groups.add(groupId)
        prefs.edit()
            .putStringSet(privateGroupIdsKey(userId), LinkedHashSet(groups))
            .apply()
        writeProtectedFile(
            File(rootDir, "private-groups/$userId/$groupId.json"),
            gson.toJson(
                PrivateGroupLocalState(
                    groupId = groupId,
                    stateJson = stateJson,
                    memberCredentialJson = memberCredentialJson,
                    stateCommitmentSha256 = stateCommitmentSha256?.trim()?.ifBlank { null },
                    updatedAtMillis = System.currentTimeMillis(),
                ),
            ),
        )
    }

    fun readPrivateGroupState(userId: String, groupId: String): PrivateGroupLocalState? {
        if (userId.isBlank() || groupId.isBlank()) return null
        val path = File(rootDir, "private-groups/$userId/$groupId.json")
        val raw = readProtectedFile(path) ?: return null
        return runCatching {
            gson.fromJson(raw, PrivateGroupLocalState::class.java)
        }.getOrNull()
    }

    fun listPrivateGroups(userId: String): List<PrivateGroupLocalState> {
        if (userId.isBlank()) return emptyList()
        return readPrivateGroupIds(userId)
            .mapNotNull { groupId -> readPrivateGroupState(userId, groupId) }
            .sortedByDescending { it.updatedAtMillis }
    }

    fun removePrivateGroupState(userId: String, groupId: String) {
        if (userId.isBlank() || groupId.isBlank()) return
        val groups = readPrivateGroupIds(userId)
        groups.remove(groupId)
        prefs.edit()
            .putStringSet(privateGroupIdsKey(userId), LinkedHashSet(groups))
            .remove("private_group_cursor_${userId}_$groupId")
            .apply()
        deletePath(File(rootDir, "private-groups/$userId/$groupId.json"))
    }

    fun listGroupThreadMessages(userId: String, groupId: String): List<ThreadMessage> {
        if (userId.isBlank() || groupId.isBlank()) return emptyList()
        migrateLegacyGroupThread(userId, groupId)
        return messageStore.listGroupMessages(userId, groupId)
    }

    fun appendGroupThreadMessage(
        userId: String,
        groupId: String,
        senderUserId: String,
        body: String,
        sentAtMillis: Long = System.currentTimeMillis(),
        transportMessageId: Long? = null,
        replyToId: Long? = null,
        reactions: Map<String, String>? = null,
    ) {
        if (userId.isBlank() || groupId.isBlank()) return
        val direction = if (senderUserId == userId) "outbound" else "inbound"
        val label = if (direction == "outbound") "You" else senderUserId
        migrateLegacyGroupThread(userId, groupId)
        messageStore.appendGroupMessage(
            userId,
            groupId,
            ThreadMessage(
                direction = direction,
                body = "$label: ${body.trim().ifBlank { "(empty)" }}",
                sentAtMillis = sentAtMillis,
                transportMessageId = transportMessageId,
                replyToId = replyToId,
                reactions = reactions,
            ),
        )
    }

    fun updateGroupThreadMessageReactions(
        userId: String,
        groupId: String,
        direction: String,
        sentAtMillis: Long,
        reactions: Map<String, String>?,
    ) {
        if (userId.isBlank() || groupId.isBlank()) return
        migrateLegacyGroupThread(userId, groupId)
        messageStore.updateGroupMessageReactions(userId, groupId, direction, sentAtMillis, reactions)
    }

    private fun readGroupIds(userId: String): LinkedHashSet<String> {
        return LinkedHashSet(getStringSet(groupIdsKey(userId)))
    }

    private fun groupIdsKey(userId: String) = "group_ids_$userId"

    private fun readPrivateGroupIds(userId: String): LinkedHashSet<String> {
        return LinkedHashSet(getStringSet(privateGroupIdsKey(userId)))
    }

    private fun privateGroupIdsKey(userId: String) = "private_group_ids_$userId"

    // Outbox (offline queue)

    fun enqueueOutbox(
        userId: String,
        peerUserId: String,
        plaintext: String,
        ephemeralTtlSeconds: Long? = null,
        sealedSender: Boolean = false,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) return
        migrateLegacyOutbox(userId)
        val existing = messageStore.listOutbox(userId)
        val nextId = (existing.maxOfOrNull { it.id } ?: 0L) + 1
        messageStore.enqueueOutbox(
            userId,
            OutboxItem(
                id = nextId,
                peerUserId = peerUserId,
                plaintext = plaintext,
                createdAtMillis = System.currentTimeMillis(),
                ephemeralTtlSeconds = ephemeralTtlSeconds,
                sealedSender = sealedSender,
            ),
        )
    }

    fun listOutbox(userId: String): List<OutboxItem> {
        if (userId.isBlank()) return emptyList()
        migrateLegacyOutbox(userId)
        return messageStore.listOutbox(userId)
    }

    fun removeOutboxItem(userId: String, itemId: Long) {
        if (userId.isBlank()) return
        migrateLegacyOutbox(userId)
        messageStore.removeOutboxItem(userId, itemId)
    }

    fun clearOutbox(userId: String) {
        if (userId.isBlank()) return
        messageStore.clearOutbox(userId)
        deletePath(File(rootDir, "outbox/$userId.json"))
    }

    // Receipt tracking

    fun updateMessageReceipt(userId: String, peerUserId: String, transportMessageId: Long, receiptType: String) {
        if (userId.isBlank() || peerUserId.isBlank()) return
        val messages = listThreadMessages(userId, peerUserId)
        val msg = messages.firstOrNull {
            it.transportMessageId == transportMessageId && it.direction == "outbound"
        } ?: return
        val priority = mapOf("sent" to 0, "delivered" to 1, "read" to 2)
        val currentPriority = priority[msg.receiptStatus] ?: -1
        val newPriority = priority[receiptType] ?: -1
        if (newPriority <= currentPriority) return
        messageStore.updateDirectMessageReceipt(userId, peerUserId, transportMessageId, receiptType)
    }

    fun wipeUserState(userId: String) {
        if (userId.isBlank()) {
            return
        }
        deletePath(File(rootDir, "keys/$userId.json"))
        deletePath(File(rootDir, "sessions/$userId"))
        deletePath(File(rootDir, "threads/$userId"))
        deletePath(File(rootDir, "private-groups/$userId"))
        deletePath(File(rootDir, "outbox/$userId.json"))
        messageStore.clearUser(userId)
        removePrefsForUser(userId)
        clearTransparencyCheckpoints(userId)
        clearContactDiscoveryCheckpoints(userId)

        val currentSetup = loadSetup()
        if (currentSetup.userId == userId) {
            saveSetup(
                currentSetup.copy(
                    userId = "",
                    deviceId = "",
                    peerUserId = "bob",
                ),
            )
        }
    }

    private fun migrateLegacyDirectThread(userId: String, peerUserId: String) {
        if (messageStore.listDirectMessages(userId, peerUserId).isNotEmpty()) {
            return
        }
        val path = File(rootDir, "threads/$userId/$peerUserId.json")
        val legacy = readLegacyList<ThreadMessage>(path)
        if (legacy.isEmpty()) {
            return
        }
        messageStore.importDirectMessages(userId, peerUserId, legacy)
        deletePath(path)
    }

    private fun migrateLegacyGroupThread(userId: String, groupId: String) {
        if (messageStore.listGroupMessages(userId, groupId).isNotEmpty()) {
            return
        }
        val path = File(rootDir, "threads/$userId/group_$groupId.json")
        val legacy = readLegacyList<ThreadMessage>(path)
        if (legacy.isEmpty()) {
            return
        }
        messageStore.importGroupMessages(userId, groupId, legacy)
        deletePath(path)
    }

    private fun migrateLegacyOutbox(userId: String) {
        if (messageStore.listOutbox(userId).isNotEmpty()) {
            return
        }
        val path = File(rootDir, "outbox/$userId.json")
        val legacy = readLegacyList<OutboxItem>(path)
        if (legacy.isEmpty()) {
            return
        }
        messageStore.importOutboxItems(userId, legacy)
        deletePath(path)
    }

    private fun clearTransparencyCheckpoints(userId: String) {
        val editor = prefs.edit()
        prefs.all.keys
            .filter { it.startsWith("transparency_") && it.endsWith("_${userId}") }
            .forEach(editor::remove)
        editor.apply()
    }

    private fun clearContactDiscoveryCheckpoints(userId: String) {
        val editor = prefs.edit()
        prefs.all.keys
            .filter { it.startsWith("contact_discovery_manifest_") && it.endsWith("_${userId}") }
            .forEach(editor::remove)
        editor.apply()
    }

    private fun transparencyCheckpointKey(serverUrl: String, userId: String): String {
        return "transparency_${serverUrl.trim()}_${userId.trim()}"
    }

    private fun contactDiscoveryCheckpointKey(serverUrl: String, userId: String): String {
        return "contact_discovery_manifest_${serverUrl.trim()}_${userId.trim()}"
    }

    private inline fun <reified T> readLegacyList(path: File): List<T> {
        val raw = readProtectedFile(path) ?: return emptyList()
        return runCatching {
            val type = object : TypeToken<List<T>>() {}.type
            gson.fromJson<List<T>>(raw, type) ?: emptyList()
        }.getOrDefault(emptyList())
    }

    private fun readConversationPeers(userId: String): LinkedHashSet<String> {
        return LinkedHashSet(getStringSet(conversationPeersKey(userId)))
    }

    private fun conversationPeersKey(userId: String): String {
        return "conv_peers_$userId"
    }

    private fun readMessageRequestPeers(userId: String): LinkedHashSet<String> {
        return LinkedHashSet(getStringSet(messageRequestPeersKey(userId)))
    }

    private fun messageRequestPeersKey(userId: String): String {
        return "request_peers_$userId"
    }

    private fun acceptedPeersKey(userId: String): String {
        return "accepted_peers_$userId"
    }

    private fun removePrefsForUser(userId: String) {
        val sanitized = userId.ifBlank { "_" }
        removeKeysMatching(
            prefs,
            exactKeys = setOf(
                "cursor_$userId",
                "sealed_cursor_$userId",
                groupIdsKey(userId),
                privateGroupIdsKey(userId),
                conversationPeersKey(userId),
                messageRequestPeersKey(userId),
                acceptedPeersKey(userId),
            ),
            prefixes = listOf(
                "progress_${sanitized}_",
                "peer_last_${userId}_",
                "peer_seen_${userId}_",
                "bundle_${userId}_",
                "pin_${userId}_",
                "conv_${userId}_",
                "group_${userId}_",
                "private_group_cursor_${userId}_",
                "request_${userId}_",
            ),
        )
        removeKeysMatching(
            legacyPrefs,
            exactKeys = setOf(
                "cursor_$userId",
                "sealed_cursor_$userId",
                groupIdsKey(userId),
                privateGroupIdsKey(userId),
                conversationPeersKey(userId),
                messageRequestPeersKey(userId),
                acceptedPeersKey(userId),
            ),
            prefixes = listOf(
                "progress_${sanitized}_",
                "peer_last_${userId}_",
                "peer_seen_${userId}_",
                "bundle_${userId}_",
                "pin_${userId}_",
                "conv_${userId}_",
                "group_${userId}_",
                "private_group_cursor_${userId}_",
                "request_${userId}_",
            ),
        )
    }

    private fun getNullableString(key: String): String? {
        if (prefs.contains(key)) {
            return prefs.getString(key, null)
        }
        if (!legacyPrefs.contains(key)) {
            return null
        }
        val legacy = legacyPrefs.getString(key, null)
        prefs.edit().putString(key, legacy).apply()
        removeLegacyKeys(key)
        return legacy
    }

    private fun getString(key: String, default: String): String {
        return getNullableString(key) ?: default
    }

    private fun getBoolean(key: String, default: Boolean): Boolean {
        if (prefs.contains(key)) {
            return prefs.getBoolean(key, default)
        }
        if (!legacyPrefs.contains(key)) {
            return default
        }
        val legacy = legacyPrefs.getBoolean(key, default)
        prefs.edit().putBoolean(key, legacy).apply()
        removeLegacyKeys(key)
        return legacy
    }

    private fun getInt(key: String, default: Int): Int {
        if (prefs.contains(key)) {
            return prefs.getInt(key, default)
        }
        if (!legacyPrefs.contains(key)) {
            return default
        }
        val legacy = legacyPrefs.getInt(key, default)
        prefs.edit().putInt(key, legacy).apply()
        removeLegacyKeys(key)
        return legacy
    }

    private fun getLong(key: String, default: Long): Long {
        if (prefs.contains(key)) {
            return prefs.getLong(key, default)
        }
        if (!legacyPrefs.contains(key)) {
            return default
        }
        val legacy = legacyPrefs.getLong(key, default)
        prefs.edit().putLong(key, legacy).apply()
        removeLegacyKeys(key)
        return legacy
    }

    private fun getStringSet(key: String): Set<String> {
        if (prefs.contains(key)) {
            return prefs.getStringSet(key, emptySet()) ?: emptySet()
        }
        if (!legacyPrefs.contains(key)) {
            return emptySet()
        }
        val legacy = LinkedHashSet(legacyPrefs.getStringSet(key, emptySet()) ?: emptySet())
        prefs.edit().putStringSet(key, legacy).apply()
        removeLegacyKeys(key)
        return legacy
    }

    private fun removeLegacyKeys(vararg keys: String) {
        val editor = legacyPrefs.edit()
        var changed = false
        for (key in keys) {
            if (legacyPrefs.contains(key)) {
                editor.remove(key)
                changed = true
            }
        }
        if (changed) {
            editor.apply()
        }
    }

    private fun removeKeysMatching(
        preferences: SharedPreferences,
        exactKeys: Set<String>,
        prefixes: List<String>,
    ) {
        val editor = preferences.edit()
        var changed = false
        for (key in preferences.all.keys) {
            if (key in exactKeys || prefixes.any(key::startsWith)) {
                editor.remove(key)
                changed = true
            }
        }
        if (changed) {
            editor.apply()
        }
    }

    private fun deletePath(path: File) {
        if (!path.exists()) {
            return
        }
        if (path.isDirectory) {
            path.listFiles()?.forEach(::deletePath)
        }
        path.delete()
    }
}
