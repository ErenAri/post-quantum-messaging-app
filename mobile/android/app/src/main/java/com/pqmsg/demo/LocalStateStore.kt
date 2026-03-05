package com.pqmsg.demo

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
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
    val identitySigPub: String,
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

class LocalStateStore(context: Context) {
    private val prefs = context.getSharedPreferences("pqmsg_android_setup", Context.MODE_PRIVATE)
    private val rootDir = File(context.filesDir, "pqmsg")
    private val appContext = context.applicationContext
    private val masterKey = MasterKey.Builder(appContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    fun loadSetup(): SetupConfig {
        return SetupConfig(
            serverUrl = prefs.getString("server_url", "http://10.0.2.2:3000") ?: "http://10.0.2.2:3000",
            userId = prefs.getString("user_id", "") ?: "",
            deviceId = prefs.getString("device_id", "") ?: "",
            suiteLabel = prefs.getString("suite_label", "ml-kem-768") ?: "ml-kem-768",
            peerUserId = prefs.getString("peer_user_id", "bob") ?: "bob",
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
    }

    fun loadProgress(userId: String): SetupProgress {
        val sanitized = userId.ifBlank { "_" }
        return SetupProgress(
            keysGenerated = prefs.getBoolean("progress_${sanitized}_keys", false),
            userRegistered = prefs.getBoolean("progress_${sanitized}_registered", false),
            prekeysPublished = prefs.getBoolean("progress_${sanitized}_prekeys", false),
            serverVerified = prefs.getBoolean("progress_${sanitized}_verified", false),
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
        return prefs.getLong("cursor_$userId", 0L)
    }

    fun writeCursor(userId: String, cursor: Long) {
        prefs.edit().putLong("cursor_$userId", cursor).apply()
    }

    fun readPeerLastMessageId(userId: String, peerUserId: String): Long {
        return prefs.getLong("peer_last_${userId}_$peerUserId", 0L)
    }

    fun writePeerLastMessageId(userId: String, peerUserId: String, messageId: Long) {
        prefs.edit()
            .putLong("peer_last_${userId}_$peerUserId", messageId)
            .apply()
    }

    fun readPeerSeenCipherHashes(userId: String, peerUserId: String): LinkedHashSet<String> {
        val stored = prefs.getStringSet("peer_seen_${userId}_$peerUserId", emptySet()) ?: emptySet()
        return LinkedHashSet(stored)
    }

    fun writePeerSeenCipherHashes(userId: String, peerUserId: String, hashes: Set<String>) {
        prefs.edit()
            .putStringSet("peer_seen_${userId}_$peerUserId", LinkedHashSet(hashes))
            .apply()
    }

    fun writeBundleFetchedAt(userId: String, peerUserId: String, timestamp: String) {
        prefs.edit()
            .putString("bundle_${userId}_$peerUserId", timestamp)
            .apply()
    }

    fun readBundleFetchedAt(userId: String, peerUserId: String): String? {
        return prefs.getString("bundle_${userId}_$peerUserId", null)
    }

    fun readIdentityPin(userId: String, peerUserId: String): IdentityPin? {
        val keyBase = "pin_${userId}_$peerUserId"
        val fingerprint = prefs.getString("${keyBase}_fp", null) ?: return null
        return IdentityPin(
            fingerprintSha256 = fingerprint,
            identityKeyVersion = prefs.getInt("${keyBase}_ver", 1),
            identitySigPub = prefs.getString("${keyBase}_sig", "") ?: "",
            observedAt = prefs.getString("${keyBase}_at", "") ?: "",
        )
    }

    fun writeIdentityPin(userId: String, peerUserId: String, pin: IdentityPin) {
        val keyBase = "pin_${userId}_$peerUserId"
        prefs.edit()
            .putString("${keyBase}_fp", pin.fingerprintSha256)
            .putInt("${keyBase}_ver", pin.identityKeyVersion)
            .putString("${keyBase}_sig", pin.identitySigPub)
            .putString("${keyBase}_at", pin.observedAt)
            .apply()
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
            prefs.getInt("${keyBase}_unread", 0) + 1
        } else {
            prefs.getInt("${keyBase}_unread", 0)
        }
        prefs.edit()
            .putStringSet(conversationPeersKey(userId), LinkedHashSet(peers))
            .putString("${keyBase}_preview", normalizedPreview)
            .putLong("${keyBase}_updated_ms", System.currentTimeMillis())
            .putInt("${keyBase}_unread", nextUnread)
            .apply()
    }

    fun markConversationRead(userId: String, peerUserId: String) {
        if (userId.isBlank() || peerUserId.isBlank()) {
            return
        }
        val keyBase = "conv_${userId}_$peerUserId"
        prefs.edit()
            .putInt("${keyBase}_unread", 0)
            .apply()
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
                    lastPreview = prefs.getString("${keyBase}_preview", "No messages yet") ?: "No messages yet",
                    updatedAtMillis = prefs.getLong("${keyBase}_updated_ms", 0L),
                    unreadCount = prefs.getInt("${keyBase}_unread", 0),
                )
            }
            .sortedByDescending { it.updatedAtMillis }
    }

    fun listIdentityPins(userId: String): List<IdentityPinRecord> {
        if (userId.isBlank()) {
            return emptyList()
        }
        val prefix = "pin_${userId}_"
        val suffix = "_fp"
        return prefs.all.keys
            .asSequence()
            .filter { it.startsWith(prefix) && it.endsWith(suffix) }
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

    private fun readConversationPeers(userId: String): LinkedHashSet<String> {
        val stored = prefs.getStringSet(conversationPeersKey(userId), emptySet()) ?: emptySet()
        return LinkedHashSet(stored)
    }

    private fun conversationPeersKey(userId: String): String {
        return "conv_peers_$userId"
    }
}
