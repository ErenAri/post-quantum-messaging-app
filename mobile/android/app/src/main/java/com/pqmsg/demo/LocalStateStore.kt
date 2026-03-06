package com.pqmsg.demo

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.EncryptedSharedPreferences
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
            identitySigPub = getString("${keyBase}_sig", ""),
            observedAt = getString("${keyBase}_at", ""),
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
        removeLegacyKeys(
            "${keyBase}_fp",
            "${keyBase}_ver",
            "${keyBase}_sig",
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

    fun wipeUserState(userId: String) {
        if (userId.isBlank()) {
            return
        }
        deletePath(File(rootDir, "keys/$userId.json"))
        deletePath(File(rootDir, "sessions/$userId"))
        removePrefsForUser(userId)

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

    private fun readConversationPeers(userId: String): LinkedHashSet<String> {
        return LinkedHashSet(getStringSet(conversationPeersKey(userId)))
    }

    private fun conversationPeersKey(userId: String): String {
        return "conv_peers_$userId"
    }

    private fun removePrefsForUser(userId: String) {
        val sanitized = userId.ifBlank { "_" }
        removeKeysMatching(
            prefs,
            exactKeys = setOf(
                "cursor_$userId",
                conversationPeersKey(userId),
            ),
            prefixes = listOf(
                "progress_${sanitized}_",
                "peer_last_${userId}_",
                "peer_seen_${userId}_",
                "bundle_${userId}_",
                "pin_${userId}_",
                "conv_${userId}_",
            ),
        )
        removeKeysMatching(
            legacyPrefs,
            exactKeys = setOf(
                "cursor_$userId",
                conversationPeersKey(userId),
            ),
            prefixes = listOf(
                "progress_${sanitized}_",
                "peer_last_${userId}_",
                "peer_seen_${userId}_",
                "bundle_${userId}_",
                "pin_${userId}_",
                "conv_${userId}_",
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
