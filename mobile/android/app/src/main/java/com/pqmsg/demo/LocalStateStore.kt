package com.pqmsg.demo

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import java.io.File
import java.nio.charset.StandardCharsets

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
}
