package com.pqmsg.demo

import android.content.Context
import java.io.File

data class SetupConfig(
    val serverUrl: String,
    val userId: String,
    val deviceId: String,
    val suiteLabel: String,
    val peerUserId: String,
)

class LocalStateStore(context: Context) {
    private val prefs = context.getSharedPreferences("pqmsg_android_setup", Context.MODE_PRIVATE)
    private val rootDir = File(context.filesDir, "pqmsg")

    fun loadSetup(): SetupConfig {
        return SetupConfig(
            serverUrl = prefs.getString("server_url", "http://10.0.2.2:8080") ?: "http://10.0.2.2:8080",
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

    fun writeKeys(userId: String, keysJson: String) {
        val path = File(rootDir, "keys/$userId.json")
        path.parentFile?.mkdirs()
        path.writeText(keysJson)
    }

    fun readKeys(userId: String): String? {
        val path = File(rootDir, "keys/$userId.json")
        if (!path.exists()) {
            return null
        }
        return path.readText()
    }

    fun writeSession(userId: String, peerUserId: String, sessionJson: String) {
        val path = File(rootDir, "sessions/$userId/$peerUserId.json")
        path.parentFile?.mkdirs()
        path.writeText(sessionJson)
    }

    fun readSession(userId: String, peerUserId: String): String? {
        val path = File(rootDir, "sessions/$userId/$peerUserId.json")
        if (!path.exists()) {
            return null
        }
        return path.readText()
    }

    fun readCursor(userId: String): Long {
        return prefs.getLong("cursor_$userId", 0L)
    }

    fun writeCursor(userId: String, cursor: Long) {
        prefs.edit().putLong("cursor_$userId", cursor).apply()
    }
}
