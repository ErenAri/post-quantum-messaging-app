package com.pqmsg.demo

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Base64
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val DATABASE_NAME = "pqmsg_local_messages.db"
private const val DATABASE_VERSION = 1
private const val DIRECT_THREAD_LIMIT = 300
private const val GROUP_THREAD_LIMIT = 300
private const val GCM_TAG_BITS = 128
private const val GCM_IV_BYTES = 12

class LocalMessageDatabase(
    context: Context,
    private val keyAlias: String,
) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {
    private val gson = Gson()
    private val reactionsType = object : TypeToken<Map<String, String>>() {}.type
    private val secretKey: SecretKey by lazy {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.getKey(keyAlias, null) as? SecretKey
            ?: error("missing Android keystore secret for $keyAlias")
    }

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE direct_messages (
                row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                peer_user_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                body_ciphertext TEXT NOT NULL,
                sent_at_millis INTEGER NOT NULL,
                transport_message_id INTEGER,
                ephemeral_ttl_seconds INTEGER,
                expires_at_millis INTEGER,
                receipt_status TEXT,
                reply_to_id INTEGER,
                reactions_ciphertext TEXT,
                UNIQUE(user_id, peer_user_id, direction, transport_message_id) ON CONFLICT IGNORE
            )
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE INDEX idx_direct_messages_thread
            ON direct_messages(user_id, peer_user_id, sent_at_millis, row_id)
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE TABLE group_messages (
                row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                body_ciphertext TEXT NOT NULL,
                sent_at_millis INTEGER NOT NULL,
                transport_message_id INTEGER,
                UNIQUE(user_id, group_id, transport_message_id) ON CONFLICT IGNORE
            )
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE INDEX idx_group_messages_thread
            ON group_messages(user_id, group_id, sent_at_millis, row_id)
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE TABLE outbox_items (
                user_id TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                peer_user_id TEXT NOT NULL,
                plaintext_ciphertext TEXT NOT NULL,
                created_at_millis INTEGER NOT NULL,
                ephemeral_ttl_seconds INTEGER,
                sealed_sender INTEGER NOT NULL,
                PRIMARY KEY (user_id, item_id)
            )
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE INDEX idx_outbox_items_user
            ON outbox_items(user_id, item_id)
            """.trimIndent(),
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit

    fun listDirectMessages(userId: String, peerUserId: String): List<ThreadMessage> {
        if (userId.isBlank() || peerUserId.isBlank()) return emptyList()
        val db = readableDatabase
        db.query(
            "direct_messages",
            arrayOf(
                "direction",
                "body_ciphertext",
                "sent_at_millis",
                "transport_message_id",
                "ephemeral_ttl_seconds",
                "expires_at_millis",
                "receipt_status",
                "reply_to_id",
                "reactions_ciphertext",
            ),
            "user_id = ? AND peer_user_id = ?",
            arrayOf(userId, peerUserId),
            null,
            null,
            "sent_at_millis ASC, row_id ASC",
        ).use { cursor ->
            val messages = ArrayList<ThreadMessage>(cursor.count.coerceAtLeast(0))
            while (cursor.moveToNext()) {
                messages.add(
                    ThreadMessage(
                        direction = cursor.requireString("direction"),
                        body = decryptString(cursor.requireString("body_ciphertext")),
                        sentAtMillis = cursor.requireLong("sent_at_millis"),
                        transportMessageId = cursor.optionalLong("transport_message_id"),
                        ephemeralTtlSeconds = cursor.optionalLong("ephemeral_ttl_seconds"),
                        expiresAtMillis = cursor.optionalLong("expires_at_millis"),
                        receiptStatus = cursor.optionalString("receipt_status"),
                        replyToId = cursor.optionalLong("reply_to_id"),
                        reactions = cursor.optionalString("reactions_ciphertext")?.let {
                            gson.fromJson<Map<String, String>>(decryptString(it), reactionsType)
                        },
                    ),
                )
            }
            return messages
        }
    }

    fun appendDirectMessage(userId: String, peerUserId: String, message: ThreadMessage) {
        if (userId.isBlank() || peerUserId.isBlank()) return
        writableDatabase.beginTransaction()
        try {
            writableDatabase.insertWithOnConflict(
                "direct_messages",
                null,
                ContentValues().apply {
                    put("user_id", userId)
                    put("peer_user_id", peerUserId)
                    put("direction", message.direction)
                    put("body_ciphertext", encryptString(message.body))
                    put("sent_at_millis", message.sentAtMillis)
                    put("transport_message_id", message.transportMessageId)
                    put("ephemeral_ttl_seconds", message.ephemeralTtlSeconds)
                    put("expires_at_millis", message.expiresAtMillis)
                    put("receipt_status", message.receiptStatus)
                    put("reply_to_id", message.replyToId)
                    put(
                        "reactions_ciphertext",
                        message.reactions?.let { encryptString(gson.toJson(it)) },
                    )
                },
                SQLiteDatabase.CONFLICT_IGNORE,
            )
            trimThread("direct_messages", "user_id = ? AND peer_user_id = ?", arrayOf(userId, peerUserId), DIRECT_THREAD_LIMIT)
            writableDatabase.setTransactionSuccessful()
        } finally {
            writableDatabase.endTransaction()
        }
    }

    fun importDirectMessages(userId: String, peerUserId: String, messages: List<ThreadMessage>) {
        if (messages.isEmpty()) return
        writableDatabase.beginTransaction()
        try {
            for (message in messages) {
                writableDatabase.insertWithOnConflict(
                    "direct_messages",
                    null,
                    ContentValues().apply {
                        put("user_id", userId)
                        put("peer_user_id", peerUserId)
                        put("direction", message.direction)
                        put("body_ciphertext", encryptString(message.body))
                        put("sent_at_millis", message.sentAtMillis)
                        put("transport_message_id", message.transportMessageId)
                        put("ephemeral_ttl_seconds", message.ephemeralTtlSeconds)
                        put("expires_at_millis", message.expiresAtMillis)
                        put("receipt_status", message.receiptStatus)
                        put("reply_to_id", message.replyToId)
                        put(
                            "reactions_ciphertext",
                            message.reactions?.let { encryptString(gson.toJson(it)) },
                        )
                    },
                    SQLiteDatabase.CONFLICT_IGNORE,
                )
            }
            trimThread("direct_messages", "user_id = ? AND peer_user_id = ?", arrayOf(userId, peerUserId), DIRECT_THREAD_LIMIT)
            writableDatabase.setTransactionSuccessful()
        } finally {
            writableDatabase.endTransaction()
        }
    }

    fun updateDirectMessageReceipt(
        userId: String,
        peerUserId: String,
        transportMessageId: Long,
        receiptType: String,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) return
        writableDatabase.update(
            "direct_messages",
            ContentValues().apply { put("receipt_status", receiptType) },
            "user_id = ? AND peer_user_id = ? AND direction = ? AND transport_message_id = ?",
            arrayOf(userId, peerUserId, "outbound", transportMessageId.toString()),
        )
    }

    fun listGroupMessages(userId: String, groupId: String): List<ThreadMessage> {
        if (userId.isBlank() || groupId.isBlank()) return emptyList()
        val db = readableDatabase
        db.query(
            "group_messages",
            arrayOf("direction", "body_ciphertext", "sent_at_millis", "transport_message_id"),
            "user_id = ? AND group_id = ?",
            arrayOf(userId, groupId),
            null,
            null,
            "sent_at_millis ASC, row_id ASC",
        ).use { cursor ->
            val messages = ArrayList<ThreadMessage>(cursor.count.coerceAtLeast(0))
            while (cursor.moveToNext()) {
                messages.add(
                    ThreadMessage(
                        direction = cursor.requireString("direction"),
                        body = decryptString(cursor.requireString("body_ciphertext")),
                        sentAtMillis = cursor.requireLong("sent_at_millis"),
                        transportMessageId = cursor.optionalLong("transport_message_id"),
                    ),
                )
            }
            return messages
        }
    }

    fun appendGroupMessage(userId: String, groupId: String, message: ThreadMessage) {
        if (userId.isBlank() || groupId.isBlank()) return
        writableDatabase.beginTransaction()
        try {
            writableDatabase.insertWithOnConflict(
                "group_messages",
                null,
                ContentValues().apply {
                    put("user_id", userId)
                    put("group_id", groupId)
                    put("direction", message.direction)
                    put("body_ciphertext", encryptString(message.body))
                    put("sent_at_millis", message.sentAtMillis)
                    put("transport_message_id", message.transportMessageId)
                },
                SQLiteDatabase.CONFLICT_IGNORE,
            )
            trimThread("group_messages", "user_id = ? AND group_id = ?", arrayOf(userId, groupId), GROUP_THREAD_LIMIT)
            writableDatabase.setTransactionSuccessful()
        } finally {
            writableDatabase.endTransaction()
        }
    }

    fun importGroupMessages(userId: String, groupId: String, messages: List<ThreadMessage>) {
        if (messages.isEmpty()) return
        writableDatabase.beginTransaction()
        try {
            for (message in messages) {
                writableDatabase.insertWithOnConflict(
                    "group_messages",
                    null,
                    ContentValues().apply {
                        put("user_id", userId)
                        put("group_id", groupId)
                        put("direction", message.direction)
                        put("body_ciphertext", encryptString(message.body))
                        put("sent_at_millis", message.sentAtMillis)
                        put("transport_message_id", message.transportMessageId)
                    },
                    SQLiteDatabase.CONFLICT_IGNORE,
                )
            }
            trimThread("group_messages", "user_id = ? AND group_id = ?", arrayOf(userId, groupId), GROUP_THREAD_LIMIT)
            writableDatabase.setTransactionSuccessful()
        } finally {
            writableDatabase.endTransaction()
        }
    }

    fun enqueueOutbox(userId: String, item: OutboxItem) {
        if (userId.isBlank()) return
        writableDatabase.insertWithOnConflict(
            "outbox_items",
            null,
            ContentValues().apply {
                put("user_id", userId)
                put("item_id", item.id)
                put("peer_user_id", item.peerUserId)
                put("plaintext_ciphertext", encryptString(item.plaintext))
                put("created_at_millis", item.createdAtMillis)
                put("ephemeral_ttl_seconds", item.ephemeralTtlSeconds)
                put("sealed_sender", if (item.sealedSender) 1 else 0)
            },
            SQLiteDatabase.CONFLICT_REPLACE,
        )
    }

    fun importOutboxItems(userId: String, items: List<OutboxItem>) {
        if (items.isEmpty()) return
        writableDatabase.beginTransaction()
        try {
            for (item in items) {
                enqueueOutbox(userId, item)
            }
            writableDatabase.setTransactionSuccessful()
        } finally {
            writableDatabase.endTransaction()
        }
    }

    fun listOutbox(userId: String): List<OutboxItem> {
        if (userId.isBlank()) return emptyList()
        readableDatabase.query(
            "outbox_items",
            arrayOf(
                "item_id",
                "peer_user_id",
                "plaintext_ciphertext",
                "created_at_millis",
                "ephemeral_ttl_seconds",
                "sealed_sender",
            ),
            "user_id = ?",
            arrayOf(userId),
            null,
            null,
            "item_id ASC",
        ).use { cursor ->
            val items = ArrayList<OutboxItem>(cursor.count.coerceAtLeast(0))
            while (cursor.moveToNext()) {
                items.add(
                    OutboxItem(
                        id = cursor.requireLong("item_id"),
                        peerUserId = cursor.requireString("peer_user_id"),
                        plaintext = decryptString(cursor.requireString("plaintext_ciphertext")),
                        createdAtMillis = cursor.requireLong("created_at_millis"),
                        ephemeralTtlSeconds = cursor.optionalLong("ephemeral_ttl_seconds"),
                        sealedSender = cursor.requireInt("sealed_sender") != 0,
                    ),
                )
            }
            return items
        }
    }

    fun removeOutboxItem(userId: String, itemId: Long) {
        if (userId.isBlank()) return
        writableDatabase.delete(
            "outbox_items",
            "user_id = ? AND item_id = ?",
            arrayOf(userId, itemId.toString()),
        )
    }

    fun clearOutbox(userId: String) {
        if (userId.isBlank()) return
        writableDatabase.delete("outbox_items", "user_id = ?", arrayOf(userId))
    }

    fun clearUser(userId: String) {
        if (userId.isBlank()) return
        writableDatabase.beginTransaction()
        try {
            writableDatabase.delete("direct_messages", "user_id = ?", arrayOf(userId))
            writableDatabase.delete("group_messages", "user_id = ?", arrayOf(userId))
            writableDatabase.delete("outbox_items", "user_id = ?", arrayOf(userId))
            writableDatabase.setTransactionSuccessful()
        } finally {
            writableDatabase.endTransaction()
        }
    }

    private fun trimThread(
        table: String,
        whereClause: String,
        whereArgs: Array<String>,
        limit: Int,
    ) {
        writableDatabase.execSQL(
            """
            DELETE FROM $table
            WHERE row_id IN (
                SELECT row_id
                FROM $table
                WHERE $whereClause
                ORDER BY sent_at_millis DESC, row_id DESC
                LIMIT -1 OFFSET $limit
            )
            """.trimIndent(),
            whereArgs,
        )
    }

    private fun encryptString(value: String): String {
        if (value.isEmpty()) return value
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        val payload = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, payload, 0, iv.size)
        System.arraycopy(ciphertext, 0, payload, iv.size, ciphertext.size)
        return Base64.encodeToString(payload, Base64.NO_WRAP)
    }

    private fun decryptString(value: String): String {
        if (value.isEmpty()) return value
        return runCatching {
            val payload = Base64.decode(value, Base64.NO_WRAP)
            val iv = payload.copyOfRange(0, GCM_IV_BYTES)
            val ciphertext = payload.copyOfRange(GCM_IV_BYTES, payload.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8)
        }.getOrElse {
            value
        }
    }
}

private fun Cursor.requireString(columnName: String): String = getString(getColumnIndexOrThrow(columnName))

private fun Cursor.optionalString(columnName: String): String? {
    val index = getColumnIndexOrThrow(columnName)
    return if (isNull(index)) null else getString(index)
}

private fun Cursor.requireLong(columnName: String): Long = getLong(getColumnIndexOrThrow(columnName))

private fun Cursor.optionalLong(columnName: String): Long? {
    val index = getColumnIndexOrThrow(columnName)
    return if (isNull(index)) null else getLong(index)
}

private fun Cursor.requireInt(columnName: String): Int = getInt(getColumnIndexOrThrow(columnName))
