package com.pqmsg.demo

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import net.zetetic.database.sqlcipher.SQLiteDatabase as SqlCipherDatabase
import net.zetetic.database.sqlcipher.SQLiteOpenHelper as SqlCipherOpenHelper
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private const val DATABASE_NAME = "pqmsg_local_messages.db"
private const val DATABASE_VERSION = 2
private const val DIRECT_THREAD_LIMIT = 300
private const val GROUP_THREAD_LIMIT = 300
private const val GCM_TAG_BITS = 128
private const val GCM_IV_BYTES = 12
private const val DB_SECURITY_PREFS = "pqmsg_android_db_security"
private const val DB_PASSPHRASE_KEY = "local_message_db_passphrase_v1"
private const val DB_MIGRATION_COMPLETE_KEY = "local_message_db_sqlcipher_ready_v1"
private const val SQLCIPHER_MEMORY_SECURITY_PRAGMA = "PRAGMA cipher_memory_security = ON"
private const val LOCAL_SECURE_STORAGE_UNAVAILABLE_MESSAGE =
    "Local encrypted message store is unavailable on this device. Recovery requires a linked-device package or full reprovision."
private const val SQLITE_PLAINTEXT_MAGIC = "SQLite format 3"

class LocalSecureStorageUnavailableException(
    message: String = LOCAL_SECURE_STORAGE_UNAVAILABLE_MESSAGE,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

private fun loadOrCreateSqlCipherPassphrase(context: Context): ByteArray {
    val appContext = context.applicationContext
    val masterKey = MasterKey.Builder(appContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()
    val prefs = EncryptedSharedPreferences.create(
        appContext,
        DB_SECURITY_PREFS,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
    val existing = prefs.getString(DB_PASSPHRASE_KEY, null)
    if (!existing.isNullOrBlank()) {
        return Base64.decode(existing, Base64.NO_WRAP)
    }
    val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
    prefs.edit()
        .putString(DB_PASSPHRASE_KEY, Base64.encodeToString(random, Base64.NO_WRAP))
        .apply()
    return random
}

class LocalMessageDatabase(
    context: Context,
    private val keyAlias: String,
) : SqlCipherOpenHelper(
    context,
    DATABASE_NAME,
    loadOrCreateSqlCipherPassphrase(context),
    null,
    DATABASE_VERSION,
    0,
    null,
    null,
    false,
) {
    private val gson = Gson()
    private val reactionsType = object : TypeToken<Map<String, String>>() {}.type
    private val appContext = context.applicationContext
    private val securityPrefs by lazy {
        val masterKey = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            appContext,
            DB_SECURITY_PREFS,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }
    private val secretKey: SecretKey by lazy {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.getKey(keyAlias, null) as? SecretKey
            ?: error("missing Android keystore secret for $keyAlias")
    }
    init {
        System.loadLibrary("sqlcipher")
        ensureEncryptedDatabaseReady()
    }

    override fun onCreate(db: SqlCipherDatabase) {
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
                reply_to_id INTEGER,
                reactions_ciphertext TEXT,
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

    override fun onConfigure(db: SqlCipherDatabase) {
        super.onConfigure(db)
        // SQLCipher documents this as an opt-in process-wide hardening control.
        db.rawExecSQL(SQLCIPHER_MEMORY_SECURITY_PRAGMA)
    }

    override fun onUpgrade(db: SqlCipherDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 2) {
            db.execSQL("ALTER TABLE group_messages ADD COLUMN reply_to_id INTEGER")
            db.execSQL("ALTER TABLE group_messages ADD COLUMN reactions_ciphertext TEXT")
        }
    }

    private fun readableDb(): SqlCipherDatabase =
        runCatching { super.readableDatabase as SqlCipherDatabase }
            .getOrElse { throw LocalSecureStorageUnavailableException(cause = it) }

    private fun writableDb(): SqlCipherDatabase =
        runCatching { super.writableDatabase as SqlCipherDatabase }
            .getOrElse { throw LocalSecureStorageUnavailableException(cause = it) }

    private fun ensureEncryptedDatabaseReady() {
        if (securityPrefs.getBoolean(DB_MIGRATION_COMPLETE_KEY, false)) {
            return
        }
        val dbFile = appContext.getDatabasePath(DATABASE_NAME)
        if (!dbFile.exists()) {
            securityPrefs.edit().putBoolean(DB_MIGRATION_COMPLETE_KEY, true).apply()
            return
        }
        if (!dbHeaderStartsWithPlaintextMagic(dbFile)) {
            securityPrefs.edit().putBoolean(DB_MIGRATION_COMPLETE_KEY, true).apply()
            return
        }
        val legacyDbFile = appContext.getDatabasePath("$DATABASE_NAME.legacy")
        val legacyWalFile = appContext.getDatabasePath("$DATABASE_NAME.legacy-wal")
        val legacyShmFile = appContext.getDatabasePath("$DATABASE_NAME.legacy-shm")
        appContext.getDatabasePath("$DATABASE_NAME-wal").takeIf { it.exists() }?.renameTo(legacyWalFile)
        appContext.getDatabasePath("$DATABASE_NAME-shm").takeIf { it.exists() }?.renameTo(legacyShmFile)
        if (!dbFile.renameTo(legacyDbFile)) {
            return
        }
        val plaintextDb = android.database.sqlite.SQLiteDatabase.openDatabase(
            legacyDbFile.absolutePath,
            null,
            android.database.sqlite.SQLiteDatabase.OPEN_READONLY,
        )
        val encryptedDb = writableDb()
        try {
            encryptedDb.beginTransaction()
            try {
                migrateTable(
                    plaintextDb,
                    encryptedDb,
                    table = "direct_messages",
                    columns = listOf(
                        "user_id",
                        "peer_user_id",
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
                )
                migrateTable(
                    plaintextDb,
                    encryptedDb,
                    table = "group_messages",
                    columns = listOf(
                        "user_id",
                        "group_id",
                        "direction",
                        "body_ciphertext",
                        "sent_at_millis",
                        "transport_message_id",
                    ),
                )
                migrateTable(
                    plaintextDb,
                    encryptedDb,
                    table = "outbox_items",
                    columns = listOf(
                        "user_id",
                        "item_id",
                        "peer_user_id",
                        "plaintext_ciphertext",
                        "created_at_millis",
                        "ephemeral_ttl_seconds",
                        "sealed_sender",
                    ),
                )
                encryptedDb.setTransactionSuccessful()
            } finally {
                encryptedDb.endTransaction()
            }
            securityPrefs.edit().putBoolean(DB_MIGRATION_COMPLETE_KEY, true).apply()
            legacyDbFile.delete()
            legacyWalFile.delete()
            legacyShmFile.delete()
        } finally {
            plaintextDb.close()
            encryptedDb.close()
        }
    }

    private fun dbHeaderStartsWithPlaintextMagic(path: java.io.File): Boolean {
        if (!path.exists()) {
            return false
        }
        val header = ByteArray(16)
        val bytesRead = path.inputStream().use { input -> input.read(header) }
        if (bytesRead <= 0) {
            return false
        }
        return header
            .copyOf(bytesRead)
            .toString(Charsets.US_ASCII)
            .startsWith(SQLITE_PLAINTEXT_MAGIC)
    }

    private fun migrateTable(
        plaintextDb: android.database.sqlite.SQLiteDatabase,
        encryptedDb: SqlCipherDatabase,
        table: String,
        columns: List<String>,
    ) {
        plaintextDb.query(
            table,
            columns.toTypedArray(),
            null,
            null,
            null,
            null,
            null,
        ).use { cursor ->
            while (cursor.moveToNext()) {
                val values = ContentValues()
                for (column in columns) {
                    copyColumn(values, cursor, column)
                }
                encryptedDb.insertWithOnConflict(
                    table,
                    null,
                    values,
                    SqlCipherDatabase.CONFLICT_REPLACE,
                )
            }
        }
    }

    fun listDirectMessages(userId: String, peerUserId: String): List<ThreadMessage> {
        if (userId.isBlank() || peerUserId.isBlank()) return emptyList()
        val db = readableDb()
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
        val db = writableDb()
        db.beginTransaction()
        try {
            db.insertWithOnConflict(
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
                SqlCipherDatabase.CONFLICT_IGNORE,
            )
            trimThread("direct_messages", "user_id = ? AND peer_user_id = ?", arrayOf(userId, peerUserId), DIRECT_THREAD_LIMIT)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun importDirectMessages(userId: String, peerUserId: String, messages: List<ThreadMessage>) {
        if (messages.isEmpty()) return
        val db = writableDb()
        db.beginTransaction()
        try {
            for (message in messages) {
                db.insertWithOnConflict(
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
                    SqlCipherDatabase.CONFLICT_IGNORE,
                )
            }
            trimThread("direct_messages", "user_id = ? AND peer_user_id = ?", arrayOf(userId, peerUserId), DIRECT_THREAD_LIMIT)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun updateDirectMessageReceipt(
        userId: String,
        peerUserId: String,
        transportMessageId: Long,
        receiptType: String,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) return
        writableDb().update(
            "direct_messages",
            ContentValues().apply { put("receipt_status", receiptType) },
            "user_id = ? AND peer_user_id = ? AND direction = ? AND transport_message_id = ?",
            arrayOf(userId, peerUserId, "outbound", transportMessageId.toString()),
        )
    }

    fun listGroupMessages(userId: String, groupId: String): List<ThreadMessage> {
        if (userId.isBlank() || groupId.isBlank()) return emptyList()
        val db = readableDb()
        db.query(
            "group_messages",
            arrayOf(
                "direction",
                "body_ciphertext",
                "sent_at_millis",
                "transport_message_id",
                "reply_to_id",
                "reactions_ciphertext",
            ),
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

    fun appendGroupMessage(userId: String, groupId: String, message: ThreadMessage) {
        if (userId.isBlank() || groupId.isBlank()) return
        val db = writableDb()
        db.beginTransaction()
        try {
            db.insertWithOnConflict(
                "group_messages",
                null,
                ContentValues().apply {
                    put("user_id", userId)
                    put("group_id", groupId)
                    put("direction", message.direction)
                    put("body_ciphertext", encryptString(message.body))
                    put("sent_at_millis", message.sentAtMillis)
                    put("transport_message_id", message.transportMessageId)
                    put("reply_to_id", message.replyToId)
                    put(
                        "reactions_ciphertext",
                        message.reactions?.let { encryptString(gson.toJson(it)) },
                    )
                },
                SqlCipherDatabase.CONFLICT_IGNORE,
            )
            trimThread("group_messages", "user_id = ? AND group_id = ?", arrayOf(userId, groupId), GROUP_THREAD_LIMIT)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun updateDirectMessageReactions(
        userId: String,
        peerUserId: String,
        direction: String,
        sentAtMillis: Long,
        reactions: Map<String, String>?,
    ) {
        if (userId.isBlank() || peerUserId.isBlank()) return
        writableDb().update(
            "direct_messages",
            ContentValues().apply {
                put(
                    "reactions_ciphertext",
                    reactions?.takeIf { it.isNotEmpty() }?.let { encryptString(gson.toJson(it)) },
                )
            },
            "user_id = ? AND peer_user_id = ? AND direction = ? AND sent_at_millis = ?",
            arrayOf(userId, peerUserId, direction, sentAtMillis.toString()),
        )
    }

    fun updateGroupMessageReactions(
        userId: String,
        groupId: String,
        direction: String,
        sentAtMillis: Long,
        reactions: Map<String, String>?,
    ) {
        if (userId.isBlank() || groupId.isBlank()) return
        writableDb().update(
            "group_messages",
            ContentValues().apply {
                put(
                    "reactions_ciphertext",
                    reactions?.takeIf { it.isNotEmpty() }?.let { encryptString(gson.toJson(it)) },
                )
            },
            "user_id = ? AND group_id = ? AND direction = ? AND sent_at_millis = ?",
            arrayOf(userId, groupId, direction, sentAtMillis.toString()),
        )
    }

    fun importGroupMessages(userId: String, groupId: String, messages: List<ThreadMessage>) {
        if (messages.isEmpty()) return
        val db = writableDb()
        db.beginTransaction()
        try {
            for (message in messages) {
                db.insertWithOnConflict(
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
                    SqlCipherDatabase.CONFLICT_IGNORE,
                )
            }
            trimThread("group_messages", "user_id = ? AND group_id = ?", arrayOf(userId, groupId), GROUP_THREAD_LIMIT)
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun enqueueOutbox(userId: String, item: OutboxItem) {
        if (userId.isBlank()) return
        writableDb().insertWithOnConflict(
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
            SqlCipherDatabase.CONFLICT_REPLACE,
        )
    }

    fun importOutboxItems(userId: String, items: List<OutboxItem>) {
        if (items.isEmpty()) return
        val db = writableDb()
        db.beginTransaction()
        try {
            for (item in items) {
                enqueueOutbox(userId, item)
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun listOutbox(userId: String): List<OutboxItem> {
        if (userId.isBlank()) return emptyList()
        readableDb().query(
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
        writableDb().delete(
            "outbox_items",
            "user_id = ? AND item_id = ?",
            arrayOf(userId, itemId.toString()),
        )
    }

    fun clearOutbox(userId: String) {
        if (userId.isBlank()) return
        writableDb().delete("outbox_items", "user_id = ?", arrayOf(userId))
    }

    fun clearUser(userId: String) {
        if (userId.isBlank()) return
        val db = writableDb()
        db.beginTransaction()
        try {
            db.delete("direct_messages", "user_id = ?", arrayOf(userId))
            db.delete("group_messages", "user_id = ?", arrayOf(userId))
            db.delete("outbox_items", "user_id = ?", arrayOf(userId))
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    private fun trimThread(
        table: String,
        whereClause: String,
        whereArgs: Array<String>,
        limit: Int,
    ) {
        writableDb().execSQL(
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

private fun copyColumn(values: ContentValues, cursor: Cursor, columnName: String) {
    val index = cursor.getColumnIndexOrThrow(columnName)
    when (cursor.getType(index)) {
        Cursor.FIELD_TYPE_NULL -> values.putNull(columnName)
        Cursor.FIELD_TYPE_INTEGER -> values.put(columnName, cursor.getLong(index))
        Cursor.FIELD_TYPE_FLOAT -> values.put(columnName, cursor.getDouble(index))
        Cursor.FIELD_TYPE_STRING -> values.put(columnName, cursor.getString(index))
        Cursor.FIELD_TYPE_BLOB -> values.put(columnName, cursor.getBlob(index))
        else -> values.put(columnName, cursor.getString(index))
    }
}
