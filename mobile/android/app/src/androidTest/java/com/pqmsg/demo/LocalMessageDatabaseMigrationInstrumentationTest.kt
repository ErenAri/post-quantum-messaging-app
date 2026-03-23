package com.pqmsg.demo

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

private const val TEST_DATABASE_NAME = "pqmsg_local_messages.db"
private const val TEST_DB_SECURITY_PREFS = "pqmsg_android_db_security"
private const val TEST_DB_MIGRATION_COMPLETE_KEY = "local_message_db_sqlcipher_ready_v1"
private const val TEST_DB_PASSPHRASE_KEY = "local_message_db_passphrase_v1"

@RunWith(AndroidJUnit4::class)
class LocalMessageDatabaseMigrationInstrumentationTest {
    private val appContext: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun setUp() {
        MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        wipeDatabaseState()
    }

    @After
    fun tearDown() {
        wipeDatabaseState()
    }

    @Test
    fun firstOpenMigratesPlaintextDatabaseToSqlCipher() {
        seedLegacyPlaintextDatabase()

        val database = LocalMessageDatabase(appContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS)
        try {
            val directMessages = database.listDirectMessages("alice", "bob")
            val groupMessages = database.listGroupMessages("alice", "group-launch")
            val outboxItems = database.listOutbox("alice")

            assertEquals(1, directMessages.size)
            assertEquals("legacy inbound", directMessages.single().body)
            assertEquals(mapOf("bob" to "heart"), directMessages.single().reactions)

            assertEquals(1, groupMessages.size)
            assertEquals("legacy group update", groupMessages.single().body)

            assertEquals(1, outboxItems.size)
            assertEquals("legacy queued draft", outboxItems.single().plaintext)
            assertTrue(outboxItems.single().sealedSender)
        } finally {
            database.close()
        }

        val dbPath = appContext.getDatabasePath(TEST_DATABASE_NAME)
        assertTrue(dbPath.exists())
        assertFalse(
            "migrated SQLCipher file should not keep the plaintext SQLite header",
            dbHeaderStartsWithPlaintextMagic(dbPath),
        )
        assertFalse(appContext.getDatabasePath("$TEST_DATABASE_NAME.legacy").exists())
        assertFalse(appContext.getDatabasePath("$TEST_DATABASE_NAME.legacy-wal").exists())
        assertFalse(appContext.getDatabasePath("$TEST_DATABASE_NAME.legacy-shm").exists())
        assertTrue(securityPrefs().getBoolean(TEST_DB_MIGRATION_COMPLETE_KEY, false))

        val plaintextRead = runCatching {
            SQLiteDatabase.openDatabase(
                dbPath.absolutePath,
                null,
                SQLiteDatabase.OPEN_READONLY,
            ).use { plaintextDb ->
                plaintextDb.rawQuery("SELECT COUNT(*) FROM direct_messages", null).use { cursor ->
                    cursor.moveToFirst()
                    cursor.getInt(0)
                }
            }
        }
        assertTrue(
            "plaintext SQLite should not be able to read the SQLCipher database",
            plaintextRead.isFailure,
        )
    }

    @Test
    fun encryptedDatabaseSurvivesColdReopen() {
        LocalMessageDatabase(appContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS).use { database ->
            database.appendDirectMessage(
                "alice",
                "bob",
                ThreadMessage(
                    direction = "outbound",
                    body = "cold boot direct",
                    sentAtMillis = 5_000L,
                    transportMessageId = 31L,
                ),
            )
            database.appendGroupMessage(
                "alice",
                "group-launch",
                ThreadMessage(
                    direction = "inbound",
                    body = "cold boot group",
                    sentAtMillis = 6_000L,
                    transportMessageId = 32L,
                ),
            )
            database.enqueueOutbox(
                "alice",
                OutboxItem(
                    id = 9L,
                    peerUserId = "bob",
                    plaintext = "cold boot draft",
                    createdAtMillis = 7_000L,
                    ephemeralTtlSeconds = null,
                    sealedSender = true,
                ),
            )
        }

        LocalMessageDatabase(appContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS).use { reopened ->
            val directMessages = reopened.listDirectMessages("alice", "bob")
            val groupMessages = reopened.listGroupMessages("alice", "group-launch")
            val outboxItems = reopened.listOutbox("alice")

            assertEquals(1, directMessages.size)
            assertEquals("cold boot direct", directMessages.single().body)
            assertEquals(1, groupMessages.size)
            assertEquals("cold boot group", groupMessages.single().body)
            assertEquals(1, outboxItems.size)
            assertEquals("cold boot draft", outboxItems.single().plaintext)
            assertTrue(outboxItems.single().sealedSender)
        }
    }

    @Test
    fun encryptedDatabaseFailsClosedWhenWrappedPassphraseIsMissing() {
        LocalMessageDatabase(appContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS).use { database ->
            database.appendDirectMessage(
                "alice",
                "bob",
                ThreadMessage(
                    direction = "outbound",
                    body = "persisted secret",
                    sentAtMillis = 8_000L,
                    transportMessageId = 41L,
                ),
            )
        }

        val dbPath = appContext.getDatabasePath(TEST_DATABASE_NAME)
        assertTrue(dbPath.exists())
        securityPrefs().edit()
            .remove(TEST_DB_PASSPHRASE_KEY)
            .remove(TEST_DB_MIGRATION_COMPLETE_KEY)
            .apply()

        val failure = runCatching {
            LocalMessageDatabase(appContext, MasterKey.DEFAULT_MASTER_KEY_ALIAS).use { reopened ->
                reopened.listDirectMessages("alice", "bob")
            }
        }.exceptionOrNull()

        assertTrue(
            "missing wrapped passphrase should fail closed with a reprovision-specific error",
            failure is LocalSecureStorageUnavailableException,
        )
        assertTrue(dbPath.exists())
        assertFalse(appContext.getDatabasePath("$TEST_DATABASE_NAME.legacy").exists())
        assertFalse(
            "existing SQLCipher file must not be mistaken for legacy plaintext during reopen",
            dbHeaderStartsWithPlaintextMagic(dbPath),
        )
    }

    private fun seedLegacyPlaintextDatabase() {
        val dbPath = appContext.getDatabasePath(TEST_DATABASE_NAME)
        dbPath.parentFile?.mkdirs()
        SQLiteDatabase.openOrCreateDatabase(dbPath, null).use { plaintextDb ->
            plaintextDb.execSQL(
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
                    reactions_ciphertext TEXT
                )
                """.trimIndent(),
            )
            plaintextDb.execSQL(
                """
                CREATE TABLE group_messages (
                    row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    body_ciphertext TEXT NOT NULL,
                    sent_at_millis INTEGER NOT NULL,
                    transport_message_id INTEGER
                )
                """.trimIndent(),
            )
            plaintextDb.execSQL(
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
            plaintextDb.execSQL(
                """
                INSERT INTO direct_messages(
                    user_id,
                    peer_user_id,
                    direction,
                    body_ciphertext,
                    sent_at_millis,
                    transport_message_id,
                    reactions_ciphertext
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                arrayOf("alice", "bob", "inbound", "legacy inbound", 1_000L, 11L, """{"bob":"heart"}"""),
            )
            plaintextDb.execSQL(
                """
                INSERT INTO group_messages(
                    user_id,
                    group_id,
                    direction,
                    body_ciphertext,
                    sent_at_millis,
                    transport_message_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                arrayOf("alice", "group-launch", "inbound", "legacy group update", 2_000L, 22L),
            )
            plaintextDb.execSQL(
                """
                INSERT INTO outbox_items(
                    user_id,
                    item_id,
                    peer_user_id,
                    plaintext_ciphertext,
                    created_at_millis,
                    ephemeral_ttl_seconds,
                    sealed_sender
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                arrayOf("alice", 7L, "bob", "legacy queued draft", 3_000L, null, 1),
            )
        }
    }

    private fun dbHeaderStartsWithPlaintextMagic(path: File): Boolean {
        if (!path.exists()) return false
        val header = ByteArray(16)
        val bytesRead = path.inputStream().use { input -> input.read(header) }
        if (bytesRead <= 0) {
            return false
        }
        return header
            .copyOf(bytesRead)
            .toString(Charsets.US_ASCII)
            .startsWith("SQLite format 3")
    }

    private fun securityPrefs() = EncryptedSharedPreferences.create(
        appContext,
        TEST_DB_SECURITY_PREFS,
        MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    private fun wipeDatabaseState() {
        val databaseDir = appContext.getDatabasePath(TEST_DATABASE_NAME).parentFile
        listOf(
            TEST_DATABASE_NAME,
            "$TEST_DATABASE_NAME-wal",
            "$TEST_DATABASE_NAME-shm",
            "$TEST_DATABASE_NAME-journal",
            "$TEST_DATABASE_NAME.legacy",
            "$TEST_DATABASE_NAME.legacy-wal",
            "$TEST_DATABASE_NAME.legacy-shm",
        ).forEach { fileName ->
            databaseDir?.resolve(fileName)?.delete()
        }
        appContext.deleteDatabase(TEST_DATABASE_NAME)
        appContext.deleteSharedPreferences(TEST_DB_SECURITY_PREFS)
    }
}
