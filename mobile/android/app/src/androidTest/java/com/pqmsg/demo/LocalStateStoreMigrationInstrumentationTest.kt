package com.pqmsg.demo

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.Gson
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LocalStateStoreMigrationInstrumentationTest {
    private val appContext: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val gson = Gson()

    @After
    fun tearDownState() {
        val store = LocalStateStore(appContext)
        store.wipeUserState("alice")
        FlowTestStoreHelpers.resetToBlankSetup(appContext)
    }

    @Test
    fun listThreadMessages_migrates_legacy_direct_thread_file_into_message_db() {
        val store = FlowTestStoreHelpers.seedSecureProfile(appContext, userId = "alice", peerUserId = "bob")
        val legacyPath = writeLegacyJson(
            "threads/alice/bob.json",
            listOf(
                ThreadMessage(
                    direction = "inbound",
                    body = "legacy inbound",
                    sentAtMillis = 1000L,
                    transportMessageId = 11L,
                ),
                ThreadMessage(
                    direction = "outbound",
                    body = "legacy outbound",
                    sentAtMillis = 2000L,
                    transportMessageId = 12L,
                ),
            ),
        )

        val messages = store.listThreadMessages("alice", "bob")

        assertEquals(2, messages.size)
        assertEquals("legacy inbound", messages[0].body)
        assertEquals("legacy outbound", messages[1].body)
        assertFalse("legacy direct-thread file should be removed after migration", legacyPath.exists())
        assertEquals(messages, store.listThreadMessages("alice", "bob"))
    }

    @Test
    fun listGroupThreadMessages_migrates_legacy_group_thread_file_into_message_db() {
        val store = FlowTestStoreHelpers.seedSecureProfile(appContext, userId = "alice", peerUserId = "bob")
        val legacyPath = writeLegacyJson(
            "threads/alice/group_launch-team.json",
            listOf(
                ThreadMessage(
                    direction = "outbound",
                    body = "You: legacy welcome",
                    sentAtMillis = 3000L,
                    transportMessageId = 21L,
                ),
                ThreadMessage(
                    direction = "inbound",
                    body = "bob: legacy hello",
                    sentAtMillis = 4000L,
                    transportMessageId = 22L,
                ),
            ),
        )

        val messages = store.listGroupThreadMessages("alice", "launch-team")

        assertEquals(2, messages.size)
        assertEquals("You: legacy welcome", messages[0].body)
        assertEquals("bob: legacy hello", messages[1].body)
        assertFalse("legacy group-thread file should be removed after migration", legacyPath.exists())
        assertEquals(messages, store.listGroupThreadMessages("alice", "launch-team"))
    }

    @Test
    fun listOutbox_migrates_legacy_outbox_file_into_message_db() {
        val store = FlowTestStoreHelpers.seedSecureProfile(appContext, userId = "alice", peerUserId = "bob")
        val legacyPath = writeLegacyJson(
            "outbox/alice.json",
            listOf(
                OutboxItem(
                    id = 1L,
                    peerUserId = "bob",
                    plaintext = "legacy queued 1",
                    createdAtMillis = 5000L,
                    ephemeralTtlSeconds = null,
                    sealedSender = false,
                ),
                OutboxItem(
                    id = 2L,
                    peerUserId = "carol",
                    plaintext = "legacy queued 2",
                    createdAtMillis = 6000L,
                    ephemeralTtlSeconds = 60L,
                    sealedSender = true,
                ),
            ),
        )

        val outbox = store.listOutbox("alice")

        assertEquals(2, outbox.size)
        assertEquals("legacy queued 1", outbox[0].plaintext)
        assertEquals("legacy queued 2", outbox[1].plaintext)
        assertFalse("legacy outbox file should be removed after migration", legacyPath.exists())
        assertEquals(outbox, store.listOutbox("alice"))
    }

    private fun writeLegacyJson(relativePath: String, value: Any): File {
        val path = File(appContext.filesDir, "pqmsg/$relativePath")
        path.parentFile?.mkdirs()
        path.writeText(gson.toJson(value))
        return path
    }
}
