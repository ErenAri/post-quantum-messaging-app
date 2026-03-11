package com.pqmsg.demo

import android.content.Context
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onData
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.Visibility.GONE
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.hamcrest.CoreMatchers.anything
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.containsString
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.generateIdentityKeys

@RunWith(AndroidJUnit4::class)
class ClientFlowInstrumentationTest {
    private val appContext: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @After
    fun tearDownState() {
        val store = LocalStateStore(appContext)
        listOf("alice", "bob", "carol", "group-owner").forEach(store::wipeUserState)
        store.saveSetup(
            SetupConfig(
                serverUrl = "http://10.0.2.2:3000",
                userId = "",
                deviceId = "",
                suiteLabel = "ml-kem-768",
                peerUserId = "bob",
            ),
        )
    }

    @Test
    fun main_activity_redirects_to_conversations_when_profile_exists() {
        seedIdentity("alice")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val monitor = instrumentation.addMonitor(ConversationsActivity::class.java.name, null, false)

        val scenario = ActivityScenario.launch(MainActivity::class.java)
        val launched = instrumentation.waitForMonitorWithTimeout(monitor, 5_000)

        assertNotNull("expected ConversationsActivity to launch", launched)
        launched?.finish()
        scenario.close()
        instrumentation.removeMonitor(monitor)
    }

    @Test
    fun conversations_activity_renders_seeded_conversation_and_hides_empty_state() {
        val store = seedIdentity("alice")
        store.markPeerAccepted("alice", "bob")
        store.upsertConversation("alice", "bob", "Latest hello from Bob", incrementUnread = true)

        val scenario = ActivityScenario.launch(ConversationsActivity::class.java)

        onView(withId(R.id.textCurrentProfile)).check(matches(withText(containsString("alice"))))
        onView(withText("bob")).check(matches(isDisplayed()))
        onView(withText("Latest hello from Bob")).check(matches(isDisplayed()))
        onView(withId(R.id.textConversationsEmpty)).check(matches(withEffectiveVisibility(GONE)))

        scenario.close()
    }

    @Test
    fun conversations_activity_accepts_message_request_from_local_state() {
        val store = seedIdentity("alice")
        store.upsertMessageRequest("alice", "carol", "carol: hello from a request")

        val scenario = ActivityScenario.launch(ConversationsActivity::class.java)

        onView(withId(R.id.buttonOpenMessageRequests)).check(matches(isDisplayed()))
        onView(withId(R.id.buttonOpenMessageRequests)).perform(click())
        onData(anything()).atPosition(0).perform(click())
        onView(withText(R.string.button_accept_request)).perform(click())

        assertTrue(store.isAcceptedPeer("alice", "carol"))
        assertTrue(store.listMessageRequests("alice").isEmpty())
        assertTrue(store.listConversations("alice").any { it.peerUserId == "carol" })

        scenario.close()
    }

    @Test
    fun chat_activity_renders_seeded_thread_history_and_marks_conversation_read() {
        val store = seedIdentity("alice")
        store.markPeerAccepted("alice", "bob")
        store.upsertConversation("alice", "bob", "Unread preview", incrementUnread = true)
        store.appendThreadMessage("alice", "bob", "inbound", "Hello Alice", transportMessageId = 1L)
        store.appendThreadMessage("alice", "bob", "outbound", "Hi Bob", transportMessageId = 2L)

        val scenario = ActivityScenario.launch<ChatActivity>(
            Intent(appContext, ChatActivity::class.java).apply {
                putExtra("peer", "bob")
            },
        )

        onView(withId(R.id.textChatMeta)).check(matches(withText(containsString("bob"))))
        onView(withId(R.id.textChatLog)).check(
            matches(
                withText(
                    allOf(
                        containsString("Hello Alice"),
                        containsString("Hi Bob"),
                    ),
                ),
            ),
        )

        assertTrue(store.listConversations("alice").first { it.peerUserId == "bob" }.unreadCount == 0)
        scenario.close()
    }

    @Test
    fun group_chat_activity_renders_seeded_group_history() {
        val store = seedIdentity("group-owner")
        store.upsertGroupConversation(
            userId = "group-owner",
            groupId = "group-1",
            displayName = "Launch Team",
            memberCount = 3,
            lastPreview = "You: welcome",
            incrementUnread = false,
        )
        store.appendGroupThreadMessage(
            userId = "group-owner",
            groupId = "group-1",
            senderUserId = "group-owner",
            body = "welcome",
            transportMessageId = 11L,
        )
        store.appendGroupThreadMessage(
            userId = "group-owner",
            groupId = "group-1",
            senderUserId = "bob",
            body = "hello everyone",
            transportMessageId = 12L,
        )

        val scenario = ActivityScenario.launch<GroupChatActivity>(
            Intent(appContext, GroupChatActivity::class.java).apply {
                putExtra("group_id", "group-1")
                putExtra("group_name", "Launch Team")
            },
        )

        onView(withId(R.id.textGroupTitle)).check(matches(withText("Launch Team")))
        onView(withId(R.id.textGroupMeta)).check(matches(withText(containsString("group-1"))))
        onView(withId(R.id.textGroupChatLog)).check(
            matches(
                withText(
                    allOf(
                        containsString("You: welcome"),
                        containsString("bob: hello everyone"),
                    ),
                ),
            ),
        )

        scenario.close()
    }

    private fun seedIdentity(userId: String): LocalStateStore {
        val store = LocalStateStore(appContext)
        store.wipeUserState(userId)
        val deviceId = "$userId-android-test"
        val keysJson = generateIdentityKeys(userId, deviceId, Suite.ML_KEM768, 8u)
        store.writeKeys(userId, keysJson)
        store.saveSetup(
            SetupConfig(
                serverUrl = "http://10.0.2.2:3000",
                userId = userId,
                deviceId = deviceId,
                suiteLabel = "ml-kem-768",
                peerUserId = "bob",
            ),
        )
        return store
    }
}
