package com.pqmsg.demo

import android.widget.ListView
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ConversationsActivityFlowTest {
    @Test
    fun seeded_conversation_is_visible_in_home_list() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val userId = "flow-home-user"
        val store = FlowTestStoreHelpers.seedSecureProfile(context, userId, "test2")
        store.markPeerAccepted(userId, "test2")
        store.upsertConversation(userId, "test2", "You: hello from seed", false)

        val scenario = ActivityScenario.launch(ConversationsActivity::class.java)
        scenario.onActivity { activity ->
            val list = activity.findViewById<ListView>(R.id.listConversations)
            val profile = activity.findViewById<TextView>(R.id.textCurrentProfile)
            val row = list.adapter.getView(0, null, list)

            assertTrue(profile.text.toString().contains(userId))
            assertEquals(1, list.adapter.count)
            assertEquals("test2", row.findViewById<TextView>(R.id.textConversationPeer).text.toString())
            assertTrue(
                row.findViewById<TextView>(R.id.textConversationPreview)
                    .text
                    .toString()
                    .contains("hello from seed"),
            )
        }
        scenario.close()
    }
}
