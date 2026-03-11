package com.pqmsg.demo

import android.content.Intent
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.button.MaterialButton
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ChatActivityFlowTest {
    @Test
    fun seeded_thread_renders_and_send_button_tracks_compose_text() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val userId = "flow-chat-user"
        val peerId = "test2"
        val store = FlowTestStoreHelpers.seedSecureProfile(context, userId, peerId)
        store.markPeerAccepted(userId, peerId)
        store.upsertConversation(userId, peerId, "You: seeded hello", false)
        store.appendThreadMessage(userId, peerId, "outbound", "Seeded hello")

        val intent = Intent(context, ChatActivity::class.java).apply {
            putExtra("peer", peerId)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

        val scenario = ActivityScenario.launch<ChatActivity>(intent)
        scenario.onActivity { activity ->
            val chatLog = activity.findViewById<TextView>(R.id.textChatLog)
            val messageInput = activity.findViewById<EditText>(R.id.editMessage)
            val sendButton = activity.findViewById<MaterialButton>(R.id.buttonSend)

            assertTrue(chatLog.text.toString().contains("Seeded hello"))
            assertFalse(sendButton.isEnabled)

            messageInput.setText("draft reply")
            assertTrue(sendButton.isEnabled)
        }
        scenario.close()
    }
}
