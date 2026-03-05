package com.pqmsg.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged

class ConversationsActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var peerInput: EditText
    private lateinit var openPeerButton: Button
    private lateinit var openSecurityButton: Button
    private lateinit var refreshButton: Button
    private lateinit var backButton: Button
    private lateinit var statusText: TextView
    private lateinit var emptyText: TextView
    private lateinit var conversationsList: ListView
    private lateinit var adapter: ArrayAdapter<String>
    private var currentConversations: List<ConversationSummary> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_conversations)
        store = LocalStateStore(this)

        serverInput = findViewById(R.id.editConversationsServer)
        userInput = findViewById(R.id.editConversationsUser)
        peerInput = findViewById(R.id.editConversationsPeer)
        openPeerButton = findViewById(R.id.buttonOpenPeerChat)
        openSecurityButton = findViewById(R.id.buttonOpenSecurityCenter)
        refreshButton = findViewById(R.id.buttonRefreshConversations)
        backButton = findViewById(R.id.buttonBackSetupFromConversations)
        statusText = findViewById(R.id.textConversationsStatus)
        emptyText = findViewById(R.id.textConversationsEmpty)
        conversationsList = findViewById(R.id.listConversations)
        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, mutableListOf())
        conversationsList.adapter = adapter

        val setup = store.loadSetup()
        serverInput.setText(intent.getStringExtra("server") ?: setup.serverUrl)
        userInput.setText(intent.getStringExtra("user") ?: setup.userId)
        peerInput.setText(intent.getStringExtra("peer_seed") ?: setup.peerUserId)

        configureInputObservers()
        configureListEvents()
        configureButtons()
        refreshConversations()
        syncActionAvailability()
    }

    override fun onResume() {
        super.onResume()
        refreshConversations()
    }

    private fun configureInputObservers() {
        serverInput.doAfterTextChanged { syncActionAvailability() }
        userInput.doAfterTextChanged {
            refreshConversations()
            syncActionAvailability()
        }
        peerInput.doAfterTextChanged { syncActionAvailability() }
    }

    private fun configureListEvents() {
        conversationsList.setOnItemClickListener { _, _, position, _ ->
            val conversation = currentConversations.getOrNull(position) ?: return@setOnItemClickListener
            openChat(conversation.peerUserId)
        }
    }

    private fun configureButtons() {
        openPeerButton.setOnClickListener {
            val peer = peerInput.text.toString().trim()
            if (peer.isBlank()) {
                statusText.text = "Enter peer user id to start chat."
                return@setOnClickListener
            }
            openChat(peer)
        }
        openSecurityButton.setOnClickListener {
            val intent = Intent(this, SecurityInfoActivity::class.java).apply {
                putExtra("server", serverInput.text.toString().trim())
                putExtra("user", userInput.text.toString().trim())
            }
            startActivity(intent)
        }
        refreshButton.setOnClickListener {
            refreshConversations()
        }
        backButton.setOnClickListener {
            finish()
        }
    }

    private fun openChat(peerUserId: String) {
        val server = serverInput.text.toString().trim()
        val user = userInput.text.toString().trim()
        if (server.isBlank() || user.isBlank()) {
            statusText.text = "Server URL and user id are required."
            return
        }
        val existingSetup = store.loadSetup()
        store.saveSetup(
            existingSetup.copy(
                serverUrl = server,
                userId = user,
                peerUserId = peerUserId,
            ),
        )
        store.markConversationRead(user, peerUserId)
        val intent = Intent(this, ChatActivity::class.java).apply {
            putExtra("server", server)
            putExtra("user", user)
            putExtra("peer", peerUserId)
        }
        startActivity(intent)
    }

    private fun refreshConversations() {
        val user = userInput.text.toString().trim()
        val seedPeer = peerInput.text.toString().trim()
        val listed = store.listConversations(user)
        currentConversations = if (listed.isEmpty() && seedPeer.isNotBlank()) {
            listOf(
                ConversationSummary(
                    peerUserId = seedPeer,
                    lastPreview = "Ready to start secure session",
                    updatedAtMillis = 0L,
                    unreadCount = 0,
                ),
            )
        } else {
            listed
        }
        adapter.clear()
        adapter.addAll(currentConversations.map(::formatConversationLine))
        adapter.notifyDataSetChanged()
        if (currentConversations.isEmpty()) {
            conversationsList.visibility = View.GONE
            emptyText.visibility = View.VISIBLE
            statusText.text = "No conversations yet."
        } else {
            conversationsList.visibility = View.VISIBLE
            emptyText.visibility = View.GONE
            statusText.text = "${currentConversations.size} conversation(s) available."
        }
    }

    private fun formatConversationLine(item: ConversationSummary): String {
        val unreadSuffix = if (item.unreadCount > 0) {
            "  [${item.unreadCount} unread]"
        } else {
            ""
        }
        return "${item.peerUserId}\n${item.lastPreview}$unreadSuffix"
    }

    private fun syncActionAvailability() {
        val serverReady = serverInput.text.toString().trim().isNotBlank()
        val userReady = userInput.text.toString().trim().isNotBlank()
        val peerReady = peerInput.text.toString().trim().isNotBlank()
        openPeerButton.isEnabled = serverReady && userReady && peerReady
        openSecurityButton.isEnabled = serverReady && userReady
    }
}
