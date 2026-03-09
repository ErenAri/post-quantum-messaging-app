package com.pqmsg.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class ConversationsActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var composeButton: Button
    private lateinit var requestsButton: Button
    private lateinit var openSecurityButton: Button
    private lateinit var refreshButton: Button
    private lateinit var shareInviteButton: Button
    private lateinit var groupsButton: Button
    private lateinit var contactsButton: Button
    private lateinit var statusText: TextView
    private lateinit var profileText: TextView
    private lateinit var emptyText: TextView
    private lateinit var conversationsList: ListView
    private lateinit var adapter: ConversationSummaryAdapter
    private var currentConversations: List<ConversationSummary> = emptyList()
    private var syncInFlight = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = LocalStateStore(this)
        if (!hasIdentity()) {
            redirectToOnboarding()
            return
        }
        setContentView(R.layout.activity_conversations)

        composeButton = findViewById(R.id.buttonComposeConversation)
        requestsButton = findViewById(R.id.buttonOpenMessageRequests)
        openSecurityButton = findViewById(R.id.buttonOpenSecurityCenter)
        refreshButton = findViewById(R.id.buttonRefreshConversations)
        shareInviteButton = findViewById(R.id.buttonShareInvite)
        groupsButton = findViewById(R.id.buttonOpenGroups)
        contactsButton = findViewById(R.id.buttonOpenContacts)
        statusText = findViewById(R.id.textConversationsStatus)
        profileText = findViewById(R.id.textCurrentProfile)
        emptyText = findViewById(R.id.textConversationsEmpty)
        conversationsList = findViewById(R.id.listConversations)
        adapter = ConversationSummaryAdapter(this)
        conversationsList.adapter = adapter

        configureListEvents()
        configureButtons()
        renderHome()
    }

    override fun onResume() {
        super.onResume()
        if (!hasIdentity()) {
            redirectToOnboarding()
            return
        }
        renderHome()
        syncInbox()
    }

    private fun hasIdentity(): Boolean {
        val setup = store.loadSetup()
        if (setup.userId.isBlank() || setup.serverUrl.isBlank()) {
            return false
        }
        return !store.readKeys(setup.userId).isNullOrBlank()
    }

    private fun redirectToOnboarding() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private fun configureListEvents() {
        conversationsList.setOnItemClickListener { _, _, position, _ ->
            val conversation = currentConversations.getOrNull(position) ?: return@setOnItemClickListener
            openChat(conversation.peerUserId)
        }
    }

    private fun configureButtons() {
        composeButton.setOnClickListener { showComposeDialog() }
        refreshButton.setOnClickListener { syncInbox(forceStatus = true) }
        requestsButton.setOnClickListener { showMessageRequestsDialog() }
        shareInviteButton.setOnClickListener { shareInvite() }
        openSecurityButton.setOnClickListener {
            startActivity(Intent(this, SecurityInfoActivity::class.java))
        }
        groupsButton.setOnClickListener { showGroupsDialog() }
        contactsButton.setOnClickListener {
            startActivity(Intent(this, ContactDiscoveryActivity::class.java))
        }
    }

    private fun renderHome() {
        val setup = store.loadSetup()
        profileText.text = "${setup.userId}\n${setup.serverUrl}"
        refreshConversations()
        updateRequestsButton()
    }

    private fun refreshConversations() {
        val user = store.loadSetup().userId
        currentConversations = store.listConversations(user)
        adapter.submitList(currentConversations)
        if (currentConversations.isEmpty()) {
            conversationsList.visibility = View.GONE
            emptyText.visibility = View.VISIBLE
            statusText.text = "No chats yet. Use Compose to start the first conversation."
        } else {
            conversationsList.visibility = View.VISIBLE
            emptyText.visibility = View.GONE
            statusText.text = "${currentConversations.size} chat(s) ready."
        }
    }

    private fun updateRequestsButton() {
        val requestCount = store.listMessageRequests(store.loadSetup().userId).size
        if (requestCount == 0) {
            requestsButton.visibility = View.GONE
            requestsButton.text = getString(R.string.button_open_message_requests)
            return
        }
        requestsButton.visibility = View.VISIBLE
        requestsButton.text = resources.getQuantityString(
            R.plurals.message_request_count,
            requestCount,
            requestCount,
        )
    }

    private fun syncInbox(forceStatus: Boolean = false) {
        if (syncInFlight) {
            return
        }
        val setup = store.loadSetup()
        lifecycleScope.launch {
            syncInFlight = true
            if (forceStatus) {
                statusText.text = "Syncing chats..."
            }
            runCatching {
                MessagingCoordinator.syncInbox(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
            }.onSuccess { outcome ->
                renderHome()
                statusText.text = when {
                    outcome.discoveredGroups > 0 ->
                        "Synced ${outcome.discoveredGroups} group(s)."
                    outcome.pendingRequests > 0 ->
                        "${outcome.pendingRequests} message request(s) need review."
                    outcome.deliveredMessages > 0 ->
                        "Synced ${outcome.deliveredMessages} new message(s)."
                    else ->
                        "Inbox is up to date."
                }
            }.onFailure {
                val mapped = UiErrorMapper.fromThrowable(it, "Sync inbox")
                statusText.text = mapped.headline
            }
            syncInFlight = false
        }
    }

    private fun showComposeDialog() {
        val setup = store.loadSetup()
        val input = EditText(this).apply {
            hint = getString(R.string.hint_username_or_invite)
            setText(setup.peerUserId)
            setSelection(text?.length ?: 0)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.compose_dialog_title)
            .setView(input)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.button_open_peer_chat) { _, _ ->
                runCatching {
                    val target = MessagingCoordinator.parseComposeTarget(
                        input.text.toString(),
                        setup.serverUrl,
                    )
                    val updatedSetup = setup.copy(
                        serverUrl = target.serverUrl,
                        peerUserId = target.peerUserId,
                    )
                    store.saveSetup(updatedSetup)
                    store.markPeerAccepted(updatedSetup.userId, target.peerUserId)
                    openChat(target.peerUserId)
                }.onFailure {
                    val mapped = UiErrorMapper.fromThrowable(it, "Compose conversation")
                    statusText.text = mapped.headline
                }
            }
            .show()
    }

    private fun showMessageRequestsDialog() {
        val user = store.loadSetup().userId
        val requests = store.listMessageRequests(user)
        if (requests.isEmpty()) {
            statusText.text = "No pending message requests."
            updateRequestsButton()
            return
        }
        val labels = requests.map { "${it.peerUserId}\n${it.lastPreview}" }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle(R.string.message_requests_title)
            .setItems(labels) { _, which ->
                val request = requests[which]
                AlertDialog.Builder(this)
                    .setTitle(request.peerUserId)
                    .setMessage(request.lastPreview)
                    .setNegativeButton(R.string.button_ignore_request) { _, _ ->
                        store.dismissMessageRequest(user, request.peerUserId)
                        renderHome()
                    }
                    .setPositiveButton(R.string.button_accept_request) { _, _ ->
                        store.acceptMessageRequest(user, request.peerUserId)
                        renderHome()
                        openChat(request.peerUserId)
                    }
                    .show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun shareInvite() {
        val setup = store.loadSetup()
        val invite = MessagingCoordinator.buildInviteLink(setup.serverUrl, setup.userId)
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, invite)
        }
        startActivity(Intent.createChooser(intent, getString(R.string.share_invite_chooser_title)))
    }

    private fun showGroupsDialog() {
        val user = store.loadSetup().userId
        val groups = store.listGroups(user)
        if (groups.isEmpty()) {
            showCreateGroupDialog()
            return
        }
        val labels = groups.map { "${it.displayName} (${it.memberCount} members)\n${it.lastPreview}" }.toTypedArray()
        val options = labels + arrayOf("+ Create new group")
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.button_open_groups))
            .setItems(options) { _, which ->
                if (which < groups.size) {
                    val group = groups[which]
                    startActivity(
                        Intent(this, GroupChatActivity::class.java).apply {
                            putExtra("group_id", group.groupId)
                            putExtra("group_name", group.displayName)
                        },
                    )
                } else {
                    showCreateGroupDialog()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showCreateGroupDialog() {
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 24, 48, 8)
        }
        val nameInput = EditText(this).apply {
            hint = getString(R.string.hint_group_name)
        }
        val membersInput = EditText(this).apply {
            hint = "Members (comma-separated usernames)"
        }
        layout.addView(nameInput)
        layout.addView(membersInput)

        AlertDialog.Builder(this)
            .setTitle(getString(R.string.create_group_dialog_title))
            .setView(layout)
            .setPositiveButton(getString(R.string.button_create_group)) { _, _ ->
                val groupName = nameInput.text.toString().trim()
                val members = membersInput.text.toString().split(",").map { it.trim() }.filter { it.isNotBlank() }
                if (groupName.isNotBlank() && members.isNotEmpty()) {
                    createGroup(groupName, members)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun createGroup(groupName: String, members: List<String>) {
        val setup = store.loadSetup()
        lifecycleScope.launch {
            runCatching {
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                )
                val keysJson = context.keysJson
                val groupId = "${setup.userId}-${groupName.lowercase().replace(" ", "-")}-${System.currentTimeMillis() % 10000}"
                val allMembers = (members + setup.userId).distinct()
                val response = context.api.createGroup(
                    headers = uniffi.pqmsg_android.buildInboxAuthHeaders(
                        keysJson = keysJson,
                        userId = context.profile.userId,
                        since = 0L,
                    ).toHeaderMap(),
                    request = CreateGroupRequest(
                        group_id = groupId,
                        member_user_ids = allMembers,
                    ),
                )
                store.upsertGroupConversation(
                    userId = setup.userId,
                    groupId = groupId,
                    displayName = groupName,
                    memberCount = response.member_count,
                    lastPreview = "Group created",
                    incrementUnread = false,
                )
                statusText.text = "Group '$groupName' created"
                startActivity(
                    Intent(this@ConversationsActivity, GroupChatActivity::class.java).apply {
                        putExtra("group_id", groupId)
                        putExtra("group_name", groupName)
                    },
                )
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Create group").headline
            }
        }
    }

    private fun openChat(peerUserId: String) {
        val setup = store.loadSetup()
        store.markPeerAccepted(setup.userId, peerUserId)
        store.markConversationRead(setup.userId, peerUserId)
        startActivity(
            Intent(this, ChatActivity::class.java).apply {
                putExtra("peer", peerUserId)
            },
        )
    }
}
