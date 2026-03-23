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
import com.google.gson.Gson
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.buildContactInviteCreateAuthHeaders
import uniffi.pqmsg_android.buildContactsListAuthHeaders
import uniffi.pqmsg_android.privateGroupCreateState
import uniffi.pqmsg_android.privateGroupEncryptJoinPackageForShareLink
import uniffi.pqmsg_android.privateGroupOpenShareLinkInvite
import uniffi.pqmsg_android.privateGroupPrepareBootstrapMaterial
import uniffi.pqmsg_android.privateGroupRestoreJoinPackage
import java.util.Base64

class ConversationsActivity : AppCompatActivity() {
    private val gson = Gson()
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
    private var currentContactsByPeer: Map<String, ContactListItem> = emptyMap()
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
        refreshContactLabels()
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
        groupsButton.alpha = 1f
        refreshConversations()
        updateRequestsButton()
    }

    private fun showGroupMessagingUnavailable() {
        statusText.text = "Group messaging is disabled pending a private group design."
    }

    private fun refreshConversations() {
        val user = store.loadSetup().userId
        currentConversations = store.listConversations(user)
        adapter.submitContactLabels(currentContactsByPeer)
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

    private fun refreshContactLabels() {
        val setup = store.loadSetup()
        if (setup.userId.isBlank() || setup.serverUrl.isBlank()) {
            return
        }
        lifecycleScope.launch {
            runCatching {
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                    deviceId = setup.deviceId,
                )
                context.api.listContacts(
                    userId = context.profile.userId,
                    headers = buildContactsListAuthHeaders(
                        keysJson = context.keysJson,
                        userId = context.profile.userId,
                    ).toHeaderMap(),
                ).contacts.associateBy { it.contact_user_id }
            }.onSuccess { contacts ->
                if (contacts != currentContactsByPeer) {
                    currentContactsByPeer = contacts
                    adapter.submitContactLabels(currentContactsByPeer)
                }
            }
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
                statusText.text = "Checking peer..."
                lifecycleScope.launch {
                    runCatching {
                        val target = MessagingCoordinator.parseComposeTarget(
                            input.text.toString(),
                            setup.serverUrl,
                        )
                        val context = MessagingCoordinator.ensureReady(
                            store = store,
                            serverUrl = target.serverUrl,
                            userId = setup.userId,
                            suiteLabel = setup.suiteLabel,
                            deviceId = setup.deviceId,
                        )
                        val validatedBundle = when {
                            !target.inviteToken.isNullOrBlank() -> context.api.getContactInviteBundle(
                                target.inviteToken.trim(),
                            )
                            !target.username.isNullOrBlank() -> context.api.getUsernameBundle(
                                target.username.trim(),
                            )
                            else -> null
                        }
                        val resolvedPeerUserId = validatedBundle?.user_id?.trim()?.removePrefix("@")
                            ?.takeIf { it.isNotBlank() }
                            ?: MessagingCoordinator.resolvePeerUserId(
                                context.api,
                                target,
                            )
                        val peerBundle = validatedBundle ?: context.api.getBundle(resolvedPeerUserId)
                        val updatedSetup = setup.copy(
                            serverUrl = target.serverUrl,
                            peerUserId = resolvedPeerUserId,
                        )
                        store.saveSetup(updatedSetup)
                        store.markPeerAccepted(updatedSetup.userId, resolvedPeerUserId)
                        openChat(resolvedPeerUserId, peerBundle)
                    }.onFailure {
                        val mapped = UiErrorMapper.fromThrowable(it, "Compose conversation")
                        statusText.text = mapped.headline
                    }
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
        val labels = requests.map { request ->
            buildString {
                append(resolvePeerPrimaryLabel(request.peerUserId))
                resolvePeerSecondaryLabel(request.peerUserId)?.let { secondary ->
                    append('\n')
                    append(secondary)
                }
                append('\n')
                append(request.lastPreview)
            }
        }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle(R.string.message_requests_title)
            .setItems(labels) { _, which ->
                val request = requests[which]
                AlertDialog.Builder(this)
                    .setTitle(resolvePeerPrimaryLabel(request.peerUserId))
                    .setMessage(
                        listOfNotNull(
                            resolvePeerSecondaryLabel(request.peerUserId),
                            request.lastPreview,
                        ).joinToString("\n"),
                    )
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

    private fun resolvePeerPrimaryLabel(peerUserId: String): String {
        val contact = currentContactsByPeer[peerUserId] ?: return peerUserId
        return contact.alias?.trim()?.takeIf { it.isNotBlank() } ?: contactHandle(contact)
    }

    private fun resolvePeerSecondaryLabel(peerUserId: String): String? {
        val contact = currentContactsByPeer[peerUserId] ?: return null
        val handle = contactHandle(contact)
        return if (resolvePeerPrimaryLabel(peerUserId) == handle) null else handle
    }

    private fun contactHandle(contact: ContactListItem): String {
        val username = contact.username?.trim()?.removePrefix("@").orEmpty()
        return if (username.isNotBlank()) "@$username" else contact.contact_user_id
    }

    private fun shareInvite() {
        val setup = store.loadSetup()
        lifecycleScope.launch {
            runCatching {
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                    deviceId = setup.deviceId,
                )
                val invite = context.api.createContactInvite(
                    userId = context.profile.userId,
                    headers = buildContactInviteCreateAuthHeaders(
                        context.keysJson,
                        context.profile.userId,
                    ).toHeaderMap(),
                )
                val link = MessagingCoordinator.buildInviteLink(setup.serverUrl, invite.invite_token)
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, link)
                }
                statusText.text = "Private invite link ready to share"
                startActivity(
                    Intent.createChooser(intent, getString(R.string.share_invite_chooser_title)),
                )
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Share invite").headline
            }
        }
    }

    private fun showGroupsDialog() {
        val user = store.loadSetup().userId
        val groups = store.listGroups(user)
        if (groups.isEmpty()) {
            showCreateGroupDialog()
            return
        }
        val labels = groups.map { "${it.displayName} (${it.memberCount} members)\n${it.lastPreview}" }.toTypedArray()
        val options = labels + arrayOf("+ Create private group", "+ Join private group")
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
                } else if (which == groups.size) {
                    showCreateGroupDialog()
                } else {
                    showJoinPrivateGroupDialog()
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
                if (groupName.isNotBlank()) {
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
                val resolvedMembers = linkedSetOf<String>()
                for (rawTarget in members) {
                    val target = MessagingCoordinator.parseComposeTarget(rawTarget, setup.serverUrl)
                    require(
                        ApiClientFactory.normalizeBaseUrl(target.serverUrl) ==
                            ApiClientFactory.normalizeBaseUrl(setup.serverUrl),
                    ) { "Private-group members must use the current account server." }
                    val resolved = MessagingCoordinator.resolvePeerUserId(context.api, target)
                    require(resolved != context.profile.userId) { "You are already in this private group." }
                    resolvedMembers.add(resolved)
                }
                val stateJson = privateGroupCreateState(
                    context.profile.userId,
                    gson.toJson(
                        PrivateGroupAttributes(
                            title = groupName,
                            description = null,
                            avatar_hash_sha256 = null,
                            disappearing_message_timer_seconds = null,
                        ),
                    ),
                    gson.toJson(
                        resolvedMembers.map { memberUserId ->
                            PrivateGroupMember(user_id = memberUserId, role = "Member")
                        },
                    ),
                    (System.currentTimeMillis() / 1000).toULong(),
                )
                val state = parsePrivateGroupStateJson(stateJson)
                val bootstrap = parsePrivateGroupBootstrapMaterial(
                    privateGroupPrepareBootstrapMaterial(stateJson, context.profile.userId),
                )
                val stateCommitmentSha256 = publishPrivateGroupBootstrap(context.api, bootstrap)
                updateLocalPrivateGroupState(
                    store = store,
                    userId = context.profile.userId,
                    state = state,
                    memberCredential = bootstrap.authorizing_member_credential,
                    stateCommitmentSha256 = stateCommitmentSha256,
                    preview = "Private group created",
                    incrementUnread = false,
                )
                val inviteLinks = bootstrap.member_join_packages
                    .filter { it.member_user_id != context.profile.userId }
                    .map { joinPackage ->
                        val inviteMaterial = parsePrivateGroupLinkInviteMaterial(
                            privateGroupEncryptJoinPackageForShareLink(gson.toJson(joinPackage.join_package)),
                        )
                        "${joinPackage.member_user_id}: ${
                            createPrivateGroupInviteLinkFromJoinPackage(
                                api = context.api,
                                serverUrl = setup.serverUrl,
                                state = state,
                                authorizingCredential = bootstrap.authorizing_member_credential,
                                inviteMaterial = inviteMaterial,
                            )
                        }"
                    }
                statusText.text = "Private group '$groupName' created"
                if (inviteLinks.isNotEmpty()) {
                    startActivity(
                        Intent.createChooser(
                            Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, inviteLinks.joinToString("\n"))
                            },
                            getString(R.string.share_invite_chooser_title),
                        ),
                    )
                }
                startActivity(
                    Intent(this@ConversationsActivity, GroupChatActivity::class.java).apply {
                        putExtra("group_id", state.group_id)
                        putExtra("group_name", groupName)
                    },
                )
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Create group").headline
            }
        }
    }

    private fun showJoinPrivateGroupDialog() {
        val input = EditText(this).apply {
            hint = "Paste a private-group link"
        }
        AlertDialog.Builder(this)
            .setTitle("Join private group")
            .setView(input)
            .setPositiveButton("Join") { _, _ ->
                val link = input.text.toString().trim()
                if (link.isNotBlank()) {
                    joinPrivateGroup(link)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun joinPrivateGroup(rawLink: String) {
        val setup = store.loadSetup()
        lifecycleScope.launch {
            runCatching {
                val target = extractPrivateGroupInviteTarget(rawLink, setup.serverUrl)
                    ?: error("Private-group link is invalid or missing its secret fragment.")
                require(
                    ApiClientFactory.normalizeBaseUrl(target.serverUrl) ==
                        ApiClientFactory.normalizeBaseUrl(setup.serverUrl),
                ) { "Private-group links must target the current account server." }
                val context = MessagingCoordinator.ensureReady(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                    deviceId = setup.deviceId,
                )
                val invite = context.api.resolvePrivateGroupInvite(target.inviteToken)
                val joinPackageJson = privateGroupOpenShareLinkInvite(
                    gson.toJson(
                        PrivateGroupLinkInviteEnvelope(
                            group_id = invite.group_id,
                            epoch = invite.epoch,
                            invite_commitment_sha256 = privateGroupHexToIntList(invite.invite_commitment_sha256),
                            ciphertext = PrivateGroupCiphertextEnvelope(
                                nonce = Base64.getDecoder().decode(invite.invite_ciphertext_nonce_base64)
                                    .map { it.toInt() and 0xff },
                                ciphertext = Base64.getDecoder().decode(invite.invite_ciphertext_base64)
                                    .map { it.toInt() and 0xff },
                                aad = Base64.getDecoder().decode(invite.invite_ciphertext_aad_base64)
                                    .map { it.toInt() and 0xff },
                            ),
                        ),
                    ),
                    target.inviteSecretBase64,
                )
                val joinPackage = parsePrivateGroupJoinPackage(joinPackageJson)
                val restored = parsePrivateGroupRestoreResult(
                    privateGroupRestoreJoinPackage(joinPackageJson),
                )
                val memberMaterial = describePrivateGroupMemberCredential(restored.member_credential)
                val fetchedState = context.api.fetchPrivateGroupState(
                    FetchPrivateGroupStateRequest(
                        membership_handle_sha256 = memberMaterial.membership_handle_sha256,
                        fetch_key_base64 = memberMaterial.fetch_key_base64,
                    ),
                )
                require(fetchedState.group_id == restored.state.group_id && fetchedState.epoch == restored.state.epoch) {
                    "Private-group state fetch does not match the invite package."
                }
                require(
                    fetchedState.state_commitment_sha256 ==
                        privateGroupBytesToHex(joinPackage.invite.snapshot.state_commitment_sha256),
                ) { "Private-group state fetch failed commitment verification." }
                context.api.consumePrivateGroupInvite(target.inviteToken)
                updateLocalPrivateGroupState(
                    store = store,
                    userId = context.profile.userId,
                    state = restored.state,
                    memberCredential = restored.member_credential,
                    stateCommitmentSha256 = fetchedState.state_commitment_sha256,
                    preview = "Joined private group",
                    incrementUnread = false,
                )
                statusText.text = "Joined private group '${getPrivateGroupTitle(restored.state)}'"
                startActivity(
                    Intent(this@ConversationsActivity, GroupChatActivity::class.java).apply {
                        putExtra("group_id", restored.state.group_id)
                        putExtra("group_name", getPrivateGroupTitle(restored.state))
                    },
                )
            }.onFailure {
                statusText.text = UiErrorMapper.fromThrowable(it, "Join private group").headline
            }
        }
    }

    private fun openChat(peerUserId: String, initialBundle: BundleResponse? = null) {
        val setup = store.loadSetup()
        store.markPeerAccepted(setup.userId, peerUserId)
        store.markConversationRead(setup.userId, peerUserId)
        startActivity(
            Intent(this, ChatActivity::class.java).apply {
                putExtra("peer", peerUserId)
                initialBundle?.let { putExtra("peer_bundle_json", gson.toJson(it)) }
            },
        )
    }
}
