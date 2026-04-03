package com.pqmsg.demo

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.view.MotionEvent
import android.widget.AdapterView
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.snackbar.Snackbar
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
import kotlin.math.abs

class ConversationsActivity : AppCompatActivity() {
    private enum class InboxFilter {
        ALL,
        UNREAD,
        GROUPS,
        REQUESTS,
    }

    private val gson = Gson()
    private lateinit var store: LocalStateStore
    private lateinit var composeButton: Button
    private lateinit var refreshButton: Button
    private lateinit var archivedButton: Button
    private lateinit var profileMenuButton: TextView
    private lateinit var filterAllButton: Button
    private lateinit var filterUnreadButton: Button
    private lateinit var filterGroupsButton: Button
    private lateinit var filterRequestsButton: Button
    private lateinit var statusText: TextView
    private lateinit var profileText: TextView
    private lateinit var emptyText: TextView
    private lateinit var conversationsList: ListView
    private lateinit var adapter: ConversationSummaryAdapter
    private var currentConversations: List<ConversationSummary> = emptyList()
    private var currentGroups: List<GroupSummary> = emptyList()
    private var currentRequests: List<MessageRequestSummary> = emptyList()
    private var currentInboxItems: List<InboxListItem> = emptyList()
    private var currentContactsByPeer: Map<String, ContactListItem> = emptyMap()
    private var selectedFilter = InboxFilter.ALL
    private var showArchivedOnly = false
    private var syncInFlight = false
    private var listTouchStartX = 0f
    private var listTouchStartY = 0f
    private var listTouchStartPosition = AdapterView.INVALID_POSITION
    private var activeSwipeContent: View? = null
    private var activeSwipeItem: InboxListItem? = null
    private var swipeGestureActive = false
    private val swipeActivationThresholdPx by lazy { resources.displayMetrics.density * 16f }
    private val archiveSwipeThresholdPx by lazy { resources.displayMetrics.density * 72f }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = LocalStateStore(this)
        /*
        if (!hasIdentity()) {
            redirectToOnboarding()
            return
        }
        */
        setContentView(R.layout.activity_conversations)

        composeButton = findViewById(R.id.buttonComposeConversation)
        refreshButton = findViewById(R.id.buttonRefreshConversations)
        archivedButton = findViewById(R.id.buttonArchivedConversations)
        profileMenuButton = findViewById(R.id.textProfileMenu)
        filterAllButton = findViewById(R.id.buttonFilterAll)
        filterUnreadButton = findViewById(R.id.buttonFilterUnread)
        filterGroupsButton = findViewById(R.id.buttonFilterGroups)
        filterRequestsButton = findViewById(R.id.buttonFilterRequests)
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
        /*
        if (!hasIdentity()) {
            redirectToOnboarding()
            return
        }
        */
        renderHome()
        refreshContactLabels()
        syncInbox()
    }

    private fun hasIdentity(): Boolean {
        return true
        /*
        val setup = store.loadSetup()
        if (setup.userId.isBlank() || setup.serverUrl.isBlank()) {
            return false
        }
        return !store.readKeys(setup.userId).isNullOrBlank()
        */
    }

    private fun redirectToOnboarding() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private fun configureListEvents() {
        conversationsList.setOnTouchListener { _, event ->
            handleInboxSwipeGesture(event)
        }
        conversationsList.setOnItemClickListener { _, _, position, _ ->
            val item = currentInboxItems.getOrNull(position) ?: return@setOnItemClickListener
            when (item.kind) {
                InboxItemKind.DIRECT -> openChat(item.id)
                InboxItemKind.GROUP -> openGroup(item.id)
                InboxItemKind.REQUEST -> showMessageRequestDialog(item.id)
            }
        }
        conversationsList.setOnItemLongClickListener { _, _, position, _ ->
            val item = currentInboxItems.getOrNull(position) ?: return@setOnItemLongClickListener false
            showInboxItemActions(item)
            true
        }
    }

    private fun handleInboxSwipeGesture(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                resetSwipeTracking()
                listTouchStartX = event.x
                listTouchStartY = event.y
                listTouchStartPosition = conversationsList.pointToPosition(event.x.toInt(), event.y.toInt())
                activeSwipeItem = currentInboxItems.getOrNull(listTouchStartPosition)?.takeIf {
                    it.kind == InboxItemKind.DIRECT || it.kind == InboxItemKind.GROUP
                }
                activeSwipeContent = findSwipeContentView(listTouchStartPosition)
            }
            MotionEvent.ACTION_MOVE -> {
                activeSwipeItem ?: return false
                val content = activeSwipeContent ?: return false
                val deltaX = event.x - listTouchStartX
                val deltaY = event.y - listTouchStartY
                if (!swipeGestureActive) {
                    if (deltaX <= 0f) {
                        return false
                    }
                    if (abs(deltaY) > swipeActivationThresholdPx && abs(deltaY) > deltaX) {
                        resetSwipeTracking()
                        return false
                    }
                    if (deltaX < swipeActivationThresholdPx || deltaX <= abs(deltaY) * 1.2f) {
                        return false
                    }
                    swipeGestureActive = true
                    conversationsList.requestDisallowInterceptTouchEvent(true)
                }
                val maxTranslation = content.width * 0.86f
                val translation = deltaX.coerceIn(0f, maxTranslation)
                content.translationX = translation
                content.alpha = 1f - (translation / maxTranslation) * 0.12f
                return true
            }
            MotionEvent.ACTION_UP -> {
                val item = activeSwipeItem
                val content = activeSwipeContent
                if (swipeGestureActive && item != null && content != null) {
                    val shouldArchive = content.translationX >= archiveSwipeThresholdPx
                    val animatedContent = content
                    resetSwipeTracking()
                    if (shouldArchive) {
                        animateSwipeCommit(animatedContent) {
                            performSwipeArchive(item)
                        }
                    } else {
                        animateSwipeReset(animatedContent)
                    }
                    return true
                }
                resetSwipeTracking()
            }
            MotionEvent.ACTION_CANCEL -> {
                activeSwipeContent?.let(::animateSwipeReset)
                resetSwipeTracking()
            }
        }
        return false
    }

    private fun findSwipeContentView(position: Int): View? {
        if (position == AdapterView.INVALID_POSITION) {
            return null
        }
        val childIndex = position - conversationsList.firstVisiblePosition
        if (childIndex < 0 || childIndex >= conversationsList.childCount) {
            return null
        }
        return conversationsList.getChildAt(childIndex)?.findViewById(R.id.conversationSwipeContent)
    }

    private fun animateSwipeReset(content: View) {
        content.animate()
            .translationX(0f)
            .alpha(1f)
            .setDuration(170L)
            .start()
    }

    private fun animateSwipeCommit(content: View, onCommitted: () -> Unit) {
        content.animate()
            .translationX(content.width.toFloat())
            .alpha(0.94f)
            .setDuration(150L)
            .withEndAction {
                content.translationX = 0f
                content.alpha = 1f
                onCommitted()
            }
            .start()
    }

    private fun performSwipeArchive(item: InboxListItem) {
        when (item.kind) {
            InboxItemKind.DIRECT -> setDirectConversationArchived(item.id, item.archivedAtMillis == 0L)
            InboxItemKind.GROUP -> setGroupConversationArchived(item.id, item.archivedAtMillis == 0L)
            InboxItemKind.REQUEST -> Unit
        }
    }

    private fun resetSwipeTracking() {
        listTouchStartPosition = AdapterView.INVALID_POSITION
        activeSwipeContent = null
        activeSwipeItem = null
        swipeGestureActive = false
    }

    private fun configureButtons() {
        composeButton.setOnClickListener { showComposeChooser() }
        refreshButton.setOnClickListener { syncInbox(forceStatus = true) }
        archivedButton.setOnClickListener { toggleArchivedView() }
        profileMenuButton.setOnClickListener { showProfileMenu() }
        filterAllButton.setOnClickListener { selectFilter(InboxFilter.ALL) }
        filterUnreadButton.setOnClickListener { selectFilter(InboxFilter.UNREAD) }
        filterGroupsButton.setOnClickListener { selectFilter(InboxFilter.GROUPS) }
        filterRequestsButton.setOnClickListener { selectFilter(InboxFilter.REQUESTS) }
    }

    private fun renderHome() {
        val setup = store.loadSetup()
        profileText.text = getString(R.string.conversations_profile_summary, setup.userId)
        profileMenuButton.text = buildAvatarText(setup.userId)
        refreshConversations()
    }

    private fun showGroupMessagingUnavailable() {
        statusText.text = getString(R.string.conversations_status_group_unavailable)
    }

    private fun requirePrivateGroupMessagingEnabled(context: ReadyMessagingContext) {
        require(context.capabilities.private_group_messaging_supported) {
            "Private-group messaging is not enabled on this server."
        }
    }

    private fun refreshConversations() {
        val user = store.loadSetup().userId
        currentConversations = store.listConversations(user)
        currentGroups = store.listGroups(user)
        currentRequests = store.listMessageRequests(user)
        currentInboxItems = buildInboxItems()
        adapter.submitList(currentInboxItems)
        updateArchivedButton()
        updateFilterButtons()
        updateRequestsFilterButton()
        if (currentInboxItems.isEmpty()) {
            conversationsList.visibility = View.GONE
            emptyText.visibility = View.VISIBLE
            emptyText.text = emptyStateMessage()
            statusText.text = emptyStateMessage()
        } else {
            conversationsList.visibility = View.VISIBLE
            emptyText.visibility = View.GONE
            statusText.text = statusSummary()
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
                    refreshConversations()
                }
            }
        }
    }

    private fun selectFilter(next: InboxFilter) {
        if (selectedFilter == next) {
            if (showArchivedOnly) {
                showArchivedOnly = false
                refreshConversations()
            }
            return
        }
        showArchivedOnly = false
        selectedFilter = next
        refreshConversations()
    }

    private fun updateFilterButtons() {
        updateFilterButton(filterAllButton, !showArchivedOnly && selectedFilter == InboxFilter.ALL)
        updateFilterButton(filterUnreadButton, !showArchivedOnly && selectedFilter == InboxFilter.UNREAD)
        updateFilterButton(filterGroupsButton, !showArchivedOnly && selectedFilter == InboxFilter.GROUPS)
        updateFilterButton(filterRequestsButton, !showArchivedOnly && selectedFilter == InboxFilter.REQUESTS)
    }

    private fun updateFilterButton(button: Button, active: Boolean) {
        button.isEnabled = !active
        button.alpha = if (active) 1f else 0.72f
    }

    private fun updateRequestsFilterButton() {
        filterRequestsButton.text = getString(R.string.conversations_filter_requests)
    }

    private fun updateArchivedButton() {
        val archivedCount = archivedConversationCount()
        if (showArchivedOnly || archivedCount > 0) {
            archivedButton.visibility = View.VISIBLE
            archivedButton.text = if (showArchivedOnly) {
                getString(R.string.button_back_to_inbox)
            } else {
                getString(R.string.conversations_archived_count, archivedCount)
            }
        } else {
            archivedButton.visibility = View.GONE
        }
    }

    private fun statusSummary(): String {
        val requestCount = currentRequests.size
        val visibleCount = currentInboxItems.size
        return when {
            showArchivedOnly ->
                getString(R.string.conversations_status_archived, visibleCount)
            requestCount > 0 && selectedFilter != InboxFilter.REQUESTS ->
                getString(R.string.conversations_status_requests, requestCount, visibleCount)
            selectedFilter == InboxFilter.REQUESTS ->
                getString(R.string.conversations_status_requests_only, visibleCount)
            else ->
                getString(R.string.conversations_status_visible, visibleCount)
        }
    }

    private fun emptyStateMessage(): String {
        if (showArchivedOnly) {
            return getString(R.string.conversations_empty_archived)
        }
        return when (selectedFilter) {
            InboxFilter.ALL -> getString(R.string.conversations_empty)
            InboxFilter.UNREAD -> getString(R.string.conversations_empty_unread)
            InboxFilter.GROUPS -> getString(R.string.conversations_empty_groups)
            InboxFilter.REQUESTS -> getString(R.string.conversations_empty_requests)
        }
    }

    private fun buildInboxItems(): List<InboxListItem> {
        val userId = store.loadSetup().userId
        val directItems = currentConversations.map { conversation ->
            val draft = store.readDirectThreadDraft(userId, conversation.peerUserId)
            val draftUpdatedAt = store.readDirectThreadDraftUpdatedAt(userId, conversation.peerUserId)
            InboxListItem(
                kind = InboxItemKind.DIRECT,
                id = conversation.peerUserId,
                title = resolvePeerPrimaryLabel(conversation.peerUserId),
                secondaryLabel = resolvePeerSecondaryLabel(conversation.peerUserId)
                    ?: getString(R.string.conversation_secondary_direct),
                kindBadge = null,
                pinnedAtMillis = store.readConversationPinnedAt(userId, conversation.peerUserId),
                archivedAtMillis = store.readConversationArchivedAt(userId, conversation.peerUserId),
                preview = if (draft.isNotBlank()) {
                    getString(R.string.conversation_preview_draft, draft)
                } else {
                    conversation.lastPreview
                },
                previewIsDraft = draft.isNotBlank(),
                updatedAtMillis = maxOf(conversation.updatedAtMillis, draftUpdatedAt),
                unreadCount = conversation.unreadCount,
            )
        }
        val groupItems = currentGroups.map { group ->
            val draft = store.readGroupThreadDraft(userId, group.groupId)
            val draftUpdatedAt = store.readGroupThreadDraftUpdatedAt(userId, group.groupId)
            InboxListItem(
                kind = InboxItemKind.GROUP,
                id = group.groupId,
                title = group.displayName,
                secondaryLabel = getString(R.string.conversation_secondary_group, group.memberCount),
                kindBadge = getString(R.string.conversation_state_group),
                pinnedAtMillis = store.readGroupPinnedAt(userId, group.groupId),
                archivedAtMillis = store.readGroupArchivedAt(userId, group.groupId),
                preview = if (draft.isNotBlank()) {
                    getString(R.string.conversation_preview_draft, draft)
                } else {
                    group.lastPreview
                },
                previewIsDraft = draft.isNotBlank(),
                updatedAtMillis = maxOf(group.updatedAtMillis, draftUpdatedAt),
                unreadCount = group.unreadCount,
            )
        }
        val requestItems = currentRequests.map { request ->
            InboxListItem(
                kind = InboxItemKind.REQUEST,
                id = request.peerUserId,
                title = resolvePeerPrimaryLabel(request.peerUserId),
                secondaryLabel = resolvePeerSecondaryLabel(request.peerUserId)
                    ?: getString(R.string.conversation_secondary_request),
                kindBadge = getString(R.string.conversation_state_request),
                pinnedAtMillis = 0L,
                archivedAtMillis = 0L,
                preview = request.lastPreview,
                previewIsDraft = false,
                updatedAtMillis = request.updatedAtMillis,
                unreadCount = request.unreadCount.coerceAtLeast(1),
            )
        }

        val inboxItems = directItems + groupItems
        val filtered = when {
            showArchivedOnly -> inboxItems.filter { it.archivedAtMillis > 0L }
            selectedFilter == InboxFilter.ALL -> inboxItems.filter { it.archivedAtMillis == 0L }
            selectedFilter == InboxFilter.UNREAD -> inboxItems.filter {
                it.archivedAtMillis == 0L && it.unreadCount > 0
            } + requestItems
            selectedFilter == InboxFilter.GROUPS -> groupItems.filter { it.archivedAtMillis == 0L }
            selectedFilter == InboxFilter.REQUESTS -> requestItems
            else -> emptyList()
        }
        return filtered.sortedWith(
            compareByDescending<InboxListItem> { it.pinnedAtMillis > 0L }
                .thenByDescending { it.pinnedAtMillis }
                .thenByDescending { it.updatedAtMillis },
        )
    }

    private fun archivedConversationCount(): Int {
        val userId = store.loadSetup().userId
        val directArchived = currentConversations.count {
            store.readConversationArchivedAt(userId, it.peerUserId) > 0L
        }
        val groupArchived = currentGroups.count {
            store.readGroupArchivedAt(userId, it.groupId) > 0L
        }
        return directArchived + groupArchived
    }

    private fun toggleArchivedView() {
        showArchivedOnly = !showArchivedOnly
        refreshConversations()
    }

    private fun buildAvatarText(label: String): String {
        val trimmed = label.trim()
        if (trimmed.isEmpty()) {
            return "?"
        }
        val parts = trimmed.split(" ", "-", "_", "@").filter { it.isNotBlank() }
        return when {
            parts.size >= 2 -> (parts[0].first().toString() + parts[1].first().toString()).uppercase()
            else -> trimmed.take(2).uppercase()
        }
    }

    private fun showProfileMenu() {
        val options = listOf(
            getString(R.string.profile_menu_contacts) to {
                startActivity(Intent(this, ContactDiscoveryActivity::class.java))
            },
            getString(R.string.profile_menu_share_invite) to {
                shareInvite()
            },
            getString(R.string.profile_menu_security) to {
                startActivity(Intent(this, SecurityInfoActivity::class.java))
            },
            getString(R.string.profile_menu_refresh) to {
                syncInbox(forceStatus = true)
            },
        )
        AlertDialog.Builder(this)
            .setTitle(R.string.profile_menu_title)
            .setItems(options.map { it.first }.toTypedArray()) { _, which ->
                options[which].second.invoke()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showInboxItemActions(item: InboxListItem) {
        val options = when (item.kind) {
            InboxItemKind.DIRECT -> listOf(
                getString(R.string.inbox_action_open_chat) to { openChat(item.id) },
                if (item.archivedAtMillis > 0L) {
                    getString(R.string.inbox_action_unarchive_chat) to { setDirectConversationArchived(item.id, false) }
                } else {
                    getString(R.string.inbox_action_archive_chat) to { setDirectConversationArchived(item.id, true) }
                },
                if (item.pinnedAtMillis > 0L) {
                    getString(R.string.inbox_action_unpin_chat) to { setDirectConversationPinned(item.id, false) }
                } else {
                    getString(R.string.inbox_action_pin_chat) to { setDirectConversationPinned(item.id, true) }
                },
                if (item.unreadCount > 0) {
                    getString(R.string.inbox_action_mark_read) to { markDirectConversationRead(item.id) }
                } else {
                    getString(R.string.inbox_action_mark_unread) to { markDirectConversationUnread(item.id) }
                },
            )
            InboxItemKind.GROUP -> listOf(
                getString(R.string.inbox_action_open_group) to { openGroup(item.id) },
                if (item.archivedAtMillis > 0L) {
                    getString(R.string.inbox_action_unarchive_chat) to { setGroupConversationArchived(item.id, false) }
                } else {
                    getString(R.string.inbox_action_archive_chat) to { setGroupConversationArchived(item.id, true) }
                },
                if (item.pinnedAtMillis > 0L) {
                    getString(R.string.inbox_action_unpin_chat) to { setGroupConversationPinned(item.id, false) }
                } else {
                    getString(R.string.inbox_action_pin_chat) to { setGroupConversationPinned(item.id, true) }
                },
                if (item.unreadCount > 0) {
                    getString(R.string.inbox_action_mark_read) to { markGroupConversationRead(item.id) }
                } else {
                    getString(R.string.inbox_action_mark_unread) to { markGroupConversationUnread(item.id) }
                },
            )
            InboxItemKind.REQUEST -> listOf(
                getString(R.string.inbox_action_review_request) to { showMessageRequestDialog(item.id) },
                getString(R.string.inbox_action_accept_request) to { acceptMessageRequestQuick(item.id) },
                getString(R.string.inbox_action_ignore_request) to { ignoreMessageRequestQuick(item.id) },
            )
        }
        AlertDialog.Builder(this)
            .setTitle(item.title)
            .setItems(options.map { it.first }.toTypedArray()) { _, which ->
                options[which].second.invoke()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun markDirectConversationRead(peerUserId: String) {
        val setup = store.loadSetup()
        store.markConversationRead(setup.userId, peerUserId)
        renderHome()
        statusText.text = getString(R.string.inbox_status_marked_read)
    }

    private fun markDirectConversationUnread(peerUserId: String) {
        val setup = store.loadSetup()
        store.setConversationUnreadCount(setup.userId, peerUserId, 1)
        renderHome()
        statusText.text = getString(R.string.inbox_status_marked_unread)
    }

    private fun markGroupConversationRead(groupId: String) {
        val setup = store.loadSetup()
        store.markGroupRead(setup.userId, groupId)
        renderHome()
        statusText.text = getString(R.string.inbox_status_marked_read)
    }

    private fun markGroupConversationUnread(groupId: String) {
        val setup = store.loadSetup()
        store.setGroupUnreadCount(setup.userId, groupId, 1)
        renderHome()
        statusText.text = getString(R.string.inbox_status_marked_unread)
    }

    private fun setDirectConversationPinned(peerUserId: String, pinned: Boolean) {
        val setup = store.loadSetup()
        store.setConversationPinned(setup.userId, peerUserId, pinned)
        renderHome()
        statusText.text = getString(if (pinned) R.string.inbox_status_pinned else R.string.inbox_status_unpinned)
    }

    private fun setDirectConversationArchived(peerUserId: String, archived: Boolean) {
        applyDirectConversationArchived(peerUserId, archived, allowUndo = true)
    }

    private fun applyDirectConversationArchived(
        peerUserId: String,
        archived: Boolean,
        allowUndo: Boolean,
    ) {
        val setup = store.loadSetup()
        store.setConversationArchived(setup.userId, peerUserId, archived)
        if (!archived && showArchivedOnly) {
            refreshConversations()
        } else {
            renderHome()
        }
        statusText.text = getString(
            if (archived) R.string.inbox_status_archived else R.string.inbox_status_unarchived,
        )
        if (allowUndo) {
            showArchiveUndoSnackbar(archived) {
                applyDirectConversationArchived(peerUserId, !archived, allowUndo = false)
            }
        }
    }

    private fun setGroupConversationPinned(groupId: String, pinned: Boolean) {
        val setup = store.loadSetup()
        store.setGroupPinned(setup.userId, groupId, pinned)
        renderHome()
        statusText.text = getString(if (pinned) R.string.inbox_status_pinned else R.string.inbox_status_unpinned)
    }

    private fun setGroupConversationArchived(groupId: String, archived: Boolean) {
        applyGroupConversationArchived(groupId, archived, allowUndo = true)
    }

    private fun applyGroupConversationArchived(
        groupId: String,
        archived: Boolean,
        allowUndo: Boolean,
    ) {
        val setup = store.loadSetup()
        store.setGroupArchived(setup.userId, groupId, archived)
        if (!archived && showArchivedOnly) {
            refreshConversations()
        } else {
            renderHome()
        }
        statusText.text = getString(
            if (archived) R.string.inbox_status_archived else R.string.inbox_status_unarchived,
        )
        if (allowUndo) {
            showArchiveUndoSnackbar(archived) {
                applyGroupConversationArchived(groupId, !archived, allowUndo = false)
            }
        }
    }

    private fun showArchiveUndoSnackbar(archived: Boolean, undoAction: () -> Unit) {
        Snackbar.make(
            findViewById(android.R.id.content),
            getString(if (archived) R.string.inbox_status_archived else R.string.inbox_status_unarchived),
            Snackbar.LENGTH_LONG,
        ).setAction(R.string.action_undo) {
            undoAction()
        }.show()
    }

    private fun acceptMessageRequestQuick(peerUserId: String) {
        val setup = store.loadSetup()
        store.acceptMessageRequest(setup.userId, peerUserId)
        renderHome()
        statusText.text = getString(R.string.inbox_status_request_accepted)
    }

    private fun ignoreMessageRequestQuick(peerUserId: String) {
        val setup = store.loadSetup()
        store.dismissMessageRequest(setup.userId, peerUserId)
        renderHome()
        statusText.text = getString(R.string.inbox_status_request_ignored)
    }

    private fun syncInbox(forceStatus: Boolean = false) {
        if (syncInFlight) {
            return
        }
        val setup = store.loadSetup()
        lifecycleScope.launch {
            syncInFlight = true
            if (forceStatus) {
                statusText.text = getString(R.string.conversations_status_syncing)
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
                        getString(R.string.conversations_status_groups_synced, outcome.discoveredGroups)
                    outcome.pendingRequests > 0 ->
                        getString(R.string.conversations_status_requests_pending, outcome.pendingRequests)
                    outcome.deliveredMessages > 0 ->
                        getString(R.string.conversations_status_messages_synced, outcome.deliveredMessages)
                    else ->
                        getString(R.string.conversations_status_up_to_date)
                }
            }.onFailure {
                statusText.text = getString(R.string.conversations_status_sync_failed)
            }
            syncInFlight = false
        }
    }

    private fun showComposeChooser() {
        val options = arrayOf(
            getString(R.string.compose_option_message),
            getString(R.string.compose_option_create_group),
            getString(R.string.compose_option_join_group),
        )
        AlertDialog.Builder(this)
            .setTitle(R.string.compose_dialog_title)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> showComposeDialog()
                    1 -> showCreateGroupDialog()
                    2 -> showJoinPrivateGroupDialog()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
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
                statusText.text = getString(R.string.conversations_status_checking_peer)
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
        if (currentRequests.isEmpty()) {
            statusText.text = getString(R.string.conversations_empty_requests)
            updateRequestsFilterButton()
            return
        }
        val labels = currentRequests.map { request ->
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
                showMessageRequestDialog(currentRequests[which].peerUserId)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showMessageRequestDialog(peerUserId: String) {
        val user = store.loadSetup().userId
        val request = currentRequests.firstOrNull { it.peerUserId == peerUserId } ?: run {
            statusText.text = getString(R.string.conversations_empty_requests)
            refreshConversations()
            return
        }
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
                statusText.text = getString(R.string.conversations_status_invite_ready)
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
                requirePrivateGroupMessagingEnabled(context)
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
                requirePrivateGroupMessagingEnabled(context)
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

    private fun openGroup(groupId: String) {
        val group = currentGroups.firstOrNull { it.groupId == groupId } ?: return
        val setup = store.loadSetup()
        store.markGroupRead(setup.userId, groupId)
        startActivity(
            Intent(this, GroupChatActivity::class.java).apply {
                putExtra("group_id", group.groupId)
                putExtra("group_name", group.displayName)
            },
        )
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
