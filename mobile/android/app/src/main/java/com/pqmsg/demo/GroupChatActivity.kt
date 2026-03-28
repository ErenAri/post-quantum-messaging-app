package com.pqmsg.demo

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButton
import com.google.gson.Gson
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.ServerBundle
import uniffi.pqmsg_android.buildContactsUpsertAuthHeaders
import uniffi.pqmsg_android.buildGroupMembersListAuthHeaders
import uniffi.pqmsg_android.buildProfileGetAuthHeaders
import uniffi.pqmsg_android.buildSenderCertificateAuthHeaders
import uniffi.pqmsg_android.encryptWithSession
import uniffi.pqmsg_android.initiateSessionAndEncrypt
import uniffi.pqmsg_android.privateGroupEncryptJoinPackageForShareLink
import uniffi.pqmsg_android.privateGroupEncryptSnapshot
import uniffi.pqmsg_android.privateGroupExportJoinPackageForMember
import uniffi.pqmsg_android.privateGroupPrepareAddMemberTransition
import uniffi.pqmsg_android.privateGroupPrepareRemoveMemberTransition
import uniffi.pqmsg_android.sealMessageWithSenderCert
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64

class GroupChatActivity : AppCompatActivity() {
    private val gson = Gson()
    private val maxAttachmentBytes = 128 * 1024
    private lateinit var store: LocalStateStore
    private lateinit var titleText: TextView
    private lateinit var metaText: TextView
    private lateinit var messageInput: EditText
    private lateinit var attachMediaButton: MaterialButton
    private lateinit var clearAttachmentButton: MaterialButton
    private lateinit var sendButton: MaterialButton
    private lateinit var searchButton: MaterialButton
    private lateinit var syncButton: MaterialButton
    private lateinit var threadTipsButton: MaterialButton
    private lateinit var backButton: MaterialButton
    private lateinit var groupHeaderContainer: View
    private lateinit var groupMessages: ListView
    private lateinit var groupEmptyText: TextView
    private lateinit var selectionModeLayout: View
    private lateinit var selectionCountText: TextView
    private lateinit var selectionCopyButton: MaterialButton
    private lateinit var selectionShareButton: MaterialButton
    private lateinit var selectionDeleteButton: MaterialButton
    private lateinit var selectionCloseButton: MaterialButton
    private lateinit var searchModeLayout: View
    private lateinit var searchInput: EditText
    private lateinit var searchCountText: TextView
    private lateinit var searchPrevButton: MaterialButton
    private lateinit var searchNextButton: MaterialButton
    private lateinit var searchCloseButton: MaterialButton
    private lateinit var replyPreviewLayout: View
    private lateinit var replyPreviewText: TextView
    private lateinit var clearReplyButton: MaterialButton
    private lateinit var attachmentPreviewCard: View
    private lateinit var attachmentTitle: TextView
    private lateinit var attachmentInfo: TextView
    private lateinit var composerBar: View
    private var groupId = ""
    private var groupName = ""
    private var syncInFlight = false
    private var privateGroupState: PrivateGroupState? = null
    private var privateGroupCredential: PrivateGroupMemberCredential? = null
    private var localStoreAvailable = true
    private var pendingAttachment: PendingAttachment? = null
    private lateinit var threadAdapter: ThreadMessageAdapter
    private var currentThreadMessages: List<ThreadMessage> = emptyList()
    private var pendingReplyMessage: ThreadMessage? = null
    private val selectedMessageKeys = linkedSetOf<String>()
    private var searchResultKeys: List<String> = emptyList()
    private var activeSearchIndex = 0

    private val pickAttachmentLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            handlePickedUri(uri, "Read attachment")
        }

    private val pickAudioAttachmentLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            handlePickedUri(uri, "Read audio")
        }

    private val pickDocumentAttachmentLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            handlePickedUri(uri, "Read document")
        }

    private val takePhotoAttachmentLauncher =
        registerForActivityResult(ActivityResultContracts.TakePicturePreview()) { bitmap ->
            if (bitmap == null) {
                return@registerForActivityResult
            }
            runCatching {
                pendingAttachment = readCameraAttachment(bitmap)
                renderAttachmentInfo()
            }.onFailure {
                metaText.text = UiErrorMapper.fromThrowable(it, "Capture photo").headline
            }
            syncActions()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = LocalStateStore(this)
        groupId = intent.getStringExtra("group_id") ?: ""
        groupName = intent.getStringExtra("group_name") ?: groupId
        if (groupId.isBlank()) {
            finish()
            return
        }
        setContentView(R.layout.activity_group_chat)
        titleText = findViewById(R.id.textGroupTitle)
        metaText = findViewById(R.id.textGroupMeta)
        messageInput = findViewById(R.id.editGroupMessage)
        attachMediaButton = findViewById(R.id.buttonAttachGroupMedia)
        clearAttachmentButton = findViewById(R.id.buttonClearGroupAttachment)
        sendButton = findViewById(R.id.buttonSendGroup)
        searchButton = findViewById(R.id.buttonGroupThreadSearch)
        syncButton = findViewById(R.id.buttonSyncGroup)
        threadTipsButton = findViewById(R.id.buttonGroupThreadTips)
        backButton = findViewById(R.id.buttonBackFromGroup)
        groupHeaderContainer = findViewById(R.id.groupHeaderContainer)
        groupMessages = findViewById(R.id.listGroupMessages)
        groupEmptyText = findViewById(R.id.textGroupChatEmpty)
        selectionModeLayout = findViewById(R.id.layoutGroupSelectionMode)
        selectionCountText = findViewById(R.id.textGroupSelectionCount)
        selectionCopyButton = findViewById(R.id.buttonGroupSelectionCopy)
        selectionShareButton = findViewById(R.id.buttonGroupSelectionShare)
        selectionDeleteButton = findViewById(R.id.buttonGroupSelectionDelete)
        selectionCloseButton = findViewById(R.id.buttonGroupSelectionClose)
        searchModeLayout = findViewById(R.id.layoutGroupSearchMode)
        searchInput = findViewById(R.id.editGroupThreadSearch)
        searchCountText = findViewById(R.id.textGroupThreadSearchCount)
        searchPrevButton = findViewById(R.id.buttonGroupThreadSearchPrev)
        searchNextButton = findViewById(R.id.buttonGroupThreadSearchNext)
        searchCloseButton = findViewById(R.id.buttonGroupThreadSearchClose)
        replyPreviewLayout = findViewById(R.id.layoutGroupReplyPreview)
        replyPreviewText = findViewById(R.id.textGroupReplyPreview)
        clearReplyButton = findViewById(R.id.buttonClearGroupReply)
        attachmentPreviewCard = findViewById(R.id.cardGroupAttachmentPreview)
        attachmentTitle = findViewById(R.id.textGroupAttachmentPreviewTitle)
        attachmentInfo = findViewById(R.id.textGroupAttachmentPreviewMeta)
        composerBar = findViewById(R.id.layoutGroupComposerBar)
        threadAdapter = ThreadMessageAdapter(
            this,
            onSwipeReply = { message -> beginReply(message) },
            onOpenReplyThread = { message -> openReplyThread(message) },
            onOpenQuotedReply = { targetId -> jumpToReplySource(targetId) },
        )
        groupMessages.adapter = threadAdapter
        groupMessages.emptyView = groupEmptyText
        groupMessages.setOnItemClickListener { _, _, position, _ ->
            if (!isSelectionModeActive()) {
                return@setOnItemClickListener
            }
            toggleSelectedMessage(threadAdapter.getItem(position))
        }
        groupMessages.setOnItemLongClickListener { _, _, position, _ ->
            val message = threadAdapter.getItem(position)
            if (isSelectionModeActive()) {
                toggleSelectedMessage(message)
            } else {
                showThreadMessageActions(message)
            }
            true
        }

        reloadPrivateGroupState()
        titleText.text = privateGroupState?.let { getPrivateGroupTitle(it, groupName) } ?: groupName
        messageInput.doAfterTextChanged {
            persistDraft()
            syncActions()
        }
        configureAttachmentButtons()
        renderAttachmentInfo()
        clearReplyButton.setOnClickListener {
            pendingReplyMessage = null
            renderReplyPreview()
            syncActions()
        }
        configureSelectionMode()
        configureThreadSearch()
        searchButton.setOnClickListener { openThreadSearch() }
        threadTipsButton.setOnClickListener { showThreadTipsDialog() }
        sendButton.setOnClickListener {
            lifecycleScope.launch { runAction("Send group message") { sendGroupMessage() } }
        }
        syncButton.setOnClickListener { syncGroupMessages() }
        groupHeaderContainer.setOnClickListener { showGroupInfo() }
        backButton.setOnClickListener { finish() }

        if (privateGroupState == null || privateGroupCredential == null) {
            renderUnavailableState()
            return
        }

        renderChatLog()
        renderReplyPreview()
        renderSelectionMode()
        refreshMeta()
        restoreDraft()
        syncActions()
        maybeShowThreadTipsOnFirstOpen()
    }

    override fun onResume() {
        super.onResume()
        reloadPrivateGroupState()
        if (privateGroupState == null || privateGroupCredential == null) {
            renderUnavailableState()
            return
        }
        renderChatLog()
        refreshMeta()
    }

    private fun renderUnavailableState() {
        selectedMessageKeys.clear()
        titleText.text = groupName
        messageInput.setText("")
        pendingAttachment = null
        messageInput.hint = "Private-group state unavailable"
        messageInput.isEnabled = false
        renderAttachmentInfo()
        sendButton.isEnabled = false
        syncButton.isEnabled = true
        threadAdapter.submitList(emptyList())
        renderSelectionMode()
        groupEmptyText.text = "This device does not have the local opaque state needed to open this private group."
        metaText.text = "Open the group from an invite link or a device that already has the current epoch state."
        renderReplyPreview()
        syncThreadSearch(scrollToActive = false)
    }

    private fun showThreadTipsDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.thread_tips_title)
            .setMessage(getString(R.string.thread_tips_group_body))
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun maybeShowThreadTipsOnFirstOpen() {
        if (store.hasSeenThreadTips()) {
            return
        }
        store.markThreadTipsSeen()
        showThreadTipsDialog()
    }

    private suspend fun runAction(label: String, block: suspend () -> Unit) {
        runCatching { block() }.onFailure {
            metaText.text = UiErrorMapper.fromThrowable(it, label).headline
        }
        syncActions()
        renderChatLog()
        refreshMeta()
    }

    private fun refreshMeta() {
        val setup = store.loadSetup()
        val state = privateGroupState
        val canManage = privateGroupCredential
            ?.let { describePrivateGroupMemberCredential(it).publish_key_base64?.isNotBlank() == true }
            ?: false
        metaText.text = if (state == null) {
            "Private group state unavailable\nSigned in as ${setup.userId}"
        } else {
            "${getPrivateGroupTitle(state)}\nEpoch ${state.epoch} • ${state.members.size} members • ${if (canManage) "manage enabled" else "read/send only"}"
        }
        if (state != null) {
            val ownerUserId = privateGroupOwnerUserId(state)
            val role = privateGroupRoleForUser(state, setup.userId)
            metaText.text =
                "${getPrivateGroupTitle(state)}\nEpoch ${state.epoch} | ${state.members.size} members | role $role | owner $ownerUserId | ${if (canManage) "manage enabled" else "read/send only"}"
        }
    }

    private fun privateGroupOwnerUserId(state: PrivateGroupState): String {
        return state.members.firstOrNull { it.role.equals("Owner", ignoreCase = true) }?.user_id
            ?: state.members.firstOrNull()?.user_id
            ?: store.loadSetup().userId
    }

    private fun privateGroupRoleForUser(state: PrivateGroupState, userId: String): String {
        return state.members.firstOrNull { it.user_id == userId }?.role ?: "Member"
    }

    private fun describePrivateGroupMemberTrust(memberUserId: String): String {
        val setup = store.loadSetup()
        if (memberUserId == setup.userId) {
            return "Local member credential"
        }
        val identityPin = store.readIdentityPin(setup.userId, memberUserId)
        val transparencyCheckpoint = store.readTransparencyCheckpoint(setup.serverUrl, memberUserId)
        return when {
            !transparencyCheckpoint.isNullOrBlank() && identityPin != null ->
                "Transparency checkpoint saved | identity pin present"
            !transparencyCheckpoint.isNullOrBlank() ->
                "Transparency checkpoint saved"
            identityPin != null ->
                "Identity pin present"
            else ->
                "No local trust checkpoint"
        }
    }

    private fun configureSelectionMode() {
        selectionCopyButton.setOnClickListener {
            copySelectedMessages()
        }
        selectionShareButton.setOnClickListener {
            shareSelectedMessages()
        }
        selectionDeleteButton.setOnClickListener {
            confirmDeleteSelectedMessages()
        }
        selectionCloseButton.setOnClickListener {
            clearSelectionMode()
        }
    }

    private fun configureThreadSearch() {
        searchInput.doAfterTextChanged {
            activeSearchIndex = 0
            syncThreadSearch(scrollToActive = false)
        }
        searchPrevButton.setOnClickListener { moveThreadSearch(-1) }
        searchNextButton.setOnClickListener { moveThreadSearch(1) }
        searchCloseButton.setOnClickListener { closeThreadSearch() }
        syncThreadSearch(scrollToActive = false)
    }

    private fun restoreDraft() {
        val setup = store.loadSetup()
        val draft = store.readGroupThreadDraft(setup.userId, groupId)
        if (draft.isNotEmpty() && messageInput.text.toString() != draft) {
            messageInput.setText(draft)
            messageInput.setSelection(draft.length)
        }
    }

    private fun persistDraft() {
        val setup = store.loadSetup()
        store.writeGroupThreadDraft(setup.userId, groupId, messageInput.text.toString())
    }

    private fun configureAttachmentButtons() {
        attachMediaButton.setOnClickListener {
            showAttachmentSheet()
        }
        clearAttachmentButton.setOnClickListener {
            pendingAttachment = null
            renderAttachmentInfo()
            syncActions()
        }
    }

    private fun showAttachmentSheet() {
        val dialog = BottomSheetDialog(this)
        val content = layoutInflater.inflate(R.layout.view_attachment_sheet, null)
        dialog.setContentView(content)
        content.findViewById<Button>(R.id.buttonAttachmentCamera).setOnClickListener {
            dialog.dismiss()
            takePhotoAttachmentLauncher.launch(null)
        }
        content.findViewById<Button>(R.id.buttonAttachmentMedia).setOnClickListener {
            dialog.dismiss()
            pickAttachmentLauncher.launch(arrayOf("image/*", "video/*"))
        }
        content.findViewById<Button>(R.id.buttonAttachmentAudio).setOnClickListener {
            dialog.dismiss()
            pickAudioAttachmentLauncher.launch(arrayOf("audio/*"))
        }
        content.findViewById<Button>(R.id.buttonAttachmentDocument).setOnClickListener {
            dialog.dismiss()
            pickDocumentAttachmentLauncher.launch(arrayOf("*/*"))
        }
        content.findViewById<Button>(R.id.buttonAttachmentCancel).setOnClickListener {
            dialog.dismiss()
        }
        dialog.show()
    }

    private fun handlePickedUri(uri: Uri?, action: String) {
        if (uri == null) {
            return
        }
        runCatching {
            pendingAttachment = readAttachment(uri)
            renderAttachmentInfo()
        }.onFailure {
            metaText.text = UiErrorMapper.fromThrowable(it, action).headline
        }
        syncActions()
    }

    private fun syncActions() {
        if (isSelectionModeActive()) {
            attachMediaButton.isEnabled = false
            clearAttachmentButton.isEnabled = false
            sendButton.isEnabled = false
            syncButton.isEnabled = false
            return
        }
        val hasText = messageInput.text.toString().isNotBlank()
        val hasAttachment = pendingAttachment != null
        attachMediaButton.isEnabled = !syncInFlight && localStoreAvailable
        clearAttachmentButton.isEnabled = hasAttachment && !syncInFlight
        sendButton.isEnabled =
            (hasText || hasAttachment) && !syncInFlight && localStoreAvailable && privateGroupState != null && privateGroupCredential != null
        syncButton.isEnabled = !syncInFlight && localStoreAvailable
    }

    private fun renderAttachmentInfo() {
        if (isSelectionModeActive()) {
            attachmentPreviewCard.visibility = View.GONE
            return
        }
        val attachment = pendingAttachment
        if (attachment == null) {
            attachmentPreviewCard.visibility = View.GONE
            attachmentTitle.text = getString(R.string.chat_attachment_none_title)
            attachmentInfo.text = getString(R.string.chat_attachment_none)
            messageInput.hint = getString(R.string.hint_message)
            return
        }
        attachmentPreviewCard.visibility = View.VISIBLE
        val attachmentType = when {
            attachment.mimeType.startsWith("image/") -> "Photo"
            attachment.mimeType.startsWith("video/") -> "Video"
            attachment.mimeType.startsWith("audio/") -> "Audio"
            attachment.mimeType.startsWith("text/") -> "Document"
            else -> "File"
        }
        val attachmentSize = when {
            attachment.byteLength >= 1024 * 1024 -> String.format("%.1f MB", attachment.byteLength / (1024f * 1024f))
            attachment.byteLength >= 1024 -> String.format("%.1f KB", attachment.byteLength / 1024f)
            else -> "${attachment.byteLength} B"
        }
        attachmentTitle.text = getString(R.string.chat_attachment_ready_title)
        attachmentInfo.text = "${attachment.fileName}\n$attachmentType | $attachmentSize"
        messageInput.hint = "Add a caption"
    }

    private fun renderReplyPreview() {
        val reply = pendingReplyMessage
        if (reply == null || isSelectionModeActive()) {
            replyPreviewLayout.visibility = View.GONE
            replyPreviewText.text = ""
            return
        }
        replyPreviewLayout.visibility = View.VISIBLE
        replyPreviewText.text =
            "${getString(R.string.thread_reply_prefix)}: ${reply.body.take(72)}"
    }

    private fun threadMessageKey(message: ThreadMessage): String = threadAdapter.messageKey(message)

    private fun isSelectionModeActive(): Boolean = selectedMessageKeys.isNotEmpty()

    private fun selectedMessages(): List<ThreadMessage> {
        if (selectedMessageKeys.isEmpty()) {
            return emptyList()
        }
        val keys = selectedMessageKeys.toSet()
        return currentThreadMessages.filter { keys.contains(threadMessageKey(it)) }
    }

    private fun enterSelectionMode(message: ThreadMessage) {
        selectedMessageKeys.clear()
        selectedMessageKeys.add(threadMessageKey(message))
        renderSelectionMode()
    }

    private fun toggleSelectedMessage(message: ThreadMessage) {
        val key = threadMessageKey(message)
        if (!selectedMessageKeys.add(key)) {
            selectedMessageKeys.remove(key)
        }
        if (selectedMessageKeys.isEmpty()) {
            clearSelectionMode()
        } else {
            renderSelectionMode()
        }
    }

    private fun clearSelectionMode() {
        if (selectedMessageKeys.isEmpty()) {
            renderSelectionMode()
            return
        }
        selectedMessageKeys.clear()
        renderSelectionMode()
    }

    private fun syncSelectionAfterThreadUpdate() {
        if (selectedMessageKeys.isEmpty()) {
            threadAdapter.setSelectionState(false, emptySet())
            return
        }
        val validKeys = currentThreadMessages.mapTo(linkedSetOf()) { threadMessageKey(it) }
        selectedMessageKeys.retainAll(validKeys)
        renderSelectionMode()
    }

    private fun renderSelectionMode() {
        val active = isSelectionModeActive()
        selectionModeLayout.visibility = if (active) View.VISIBLE else View.GONE
        composerBar.visibility = if (active) View.GONE else View.VISIBLE
        selectionCountText.text = resources.getQuantityString(
            R.plurals.thread_selection_count,
            selectedMessageKeys.size,
            selectedMessageKeys.size,
        )
        selectionCopyButton.isEnabled = active
        selectionShareButton.isEnabled = active
        selectionDeleteButton.isEnabled = active
        threadAdapter.setSelectionState(active, selectedMessageKeys)
        if (active) {
            replyPreviewLayout.visibility = View.GONE
        } else {
            renderReplyPreview()
        }
        renderAttachmentInfo()
        syncActions()
    }

    private fun openThreadSearch() {
        if (isSelectionModeActive()) {
            clearSelectionMode()
        }
        searchModeLayout.visibility = View.VISIBLE
        searchInput.requestFocus()
        searchInput.selectAll()
        syncThreadSearch(scrollToActive = false)
    }

    private fun closeThreadSearch() {
        activeSearchIndex = 0
        searchResultKeys = emptyList()
        searchInput.setText("")
        searchModeLayout.visibility = View.GONE
        searchCountText.text = getString(R.string.thread_search_empty)
        searchPrevButton.isEnabled = false
        searchNextButton.isEnabled = false
        threadAdapter.setSearchState(emptySet(), null)
    }

    private fun moveThreadSearch(delta: Int) {
        if (searchResultKeys.isEmpty()) {
            return
        }
        activeSearchIndex = (activeSearchIndex + delta + searchResultKeys.size) % searchResultKeys.size
        syncThreadSearch()
    }

    private fun syncThreadSearch(scrollToActive: Boolean = true) {
        if (searchModeLayout.visibility != View.VISIBLE) {
            searchResultKeys = emptyList()
            activeSearchIndex = 0
            threadAdapter.setSearchState(emptySet(), null)
            return
        }
        val query = searchInput.text?.toString()?.trim().orEmpty()
        if (query.isBlank()) {
            searchResultKeys = emptyList()
            activeSearchIndex = 0
            searchCountText.text = getString(R.string.thread_search_empty)
            searchPrevButton.isEnabled = false
            searchNextButton.isEnabled = false
            threadAdapter.setSearchState(emptySet(), null)
            return
        }
        val matches = currentThreadMessages.filter {
            threadMessageSearchText(it).contains(query, ignoreCase = true)
        }
            .map { threadMessageKey(it) }
        searchResultKeys = matches
        if (matches.isEmpty()) {
            activeSearchIndex = 0
            searchCountText.text = getString(R.string.thread_search_no_results)
            searchPrevButton.isEnabled = false
            searchNextButton.isEnabled = false
            threadAdapter.setSearchState(emptySet(), null)
            return
        }
        if (activeSearchIndex !in matches.indices) {
            activeSearchIndex = 0
        }
        val activeKey = matches[activeSearchIndex]
        searchCountText.text =
            getString(R.string.thread_search_count, activeSearchIndex + 1, matches.size)
        searchPrevButton.isEnabled = matches.size > 1
        searchNextButton.isEnabled = matches.size > 1
        threadAdapter.setSearchState(matches.toSet(), activeKey)
        if (scrollToActive) {
            val activeIndex = currentThreadMessages.indexOfFirst { threadMessageKey(it) == activeKey }
            if (activeIndex >= 0) {
                groupMessages.post {
                    groupMessages.smoothScrollToPosition(activeIndex)
                }
            }
        }
    }

    private fun showThreadMessageActions(message: ThreadMessage) {
        val options = arrayOf(
            getString(R.string.thread_action_reply),
            getString(R.string.thread_action_react),
            getString(R.string.thread_action_copy),
            getString(R.string.thread_action_share),
            getString(R.string.thread_action_delete_local),
            getString(R.string.thread_action_select_multiple),
        )
        AlertDialog.Builder(this)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> beginReply(message)
                    1 -> showReactionPickerSheet(message)
                    2 -> copyThreadMessage(message)
                    3 -> shareThreadMessage(message)
                    4 -> confirmDeleteThreadMessage(message)
                    5 -> enterSelectionMode(message)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun beginReply(message: ThreadMessage) {
        pendingReplyMessage = message
        renderReplyPreview()
        syncActions()
        messageInput.requestFocus()
    }

    private fun openReplyThread(message: ThreadMessage) {
        val targetId = message.transportMessageId ?: message.sentAtMillis
        if (threadAdapter.getFocusedReplyThreadId() == targetId) {
            threadAdapter.focusReplyThread(null)
            return
        }
        val firstReplyIndex = currentThreadMessages.indexOfFirst { it.replyToId == targetId }
        if (firstReplyIndex < 0) {
            threadAdapter.focusReplyThread(null)
            return
        }
        threadAdapter.focusReplyThread(targetId)
        groupMessages.post {
            groupMessages.smoothScrollToPosition(firstReplyIndex)
        }
    }

    private fun jumpToReplySource(targetId: Long) {
        val sourceIndex = currentThreadMessages.indexOfFirst {
            (it.transportMessageId ?: it.sentAtMillis) == targetId
        }
        if (sourceIndex < 0) {
            threadAdapter.focusReplyThread(null)
            return
        }
        threadAdapter.focusReplyThread(targetId)
        groupMessages.post {
            groupMessages.smoothScrollToPosition(sourceIndex)
        }
    }

    private fun showReactionPicker(message: ThreadMessage) {
        val emojiOptions = arrayOf("👍", "❤️", "😂", "😮", "😢", "👏")
        AlertDialog.Builder(this)
            .setItems(emojiOptions) { _, which ->
                val setup = store.loadSetup()
                val next = LinkedHashMap(message.reactions.orEmpty())
                val emoji = emojiOptions[which]
                if (next[emoji] == "You") {
                    next.remove(emoji)
                } else {
                    next[emoji] = "You"
                }
                store.updateGroupThreadMessageReactions(
                    userId = setup.userId,
                    groupId = groupId,
                    direction = message.direction,
                    sentAtMillis = message.sentAtMillis,
                    reactions = next.ifEmpty { null },
                )
                renderChatLog()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showReactionPickerSheet(message: ThreadMessage) {
        val emojiOptions = arrayOf(
            "\uD83D\uDC4D",
            "\u2764\uFE0F",
            "\uD83D\uDE02",
            "\uD83D\uDE2E",
            "\uD83D\uDE22",
            "\uD83D\uDC4F",
        )
        AlertDialog.Builder(this)
            .setItems(emojiOptions) { _, which ->
                val setup = store.loadSetup()
                val next = LinkedHashMap(message.reactions.orEmpty())
                val emoji = emojiOptions[which]
                if (next[emoji] == "You") {
                    next.remove(emoji)
                } else {
                    next[emoji] = "You"
                }
                store.updateGroupThreadMessageReactions(
                    userId = setup.userId,
                    groupId = groupId,
                    direction = message.direction,
                    sentAtMillis = message.sentAtMillis,
                    reactions = next.ifEmpty { null },
                )
                renderChatLog()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun copyThreadMessage(message: ThreadMessage) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(
            ClipData.newPlainText("pqmsg-group-message", threadMessageTranscript(message)),
        )
        Toast.makeText(this, R.string.thread_message_copied, Toast.LENGTH_SHORT).show()
    }

    private fun shareThreadMessage(message: ThreadMessage) {
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, threadMessageTranscript(message))
                },
                getString(R.string.thread_share_chooser_title),
            ),
        )
    }

    private fun confirmDeleteThreadMessage(message: ThreadMessage) {
        AlertDialog.Builder(this)
            .setTitle(R.string.thread_delete_local_title)
            .setMessage(R.string.thread_delete_local_message)
            .setPositiveButton(R.string.thread_action_delete_local) { _, _ ->
                val setup = store.loadSetup()
                store.deleteGroupThreadMessage(
                    userId = setup.userId,
                    groupId = groupId,
                    direction = message.direction,
                    sentAtMillis = message.sentAtMillis,
                    transportMessageId = message.transportMessageId,
                )
                if (pendingReplyMessage?.direction == message.direction &&
                    pendingReplyMessage?.sentAtMillis == message.sentAtMillis &&
                    pendingReplyMessage?.transportMessageId == message.transportMessageId
                ) {
                    pendingReplyMessage = null
                    renderReplyPreview()
                }
                renderChatLog()
                Toast.makeText(this, R.string.thread_delete_local_done, Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun copySelectedMessages() {
        val messages = selectedMessages()
        if (messages.isEmpty()) {
            clearSelectionMode()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(
            ClipData.newPlainText(
                "pqmsg-group-messages",
                messages.joinToString("\n\n") { threadMessageTranscript(it) },
            ),
        )
        Toast.makeText(this, R.string.thread_messages_copied, Toast.LENGTH_SHORT).show()
    }

    private fun shareSelectedMessages() {
        val messages = selectedMessages()
        if (messages.isEmpty()) {
            clearSelectionMode()
            return
        }
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, messages.joinToString("\n\n") { threadMessageTranscript(it) })
                },
                getString(R.string.thread_share_chooser_multiple_title),
            ),
        )
    }

    private fun confirmDeleteSelectedMessages() {
        val messages = selectedMessages()
        if (messages.isEmpty()) {
            clearSelectionMode()
            return
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.thread_delete_local_multiple_title)
            .setMessage(
                getString(
                    R.string.thread_delete_local_multiple_message,
                    messages.size,
                ),
            )
            .setPositiveButton(R.string.thread_selection_delete) { _, _ ->
                val setup = store.loadSetup()
                messages.forEach { message ->
                    store.deleteGroupThreadMessage(
                        userId = setup.userId,
                        groupId = groupId,
                        direction = message.direction,
                        sentAtMillis = message.sentAtMillis,
                        transportMessageId = message.transportMessageId,
                    )
                }
                if (pendingReplyMessage != null) {
                    val pendingKey = threadMessageKey(pendingReplyMessage!!)
                    if (messages.any { threadMessageKey(it) == pendingKey }) {
                        pendingReplyMessage = null
                    }
                }
                selectedMessageKeys.clear()
                renderReplyPreview()
                renderChatLog()
                Toast.makeText(this, R.string.thread_delete_local_multiple_done, Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun requirePrivateGroupMessagingEnabled(context: ReadyMessagingContext) {
        require(context.capabilities.private_group_messaging_supported) {
            "Private-group messaging is not enabled on this server."
        }
    }

    private suspend fun sendGroupMessage() {
        val setup = store.loadSetup()
        val state = privateGroupState ?: error("Private-group state is unavailable on this device.")
        val credential = privateGroupCredential ?: error("Private-group credential is unavailable on this device.")
        val text = messageInput.text.toString().trim()
        val replyToId = pendingReplyMessage?.transportMessageId ?: pendingReplyMessage?.sentAtMillis
        require(text.isNotBlank() || pendingAttachment != null) { "message and attachment are both empty" }

        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
            deviceId = setup.deviceId,
        )
        requirePrivateGroupMessagingEnabled(context)
        val outbound = composeOutboundPayload(text)
        val keysJson = MessagingCoordinator.ensurePrekeysReplenished(
            store = store,
            api = context.api,
            userId = context.profile.userId,
            keysJson = context.keysJson,
        )
        val credentialMaterial = describePrivateGroupMemberCredential(credential)
        val encryptedMessage = encryptPrivateGroupTransportMessage(
            state = state,
            keysJson = keysJson,
            senderUserId = context.profile.userId,
            body = outbound.plaintext,
        )
        val publishResponse = context.api.publishPrivateGroupMessage(
            PublishPrivateGroupMessageRequest(
                group_id = encryptedMessage.group_id,
                epoch = encryptedMessage.epoch,
                sent_at_unix_ms = encryptedMessage.sent_at_unix_ms,
                ciphertext_nonce_base64 = encryptedMessage.ciphertext.nonce.toByteArray().toBase64(),
                ciphertext_base64 = encryptedMessage.ciphertext.ciphertext.toByteArray().toBase64(),
                ciphertext_aad_base64 = encryptedMessage.ciphertext.aad.toByteArray().toBase64(),
                sender_hybrid_signature_base64 = encryptedMessage.sender_hybrid_signature.toByteArray().toBase64(),
                authorizing_membership_handle_sha256 = credentialMaterial.membership_handle_sha256,
                authorizing_fetch_key_base64 = credentialMaterial.fetch_key_base64,
            ),
        )
        store.writePrivateGroupCursor(
            context.profile.userId,
            groupId,
            publishResponse.message_id,
        )

        store.appendGroupThreadMessage(
            userId = context.profile.userId,
            groupId = groupId,
            senderUserId = context.profile.userId,
            body = outbound.preview,
            sentAtMillis = encryptedMessage.sent_at_unix_ms,
            transportMessageId = publishResponse.message_id,
            replyToId = replyToId,
            attachmentEnvelope = MessageEnvelopeCodec.decodeMediaEnvelope(outbound.plaintext),
        )
        store.upsertGroupConversation(
            userId = context.profile.userId,
            groupId = groupId,
            displayName = getPrivateGroupTitle(state, groupName),
            memberCount = state.members.size,
            lastPreview = "You: ${outbound.preview}",
            incrementUnread = false,
        )
        messageInput.setText("")
        store.writeGroupThreadDraft(context.profile.userId, groupId, "")
        pendingAttachment = null
        pendingReplyMessage = null
        renderAttachmentInfo()
        renderReplyPreview()
    }

    private fun syncGroupMessages() {
        if (syncInFlight) return
        lifecycleScope.launch {
            syncInFlight = true
            syncActions()
            runCatching {
                // Sync inbox — group messages come through normal inbox
                val setup = store.loadSetup()
                MessagingCoordinator.syncInbox(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                    activeGroup = groupId,
                )
                store.markGroupRead(setup.userId, groupId)
            }.onFailure {
                metaText.text = UiErrorMapper.fromThrowable(it, "Sync group").headline
            }
            syncInFlight = false
            syncActions()
            renderChatLog()
            refreshMeta()
        }
    }

    private fun showGroupInfo() {
        val state = privateGroupState ?: run {
            metaText.text = "Private-group state is unavailable on this device."
            return
        }
        val canManage = privateGroupCredential
            ?.let { describePrivateGroupMemberCredential(it).publish_key_base64?.isNotBlank() == true }
            ?: false
        val memberList = state.members.joinToString("\n") { member ->
            val you = if (member.user_id == store.loadSetup().userId) " (you)" else ""
            "- ${member.user_id} [${member.role}]$you"
        }
        val ownerUserId = privateGroupOwnerUserId(state)
        val yourRole = privateGroupRoleForUser(state, store.loadSetup().userId)
        val detailedMemberList = state.members.joinToString("\n\n") { member ->
            val you = if (member.user_id == store.loadSetup().userId) " (you)" else ""
            "- ${member.user_id} [${member.role}]$you\n  Trust: ${describePrivateGroupMemberTrust(member.user_id)}"
        }
        val groupInfoMessage =
            "Group: ${getPrivateGroupTitle(state, groupName)}\n" +
                "Owner: $ownerUserId\n" +
                "Your role: $yourRole\n" +
                "Epoch ${state.epoch}\n\n" +
                "Member trust uses local identity pins and transparency checkpoints from direct chats.\n\n" +
                "Members (${state.members.size}):\n$detailedMemberList"
        AlertDialog.Builder(this@GroupChatActivity)
            .setTitle(getString(R.string.group_info_title))
            .setMessage(
                "Group: ${getPrivateGroupTitle(state, groupName)}\n" +
                    "Epoch ${state.epoch}\n\n" +
                    "Members (${state.members.size}):\n$memberList",
            )
            .setMessage(groupInfoMessage)
            .setPositiveButton(android.R.string.ok, null)
            .setNeutralButton(R.string.button_shared_media) { _, _ ->
                ThreadSharedMediaBrowser.show(
                    context = this,
                    title = "${getPrivateGroupTitle(state, groupName)} shared media",
                    messages = currentThreadMessages,
                    emptyMessage = "No shared media saved in this group on this device yet.",
                ) {
                    metaText.text = UiErrorMapper.fromThrowable(it, "Open shared media").headline
                }
            }
            .apply {
                if (canManage) {
                    setNegativeButton("Manage Members") { _, _ ->
                        showMemberManagementDialog()
                    }
                }
            }
            .show()
        return

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
                val members = context.api.listGroupMembers(
                    groupId = groupId,
                    headers = buildGroupMembersListAuthHeaders(
                        keysJson = keysJson,
                        groupId = groupId,
                    ).toHeaderMap(),
                )
                val memberList = members.members.joinToString("\n") {
                    "  • ${it.user_id} (joined ${it.joined_at})"
                }
                val info = "Group: $groupId\nMembers (${members.members.size}):\n$memberList"

                AlertDialog.Builder(this@GroupChatActivity)
                    .setTitle(getString(R.string.group_info_title))
                    .setMessage(info)
                    .setPositiveButton(android.R.string.ok, null)
                    .setNeutralButton(getString(R.string.button_add_member)) { _, _ ->
                        showAddMemberDialog(context.api, keysJson, context.profile.userId)
                    }
                    .show()
            }.onFailure {
                metaText.text = UiErrorMapper.fromThrowable(it, "Group info").headline
            }
        }
    }

    private fun showAddMemberDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.hint_username_or_invite)
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.button_add_member))
            .setView(input)
            .setPositiveButton(getString(R.string.button_add_member)) { _, _ ->
                val memberTarget = input.text.toString().trim()
                if (memberTarget.isNotBlank()) {
                    lifecycleScope.launch {
                        runCatching {
                            addGroupMember(memberTarget)
                            metaText.text = "Added member and rotated the group epoch."
                            refreshMeta()
                            renderChatLog()
                        }.onFailure {
                            metaText.text = UiErrorMapper.fromThrowable(it, "Add member").headline
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private suspend fun addGroupMember(rawTarget: String) {
        val setup = store.loadSetup()
        val state = privateGroupState ?: error("Private-group state is unavailable on this device.")
        val credential = privateGroupCredential ?: error("Private-group credential is unavailable on this device.")
        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
        )
        requirePrivateGroupMessagingEnabled(context)
        val target = MessagingCoordinator.parseComposeTarget(rawTarget, setup.serverUrl)
        require(
            ApiClientFactory.normalizeBaseUrl(target.serverUrl) ==
                ApiClientFactory.normalizeBaseUrl(setup.serverUrl),
        ) { "Private-group members must use the current account server." }
        val memberUserId = MessagingCoordinator.resolvePeerUserId(context.api, target)
        require(memberUserId != context.profile.userId) { "You are already in this private group." }
        require(state.members.none { it.user_id == memberUserId }) { "@$memberUserId is already a member." }
        val transition = parsePrivateGroupEpochTransition(
            privateGroupPrepareAddMemberTransition(
                gson.toJson(state),
                memberUserId,
                "member",
                (System.currentTimeMillis() / 1000).toULong(),
            ),
        )
        val nextCredential = findPrivateGroupCredentialForUser(
            transition.member_credentials,
            context.profile.userId,
        )
        val stateCommitmentSha256 = publishPrivateGroupTransition(
            api = context.api,
            state = transition.next_state,
            authorizingCredential = credential,
            memberCredentials = transition.member_credentials,
            encryptedSnapshotJson = privateGroupEncryptSnapshot(gson.toJson(transition.next_state)),
        )
        updateLocalPrivateGroupState(
            store = store,
            userId = context.profile.userId,
            state = transition.next_state,
            memberCredential = nextCredential,
            stateCommitmentSha256 = stateCommitmentSha256,
            preview = "Added @$memberUserId",
            incrementUnread = false,
        )
        val joinPackageJson = transition.added_member_join_package?.let { gson.toJson(it) }
            ?: privateGroupExportJoinPackageForMember(gson.toJson(transition.next_state), memberUserId)
        val inviteMaterial = parsePrivateGroupLinkInviteMaterial(
            privateGroupEncryptJoinPackageForShareLink(joinPackageJson),
        )
        val inviteLink = createPrivateGroupInviteLinkFromJoinPackage(
            api = context.api,
            serverUrl = setup.serverUrl,
            state = transition.next_state,
            authorizingCredential = nextCredential,
            inviteMaterial = inviteMaterial,
        )
        privateGroupState = transition.next_state
        privateGroupCredential = nextCredential
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, inviteLink)
                },
                getString(R.string.share_invite_chooser_title),
            ),
        )
    }

    private fun showMemberManagementDialog() {
        val state = privateGroupState ?: return
        val credential = privateGroupCredential ?: return
        val canManage = describePrivateGroupMemberCredential(credential).publish_key_base64?.isNotBlank() == true
        if (!canManage) {
            metaText.text = "This device cannot rotate private-group membership."
            return
        }
        val actions = mutableListOf<Pair<String, suspend () -> Unit>>()
        actions += "Add member..." to suspend {
            showAddMemberDialog()
        }
        state.members
            .filter { it.user_id != store.loadSetup().userId }
            .forEach { member ->
                actions += "Copy invite for @${member.user_id}" to suspend {
                    copyInviteForMember(member.user_id)
                }
                if (!member.role.equals("Owner", ignoreCase = true)) {
                    actions += "Remove @${member.user_id}" to suspend {
                        removeGroupMember(member.user_id)
                    }
                }
            }
        if (actions.isEmpty()) {
            metaText.text = "No removable private-group members."
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Manage Members")
            .setItems(actions.map { it.first }.toTypedArray()) { _, which ->
                lifecycleScope.launch {
                    runCatching {
                        actions[which].second.invoke()
                        refreshMeta()
                        renderChatLog()
                    }.onFailure {
                        metaText.text = UiErrorMapper.fromThrowable(it, "Manage members").headline
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private suspend fun copyInviteForMember(memberUserId: String) {
        val setup = store.loadSetup()
        val state = privateGroupState ?: error("Private-group state is unavailable on this device.")
        val credential = privateGroupCredential ?: error("Private-group credential is unavailable on this device.")
        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
        )
        requirePrivateGroupMessagingEnabled(context)
        val inviteMaterial = parsePrivateGroupLinkInviteMaterial(
            privateGroupEncryptJoinPackageForShareLink(
                privateGroupExportJoinPackageForMember(gson.toJson(state), memberUserId),
            ),
        )
        val inviteLink = createPrivateGroupInviteLinkFromJoinPackage(
            api = context.api,
            serverUrl = setup.serverUrl,
            state = state,
            authorizingCredential = credential,
            inviteMaterial = inviteMaterial,
        )
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, inviteLink)
                },
                getString(R.string.share_invite_chooser_title),
            ),
        )
    }

    private suspend fun removeGroupMember(memberUserId: String) {
        val setup = store.loadSetup()
        val state = privateGroupState ?: error("Private-group state is unavailable on this device.")
        val credential = privateGroupCredential ?: error("Private-group credential is unavailable on this device.")
        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
        )
        requirePrivateGroupMessagingEnabled(context)
        val transition = parsePrivateGroupEpochTransition(
            privateGroupPrepareRemoveMemberTransition(
                gson.toJson(state),
                memberUserId,
                (System.currentTimeMillis() / 1000).toULong(),
            ),
        )
        val nextCredential = findPrivateGroupCredentialForUser(
            transition.member_credentials,
            context.profile.userId,
        )
        val stateCommitmentSha256 = publishPrivateGroupTransition(
            api = context.api,
            state = transition.next_state,
            authorizingCredential = credential,
            memberCredentials = transition.member_credentials,
            encryptedSnapshotJson = privateGroupEncryptSnapshot(gson.toJson(transition.next_state)),
        )
        updateLocalPrivateGroupState(
            store = store,
            userId = context.profile.userId,
            state = transition.next_state,
            memberCredential = nextCredential,
            stateCommitmentSha256 = stateCommitmentSha256,
            preview = "Removed @$memberUserId",
            incrementUnread = false,
        )
        privateGroupState = transition.next_state
        privateGroupCredential = nextCredential
    }

    private fun showAddMemberDialog(api: PqmsgApi, keysJson: String, userId: String) {
        showAddMemberDialog()
    }

    private fun reloadPrivateGroupState() {
        val setup = store.loadSetup()
        val localState = store.readPrivateGroupState(setup.userId, groupId)
        if (localState == null) {
            privateGroupState = null
            privateGroupCredential = null
            return
        }
        privateGroupState = parsePrivateGroupStateJson(localState.stateJson)
        privateGroupCredential = parsePrivateGroupCredentialJson(localState.memberCredentialJson)
        groupName = privateGroupState?.let { getPrivateGroupTitle(it, groupName) } ?: groupName
    }

    private suspend fun resolvePeerTransportIdentityX25519(
        context: ReadyMessagingContext,
        localUserId: String,
        peerUserId: String,
    ): String {
        val pinned = store.readIdentityPin(localUserId, peerUserId)
        if (pinned?.identityX25519Pub?.isNotBlank() == true) {
            return pinned.identityX25519Pub
        }
        val fetched = context.api.getBundle(peerUserId)
        enforceIdentityPin(localUserId, peerUserId, fetched)
        return fetched.identity_x25519_pub
    }

    private suspend fun resolvePeerSealedDeliveryToken(
        context: ReadyMessagingContext,
        peerUserId: String,
    ): String {
        val headers = buildProfileGetAuthHeaders(
            keysJson = context.keysJson,
            userId = peerUserId,
        ).toHeaderMap()
        var profile = context.api.getUserProfile(
            peerUserId,
            headers,
        )
        if (profile.sealed_delivery_token.isNullOrBlank()) {
            context.api.upsertContact(
                userId = context.profile.userId,
                headers = buildContactsUpsertAuthHeaders(
                    keysJson = context.keysJson,
                    userId = context.profile.userId,
                    contactUserId = peerUserId,
                    alias = "",
                    verifiedByQr = false,
                    verifiedFingerprintSha256 = "",
                ).toHeaderMap(),
                request = UpsertContactRequest(
                    contact_user_id = peerUserId,
                    alias = null,
                    verified_by_qr = false,
                    verified_fingerprint_sha256 = null,
                ),
            )
            store.markPeerAccepted(context.profile.userId, peerUserId)
            profile = context.api.getUserProfile(
                peerUserId,
                headers,
            )
        }
        return profile.sealed_delivery_token
            ?.takeIf { it.isNotBlank() }
            ?: error("Direct messaging requires adding this user as a contact first")
    }

    private suspend fun enforceIdentityPin(localUser: String, peerUser: String, bundle: BundleResponse) {
        val fingerprint = bundle.identity_fingerprint_sha256
            ?.takeIf { it.isNotBlank() }
            ?: computeIdentityFingerprint(
                identityX25519Pub = bundle.identity_x25519_pub,
                identityPqSigPub = bundle.identity_pq_sig_pub.orEmpty(),
            )
        store.writeIdentityPin(
            userId = localUser,
            peerUserId = peerUser,
            pin = IdentityPin(
                fingerprintSha256 = fingerprint,
                identityKeyVersion = bundle.identity_key_version ?: 0,
                identityX25519Pub = bundle.identity_x25519_pub,
                identitySigPub = bundle.identity_sig_pub,
                identityPqSigPub = bundle.identity_pq_sig_pub.orEmpty(),
                observedAt = bundle.bundle_generated_at,
            ),
        )
    }

    private fun computeIdentityFingerprint(identityX25519Pub: String, identityPqSigPub: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(Base64.getDecoder().decode(identityX25519Pub))
        if (identityPqSigPub.isNotBlank()) {
            digest.update(Base64.getDecoder().decode(identityPqSigPub))
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
    }

    private fun renderChatLog() {
        val setup = store.loadSetup()
        runCatching {
            store.listGroupThreadMessages(setup.userId, groupId)
        }.onSuccess { messages ->
            localStoreAvailable = true
            currentThreadMessages = messages
            threadAdapter.submitList(messages)
            syncSelectionAfterThreadUpdate()
            syncThreadSearch(scrollToActive = false)
            groupEmptyText.text = getString(R.string.group_chat_log_empty)
            groupMessages.post {
                if (messages.isNotEmpty() && !isSelectionModeActive()) {
                    groupMessages.setSelection(messages.lastIndex)
                }
            }
        }.onFailure {
            localStoreAvailable = false
            currentThreadMessages = emptyList()
            metaText.text = UiErrorMapper.fromThrowable(it, "Open local secure state").headline
            threadAdapter.submitList(emptyList())
            syncSelectionAfterThreadUpdate()
            syncThreadSearch(scrollToActive = false)
            groupEmptyText.text =
                "Local encrypted group history is unavailable on this device.\nRe-import the current group state from a linked device or fully reprovision this device."
        }
        syncActions()
    }

    private fun composeOutboundPayload(text: String): OutboundPayload {
        val attachment = pendingAttachment
        if (attachment == null) {
            return OutboundPayload(plaintext = text, preview = text)
        }
        val envelope = MessageEnvelopeCodec.encodeMediaEnvelope(
            fileName = attachment.fileName,
            mimeType = attachment.mimeType,
            noteText = text,
            dataBase64 = attachment.dataBase64,
        )
        val mediaTag = "[media:${attachment.fileName} ${attachment.byteLength}B]"
        val preview = if (text.isBlank()) mediaTag else "$mediaTag $text"
        return OutboundPayload(plaintext = envelope, preview = preview)
    }

    private fun readCameraAttachment(bitmap: Bitmap): PendingAttachment {
        val output = ByteArrayOutputStream()
        check(bitmap.compress(Bitmap.CompressFormat.JPEG, 85, output)) {
            "unable to encode camera photo"
        }
        val bytes = output.toByteArray()
        require(bytes.size <= maxAttachmentBytes) {
            "attachment exceeds ${maxAttachmentBytes} bytes"
        }
        return PendingAttachment(
            fileName = "camera-${System.currentTimeMillis()}.jpg",
            mimeType = "image/jpeg",
            dataBase64 = Base64.getEncoder().encodeToString(bytes),
            byteLength = bytes.size,
        )
    }

    private fun readAttachment(uri: Uri): PendingAttachment {
        val resolver = contentResolver
        val mimeType = resolver.getType(uri) ?: "application/octet-stream"
        val fileName = resolveFileName(uri) ?: "attachment.bin"
        val bytes = resolver.openInputStream(uri)?.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) {
                    break
                }
                total += read
                if (total > maxAttachmentBytes) {
                    error("attachment exceeds ${maxAttachmentBytes} bytes")
                }
                output.write(buffer, 0, read)
            }
            output.toByteArray()
        } ?: error("unable to read attachment stream")
        return PendingAttachment(
            fileName = fileName,
            mimeType = mimeType,
            dataBase64 = Base64.getEncoder().encodeToString(bytes),
            byteLength = bytes.size,
        )
    }

    private fun resolveFileName(uri: Uri): String? {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) {
                return cursor.getString(index)
            }
        }
        return uri.lastPathSegment
    }

    private fun BundleResponse.toRustBundle(): ServerBundle {
        return ServerBundle(
            userId = user_id,
            identityX25519Pub = identity_x25519_pub,
            identitySigPub = identity_sig_pub,
            identityPqSigPub = identity_pq_sig_pub,
            signedPrekeyX25519Pub = signed_prekey_x25519_pub,
            sigOverSpk = sig_over_spk,
            pqSignedPrekeyPubMlkem768 = pq_signed_prekey_pub_mlkem768,
            sigOverPqspk = sig_over_pqspk,
            pqSigOverSpk = pq_sig_over_spk,
            pqSigOverPqspk = pq_sig_over_pqspk,
            oneTimePrekeyX25519 = one_time_prekey_x25519,
            oneTimePrekeyMlkem768 = one_time_prekey_mlkem768,
        )
    }

    private data class PendingAttachment(
        val fileName: String,
        val mimeType: String,
        val dataBase64: String,
        val byteLength: Int,
    )

    private data class OutboundPayload(
        val plaintext: String,
        val preview: String,
    )
}
