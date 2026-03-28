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
import com.google.gson.Gson
import com.google.android.material.bottomsheet.BottomSheetDialog
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import uniffi.pqmsg_android.ServerBundle
import uniffi.pqmsg_android.buildContactsListAuthHeaders
import uniffi.pqmsg_android.buildContactsUpsertAuthHeaders
import uniffi.pqmsg_android.buildProfileGetAuthHeaders
import uniffi.pqmsg_android.buildPresenceGetAuthHeaders
import uniffi.pqmsg_android.buildPresenceUpdateAuthHeaders
import uniffi.pqmsg_android.buildSendReceiptAuthHeaders
import uniffi.pqmsg_android.buildSenderCertificateAuthHeaders
import uniffi.pqmsg_android.buildTypingGetAuthHeaders
import uniffi.pqmsg_android.buildTypingUpdateAuthHeaders
import uniffi.pqmsg_android.computeSafetyNumberWithPeer
import uniffi.pqmsg_android.encryptWithSession
import uniffi.pqmsg_android.initiateSessionAndEncrypt
import uniffi.pqmsg_android.sealMessageWithSenderCert
import java.io.ByteArrayOutputStream
import java.util.Base64
import kotlin.coroutines.resume

class ChatActivity : AppCompatActivity() {
    private val gson = Gson()
    private val maxAttachmentBytes = 128 * 1024
    private lateinit var store: LocalStateStore
    private lateinit var messageInput: EditText
    private lateinit var attachMediaButton: Button
    private lateinit var clearAttachmentButton: Button
    private lateinit var sendButton: Button
    private lateinit var searchButton: Button
    private lateinit var syncButton: Button
    private lateinit var threadTipsButton: Button
    private lateinit var backButton: Button
    private lateinit var chatHeaderContainer: View
    private lateinit var chatMessages: ListView
    private lateinit var chatEmptyText: TextView
    private lateinit var chatTitleText: TextView
    private lateinit var chatMeta: TextView
    private lateinit var selectionModeLayout: View
    private lateinit var selectionCountText: TextView
    private lateinit var selectionCopyButton: Button
    private lateinit var selectionShareButton: Button
    private lateinit var selectionDeleteButton: Button
    private lateinit var selectionCloseButton: Button
    private lateinit var searchModeLayout: View
    private lateinit var searchInput: EditText
    private lateinit var searchCountText: TextView
    private lateinit var searchPrevButton: Button
    private lateinit var searchNextButton: Button
    private lateinit var searchCloseButton: Button
    private lateinit var replyPreviewLayout: View
    private lateinit var replyPreviewText: TextView
    private lateinit var clearReplyButton: Button
    private lateinit var attachmentPreviewCard: View
    private lateinit var attachmentTitle: TextView
    private lateinit var attachmentInfo: TextView
    private lateinit var composerBar: View
    private lateinit var errorSummaryText: TextView
    private lateinit var errorDetailsText: TextView
    private lateinit var errorToggleButton: Button
    private var latestBundle: BundleResponse? = null
    private var errorExpanded = false
    private var pendingAttachment: PendingAttachment? = null
    private var activePeerUserId = ""
    private var syncInFlight = false
    private var typingJob: Job? = null
    private var presencePollingJob: Job? = null
    private var typingPollingJob: Job? = null
    private var peerPresenceOnline = false
    private var peerIsTyping = false
    private var sealedSenderEnabled = true
    private var ephemeralTtlSeconds: Long? = null
    private var localStoreAvailable = true
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
                renderError(null)
            }.onFailure {
                renderError(UiErrorMapper.fromThrowable(it, "Capture photo"))
            }
            syncActionAvailability()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = LocalStateStore(this)
        val setup = store.loadSetup()
        activePeerUserId = (intent.getStringExtra("peer") ?: setup.peerUserId).trim()
        latestBundle = intent.getStringExtra("peer_bundle_json")?.let { serialized ->
            runCatching { gson.fromJson(serialized, BundleResponse::class.java) }.getOrNull()
        }
        if (setup.userId.isBlank() || setup.serverUrl.isBlank() || activePeerUserId.isBlank()) {
            redirectToHome()
            return
        }

        store.saveSetup(setup.copy(peerUserId = activePeerUserId))
        store.markConversationRead(setup.userId, activePeerUserId)

        setContentView(R.layout.activity_chat)
        messageInput = findViewById(R.id.editMessage)
        attachMediaButton = findViewById(R.id.buttonAttachMedia)
        clearAttachmentButton = findViewById(R.id.buttonClearAttachment)
        sendButton = findViewById(R.id.buttonSend)
        searchButton = findViewById(R.id.buttonThreadSearch)
        syncButton = findViewById(R.id.buttonSyncThread)
        threadTipsButton = findViewById(R.id.buttonThreadTips)
        backButton = findViewById(R.id.buttonBackSetup)
        chatHeaderContainer = findViewById(R.id.chatHeaderContainer)
        chatMessages = findViewById(R.id.listChatMessages)
        chatEmptyText = findViewById(R.id.textChatEmpty)
        chatTitleText = findViewById(R.id.textChatTitle)
        chatMeta = findViewById(R.id.textChatMeta)
        selectionModeLayout = findViewById(R.id.layoutChatSelectionMode)
        selectionCountText = findViewById(R.id.textChatSelectionCount)
        selectionCopyButton = findViewById(R.id.buttonChatSelectionCopy)
        selectionShareButton = findViewById(R.id.buttonChatSelectionShare)
        selectionDeleteButton = findViewById(R.id.buttonChatSelectionDelete)
        selectionCloseButton = findViewById(R.id.buttonChatSelectionClose)
        searchModeLayout = findViewById(R.id.layoutChatSearchMode)
        searchInput = findViewById(R.id.editThreadSearch)
        searchCountText = findViewById(R.id.textThreadSearchCount)
        searchPrevButton = findViewById(R.id.buttonThreadSearchPrev)
        searchNextButton = findViewById(R.id.buttonThreadSearchNext)
        searchCloseButton = findViewById(R.id.buttonThreadSearchClose)
        replyPreviewLayout = findViewById(R.id.layoutReplyPreview)
        replyPreviewText = findViewById(R.id.textReplyPreview)
        clearReplyButton = findViewById(R.id.buttonClearReply)
        attachmentPreviewCard = findViewById(R.id.cardAttachmentPreview)
        attachmentTitle = findViewById(R.id.textAttachmentPreviewTitle)
        attachmentInfo = findViewById(R.id.textAttachmentPreviewMeta)
        composerBar = findViewById(R.id.layoutChatComposerBar)
        errorSummaryText = findViewById(R.id.textErrorSummaryChat)
        errorDetailsText = findViewById(R.id.textErrorDetailsChat)
        errorToggleButton = findViewById(R.id.buttonToggleErrorDetailsChat)
        threadAdapter = ThreadMessageAdapter(
            this,
            onSwipeReply = { message -> beginReply(message) },
            onOpenReplyThread = { message -> openReplyThread(message) },
            onOpenQuotedReply = { targetId -> jumpToReplySource(targetId) },
        )
        chatMessages.adapter = threadAdapter
        chatMessages.emptyView = chatEmptyText
        chatMessages.setOnItemClickListener { _, _, position, _ ->
            if (!isSelectionModeActive()) {
                return@setOnItemClickListener
            }
            toggleSelectedMessage(threadAdapter.getItem(position))
        }
        chatMessages.setOnItemLongClickListener { _, _, position, _ ->
            val message = threadAdapter.getItem(position)
            if (isSelectionModeActive()) {
                toggleSelectedMessage(message)
            } else {
                showThreadMessageActions(message)
            }
            true
        }

        configureInputObservers()
        configureErrorToggle()
        configureAttachmentButtons()
        configureReplyPreview()
        configureSelectionMode()
        configureThreadSearch()
        renderAttachmentInfo()
        renderReplyPreview()
        renderSelectionMode()
        renderThreadHistory()
        refreshMeta()
        restoreDraft()
        syncActionAvailability()
        maybeShowThreadTipsOnFirstOpen()

        sendButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Send message") {
                    sendMessageFlow()
                }
            }
        }

        syncButton.setOnClickListener {
            syncThread()
        }
        searchButton.setOnClickListener {
            openThreadSearch()
        }
        threadTipsButton.setOnClickListener {
            showThreadTipsDialog()
        }

        chatHeaderContainer.setOnClickListener {
            lifecycleScope.launch {
                showChatInfoDialog()
            }
        }

        backButton.setOnClickListener {
            finish()
        }

    }

    override fun onResume() {
        super.onResume()
        if (!hasIdentity()) {
            redirectToHome()
            return
        }
        renderThreadHistory()
        refreshMeta()
        syncThread()
    }

    override fun onPause() {
        super.onPause()
        presencePollingJob?.cancel()
        typingPollingJob?.cancel()
        typingJob?.cancel()
    }

    private fun showThreadTipsDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.thread_tips_title)
            .setMessage(getString(R.string.thread_tips_direct_body))
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

    private fun configureInputObservers() {
        messageInput.doAfterTextChanged {
            persistDraft()
            syncActionAvailability()
        }
    }

    private fun configureErrorToggle() {
        errorToggleButton.setOnClickListener {
            errorExpanded = !errorExpanded
            refreshErrorDetailsVisibility()
        }
        renderError(null)
    }

    private fun configureAttachmentButtons() {
        attachMediaButton.setOnClickListener {
            showAttachmentSheet()
        }
        clearAttachmentButton.setOnClickListener {
            pendingAttachment = null
            renderAttachmentInfo()
            syncActionAvailability()
        }
    }

    private fun restoreDraft() {
        val setup = currentSetup()
        val draft = store.readDirectThreadDraft(setup.userId, activePeerUserId)
        if (draft.isNotEmpty() && messageInput.text.toString() != draft) {
            messageInput.setText(draft)
            messageInput.setSelection(draft.length)
        }
    }

    private fun persistDraft() {
        val setup = currentSetup()
        store.writeDirectThreadDraft(setup.userId, activePeerUserId, messageInput.text.toString())
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

    private fun configureReplyPreview() {
        clearReplyButton.setOnClickListener {
            pendingReplyMessage = null
            renderReplyPreview()
            syncActionAvailability()
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
            renderError(null)
        }.onFailure {
            renderError(UiErrorMapper.fromThrowable(it, action))
        }
        syncActionAvailability()
    }

    private suspend fun runAction(action: String, block: suspend () -> Unit) {
        runCatching {
            block()
        }.onSuccess {
            renderError(null)
        }.onFailure {
            renderError(UiErrorMapper.fromThrowable(it, action))
        }
        syncActionAvailability()
        refreshMeta()
        renderThreadHistory()
    }

    private fun currentSetup(): SetupConfig {
        return store.loadSetup()
    }

    private fun redirectToHome() {
        startActivity(Intent(this, ConversationsActivity::class.java))
        finish()
    }

    private suspend fun sendMessageFlow() {
        val setup = currentSetup()
        val messageText = messageInput.text.toString()
        val replyToId = pendingReplyMessage?.transportMessageId ?: pendingReplyMessage?.sentAtMillis
        require(messageText.isNotBlank() || pendingAttachment != null) {
            "message and attachment are both empty"
        }

        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
            deviceId = setup.deviceId,
            pushToken = "",
        )
        val outbound = composeOutboundPayload(messageText)
        val keysJson = MessagingCoordinator.ensurePrekeysReplenished(
            store = store,
            api = context.api,
            userId = context.profile.userId,
            keysJson = context.keysJson,
        )
        val existingSession = MessagingCoordinator.loadCompatibleSession(
            store = store,
            userId = context.profile.userId,
            peerUserId = activePeerUserId,
            sessionJson = store.readSession(context.profile.userId, activePeerUserId),
            requiredPqRatchetInterval = context.capabilities.pq_ratchet_interval,
        )
        var peerTransportIdentityX25519Pub: String? =
            store.readIdentityPin(context.profile.userId, activePeerUserId)
                ?.identityX25519Pub
                ?.takeIf { it.isNotBlank() }

        val sendResult = if (existingSession.isNullOrBlank()) {
            val fetched = latestBundle ?: context.api.getBundle(activePeerUserId).also {
                latestBundle = it
                store.writeBundleFetchedAt(
                    context.profile.userId,
                    activePeerUserId,
                    it.bundle_generated_at,
                )
            }
            enforceIdentityPin(context.profile.userId, activePeerUserId, fetched)
            peerTransportIdentityX25519Pub = fetched.identity_x25519_pub
            initiateSessionAndEncrypt(
                keysJson = keysJson,
                fromUserId = context.profile.userId,
                peerUserId = activePeerUserId,
                peerBundle = fetched.toRustBundle(),
                plaintextUtf8 = outbound.plaintext,
                suiteOverride = null,
            )
        } else {
            encryptWithSession(
                sessionJson = existingSession,
                senderUserId = context.profile.userId,
                peerUserId = activePeerUserId,
                plaintextUtf8 = outbound.plaintext,
            )
        }

        store.writeSession(context.profile.userId, activePeerUserId, sendResult.sessionJson)
        val resolvedPeerIdentityX25519Pub = peerTransportIdentityX25519Pub ?: resolvePeerTransportIdentityX25519(
            context = context,
            localUserId = context.profile.userId,
            peerUserId = activePeerUserId,
        )
        MessagingCoordinator.ensurePeerTransparencyVerified(
            store = store,
            context = context,
            peerUserId = activePeerUserId,
            bundleOverride = latestBundle,
        )
        val senderCertificateBase64 = context.api.getSenderCertificate(
            context.profile.userId,
            buildSenderCertificateAuthHeaders(
                keysJson = keysJson,
                userId = context.profile.userId,
            ).toHeaderMap(),
        ).certificate_base64
        val deliveryToken = resolvePeerSealedDeliveryToken(
            context = context,
            peerUserId = activePeerUserId,
        )
        val sealedMessageBytesBase64 = sealMessageWithSenderCert(
            keysJson = keysJson,
            recipientUserId = activePeerUserId,
            recipientIdentityX25519Pub = resolvedPeerIdentityX25519Pub,
            payloadMessageBytesBase64 = sendResult.messageBytesBase64,
            senderCertificateBase64 = senderCertificateBase64,
        )

        context.api.sealedRelay(
            recipientUserId = activePeerUserId,
            headers = emptyMap(),
            request = SealedRelayRequest(
                delivery_token = deliveryToken,
                message_bytes_base64 = sealedMessageBytesBase64,
            ),
        )
        store.markPeerAccepted(context.profile.userId, activePeerUserId)
        store.upsertConversation(
            userId = context.profile.userId,
            peerUserId = activePeerUserId,
            lastPreview = "You: ${outbound.preview}",
            incrementUnread = false,
        )
        store.markConversationRead(context.profile.userId, activePeerUserId)
        val outboundAttachment = MessageEnvelopeCodec.decodeMediaEnvelope(outbound.plaintext)
        store.appendThreadMessage(
            userId = context.profile.userId,
            peerUserId = activePeerUserId,
            direction = "outbound",
            body = outbound.preview,
            transportMessageId = null,
            replyToId = replyToId,
            attachmentEnvelope = outboundAttachment,
        )
        messageInput.setText("")
        store.writeDirectThreadDraft(context.profile.userId, activePeerUserId, "")
        pendingAttachment = null
        pendingReplyMessage = null
        renderAttachmentInfo()
        renderReplyPreview()
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
        val fetched = latestBundle ?: context.api.getBundle(peerUserId).also {
            latestBundle = it
            store.writeBundleFetchedAt(localUserId, peerUserId, it.bundle_generated_at)
        }
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
        var profile = context.api.getUserProfile(peerUserId, headers)
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
            profile = context.api.getUserProfile(peerUserId, headers)
        }
        return profile.sealed_delivery_token
            ?.takeIf { it.isNotBlank() }
            ?: error("Direct messaging requires adding this user as a contact first")
    }

    private suspend fun ensurePeerIdentityPinForTrust(
        context: ReadyMessagingContext,
        localUserId: String,
        peerUserId: String,
    ): IdentityPin {
        val existing = store.readIdentityPin(localUserId, peerUserId)
        if (existing?.identityPqSigPub?.isNotBlank() == true) {
            return existing
        }
        val fetched = latestBundle ?: context.api.getBundle(peerUserId).also {
            latestBundle = it
            store.writeBundleFetchedAt(localUserId, peerUserId, it.bundle_generated_at)
        }
        enforceIdentityPin(localUserId, peerUserId, fetched)
        return store.readIdentityPin(localUserId, peerUserId)
            ?: error("Unable to pin peer identity for $peerUserId")
    }

    private suspend fun verifySafetyNumberFlow() {
        val setup = currentSetup()
        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
            deviceId = setup.deviceId,
            pushToken = "",
        )
        val pin = ensurePeerIdentityPinForTrust(context, context.profile.userId, activePeerUserId)
        if (pin.identityPqSigPub.isBlank()) {
            error("Peer PQ identity key is unavailable for safety-number verification")
        }
        val safetyNumber = computeSafetyNumberWithPeer(
            keysJson = context.keysJson,
            peerUserId = activePeerUserId,
            peerIdentityX25519PubB64 = pin.identityX25519Pub,
            peerIdentityPqSigPubB64 = pin.identityPqSigPub,
        )
        val contacts = context.api.listContacts(
            userId = context.profile.userId,
            headers = buildContactsListAuthHeaders(
                keysJson = context.keysJson,
                userId = context.profile.userId,
            ).toHeaderMap(),
        ).contacts
        val existingContact = contacts.find { it.contact_user_id == activePeerUserId }
        val alreadyVerified =
            existingContact?.verified_by_qr == true &&
                existingContact.verified_fingerprint_sha256
                    ?.trim()
                    ?.lowercase() == pin.fingerprintSha256.trim().lowercase()
        if (alreadyVerified) {
            AlertDialog.Builder(this)
                .setTitle(R.string.safety_number_dialog_title)
                .setMessage(
                    getString(
                        R.string.safety_number_dialog_body,
                        activePeerUserId,
                        safetyNumber,
                    ) + "\n\n" + getString(R.string.safety_number_dialog_verified_note),
                )
                .setPositiveButton(R.string.button_close, null)
                .show()
            return
        }
        val accepted = confirmSafetyNumberVerification(activePeerUserId, safetyNumber)
        if (!accepted) {
            return
        }
        val aliasForHeaders = existingContact?.alias?.takeIf { it.isNotBlank() } ?: activePeerUserId
        context.api.upsertContact(
            userId = context.profile.userId,
            headers = buildContactsUpsertAuthHeaders(
                keysJson = context.keysJson,
                userId = context.profile.userId,
                contactUserId = activePeerUserId,
                alias = aliasForHeaders,
                verifiedByQr = true,
                verifiedFingerprintSha256 = pin.fingerprintSha256,
            ).toHeaderMap(),
            request = UpsertContactRequest(
                contact_user_id = activePeerUserId,
                alias = existingContact?.alias,
                verified_by_qr = true,
                verified_fingerprint_sha256 = pin.fingerprintSha256,
            ),
        )
        store.markPeerAccepted(context.profile.userId, activePeerUserId)
        AlertDialog.Builder(this)
            .setTitle(R.string.safety_number_dialog_title)
            .setMessage(getString(R.string.safety_number_verified_message))
            .setPositiveButton(R.string.button_close, null)
            .show()
        refreshMeta()
    }

    private fun syncThread() {
        if (syncInFlight) {
            return
        }
        val setup = currentSetup()
        lifecycleScope.launch {
            syncInFlight = true
            syncActionAvailability()
            runCatching {
                MessagingCoordinator.syncInbox(
                    store = store,
                    serverUrl = setup.serverUrl,
                    userId = setup.userId,
                    suiteLabel = setup.suiteLabel,
                    activePeer = activePeerUserId,
                )
            }.onSuccess {
                store.markConversationRead(setup.userId, activePeerUserId)
                renderError(null)
            }.onFailure {
                renderError(UiErrorMapper.fromThrowable(it, "Sync thread"))
            }
            syncInFlight = false
            syncActionAvailability()
            refreshMeta()
            renderThreadHistory()
        }
    }

    private suspend fun enforceIdentityPin(localUser: String, peerUser: String, bundle: BundleResponse) {
        val observedFingerprint = bundleIdentityFingerprint(bundle)
        val observedVersion = bundle.identity_key_version ?: 1
        val observedX25519Pub = bundle.identity_x25519_pub
        val observedSigPub = bundle.identity_sig_pub
        val observedPqSigPub = bundle.identity_pq_sig_pub
        val observedAt = bundle.bundle_generated_at
        val existing = store.readIdentityPin(localUser, peerUser)
        if (existing == null) {
            store.writeIdentityPin(
                localUser,
                peerUser,
                IdentityPin(
                    fingerprintSha256 = observedFingerprint,
                    identityKeyVersion = observedVersion,
                    identityX25519Pub = observedX25519Pub,
                    identitySigPub = observedSigPub,
                    identityPqSigPub = observedPqSigPub,
                    observedAt = observedAt,
                ),
            )
            return
        }

        if (existing.fingerprintSha256 == observedFingerprint) {
            if (
                existing.identityKeyVersion != observedVersion ||
                    existing.identityX25519Pub != observedX25519Pub ||
                    existing.identitySigPub != observedSigPub ||
                    existing.identityPqSigPub != observedPqSigPub
            ) {
                store.writeIdentityPin(
                    localUser,
                    peerUser,
                    IdentityPin(
                        fingerprintSha256 = observedFingerprint,
                        identityKeyVersion = observedVersion,
                        identityX25519Pub = observedX25519Pub,
                        identitySigPub = observedSigPub,
                        identityPqSigPub = observedPqSigPub,
                        observedAt = observedAt,
                    ),
                )
            }
            return
        }

        val accepted = confirmIdentityKeyChange(peerUser, existing, observedFingerprint, observedVersion)
        if (!accepted) {
            error("identity key changed for $peerUser; send blocked")
        }
        store.writeIdentityPin(
            localUser,
            peerUser,
            IdentityPin(
                fingerprintSha256 = observedFingerprint,
                identityKeyVersion = observedVersion,
                identityX25519Pub = observedX25519Pub,
                identitySigPub = observedSigPub,
                identityPqSigPub = observedPqSigPub,
                observedAt = observedAt,
            ),
        )
    }

    private suspend fun confirmSafetyNumberVerification(
        peerUser: String,
        safetyNumber: String,
    ): Boolean {
        return suspendCancellableCoroutine { continuation ->
            val dialog = AlertDialog.Builder(this)
                .setTitle(R.string.safety_number_dialog_title)
                .setMessage(
                    getString(
                        R.string.safety_number_dialog_body,
                        peerUser,
                        safetyNumber,
                    ),
                )
                .setPositiveButton(R.string.button_mark_verified) { _, _ ->
                    if (continuation.isActive) {
                        continuation.resume(true)
                    }
                }
                .setNegativeButton(R.string.button_cancel) { _, _ ->
                    if (continuation.isActive) {
                        continuation.resume(false)
                    }
                }
                .setOnCancelListener {
                    if (continuation.isActive) {
                        continuation.resume(false)
                    }
                }
                .create()
            dialog.show()
            continuation.invokeOnCancellation {
                dialog.dismiss()
            }
        }
    }

    private suspend fun confirmIdentityKeyChange(
        peerUser: String,
        existing: IdentityPin,
        observedFingerprint: String,
        observedVersion: Int,
    ): Boolean {
        return suspendCancellableCoroutine { continuation ->
            val message = buildString {
                append("Identity key changed for ")
                append(peerUser)
                append(".\n\nOld fingerprint: ")
                append(existing.fingerprintSha256)
                append(" (v")
                append(existing.identityKeyVersion)
                append(")\nNew fingerprint: ")
                append(observedFingerprint)
                append(" (v")
                append(observedVersion)
                append(")\n\nTrust new key?")
            }
            val dialog = AlertDialog.Builder(this)
                .setTitle(R.string.security_warning_title)
                .setMessage(message)
                .setCancelable(false)
                .setNegativeButton(android.R.string.cancel) { _, _ ->
                    if (continuation.isActive) {
                        continuation.resume(false)
                    }
                }
                .setPositiveButton(R.string.button_trust_new_key) { _, _ ->
                    if (continuation.isActive) {
                        continuation.resume(true)
                    }
                }
                .create()
            dialog.setOnDismissListener {
                if (continuation.isActive) {
                    continuation.resume(false)
                }
            }
            dialog.show()
            continuation.invokeOnCancellation {
                dialog.dismiss()
            }
        }
    }

    private fun bundleIdentityFingerprint(bundle: BundleResponse): String {
        return MessagingCoordinator.bundleIdentityFingerprint(bundle)
    }

    private suspend fun showChatInfoDialog() {
        val setup = currentSetup()
        val cursor = store.readSealedCursor(setup.userId)
        val bundleFetched = store.readBundleFetchedAt(setup.userId, activePeerUserId)
        val transparencyCheckpoint = store.readTransparencyCheckpoint(setup.serverUrl, activePeerUserId)
        val pin = store.readIdentityPin(setup.userId, activePeerUserId)
        val details = buildList {
            add("Contact: $activePeerUserId")
            add("Presence: ${if (peerIsTyping) getString(R.string.typing_indicator) else if (peerPresenceOnline) getString(R.string.presence_online) else getString(R.string.presence_offline)}")
            add("Sealed sender: required")
            add("Sealed cursor: $cursor")
            add(
                if (pin == null) {
                    "Trust: no local identity pin yet"
                } else {
                    "Trust: pinned identity v${pin.identityKeyVersion}"
                },
            )
            add(
                if (bundleFetched.isNullOrBlank()) {
                    "Bundle cache: fetched automatically on first send"
                } else {
                    "Bundle cache: $bundleFetched"
                },
            )
            add(
                if (transparencyCheckpoint.isNullOrBlank()) {
                    "Transparency: checked automatically before encrypted traffic"
                } else {
                    "Transparency: checkpoint saved for this chat"
                },
            )
        }.joinToString("\n")

        AlertDialog.Builder(this)
            .setTitle(activePeerUserId)
            .setMessage(details)
            .setNeutralButton(R.string.button_verify_safety_number) { _, _ ->
                lifecycleScope.launch {
                    runAction("Verify safety number") {
                        verifySafetyNumberFlow()
                    }
                }
            }
            .setNegativeButton(R.string.button_shared_media) { _, _ ->
                ThreadSharedMediaBrowser.show(
                    context = this,
                    title = "$activePeerUserId shared media",
                    messages = currentThreadMessages,
                    emptyMessage = "No shared media saved in this chat on this device yet.",
                ) {
                    renderError(UiErrorMapper.fromThrowable(it, "Open shared media"))
                }
            }
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    private fun refreshMeta() {
        val setup = currentSetup()
        chatTitleText.text = activePeerUserId
        val trustSummary = if (store.readIdentityPin(setup.userId, activePeerUserId) != null) {
            "trusted locally"
        } else {
            "tap for safety details"
        }
        val presenceSummary = when {
            peerIsTyping -> getString(R.string.typing_indicator)
            peerPresenceOnline -> getString(R.string.presence_online)
            else -> getString(R.string.presence_offline)
        }
        val syncSummary = if (syncInFlight) "refreshing" else "ready"
        chatMeta.text = "$presenceSummary | sealed sender | $trustSummary | $syncSummary"
    }

    private fun renderThreadHistory() {
        val setup = currentSetup()
        runCatching {
            store.listThreadMessages(setup.userId, activePeerUserId)
        }.onSuccess { messages ->
            localStoreAvailable = true
            currentThreadMessages = messages
            threadAdapter.submitList(messages)
            syncSelectionAfterThreadUpdate()
            syncThreadSearch(scrollToActive = false)
            chatEmptyText.text = getString(R.string.chat_log_empty)
            chatMessages.post {
                if (messages.isNotEmpty() && !isSelectionModeActive()) {
                    chatMessages.setSelection(messages.lastIndex)
                }
            }
        }.onFailure {
            localStoreAvailable = false
            currentThreadMessages = emptyList()
            renderError(UiErrorMapper.fromThrowable(it, "Open local secure state"))
            threadAdapter.submitList(emptyList())
            syncSelectionAfterThreadUpdate()
            syncThreadSearch(scrollToActive = false)
            chatEmptyText.text =
                "Local encrypted message history is unavailable on this device.\nRe-import a linked-device package or fully reprovision this device."
        }
        syncActionAvailability()
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
                chatMessages.post {
                    chatMessages.smoothScrollToPosition(activeIndex)
                }
            }
        }
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

    private fun syncActionAvailability() {
        if (isSelectionModeActive()) {
            sendButton.isEnabled = false
            clearAttachmentButton.isEnabled = false
            syncButton.isEnabled = false
            return
        }
        val hasPayload = messageInput.text.toString().isNotBlank() || pendingAttachment != null
        val hasIdentity = hasIdentity()
        sendButton.isEnabled = hasPayload && hasIdentity && localStoreAvailable && !syncInFlight
        clearAttachmentButton.isEnabled = pendingAttachment != null
        syncButton.isEnabled = hasIdentity && localStoreAvailable && !syncInFlight
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
            attachmentPreviewCard.visibility = View.GONE
        } else {
            renderReplyPreview()
            renderAttachmentInfo()
        }
        syncActionAvailability()
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
        syncActionAvailability()
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
        chatMessages.post {
            chatMessages.smoothScrollToPosition(firstReplyIndex)
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
        chatMessages.post {
            chatMessages.smoothScrollToPosition(sourceIndex)
        }
    }

    private fun showReactionPicker(message: ThreadMessage) {
        val emojiOptions = arrayOf("👍", "❤️", "😂", "😮", "😢", "👏")
        AlertDialog.Builder(this)
            .setItems(emojiOptions) { _, which ->
                val setup = currentSetup()
                val next = LinkedHashMap(message.reactions.orEmpty())
                val emoji = emojiOptions[which]
                if (next[emoji] == "You") {
                    next.remove(emoji)
                } else {
                    next[emoji] = "You"
                }
                store.updateThreadMessageReactions(
                    userId = setup.userId,
                    peerUserId = activePeerUserId,
                    direction = message.direction,
                    sentAtMillis = message.sentAtMillis,
                    reactions = next.ifEmpty { null },
                )
                renderThreadHistory()
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
                val setup = currentSetup()
                val next = LinkedHashMap(message.reactions.orEmpty())
                val emoji = emojiOptions[which]
                if (next[emoji] == "You") {
                    next.remove(emoji)
                } else {
                    next[emoji] = "You"
                }
                store.updateThreadMessageReactions(
                    userId = setup.userId,
                    peerUserId = activePeerUserId,
                    direction = message.direction,
                    sentAtMillis = message.sentAtMillis,
                    reactions = next.ifEmpty { null },
                )
                renderThreadHistory()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun copyThreadMessage(message: ThreadMessage) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(
            ClipData.newPlainText("pqmsg-message", threadMessageTranscript(message)),
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
                val setup = currentSetup()
                store.deleteThreadMessage(
                    userId = setup.userId,
                    peerUserId = activePeerUserId,
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
                renderThreadHistory()
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
                "pqmsg-messages",
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
                val setup = currentSetup()
                messages.forEach { message ->
                    store.deleteThreadMessage(
                        userId = setup.userId,
                        peerUserId = activePeerUserId,
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
                renderThreadHistory()
                Toast.makeText(this, R.string.thread_delete_local_multiple_done, Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun hasIdentity(): Boolean {
        val setup = currentSetup()
        return setup.userId.isNotBlank() && !store.readKeys(setup.userId).isNullOrBlank()
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
        attachmentInfo.text = "${attachment.fileName}\n$attachmentType • $attachmentSize"
        messageInput.hint = "Add a caption"
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
        val encoded = Base64.getEncoder().encodeToString(bytes)
        return PendingAttachment(
            fileName = fileName,
            mimeType = mimeType,
            dataBase64 = encoded,
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

    // Typing indicators

    private fun notifyTyping() {
        typingJob?.cancel()
        typingJob = lifecycleScope.launch {
            delay(300) // debounce
            runCatching {
                val setup = currentSetup()
                val keysJson = store.readKeys(setup.userId) ?: return@launch
                val api = ApiClientFactory.create(setup.serverUrl)
                api.updateTyping(
                    peerUserId = activePeerUserId,
                    headers = buildTypingUpdateAuthHeaders(
                        keysJson = keysJson,
                        peerUserId = activePeerUserId,
                        isTyping = true,
                    ).toHeaderMap(),
                    request = TypingUpdateRequest(is_typing = true),
                )
            }
        }
    }

    private fun startTypingPolling() {
        typingPollingJob?.cancel()
        typingPollingJob = lifecycleScope.launch {
            while (isActive) {
                runCatching {
                    val setup = currentSetup()
                    val keysJson = store.readKeys(setup.userId) ?: return@launch
                    val api = ApiClientFactory.create(setup.serverUrl)
                    val response = api.getTyping(
                        userId = setup.userId,
                        headers = buildTypingGetAuthHeaders(
                            keysJson = keysJson,
                            userId = setup.userId,
                        ).toHeaderMap(),
                    )
                    val wasTyping = peerIsTyping
                    peerIsTyping = response.typing.any { it.sender_user_id == activePeerUserId }
                    if (peerIsTyping != wasTyping) refreshMeta()
                }
                delay(3000)
            }
        }
    }

    // Presence

    private fun sendPresenceHeartbeat() {
        lifecycleScope.launch {
            runCatching {
                val setup = currentSetup()
                val keysJson = store.readKeys(setup.userId) ?: return@launch
                val api = ApiClientFactory.create(setup.serverUrl)
                api.updatePresence(
                    userId = setup.userId,
                    headers = buildPresenceUpdateAuthHeaders(
                        keysJson = keysJson,
                        userId = setup.userId,
                        status = "online",
                    ).toHeaderMap(),
                    request = PresenceUpdateRequest(status = "online"),
                )
            }
        }
    }

    private fun startPresencePolling() {
        presencePollingJob?.cancel()
        presencePollingJob = lifecycleScope.launch {
            while (isActive) {
                runCatching {
                    val setup = currentSetup()
                    val keysJson = store.readKeys(setup.userId) ?: return@launch
                    val api = ApiClientFactory.create(setup.serverUrl)
                    val response = api.getPresence(
                        userId = activePeerUserId,
                        headers = buildPresenceGetAuthHeaders(
                            keysJson = keysJson,
                            userId = activePeerUserId,
                        ).toHeaderMap(),
                    )
                    val wasOnline = peerPresenceOnline
                    peerPresenceOnline = response.active
                    if (peerPresenceOnline != wasOnline) refreshMeta()
                }
                delay(10000)
            }
        }
    }

    // Read receipts

    private fun sendReadReceipts() {
        lifecycleScope.launch {
            runCatching {
                val setup = currentSetup()
                val keysJson = store.readKeys(setup.userId) ?: return@launch
                val api = ApiClientFactory.create(setup.serverUrl)
                val messages = store.listThreadMessages(setup.userId, activePeerUserId)
                val lastInbound = messages.lastOrNull { it.direction == "inbound" && it.transportMessageId != null }
                if (lastInbound?.transportMessageId != null) {
                    api.sendReceipt(
                        userId = setup.userId,
                        headers = buildSendReceiptAuthHeaders(
                            keysJson = keysJson,
                            userId = setup.userId,
                            messageId = lastInbound.transportMessageId,
                            receiptType = "read",
                        ).toHeaderMap(),
                        request = SendReceiptRequest(
                            message_id = lastInbound.transportMessageId,
                            receipt_type = "read",
                        ),
                    )
                }
            }
        }
    }

    // Sealed sender toggle

    fun toggleSealedSender() {
        sealedSenderEnabled = true
        refreshMeta()
    }

    // Ephemeral TTL

    fun showEphemeralDialog() {
        ephemeralTtlSeconds = null
        renderError(
            UiError(
                headline = "Disappearing messages are unavailable",
                actionHint = "The privacy-hardened direct-messaging path now requires sealed sender only.",
                technicalDetails = "Ephemeral relay remains disabled on the supported Android direct-message path until it has a metadata-safe design.",
            )
        )
    }

    private fun renderError(error: UiError?) {
        if (error == null) {
            errorSummaryText.text = ""
            errorDetailsText.text = ""
            errorSummaryText.visibility = View.GONE
            errorDetailsText.visibility = View.GONE
            errorToggleButton.visibility = View.GONE
            errorExpanded = false
            return
        }
        errorSummaryText.text = "${error.headline}\n${error.actionHint}"
        errorDetailsText.text = error.technicalDetails
        errorSummaryText.visibility = View.VISIBLE
        errorToggleButton.visibility = View.VISIBLE
        errorExpanded = false
        refreshErrorDetailsVisibility()
    }

    private fun refreshErrorDetailsVisibility() {
        if (errorExpanded) {
            errorDetailsText.visibility = View.VISIBLE
            errorToggleButton.setText(R.string.button_hide_error_details)
        } else {
            errorDetailsText.visibility = View.GONE
            errorToggleButton.setText(R.string.button_show_error_details)
        }
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
