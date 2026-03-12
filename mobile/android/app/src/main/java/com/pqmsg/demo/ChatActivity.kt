package com.pqmsg.demo

import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.NestedScrollView
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import uniffi.pqmsg_android.ServerBundle
import uniffi.pqmsg_android.buildPresenceGetAuthHeaders
import uniffi.pqmsg_android.buildPresenceUpdateAuthHeaders
import uniffi.pqmsg_android.buildSendReceiptAuthHeaders
import uniffi.pqmsg_android.buildSenderCertificateAuthHeaders
import uniffi.pqmsg_android.buildTypingGetAuthHeaders
import uniffi.pqmsg_android.buildTypingUpdateAuthHeaders
import uniffi.pqmsg_android.encryptWithSession
import uniffi.pqmsg_android.initiateSessionAndEncrypt
import uniffi.pqmsg_android.sealMessageWithSenderCert
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.text.DateFormat
import java.util.Base64
import java.util.Date
import kotlin.coroutines.resume

class ChatActivity : AppCompatActivity() {
    private val maxAttachmentBytes = 128 * 1024
    private lateinit var store: LocalStateStore
    private lateinit var messageInput: EditText
    private lateinit var attachMediaButton: Button
    private lateinit var clearAttachmentButton: Button
    private lateinit var sendButton: Button
    private lateinit var syncButton: Button
    private lateinit var backButton: Button
    private lateinit var chatLogScroll: NestedScrollView
    private lateinit var chatLog: TextView
    private lateinit var chatMeta: TextView
    private lateinit var attachmentPreviewCard: View
    private lateinit var attachmentTitle: TextView
    private lateinit var attachmentInfo: TextView
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
        syncButton = findViewById(R.id.buttonSyncThread)
        backButton = findViewById(R.id.buttonBackSetup)
        chatLogScroll = findViewById(R.id.scrollChatLog)
        chatLog = findViewById(R.id.textChatLog)
        chatMeta = findViewById(R.id.textChatMeta)
        attachmentPreviewCard = findViewById(R.id.cardAttachmentPreview)
        attachmentTitle = findViewById(R.id.textAttachmentPreviewTitle)
        attachmentInfo = findViewById(R.id.textAttachmentPreviewMeta)
        errorSummaryText = findViewById(R.id.textErrorSummaryChat)
        errorDetailsText = findViewById(R.id.textErrorDetailsChat)
        errorToggleButton = findViewById(R.id.buttonToggleErrorDetailsChat)

        configureInputObservers()
        configureErrorToggle()
        configureAttachmentButtons()
        renderAttachmentInfo()
        renderThreadHistory()
        refreshMeta()
        syncActionAvailability()

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

    private fun configureInputObservers() {
        messageInput.doAfterTextChanged {
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
        val senderCertificateBase64 = context.api.getSenderCertificate(
            context.profile.userId,
            buildSenderCertificateAuthHeaders(
                keysJson = keysJson,
                userId = context.profile.userId,
            ).toHeaderMap(),
        ).certificate_base64
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
                sender_user_id = context.profile.userId,
                device_id = context.profile.deviceId,
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
        store.appendThreadMessage(
            userId = context.profile.userId,
            peerUserId = activePeerUserId,
            direction = "outbound",
            body = outbound.preview,
            transportMessageId = null,
        )
        messageInput.setText("")
        pendingAttachment = null
        renderAttachmentInfo()
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
                    observedAt = observedAt,
                ),
            )
            return
        }

        if (existing.fingerprintSha256 == observedFingerprint) {
            if (
                existing.identityKeyVersion != observedVersion ||
                    existing.identityX25519Pub != observedX25519Pub ||
                    existing.identitySigPub != observedSigPub
            ) {
                store.writeIdentityPin(
                    localUser,
                    peerUser,
                    IdentityPin(
                        fingerprintSha256 = observedFingerprint,
                        identityKeyVersion = observedVersion,
                        identityX25519Pub = observedX25519Pub,
                        identitySigPub = observedSigPub,
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
                observedAt = observedAt,
            ),
        )
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
        val fromServer = bundle.identity_fingerprint_sha256?.trim()?.lowercase()
        if (!fromServer.isNullOrEmpty()) {
            return fromServer
        }
        val identityKey = Base64.getDecoder().decode(bundle.identity_x25519_pub)
        val digest = MessageDigest.getInstance("SHA-256").digest(identityKey)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun refreshMeta() {
        val setup = currentSetup()
        val cursor = store.readCursor(setup.userId)
        val bundleFetched = store.readBundleFetchedAt(setup.userId, activePeerUserId)
        val bundleLine = if (bundleFetched.isNullOrBlank()) {
            "Peer bundle is fetched automatically on first send."
        } else {
            "Peer bundle cached at $bundleFetched"
        }
        val syncSummary = if (syncInFlight) "Refreshing..." else "Ready"
        val protectionSummary = buildList {
            add("Sealed sender required")
        }.joinToString(" | ")
        val statusSummary = buildString {
            append("Status: ")
            append(syncSummary)
            append(" | Cursor ")
            append(cursor)
            if (protectionSummary.isNotBlank()) {
                append(" | ")
                append(protectionSummary)
            }
        }
        chatMeta.text = "$activePeerUserId | metadata minimized\n$bundleLine\n$statusSummary"
    }

    private fun renderThreadHistory() {
        val setup = currentSetup()
        val messages = store.listThreadMessages(setup.userId, activePeerUserId)
        chatLog.text = if (messages.isEmpty()) {
            getString(R.string.chat_log_empty)
        } else {
            messages.joinToString("\n\n") { message ->
                val label = if (message.direction == "outbound") "You" else activePeerUserId
                val timeLabel = DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(message.sentAtMillis))
                "$label  $timeLabel\n${message.body}"
            }
        }
        chatLog.post {
            chatLogScroll.fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun syncActionAvailability() {
        val hasPayload = messageInput.text.toString().isNotBlank() || pendingAttachment != null
        val hasIdentity = hasIdentity()
        sendButton.isEnabled = hasPayload && hasIdentity && !syncInFlight
        clearAttachmentButton.isEnabled = pendingAttachment != null
        syncButton.isEnabled = hasIdentity && !syncInFlight
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
