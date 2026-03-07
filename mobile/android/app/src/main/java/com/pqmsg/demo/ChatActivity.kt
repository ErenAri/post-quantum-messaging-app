package com.pqmsg.demo

import android.content.Intent
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import uniffi.pqmsg_android.ServerBundle
import uniffi.pqmsg_android.buildRelayAuthHeaders
import uniffi.pqmsg_android.encryptWithSession
import uniffi.pqmsg_android.initiateSessionAndEncrypt
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
    private lateinit var attachmentInfo: TextView
    private lateinit var errorSummaryText: TextView
    private lateinit var errorDetailsText: TextView
    private lateinit var errorToggleButton: Button
    private var latestBundle: BundleResponse? = null
    private var errorExpanded = false
    private var pendingAttachment: PendingAttachment? = null
    private var activePeerUserId = ""
    private var syncInFlight = false

    private val pickAttachmentLauncher =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
            if (uri == null) {
                return@registerForActivityResult
            }
            runCatching {
                pendingAttachment = readAttachment(uri)
                renderAttachmentInfo()
                renderError(null)
            }.onFailure {
                renderError(UiErrorMapper.fromThrowable(it, "Read attachment"))
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
        store.markPeerAccepted(setup.userId, activePeerUserId)
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
        attachmentInfo = findViewById(R.id.textAttachmentInfo)
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

    private fun configureInputObservers() {
        messageInput.doAfterTextChanged { syncActionAvailability() }
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
            pickAttachmentLauncher.launch("*/*")
        }
        clearAttachmentButton.setOnClickListener {
            pendingAttachment = null
            renderAttachmentInfo()
            syncActionAvailability()
        }
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
        val existingSession = store.readSession(context.profile.userId, activePeerUserId)

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
        val relay = context.api.relay(
            recipientUserId = activePeerUserId,
            headers = buildRelayAuthHeaders(
                keysJson = keysJson,
                senderUserId = context.profile.userId,
                recipientUserId = activePeerUserId,
                messageBytesBase64 = sendResult.messageBytesBase64,
            ).toHeaderMap(),
            request = RelayRequest(
                sender_user_id = context.profile.userId,
                device_id = context.profile.deviceId,
                message_bytes_base64 = sendResult.messageBytesBase64,
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
            transportMessageId = relay.message_id,
        )
        messageInput.setText("")
        pendingAttachment = null
        renderAttachmentInfo()
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
                    identitySigPub = observedSigPub,
                    observedAt = observedAt,
                ),
            )
            return
        }

        if (existing.fingerprintSha256 == observedFingerprint) {
            if (existing.identityKeyVersion != observedVersion || existing.identitySigPub != observedSigPub) {
                store.writeIdentityPin(
                    localUser,
                    peerUser,
                    IdentityPin(
                        fingerprintSha256 = observedFingerprint,
                        identityKeyVersion = observedVersion,
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
        val syncLabel = if (syncInFlight) "Syncing..." else "Ready"
        chatMeta.text =
            "Chatting with $activePeerUserId\nSigned in as ${setup.userId}\n$bundleLine\nStatus: $syncLabel | Cursor: $cursor"
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
            attachmentInfo.text = getString(R.string.chat_attachment_none)
            return
        }
        attachmentInfo.text =
            "Attachment: ${attachment.fileName} (${attachment.mimeType}, ${attachment.byteLength} bytes)"
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
            signedPrekeyX25519Pub = signed_prekey_x25519_pub,
            sigOverSpk = sig_over_spk,
            pqSignedPrekeyPubMlkem768 = pq_signed_prekey_pub_mlkem768,
            sigOverPqspk = sig_over_pqspk,
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
