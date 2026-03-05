package com.pqmsg.demo

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
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import uniffi.pqmsg_android.ServerBundle
import uniffi.pqmsg_android.buildInboxAuthHeaders
import uniffi.pqmsg_android.buildPrekeysAuthHeaders
import uniffi.pqmsg_android.buildPrekeysStatusAuthHeaders
import uniffi.pqmsg_android.buildPublishPrekeysPayload
import uniffi.pqmsg_android.buildRelayAuthHeaders
import uniffi.pqmsg_android.decryptMessage
import uniffi.pqmsg_android.encryptWithSession
import uniffi.pqmsg_android.initiateSessionAndEncrypt
import uniffi.pqmsg_android.loadUserProfile
import uniffi.pqmsg_android.replenishOneTimePrekeys
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import kotlin.coroutines.resume

class ChatActivity : AppCompatActivity() {
    private val maxSeenCipherHashesPerPeer = 512
    private val maxAttachmentBytes = 128 * 1024
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var peerInput: EditText
    private lateinit var messageInput: EditText
    private lateinit var fetchBundleButton: Button
    private lateinit var attachMediaButton: Button
    private lateinit var clearAttachmentButton: Button
    private lateinit var sendButton: Button
    private lateinit var pollButton: Button
    private lateinit var chatLog: TextView
    private lateinit var chatMeta: TextView
    private lateinit var attachmentInfo: TextView
    private lateinit var errorSummaryText: TextView
    private lateinit var errorDetailsText: TextView
    private lateinit var errorToggleButton: Button
    private var latestBundle: BundleResponse? = null
    private var errorExpanded = false
    private var pendingAttachment: PendingAttachment? = null

    private val pickAttachmentLauncher =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
            if (uri == null) {
                return@registerForActivityResult
            }
            runCatching {
                pendingAttachment = readAttachment(uri)
                renderAttachmentInfo()
                syncActionAvailability()
                appendLog("attachment loaded: ${pendingAttachment?.fileName}")
            }.onFailure {
                renderError(UiErrorMapper.fromThrowable(it, "Read attachment"))
                appendLog("attachment load failed")
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)
        store = LocalStateStore(this)

        serverInput = findViewById(R.id.editChatServer)
        userInput = findViewById(R.id.editChatUser)
        peerInput = findViewById(R.id.editChatPeer)
        messageInput = findViewById(R.id.editMessage)
        fetchBundleButton = findViewById(R.id.buttonFetchBundle)
        attachMediaButton = findViewById(R.id.buttonAttachMedia)
        clearAttachmentButton = findViewById(R.id.buttonClearAttachment)
        sendButton = findViewById(R.id.buttonSend)
        pollButton = findViewById(R.id.buttonPoll)
        chatLog = findViewById(R.id.textChatLog)
        chatMeta = findViewById(R.id.textChatMeta)
        attachmentInfo = findViewById(R.id.textAttachmentInfo)
        errorSummaryText = findViewById(R.id.textErrorSummaryChat)
        errorDetailsText = findViewById(R.id.textErrorDetailsChat)
        errorToggleButton = findViewById(R.id.buttonToggleErrorDetailsChat)

        val setup = store.loadSetup()
        serverInput.setText(intent.getStringExtra("server") ?: setup.serverUrl)
        userInput.setText(intent.getStringExtra("user") ?: setup.userId)
        peerInput.setText(intent.getStringExtra("peer") ?: setup.peerUserId)
        store.markConversationRead(
            userInput.text.toString().trim(),
            peerInput.text.toString().trim(),
        )

        configureInputObservers()
        configureErrorToggle()
        configureAttachmentButtons()
        refreshMeta()
        renderAttachmentInfo()
        syncActionAvailability()

        fetchBundleButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Fetch peer bundle") {
                    val api = ApiClientFactory.create(serverInput.text.toString())
                    val peer = peerInput.text.toString().trim()
                    require(peer.isNotBlank()) { "peer user id is empty" }
                    latestBundle = api.getBundle(peer)
                    val me = userInput.text.toString().trim()
                    store.writeBundleFetchedAt(me, peer, latestBundle!!.bundle_generated_at)
                    store.upsertConversation(me, peer, "Bundle fetched for $peer", incrementUnread = false)
                    refreshMeta()
                    appendLog("bundle fetched for $peer")
                    "Bundle fetched for $peer"
                }
            }
        }

        sendButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Send message") {
                    sendMessageFlow()
                    "Encrypted message sent"
                }
            }
        }

        pollButton.setOnClickListener {
            lifecycleScope.launch {
                runAction("Poll inbox") {
                    pollFlow()
                    "Inbox polling completed"
                }
            }
        }

        findViewById<Button>(R.id.buttonBackSetup).setOnClickListener {
            finish()
        }
    }

    private fun configureInputObservers() {
        serverInput.doAfterTextChanged { syncActionAvailability() }
        userInput.doAfterTextChanged {
            syncActionAvailability()
            refreshMeta()
        }
        peerInput.doAfterTextChanged {
            syncActionAvailability()
            refreshMeta()
            val user = userInput.text.toString().trim()
            val peer = peerInput.text.toString().trim()
            store.markConversationRead(user, peer)
        }
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

    private suspend fun runAction(action: String, block: suspend () -> String) {
        runCatching {
            block()
        }.onSuccess {
            renderError(null)
            appendLog(it)
        }.onFailure {
            val mapped = UiErrorMapper.fromThrowable(it, action)
            renderError(mapped)
            appendLog("${action.lowercase()} failed")
        }
        syncActionAvailability()
    }

    private suspend fun sendMessageFlow() {
        val server = serverInput.text.toString().trim()
        val fromUser = userInput.text.toString().trim()
        val peerUser = peerInput.text.toString().trim()
        val text = messageInput.text.toString()
        require(server.isNotBlank()) { "server URL is empty" }
        require(fromUser.isNotBlank()) { "user id is empty" }
        require(peerUser.isNotBlank()) { "peer user id is empty" }
        require(text.isNotBlank() || pendingAttachment != null) { "message and attachment are both empty" }

        val outbound = composeOutboundPayload(text)
        var keysJson = store.readKeys(fromUser) ?: error("missing keys for $fromUser")
        val api = ApiClientFactory.create(server)
        keysJson = ensurePrekeysReplenished(api, fromUser, keysJson)
        val profile = loadUserProfile(keysJson)
        val existingSession = store.readSession(fromUser, peerUser)

        val sendResult = if (existingSession.isNullOrBlank()) {
            val fetched = latestBundle ?: api.getBundle(peerUser).also { latestBundle = it }
            if (fetched.last_resort_prekey_only == true) {
                appendLog("peer $peerUser is using last-resort prekey fallback")
            }
            enforceIdentityPin(fromUser, peerUser, fetched)
            initiateSessionAndEncrypt(
                keysJson = keysJson,
                fromUserId = fromUser,
                peerUserId = peerUser,
                peerBundle = fetched.toRustBundle(),
                plaintextUtf8 = outbound.plaintext,
                suiteOverride = null,
            )
        } else {
            encryptWithSession(
                sessionJson = existingSession,
                senderUserId = fromUser,
                peerUserId = peerUser,
                plaintextUtf8 = outbound.plaintext,
            )
        }

        store.writeSession(fromUser, peerUser, sendResult.sessionJson)
        val relay = api.relay(
            recipientUserId = peerUser,
            headers = buildRelayAuthHeaders(
                keysJson = keysJson,
                senderUserId = fromUser,
                recipientUserId = peerUser,
                messageBytesBase64 = sendResult.messageBytesBase64,
            ).toHeaderMap(),
            request = RelayRequest(
                sender_user_id = profile.userId,
                device_id = profile.deviceId,
                message_bytes_base64 = sendResult.messageBytesBase64,
            ),
        )
        appendLog("me->$peerUser: ${outbound.preview} [message_id=${relay.message_id}]")
        store.upsertConversation(fromUser, peerUser, "You: ${outbound.preview}", incrementUnread = false)
        store.markConversationRead(fromUser, peerUser)
        messageInput.setText("")
        pendingAttachment = null
        renderAttachmentInfo()
        syncActionAvailability()
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
            appendLog("pinned identity for $peerUser")
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
        appendLog("accepted identity update for $peerUser")
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
                .setTitle("Security warning")
                .setMessage(message)
                .setCancelable(false)
                .setNegativeButton("Cancel") { _, _ ->
                    if (continuation.isActive) {
                        continuation.resume(false)
                    }
                }
                .setPositiveButton("Trust new key") { _, _ ->
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

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    private suspend fun pollFlow() {
        val server = serverInput.text.toString().trim()
        val user = userInput.text.toString().trim()
        val activePeer = peerInput.text.toString().trim()
        require(server.isNotBlank()) { "server URL is empty" }
        require(user.isNotBlank()) { "user id is empty" }
        var keysJson = store.readKeys(user) ?: error("missing keys for $user")
        val api = ApiClientFactory.create(server)
        keysJson = ensurePrekeysReplenished(api, user, keysJson)
        var cursor = store.readCursor(user)
        val inbox = api.inbox(
            user,
            buildInboxAuthHeaders(
                keysJson = keysJson,
                userId = user,
                since = cursor,
            ).toHeaderMap(),
            cursor,
        )

        if (inbox.messages.isEmpty()) {
            appendLog("inbox empty")
            return
        }

        for (item in inbox.messages) {
            val peer = item.sender_user_id
            val peerLastMessageId = store.readPeerLastMessageId(user, peer)
            if (item.message_id <= peerLastMessageId) {
                appendLog("replay rejected from $peer [message_id=${item.message_id}]")
                cursor = maxOf(cursor, item.message_id)
                continue
            }
            val cipherHash = sha256Hex(item.message_bytes_base64)
            val seenCipherHashes = store.readPeerSeenCipherHashes(user, peer)
            if (seenCipherHashes.contains(cipherHash)) {
                appendLog("duplicate ciphertext rejected from $peer [message_id=${item.message_id}]")
                store.writePeerLastMessageId(user, peer, maxOf(peerLastMessageId, item.message_id))
                cursor = maxOf(cursor, item.message_id)
                continue
            }
            runCatching {
                val existingSession = store.readSession(user, peer)
                val result = decryptMessage(
                    keysJson = keysJson,
                    recipientUserId = user,
                    senderUserId = peer,
                    messageBytesBase64 = item.message_bytes_base64,
                    existingSessionJson = existingSession,
                )
                store.writeSession(user, peer, result.sessionJson)
                val rendered = renderInboundPlaintext(result.plaintextUtf8)
                appendLog("$peer: $rendered")
                val incrementUnread = peer != activePeer
                store.upsertConversation(
                    userId = user,
                    peerUserId = peer,
                    lastPreview = "$peer: $rendered",
                    incrementUnread = incrementUnread,
                )
                if (!incrementUnread) {
                    store.markConversationRead(user, peer)
                }
            }.onFailure {
                val mapped = UiErrorMapper.fromThrowable(it, "Decrypt message")
                renderError(mapped)
                appendLog("decrypt failed for ${item.sender_user_id}")
            }
            seenCipherHashes.add(cipherHash)
            while (seenCipherHashes.size > maxSeenCipherHashesPerPeer) {
                val first = seenCipherHashes.firstOrNull() ?: break
                seenCipherHashes.remove(first)
            }
            store.writePeerSeenCipherHashes(user, peer, seenCipherHashes)
            store.writePeerLastMessageId(user, peer, maxOf(peerLastMessageId, item.message_id))
            cursor = maxOf(cursor, item.message_id)
        }

        store.writeCursor(user, cursor)
        refreshMeta()
    }

    private suspend fun ensurePrekeysReplenished(
        api: PqmsgApi,
        user: String,
        keysJson: String,
    ): String {
        return runCatching {
            val status = api.prekeysStatus(
                user,
                buildPrekeysStatusAuthHeaders(
                    keysJson = keysJson,
                    userId = user,
                ).toHeaderMap(),
            )
            if (!status.low_one_time_prekeys) {
                return@runCatching keysJson
            }
            val target = maxOf(status.minimum_recommended_one_time_prekeys, 16)
            val refreshedKeysJson = replenishOneTimePrekeys(keysJson, target.toUInt())
            val payload = buildPublishPrekeysPayload(refreshedKeysJson)
            val prekeysAuth = buildPrekeysAuthHeaders(refreshedKeysJson, user)
            api.publishPrekeys(
                user,
                prekeysAuth.toHeaderMap(),
                PublishPrekeysRequest(
                    signed_prekey_x25519_pub = payload.signedPrekeyX25519Pub,
                    sig_over_spk = payload.sigOverSpk,
                    pq_signed_prekey_pub_mlkem768 = payload.pqSignedPrekeyPubMlkem768,
                    sig_over_pqspk = payload.sigOverPqspk,
                    one_time_prekeys_x25519 = payload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768 = payload.oneTimePrekeysMlkem768,
                ),
            )
            store.writeKeys(user, refreshedKeysJson)
            appendLog(
                "auto-replenished prekeys for $user at ${status.checked_at} (x=${status.remaining_one_time_prekeys_x25519}, pq=${status.remaining_one_time_prekeys_mlkem768})",
            )
            refreshedKeysJson
        }.getOrElse {
            keysJson
        }
    }

    private fun refreshMeta() {
        val user = userInput.text.toString().trim()
        val peer = peerInput.text.toString().trim()
        val cursor = if (user.isBlank()) 0L else store.readCursor(user)
        val bundleFetched = if (user.isBlank() || peer.isBlank()) null else store.readBundleFetchedAt(user, peer)
        val bundleLine = if (bundleFetched.isNullOrBlank()) {
            "Last bundle fetch: none"
        } else {
            "Last bundle fetch: $bundleFetched"
        }
        chatMeta.text = "Cursor: $cursor\n$bundleLine"
    }

    private fun syncActionAvailability() {
        val server = serverInput.text.toString().trim()
        val user = userInput.text.toString().trim()
        val peer = peerInput.text.toString().trim()
        val message = messageInput.text.toString()
        val hasPayload = message.isNotBlank() || pendingAttachment != null
        val keysReady = hasKeys(user)
        fetchBundleButton.isEnabled = server.isNotBlank() && peer.isNotBlank()
        sendButton.isEnabled = server.isNotBlank() && user.isNotBlank() && peer.isNotBlank() && hasPayload && keysReady
        pollButton.isEnabled = server.isNotBlank() && user.isNotBlank() && keysReady
        clearAttachmentButton.isEnabled = pendingAttachment != null
    }

    private fun hasKeys(userId: String): Boolean {
        if (userId.isBlank()) {
            return false
        }
        return !store.readKeys(userId).isNullOrBlank()
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

    private fun renderInboundPlaintext(plaintext: String): String {
        val decoded = MessageEnvelopeCodec.decodeMediaEnvelope(plaintext) ?: return plaintext
        val mediaTag = "[media:${decoded.fileName} ${decoded.mimeType} ${decoded.byteLength}B]"
        return if (decoded.noteText.isBlank()) {
            mediaTag
        } else {
            "$mediaTag ${decoded.noteText}"
        }
    }

    private fun renderAttachmentInfo() {
        val attachment = pendingAttachment
        if (attachment == null) {
            attachmentInfo.text = "No attachment selected"
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

    private fun appendLog(line: String) {
        val previous = chatLog.text?.toString()?.trim()
        chatLog.text = if (previous.isNullOrEmpty()) {
            line
        } else {
            "$previous\n$line"
        }
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
            errorToggleButton.text = "Hide technical details"
        } else {
            errorDetailsText.visibility = View.GONE
            errorToggleButton.text = "Show technical details"
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
