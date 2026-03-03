package com.pqmsg.demo

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.PqmsgAndroidException
import uniffi.pqmsg_android.ServerBundle
import uniffi.pqmsg_android.decryptMessage
import uniffi.pqmsg_android.encryptWithSession
import uniffi.pqmsg_android.initiateSessionAndEncrypt
import uniffi.pqmsg_android.loadUserProfile

class ChatActivity : AppCompatActivity() {
    private lateinit var store: LocalStateStore
    private lateinit var serverInput: EditText
    private lateinit var userInput: EditText
    private lateinit var peerInput: EditText
    private lateinit var messageInput: EditText
    private lateinit var chatLog: TextView
    private var latestBundle: BundleResponse? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)
        store = LocalStateStore(this)

        serverInput = findViewById(R.id.editChatServer)
        userInput = findViewById(R.id.editChatUser)
        peerInput = findViewById(R.id.editChatPeer)
        messageInput = findViewById(R.id.editMessage)
        chatLog = findViewById(R.id.textChatLog)

        val setup = store.loadSetup()
        serverInput.setText(intent.getStringExtra("server") ?: setup.serverUrl)
        userInput.setText(intent.getStringExtra("user") ?: setup.userId)
        peerInput.setText(intent.getStringExtra("peer") ?: setup.peerUserId)

        findViewById<Button>(R.id.buttonFetchBundle).setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    val api = ApiClientFactory.create(serverInput.text.toString())
                    val peer = peerInput.text.toString().trim()
                    latestBundle = api.getBundle(peer)
                    appendLog("bundle fetched for $peer")
                }.onFailure {
                    appendLog("bundle fetch failed: ${formatError(it)}")
                }
            }
        }

        findViewById<Button>(R.id.buttonSend).setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    sendMessageFlow()
                }.onFailure {
                    appendLog("send failed: ${formatError(it)}")
                }
            }
        }

        findViewById<Button>(R.id.buttonPoll).setOnClickListener {
            lifecycleScope.launch {
                runCatching {
                    pollFlow()
                }.onFailure {
                    appendLog("poll failed: ${formatError(it)}")
                }
            }
        }

        findViewById<Button>(R.id.buttonBackSetup).setOnClickListener {
            finish()
        }
    }

    private suspend fun sendMessageFlow() {
        val server = serverInput.text.toString().trim()
        val fromUser = userInput.text.toString().trim()
        val peerUser = peerInput.text.toString().trim()
        val text = messageInput.text.toString()
        require(text.isNotBlank()) { "message is empty" }

        val keysJson = store.readKeys(fromUser) ?: error("missing keys for $fromUser")
        val profile = loadUserProfile(keysJson)
        val api = ApiClientFactory.create(server)
        val existingSession = store.readSession(fromUser, peerUser)

        val sendResult = if (existingSession.isNullOrBlank()) {
            val fetched = latestBundle ?: api.getBundle(peerUser).also { latestBundle = it }
            initiateSessionAndEncrypt(
                keysJson = keysJson,
                fromUserId = fromUser,
                peerUserId = peerUser,
                peerBundle = fetched.toRustBundle(),
                plaintextUtf8 = text,
                suiteOverride = null,
            )
        } else {
            encryptWithSession(
                sessionJson = existingSession,
                senderUserId = fromUser,
                peerUserId = peerUser,
                plaintextUtf8 = text,
            )
        }

        store.writeSession(fromUser, peerUser, sendResult.sessionJson)
        val relay = api.relay(
            recipientUserId = peerUser,
            request = RelayRequest(
                sender_user_id = profile.userId,
                device_id = profile.deviceId,
                message_bytes_base64 = sendResult.messageBytesBase64,
            ),
        )
        appendLog("me->$peerUser: $text [message_id=${relay.message_id}]")
        messageInput.setText("")
    }

    private suspend fun pollFlow() {
        val server = serverInput.text.toString().trim()
        val user = userInput.text.toString().trim()
        val keysJson = store.readKeys(user) ?: error("missing keys for $user")
        val api = ApiClientFactory.create(server)
        var cursor = store.readCursor(user)
        val inbox = api.inbox(user, cursor)

        if (inbox.messages.isEmpty()) {
            appendLog("inbox empty")
            return
        }

        for (item in inbox.messages) {
            val existingSession = store.readSession(user, item.sender_user_id)
            runCatching {
                val result = decryptMessage(
                    keysJson = keysJson,
                    recipientUserId = user,
                    senderUserId = item.sender_user_id,
                    messageBytesBase64 = item.message_bytes_base64,
                    existingSessionJson = existingSession,
                )
                store.writeSession(user, item.sender_user_id, result.sessionJson)
                appendLog("${item.sender_user_id}: ${result.plaintextUtf8}")
            }.onFailure {
                appendLog("decrypt failed for ${item.sender_user_id}: ${formatError(it)}")
            }
            cursor = maxOf(cursor, item.message_id)
        }

        store.writeCursor(user, cursor)
    }

    private fun appendLog(line: String) {
        val previous = chatLog.text?.toString()?.trim()
        chatLog.text = if (previous.isNullOrEmpty()) {
            line
        } else {
            "$previous\n$line"
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

    private fun formatError(error: Throwable): String {
        return when (error) {
            is PqmsgAndroidException.InvalidInput -> "invalid input: ${error.message}"
            is PqmsgAndroidException.OperationFailed -> "operation failed: ${error.message}"
            else -> error.message ?: error.javaClass.simpleName
        }
    }
}
