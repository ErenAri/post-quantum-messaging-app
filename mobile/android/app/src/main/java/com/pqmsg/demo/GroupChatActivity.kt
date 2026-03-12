package com.pqmsg.demo

import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.NestedScrollView
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.launch
import uniffi.pqmsg_android.buildGroupMembersAddAuthHeaders
import uniffi.pqmsg_android.buildGroupMembersListAuthHeaders
import uniffi.pqmsg_android.buildGroupRelayAuthHeaders
import uniffi.pqmsg_android.ServerBundle
import uniffi.pqmsg_android.GroupRelayAuthRecipient
import uniffi.pqmsg_android.encryptWithSession
import uniffi.pqmsg_android.initiateSessionAndEncrypt
import java.text.DateFormat
import java.util.Date

class GroupChatActivity : AppCompatActivity() {
    private val groupMessagingSupported = false
    private lateinit var store: LocalStateStore
    private lateinit var titleText: TextView
    private lateinit var metaText: TextView
    private lateinit var messageInput: EditText
    private lateinit var sendButton: MaterialButton
    private lateinit var syncButton: MaterialButton
    private lateinit var infoButton: MaterialButton
    private lateinit var backButton: MaterialButton
    private lateinit var chatLogScroll: NestedScrollView
    private lateinit var chatLog: TextView
    private var groupId = ""
    private var groupName = ""
    private var syncInFlight = false

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
        sendButton = findViewById(R.id.buttonSendGroup)
        syncButton = findViewById(R.id.buttonSyncGroup)
        infoButton = findViewById(R.id.buttonGroupInfo)
        backButton = findViewById(R.id.buttonBackFromGroup)
        chatLogScroll = findViewById(R.id.scrollGroupChatLog)
        chatLog = findViewById(R.id.textGroupChatLog)

        titleText.text = groupName
        messageInput.doAfterTextChanged { syncActions() }
        sendButton.setOnClickListener {
            lifecycleScope.launch { runAction("Send group message") { sendGroupMessage() } }
        }
        syncButton.setOnClickListener { syncGroupMessages() }
        infoButton.setOnClickListener { showGroupInfo() }
        backButton.setOnClickListener { finish() }

        if (!groupMessagingSupported) {
            renderUnavailableState()
            return
        }

        renderChatLog()
        refreshMeta()
        syncActions()
    }

    override fun onResume() {
        super.onResume()
        if (!groupMessagingSupported) {
            return
        }
        renderChatLog()
        refreshMeta()
    }

    private fun renderUnavailableState() {
        titleText.text = groupName
        messageInput.setText("")
        messageInput.hint = "Group messaging unavailable"
        messageInput.isEnabled = false
        sendButton.isEnabled = false
        syncButton.isEnabled = false
        infoButton.isEnabled = false
        chatLog.text = "This build supports direct private messaging only."
        metaText.text = "Group messaging is disabled pending a private group design."
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
        metaText.text = "Group: $groupId\nSigned in as ${setup.userId}"
    }

    private fun syncActions() {
        val hasText = messageInput.text.toString().isNotBlank()
        sendButton.isEnabled = hasText && !syncInFlight
        syncButton.isEnabled = !syncInFlight
    }

    private suspend fun sendGroupMessage() {
        val setup = store.loadSetup()
        val text = messageInput.text.toString().trim()
        require(text.isNotBlank()) { "message is empty" }

        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
            deviceId = setup.deviceId,
        )
        val keysJson = MessagingCoordinator.ensurePrekeysReplenished(
            store = store,
            api = context.api,
            userId = context.profile.userId,
            keysJson = context.keysJson,
        )

        // Fetch group members and send to each via group relay
        val members = context.api.listGroupMembers(
            groupId = groupId,
            headers = buildGroupMembersListAuthHeaders(
                keysJson = keysJson,
                groupId = groupId,
            ).toHeaderMap(),
        )

        val recipients = members.members
            .filter { it.user_id != context.profile.userId }
            .map { member ->
                val peerUserId = member.user_id
                val existingSession = MessagingCoordinator.loadCompatibleSession(
                    store = store,
                    userId = context.profile.userId,
                    peerUserId = peerUserId,
                    sessionJson = store.readSession(context.profile.userId, peerUserId),
                )
                val sendResult = if (existingSession.isNullOrBlank()) {
                    val bundle = context.api.getBundle(peerUserId)
                    initiateSessionAndEncrypt(
                        keysJson = keysJson,
                        fromUserId = context.profile.userId,
                        peerUserId = peerUserId,
                        peerBundle = bundle.toRustBundle(),
                        plaintextUtf8 = text,
                        suiteOverride = null,
                    )
                } else {
                    encryptWithSession(
                        sessionJson = existingSession,
                        senderUserId = context.profile.userId,
                        peerUserId = peerUserId,
                        plaintextUtf8 = text,
                    )
                }

                store.writeSession(context.profile.userId, peerUserId, sendResult.sessionJson)
                val recipient = GroupRelayRecipient(
                    recipient_user_id = peerUserId,
                    message_bytes_base64 = sendResult.messageBytesBase64,
                )
                Pair(
                    recipient,
                    GroupRelayAuthRecipient(
                        recipientUserId = peerUserId,
                        messageBytesBase64 = sendResult.messageBytesBase64,
                    ),
                )
            }

        require(recipients.isNotEmpty()) { "No other members in group" }

        val relayRecipients = recipients.map { it.first }
        val authRecipients = recipients.map { it.second }
        val relayResult = context.api.relayGroupMessage(
            groupId = groupId,
            headers = buildGroupRelayAuthHeaders(
                keysJson = keysJson,
                groupId = groupId,
                senderUserId = context.profile.userId,
                recipients = authRecipients,
            ).toHeaderMap(),
            request = GroupRelayRequest(
                sender_user_id = context.profile.userId,
                device_id = context.profile.deviceId,
                recipients = relayRecipients,
            ),
        )

        store.appendGroupThreadMessage(
            userId = context.profile.userId,
            groupId = groupId,
            senderUserId = context.profile.userId,
            body = text,
            transportMessageId = relayResult.first_message_id,
        )
        store.upsertGroupConversation(
            userId = context.profile.userId,
            groupId = groupId,
            displayName = groupName,
            memberCount = members.members.size,
            lastPreview = "You: $text",
            incrementUnread = false,
        )
        messageInput.setText("")
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

    private fun showAddMemberDialog(api: PqmsgApi, keysJson: String, userId: String) {
        val input = EditText(this).apply {
            hint = getString(R.string.hint_member_user_id)
        }
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.button_add_member))
            .setView(input)
            .setPositiveButton(getString(R.string.button_add_member)) { _, _ ->
                val memberId = input.text.toString().trim()
                if (memberId.isNotBlank()) {
                    lifecycleScope.launch {
                        runCatching {
                            api.addGroupMember(
                                groupId = groupId,
                                headers = buildGroupMembersAddAuthHeaders(
                                    keysJson = keysJson,
                                    groupId = groupId,
                                    memberUserId = memberId,
                                ).toHeaderMap(),
                                request = AddGroupMemberRequest(member_user_id = memberId),
                            )
                            metaText.text = "Added $memberId to group"
                        }.onFailure {
                            metaText.text = UiErrorMapper.fromThrowable(it, "Add member").headline
                        }
                    }
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun renderChatLog() {
        val setup = store.loadSetup()
        val messages = store.listGroupThreadMessages(setup.userId, groupId)
        chatLog.text = if (messages.isEmpty()) {
            getString(R.string.group_chat_log_empty)
        } else {
            messages.joinToString("\n\n") { msg ->
                val timeLabel = DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(msg.sentAtMillis))
                "$timeLabel\n${msg.body}"
            }
        }
        chatLog.post { chatLogScroll.fullScroll(View.FOCUS_DOWN) }
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
}
