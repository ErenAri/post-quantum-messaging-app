package com.pqmsg.demo

import android.content.Intent
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
import java.security.MessageDigest
import java.util.Base64
import java.text.DateFormat
import java.util.Date

class GroupChatActivity : AppCompatActivity() {
    private val gson = Gson()
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
    private var privateGroupState: PrivateGroupState? = null
    private var privateGroupCredential: PrivateGroupMemberCredential? = null
    private var localStoreAvailable = true

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

        reloadPrivateGroupState()
        titleText.text = privateGroupState?.let { getPrivateGroupTitle(it, groupName) } ?: groupName
        messageInput.doAfterTextChanged { syncActions() }
        sendButton.setOnClickListener {
            lifecycleScope.launch { runAction("Send group message") { sendGroupMessage() } }
        }
        syncButton.setOnClickListener { syncGroupMessages() }
        infoButton.setOnClickListener { showGroupInfo() }
        backButton.setOnClickListener { finish() }

        if (privateGroupState == null || privateGroupCredential == null) {
            renderUnavailableState()
            return
        }

        renderChatLog()
        refreshMeta()
        syncActions()
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
        titleText.text = groupName
        messageInput.setText("")
        messageInput.hint = "Private-group state unavailable"
        messageInput.isEnabled = false
        sendButton.isEnabled = false
        syncButton.isEnabled = true
        infoButton.isEnabled = false
        chatLog.text = "This device does not have the local opaque state needed to open this private group."
        metaText.text = "Open the group from an invite link or a device that already has the current epoch state."
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

    private fun syncActions() {
        val hasText = messageInput.text.toString().isNotBlank()
        sendButton.isEnabled =
            hasText && !syncInFlight && localStoreAvailable && privateGroupState != null && privateGroupCredential != null
        syncButton.isEnabled = !syncInFlight && localStoreAvailable
        infoButton.isEnabled = localStoreAvailable && privateGroupState != null && privateGroupCredential != null
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
        require(text.isNotBlank()) { "message is empty" }

        val context = MessagingCoordinator.ensureReady(
            store = store,
            serverUrl = setup.serverUrl,
            userId = setup.userId,
            suiteLabel = setup.suiteLabel,
            deviceId = setup.deviceId,
        )
        requirePrivateGroupMessagingEnabled(context)
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
            body = text,
        )
        val publishResponse = context.api.publishPrivateGroupMessage(
            PublishPrivateGroupMessageRequest(
                group_id = encryptedMessage.group_id,
                epoch = encryptedMessage.epoch,
                sender_user_id = encryptedMessage.sender_user_id,
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
            body = text,
            sentAtMillis = encryptedMessage.sent_at_unix_ms,
            transportMessageId = publishResponse.message_id,
        )
        store.upsertGroupConversation(
            userId = context.profile.userId,
            groupId = groupId,
            displayName = getPrivateGroupTitle(state, groupName),
            memberCount = state.members.size,
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
            .apply {
                if (canManage) {
                    setNeutralButton(getString(R.string.button_add_member)) { _, _ ->
                        showAddMemberDialog()
                    }
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
            chatLog.text = if (messages.isEmpty()) {
                getString(R.string.group_chat_log_empty)
            } else {
                messages.joinToString("\n\n") { msg ->
                    val timeLabel = DateFormat.getTimeInstance(DateFormat.SHORT)
                        .format(Date(msg.sentAtMillis))
                    "$timeLabel\n${msg.body}"
                }
            }
            chatLog.post { chatLogScroll.fullScroll(View.FOCUS_DOWN) }
        }.onFailure {
            localStoreAvailable = false
            metaText.text = UiErrorMapper.fromThrowable(it, "Open local secure state").headline
            chatLog.text =
                "Local encrypted group history is unavailable on this device.\nRe-import the current group state from a linked device or fully reprovision this device."
        }
        syncActions()
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
