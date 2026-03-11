package com.pqmsg.demo

import android.net.Uri
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.buildInboxAuthHeaders
import uniffi.pqmsg_android.buildPrekeysAuthHeaders
import uniffi.pqmsg_android.buildPrekeysStatusAuthHeaders
import uniffi.pqmsg_android.buildPublishPrekeysPayload
import uniffi.pqmsg_android.buildPushTokenAuthHeaders
import uniffi.pqmsg_android.buildRegisterPayload
import uniffi.pqmsg_android.buildUserGroupsListAuthHeaders
import uniffi.pqmsg_android.decryptMessage
import uniffi.pqmsg_android.generateIdentityKeys
import uniffi.pqmsg_android.loadUserProfile
import uniffi.pqmsg_android.replenishOneTimePrekeys
import java.security.MessageDigest

data class ReadyMessagingContext(
    val keysJson: String,
    val profile: uniffi.pqmsg_android.UserProfile,
    val api: PqmsgApi,
    val capabilities: ServerCapabilitiesResponse,
)

data class SyncOutcome(
    val deliveredMessages: Int,
    val pendingRequests: Int,
    val discoveredGroups: Int,
)

data class ComposeTarget(
    val peerUserId: String,
    val serverUrl: String,
)

object MessagingCoordinator {
    private fun normalizePeerUserId(value: String): String {
        return value.trim().removePrefix("@")
    }

    suspend fun ensureReady(
        store: LocalStateStore,
        serverUrl: String,
        userId: String,
        suiteLabel: String,
        deviceId: String = "",
        pushToken: String = "",
        onStep: ((String) -> Unit)? = null,
    ): ReadyMessagingContext {
        val normalizedServer = ApiClientFactory.normalizeBaseUrl(serverUrl)
        val normalizedUser = userId.trim()
        require(normalizedUser.isNotBlank()) { "user id is empty" }

        var progress = store.loadProgress(normalizedUser)
        var keysJson = store.readKeys(normalizedUser)
        var profile = keysJson?.let { runCatching { loadUserProfile(it) }.getOrNull() }
        val normalizedSuite = normalizeSuiteLabel(suiteLabel)

        if (profile == null || profile.userId != normalizedUser) {
            keysJson = generateIdentityKeys(
                normalizedUser,
                normalizedDeviceId(normalizedUser, deviceId),
                parseSuite(normalizedSuite),
                16u,
            )
            store.writeKeys(normalizedUser, keysJson)
            profile = loadUserProfile(keysJson)
            progress = SetupProgress().afterKeysGenerated()
            store.saveProgress(normalizedUser, progress)
            onStep?.invoke("Secure identity created")
        } else if (!progress.keysGenerated) {
            progress = progress.afterKeysGenerated()
            store.saveProgress(normalizedUser, progress)
        }

        val readyKeysJson = requireNotNull(keysJson) { "identity keys were not initialized" }
        val readyProfile = requireNotNull(profile) { "user profile was not initialized" }

        val api = ApiClientFactory.create(normalizedServer)
        val capabilities = api.getCapabilities()
        ApiClientFactory.validateCapabilities(capabilities, normalizedSuite)

        if (!progress.userRegistered) {
            val payload = buildRegisterPayload(readyKeysJson)
            api.registerUser(
                RegisterUserRequest(
                    user_id = payload.userId,
                    identity_x25519_pub = payload.identityX25519Pub,
                    identity_sig_pub = payload.identitySigPub,
                    device_id = payload.deviceId,
                ),
            )
            progress = progress.afterUserRegistered()
            store.saveProgress(normalizedUser, progress)
            onStep?.invoke("Profile registered with relay")
        }

        if (!progress.prekeysPublished) {
            val payload = buildPublishPrekeysPayload(readyKeysJson)
            api.publishPrekeys(
                normalizedUser,
                buildPrekeysAuthHeaders(readyKeysJson, normalizedUser).toHeaderMap(),
                PublishPrekeysRequest(
                    signed_prekey_x25519_pub = payload.signedPrekeyX25519Pub,
                    sig_over_spk = payload.sigOverSpk,
                    pq_signed_prekey_pub_mlkem768 = payload.pqSignedPrekeyPubMlkem768,
                    sig_over_pqspk = payload.sigOverPqspk,
                    one_time_prekeys_x25519 = payload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768 = payload.oneTimePrekeysMlkem768,
                ),
            )
            progress = progress.afterPrekeysPublished()
            store.saveProgress(normalizedUser, progress)
            onStep?.invoke("Prekeys published")
        }

        if (!progress.serverVerified) {
            api.inbox(
                normalizedUser,
                buildInboxAuthHeaders(
                    keysJson = readyKeysJson,
                    userId = normalizedUser,
                    since = store.readCursor(normalizedUser),
                ).toHeaderMap(),
                store.readCursor(normalizedUser),
            )
            val cleanPushToken = pushToken.trim()
            if (cleanPushToken.isNotEmpty()) {
                api.registerPushToken(
                    userId = normalizedUser,
                    headers = buildPushTokenAuthHeaders(
                        keysJson = readyKeysJson,
                        userId = normalizedUser,
                        fcmToken = cleanPushToken,
                    ).toHeaderMap(),
                    request = RegisterPushTokenRequest(
                        device_id = readyProfile.deviceId,
                        provider = "fcm",
                        token = cleanPushToken,
                        fcm_token = null,
                    ),
                )
            }
            progress = progress.afterServerVerified()
            store.saveProgress(normalizedUser, progress)
            onStep?.invoke("Profile verified")
        }

        val existingSetup = store.loadSetup()
        store.saveSetup(
            existingSetup.copy(
                serverUrl = normalizedServer,
                userId = normalizedUser,
                deviceId = readyProfile.deviceId,
                suiteLabel = normalizeSuiteLabel(suiteLabelFor(readyProfile.suite)),
            ),
        )

        return ReadyMessagingContext(
            keysJson = readyKeysJson,
            profile = readyProfile,
            api = api,
            capabilities = capabilities,
        )
    }

    suspend fun syncInbox(
        store: LocalStateStore,
        serverUrl: String,
        userId: String,
        suiteLabel: String,
        activePeer: String? = null,
    ): SyncOutcome {
        val context = ensureReady(
            store = store,
            serverUrl = serverUrl,
            userId = userId,
            suiteLabel = suiteLabel,
        )
        val discoveredGroups = syncUserGroups(store, context)
        val activePeerId = activePeer?.trim().orEmpty()
        val knownPeers = store.listConversations(context.profile.userId)
            .mapTo(mutableSetOf()) { it.peerUserId }
        var cursor = store.readCursor(context.profile.userId)
        val inbox = context.api.inbox(
            context.profile.userId,
            buildInboxAuthHeaders(
                keysJson = context.keysJson,
                userId = context.profile.userId,
                since = cursor,
            ).toHeaderMap(),
            cursor,
        )

        if (inbox.messages.isEmpty()) {
            return SyncOutcome(
                deliveredMessages = 0,
                pendingRequests = 0,
                discoveredGroups = discoveredGroups,
            )
        }

        var deliveredMessages = 0
        var pendingRequests = 0
        var workingKeysJson = ensurePrekeysReplenished(
            store = store,
            api = context.api,
            userId = context.profile.userId,
            keysJson = context.keysJson,
        )
        for (item in inbox.messages) {
            val peer = item.sender_user_id
            val peerLastMessageId = store.readPeerLastMessageId(context.profile.userId, peer)
            if (item.message_id <= peerLastMessageId) {
                cursor = maxOf(cursor, item.message_id)
                continue
            }
            val cipherHash = sha256Hex(item.message_bytes_base64)
            val seenCipherHashes = store.readPeerSeenCipherHashes(context.profile.userId, peer)
            if (seenCipherHashes.contains(cipherHash)) {
                store.writePeerLastMessageId(
                    context.profile.userId,
                    peer,
                    maxOf(peerLastMessageId, item.message_id),
                )
                cursor = maxOf(cursor, item.message_id)
                continue
            }

            val existingSession = store.readSession(context.profile.userId, peer)
            val result = decryptMessage(
                keysJson = workingKeysJson,
                recipientUserId = context.profile.userId,
                senderUserId = peer,
                messageBytesBase64 = item.message_bytes_base64,
                existingSessionJson = existingSession,
            )
            store.writeSession(context.profile.userId, peer, result.sessionJson)
            val rendered = renderInboundPreview(result.plaintextUtf8)
            store.appendThreadMessage(
                userId = context.profile.userId,
                peerUserId = peer,
                direction = "inbound",
                body = rendered,
                transportMessageId = item.message_id,
            )
            val isAcceptedPeer =
                peer == activePeerId ||
                    knownPeers.contains(peer) ||
                    store.isAcceptedPeer(context.profile.userId, peer)
            if (isAcceptedPeer) {
                store.markPeerAccepted(context.profile.userId, peer)
                store.upsertConversation(
                    userId = context.profile.userId,
                    peerUserId = peer,
                    lastPreview = "$peer: $rendered",
                    incrementUnread = peer != activePeerId,
                )
                if (peer == activePeerId) {
                    store.markConversationRead(context.profile.userId, peer)
                }
                knownPeers.add(peer)
                deliveredMessages += 1
            } else {
                store.upsertMessageRequest(
                    userId = context.profile.userId,
                    peerUserId = peer,
                    lastPreview = "$peer: $rendered",
                )
                pendingRequests += 1
            }

            seenCipherHashes.add(cipherHash)
            while (seenCipherHashes.size > 512) {
                val first = seenCipherHashes.firstOrNull() ?: break
                seenCipherHashes.remove(first)
            }
            store.writePeerSeenCipherHashes(context.profile.userId, peer, seenCipherHashes)
            store.writePeerLastMessageId(
                context.profile.userId,
                peer,
                maxOf(peerLastMessageId, item.message_id),
            )
            cursor = maxOf(cursor, item.message_id)
            workingKeysJson = store.readKeys(context.profile.userId) ?: workingKeysJson
        }

        store.writeCursor(context.profile.userId, cursor)
        return SyncOutcome(
            deliveredMessages = deliveredMessages,
            pendingRequests = pendingRequests,
            discoveredGroups = discoveredGroups,
        )
    }

    private suspend fun syncUserGroups(
        store: LocalStateStore,
        context: ReadyMessagingContext,
    ): Int {
        val response = context.api.listUserGroups(
            context.profile.userId,
            buildUserGroupsListAuthHeaders(
                keysJson = context.keysJson,
                userId = context.profile.userId,
            ).toHeaderMap(),
        )
        val existing = store.listGroups(context.profile.userId)
            .associateBy { it.groupId }
        var discoveredGroups = 0
        for (group in response.groups) {
            if (existing.containsKey(group.group_id)) {
                continue
            }
            store.upsertGroupConversation(
                userId = context.profile.userId,
                groupId = group.group_id,
                displayName = group.group_id,
                memberCount = group.member_count,
                lastPreview =
                    if (group.owner_user_id == context.profile.userId) {
                        "Group created"
                    } else {
                        "You were added to a group"
                    },
                incrementUnread = false,
            )
            discoveredGroups += 1
        }
        return discoveredGroups
    }

    suspend fun ensurePrekeysReplenished(
        store: LocalStateStore,
        api: PqmsgApi,
        userId: String,
        keysJson: String,
    ): String {
        return runCatching {
            val status = api.prekeysStatus(
                userId,
                buildPrekeysStatusAuthHeaders(keysJson = keysJson, userId = userId).toHeaderMap(),
            )
            if (!status.low_one_time_prekeys) {
                return@runCatching keysJson
            }
            val target = maxOf(status.minimum_recommended_one_time_prekeys, 16)
            val refreshedKeysJson = replenishOneTimePrekeys(keysJson, target.toUInt())
            val payload = buildPublishPrekeysPayload(refreshedKeysJson)
            api.publishPrekeys(
                userId,
                buildPrekeysAuthHeaders(refreshedKeysJson, userId).toHeaderMap(),
                PublishPrekeysRequest(
                    signed_prekey_x25519_pub = payload.signedPrekeyX25519Pub,
                    sig_over_spk = payload.sigOverSpk,
                    pq_signed_prekey_pub_mlkem768 = payload.pqSignedPrekeyPubMlkem768,
                    sig_over_pqspk = payload.sigOverPqspk,
                    one_time_prekeys_x25519 = payload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768 = payload.oneTimePrekeysMlkem768,
                ),
            )
            store.writeKeys(userId, refreshedKeysJson)
            refreshedKeysJson
        }.getOrElse {
            keysJson
        }
    }

    fun buildInviteLink(serverUrl: String, userId: String): String {
        return Uri.Builder()
            .scheme("pqmsg")
            .authority("chat")
            .appendQueryParameter("user", userId.trim())
            .appendQueryParameter("server", ApiClientFactory.normalizeBaseUrl(serverUrl).trimEnd('/'))
            .build()
            .toString()
    }

    fun parseComposeTarget(input: String, fallbackServerUrl: String): ComposeTarget {
        val trimmed = input.trim()
        require(trimmed.isNotBlank()) { "username or invite is empty" }
        val parsed = runCatching { Uri.parse(trimmed) }.getOrNull()
        if (parsed != null && parsed.scheme == "pqmsg") {
            val peer = normalizePeerUserId(parsed.getQueryParameter("user").orEmpty())
            val server = parsed.getQueryParameter("server")?.trim().orEmpty()
            require(peer.isNotBlank()) { "invite is missing user" }
            val resolvedServer = if (server.isBlank()) fallbackServerUrl else server
            return ComposeTarget(
                peerUserId = peer,
                serverUrl = ApiClientFactory.normalizeBaseUrl(resolvedServer),
            )
        }
        val peerUserId = normalizePeerUserId(trimmed)
        require(peerUserId.isNotBlank()) { "username or invite is empty" }
        return ComposeTarget(
            peerUserId = peerUserId,
            serverUrl = ApiClientFactory.normalizeBaseUrl(fallbackServerUrl),
        )
    }

    fun normalizeSuiteLabel(label: String): String {
        return if (label.trim().equals("kyber768", ignoreCase = true)) {
            "kyber768"
        } else {
            "ml-kem-768"
        }
    }

    fun normalizedDeviceId(userId: String, deviceId: String): String {
        return if (deviceId.trim().isNotBlank()) {
            deviceId.trim()
        } else {
            "${userId.trim()}-android-1"
        }
    }

    private fun parseSuite(label: String): Suite {
        return if (label.equals("kyber768", ignoreCase = true)) {
            Suite.KYBER768
        } else {
            Suite.ML_KEM768
        }
    }

    private fun suiteLabelFor(suite: Suite): String {
        return if (suite == Suite.KYBER768) {
            "kyber768"
        } else {
            "ml-kem-768"
        }
    }

    private fun renderInboundPreview(plaintext: String): String {
        val decoded = MessageEnvelopeCodec.decodeMediaEnvelope(plaintext) ?: return plaintext
        val mediaTag = "[media:${decoded.fileName} ${decoded.mimeType} ${decoded.byteLength}B]"
        return if (decoded.noteText.isBlank()) {
            mediaTag
        } else {
            "$mediaTag ${decoded.noteText}"
        }
    }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
}
