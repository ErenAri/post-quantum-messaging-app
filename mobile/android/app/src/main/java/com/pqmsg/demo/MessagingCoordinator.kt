package com.pqmsg.demo

import android.net.Uri
import com.google.gson.Gson
import org.json.JSONObject
import uniffi.pqmsg_android.Suite
import uniffi.pqmsg_android.buildPrekeysAuthHeaders
import uniffi.pqmsg_android.buildPrekeysStatusAuthHeaders
import uniffi.pqmsg_android.buildPublishPrekeysPayload
import uniffi.pqmsg_android.buildPushTokenAuthHeaders
import uniffi.pqmsg_android.buildRegisterPayload
import uniffi.pqmsg_android.buildSealedInboxAuthHeaders
import uniffi.pqmsg_android.buildUserGroupsListAuthHeaders
import uniffi.pqmsg_android.decryptMessage
import uniffi.pqmsg_android.generateIdentityKeys
import uniffi.pqmsg_android.loadUserProfile
import uniffi.pqmsg_android.openSealedMessageWithSenderCert
import uniffi.pqmsg_android.replenishOneTimePrekeys
import uniffi.pqmsg_android.verifyTransparencyProof
import java.security.MessageDigest
import java.util.Base64

data class ReadyMessagingContext(
    val serverUrl: String,
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
    val inviteToken: String? = null,
    val username: String? = null,
)

data class PeerTransparencyStatus(
    val leafVersion: ULong,
    val treeSize: ULong,
    val consistencyVerified: Boolean,
)

object MessagingCoordinator {
    private val gson = Gson()

    private fun normalizePeerUserId(value: String): String {
        return value.trim().removePrefix("@")
    }

    private fun extractQueryParameterFallback(rawValue: String, key: String): String {
        val pattern = Regex("""(?:[?&])${Regex.escape(key)}=([^&#]+)""")
        val encoded = pattern.find(rawValue)?.groupValues?.getOrNull(1).orEmpty()
        return if (encoded.isBlank()) {
            ""
        } else {
            java.net.URLDecoder.decode(encoded, Charsets.UTF_8).trim()
        }
    }

    private fun sessionRequiresRehandshake(
        sessionJson: String,
        requiredPqRatchetInterval: Int,
    ): Boolean {
        return try {
            val parsed = JSONObject(sessionJson)
            val snapshot = parsed.optJSONObject("snapshot") ?: return true
            val pqRatchet = snapshot.optJSONObject("pq_ratchet") ?: return true
            pqRatchet.optInt("interval", -1) != requiredPqRatchetInterval
        } catch (_: Exception) {
            true
        }
    }

    fun loadCompatibleSession(
        store: LocalStateStore,
        userId: String,
        peerUserId: String,
        sessionJson: String?,
        requiredPqRatchetInterval: Int,
    ): String? {
        if (sessionJson.isNullOrBlank()) {
            return null
        }
        if (!sessionRequiresRehandshake(sessionJson, requiredPqRatchetInterval)) {
            return sessionJson
        }
        store.clearSession(userId, peerUserId)
        return null
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
                    identity_pq_sig_pub = payload.identityPqSigPub,
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
                    pq_sig_over_spk = payload.pqSigOverSpk,
                    pq_sig_over_pqspk = payload.pqSigOverPqspk,
                    one_time_prekeys_x25519 = payload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768 = payload.oneTimePrekeysMlkem768,
                ),
            )
            progress = progress.afterPrekeysPublished()
            store.saveProgress(normalizedUser, progress)
            onStep?.invoke("Prekeys published")
        }

        if (!progress.serverVerified) {
            val sealedCursor = store.readSealedCursor(normalizedUser)
            api.sealedInbox(
                normalizedUser,
                buildSealedInboxAuthHeaders(
                    keysJson = readyKeysJson,
                    userId = normalizedUser,
                    since = sealedCursor,
                ).toHeaderMap(),
                sealedCursor,
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
            serverUrl = normalizedServer,
            keysJson = readyKeysJson,
            profile = readyProfile,
            api = api,
            capabilities = capabilities,
        )
    }

    internal fun transparencyProofMatchesIdentityPin(
        peerUserId: String,
        proof: TransparencyProofResponse,
        pin: IdentityPin,
    ): Boolean {
        if (proof.user_id != peerUserId || proof.leaf.user_id != peerUserId) {
            return false
        }
        return proof.leaf.version.toInt() == pin.identityKeyVersion &&
            proof.leaf.identity_x25519_pub == pin.identityX25519Pub &&
            proof.leaf.identity_sig_pub == pin.identitySigPub &&
            (proof.leaf.identity_pq_sig_pub ?: "") == pin.identityPqSigPub
    }

    internal fun transparencyLeafFingerprint(leaf: TransparencyLeafRecord): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(Base64.getDecoder().decode(leaf.identity_x25519_pub))
        val pqSig = leaf.identity_pq_sig_pub?.trim().orEmpty()
        if (pqSig.isNotBlank()) {
            digest.update(Base64.getDecoder().decode(pqSig))
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    internal fun bundleIdentityFingerprint(bundle: BundleResponse): String {
        val fromServer = bundle.identity_fingerprint_sha256?.trim()?.lowercase()
        if (!fromServer.isNullOrEmpty()) {
            return fromServer
        }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(Base64.getDecoder().decode(bundle.identity_x25519_pub))
        bundle.identity_pq_sig_pub
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?.let { digest.update(Base64.getDecoder().decode(it)) }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private suspend fun ensurePeerIdentityPinForTransparency(
        store: LocalStateStore,
        context: ReadyMessagingContext,
        peerUserId: String,
        bundleOverride: BundleResponse? = null,
    ): IdentityPin {
        val existing = store.readIdentityPin(context.profile.userId, peerUserId)
        if (existing?.identityPqSigPub?.isNotBlank() == true) {
            return existing
        }
        val bundle = bundleOverride ?: context.api.getBundle(peerUserId)
        val observed = IdentityPin(
            fingerprintSha256 = bundleIdentityFingerprint(bundle),
            identityKeyVersion = bundle.identity_key_version ?: 1,
            identityX25519Pub = bundle.identity_x25519_pub,
            identitySigPub = bundle.identity_sig_pub,
            identityPqSigPub = bundle.identity_pq_sig_pub,
            observedAt = bundle.bundle_generated_at,
        )
        if (existing != null && existing.fingerprintSha256.trim().lowercase() != observed.fingerprintSha256) {
            error("identity key changed for $peerUserId; transparency check blocked")
        }
        if (existing != observed) {
            store.writeIdentityPin(context.profile.userId, peerUserId, observed)
        }
        return observed
    }

    suspend fun ensurePeerTransparencyVerified(
        store: LocalStateStore,
        context: ReadyMessagingContext,
        peerUserId: String,
        bundleOverride: BundleResponse? = null,
    ): PeerTransparencyStatus {
        val pin = ensurePeerIdentityPinForTransparency(
            store = store,
            context = context,
            peerUserId = peerUserId,
            bundleOverride = bundleOverride,
        )
        val previousCheckpointJson = store.readTransparencyCheckpoint(context.serverUrl, peerUserId)
        val previousTreeSize = previousCheckpointJson?.let {
            runCatching {
                gson.fromJson(it, TransparencySignedTreeHeadResponse::class.java).tree_size
            }.getOrNull()
        }
        val proof = context.api.getTransparencyProof(
            userId = peerUserId,
            previousTreeSize = previousTreeSize,
        )
        check(proof.user_id == peerUserId) {
            "transparency proof response user mismatch: expected '$peerUserId' got '${proof.user_id}'"
        }
        val verification = verifyTransparencyProof(
            gson.toJson(proof),
            context.capabilities.transparency_log_issuer_ed25519_pub,
            previousCheckpointJson,
        )
        check(verification.leafUserId == peerUserId) {
            "transparency proof leaf mismatch: expected '$peerUserId' got '${verification.leafUserId}'"
        }
        check(transparencyProofMatchesIdentityPin(peerUserId, proof, pin)) {
            "transparency proof does not match the pinned hybrid identity for $peerUserId"
        }
        store.writeTransparencyCheckpoint(
            context.serverUrl,
            peerUserId,
            gson.toJson(proof.signed_tree_head),
        )
        return PeerTransparencyStatus(
            leafVersion = verification.leafVersion,
            treeSize = verification.treeSize,
            consistencyVerified = verification.consistencyVerified,
        )
    }

    suspend fun syncInbox(
        store: LocalStateStore,
        serverUrl: String,
        userId: String,
        suiteLabel: String,
        activePeer: String? = null,
        activeGroup: String? = null,
    ): SyncOutcome {
        val context = ensureReady(
            store = store,
            serverUrl = serverUrl,
            userId = userId,
            suiteLabel = suiteLabel,
        )
        val discoveredGroups = if (context.capabilities.group_messaging_supported) {
            syncUserGroups(store, context)
        } else {
            0
        }
        val activePeerId = activePeer?.trim().orEmpty()
        val activeGroupId = activeGroup?.trim().orEmpty()
        val knownPeers = store.listConversations(context.profile.userId)
            .mapTo(mutableSetOf()) { it.peerUserId }
        val transparencyVerifiedPeers = mutableSetOf<String>()
        var deliveredMessages = 0
        var pendingRequests = 0
        var workingKeysJson = context.keysJson
        var sealedCursor = store.readSealedCursor(context.profile.userId)
        val sealedInbox = context.api.sealedInbox(
            context.profile.userId,
            buildSealedInboxAuthHeaders(
                keysJson = context.keysJson,
                userId = context.profile.userId,
                since = sealedCursor,
            ).toHeaderMap(),
            sealedCursor,
        )

        if (sealedInbox.messages.isEmpty()) {
            return SyncOutcome(
                deliveredMessages = 0,
                pendingRequests = 0,
                discoveredGroups = discoveredGroups,
            )
        }

        workingKeysJson = ensurePrekeysReplenished(
            store = store,
            api = context.api,
            userId = context.profile.userId,
            keysJson = context.keysJson,
        )
        for (item in sealedInbox.messages) {
            val openedTransport = openSealedMessageWithSenderCert(
                keysJson = workingKeysJson,
                senderIdentityX25519Pub = item.sender_identity_x25519_pub,
                sealedMessageBytesBase64 = item.message_bytes_base64,
                serverIssuerEd25519Pub =
                    context.capabilities.sender_certificate_issuer_ed25519_pub,
            )
            val peer = openedTransport.senderUserId
            val peerLastMessageId = store.readPeerLastMessageId(context.profile.userId, peer)
            if (item.message_id <= peerLastMessageId) {
                sealedCursor = maxOf(sealedCursor, item.message_id)
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
                sealedCursor = maxOf(sealedCursor, item.message_id)
                continue
            }

            val existingSession = loadCompatibleSession(
                store = store,
                userId = context.profile.userId,
                peerUserId = peer,
                sessionJson = store.readSession(context.profile.userId, peer),
                requiredPqRatchetInterval = context.capabilities.pq_ratchet_interval,
            )
            if (transparencyVerifiedPeers.add(peer)) {
                ensurePeerTransparencyVerified(
                    store = store,
                    context = context,
                    peerUserId = peer,
                )
            }
            val result = decryptMessage(
                keysJson = workingKeysJson,
                recipientUserId = context.profile.userId,
                senderUserId = peer,
                messageBytesBase64 = openedTransport.payloadMessageBytesBase64,
                existingSessionJson = existingSession,
            )
            store.writeSession(context.profile.userId, peer, result.sessionJson)
            val privateGroupMessage = decodePrivateGroupMessage(
                plaintext = result.plaintextUtf8,
                senderUserId = peer,
                store = store,
                localUserId = context.profile.userId,
            )
            val isWrappedPrivateGroup = result.plaintextUtf8.startsWith(PRIVATE_GROUP_MESSAGE_PREFIX)
            if (privateGroupMessage != null) {
                val localGroupState = store.readPrivateGroupState(
                    context.profile.userId,
                    privateGroupMessage.groupId,
                ) ?: error("Private-group state is unavailable for ${privateGroupMessage.groupId}")
                val state = parsePrivateGroupStateJson(localGroupState.stateJson)
                store.appendGroupThreadMessage(
                    userId = context.profile.userId,
                    groupId = privateGroupMessage.groupId,
                    senderUserId = peer,
                    body = privateGroupMessage.body,
                    transportMessageId = item.message_id,
                )
                store.upsertGroupConversation(
                    userId = context.profile.userId,
                    groupId = privateGroupMessage.groupId,
                    displayName = getPrivateGroupTitle(state),
                    memberCount = state.members.size,
                    lastPreview = "${peer}: ${privateGroupMessage.body}",
                    incrementUnread = privateGroupMessage.groupId != activeGroupId,
                )
                if (privateGroupMessage.groupId == activeGroupId) {
                    store.markGroupRead(context.profile.userId, privateGroupMessage.groupId)
                }
                deliveredMessages += 1
            } else if (!isWrappedPrivateGroup) {
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
            sealedCursor = maxOf(sealedCursor, item.message_id)
            workingKeysJson = store.readKeys(context.profile.userId) ?: workingKeysJson
        }
        store.writeSealedCursor(context.profile.userId, sealedCursor)
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
                    pq_sig_over_spk = payload.pqSigOverSpk,
                    pq_sig_over_pqspk = payload.pqSigOverPqspk,
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

    fun buildInviteLink(serverUrl: String, inviteToken: String): String {
        return Uri.Builder()
            .scheme("pqmsg")
            .authority("chat")
            .appendQueryParameter("token", inviteToken.trim())
            .appendQueryParameter("server", ApiClientFactory.normalizeBaseUrl(serverUrl).trimEnd('/'))
            .build()
            .toString()
    }

    suspend fun resolvePeerUserId(api: PqmsgApi, target: ComposeTarget): String {
        val inviteToken = target.inviteToken?.trim().orEmpty()
        return if (inviteToken.isNotBlank()) {
            normalizePeerUserId(api.resolveContactInvite(inviteToken).user_id)
        } else if (!target.username.isNullOrBlank()) {
            normalizePeerUserId(api.resolveUsername(target.username.trim()).user_id)
        } else {
            normalizePeerUserId(target.peerUserId)
        }
    }

    fun parseComposeTarget(input: String, fallbackServerUrl: String): ComposeTarget {
        val trimmed = input.trim()
        require(trimmed.isNotBlank()) { "username or invite is empty" }
        val webInviteToken = extractQueryParameterFallback(trimmed, "invite_token")
            .ifBlank { extractQueryParameterFallback(trimmed, "token") }
        if (webInviteToken.isNotBlank()) {
            val inviteServer = extractQueryParameterFallback(trimmed, "server")
            val resolvedInviteServer = if (inviteServer.isBlank()) fallbackServerUrl else inviteServer
            return ComposeTarget(
                peerUserId = "",
                serverUrl = ApiClientFactory.normalizeBaseUrl(resolvedInviteServer),
                inviteToken = webInviteToken,
            )
        }
        val webInvitePeer = normalizePeerUserId(extractQueryParameterFallback(trimmed, "invite"))
        if (webInvitePeer.isNotBlank()) {
            val inviteServer = extractQueryParameterFallback(trimmed, "server")
            val resolvedInviteServer = if (inviteServer.isBlank()) fallbackServerUrl else inviteServer
            val normalizedUsername = webInvitePeer.takeIf {
                extractQueryParameterFallback(trimmed, "invite").trim().startsWith("@")
            }
            return ComposeTarget(
                peerUserId = if (normalizedUsername == null) webInvitePeer else "",
                serverUrl = ApiClientFactory.normalizeBaseUrl(resolvedInviteServer),
                username = normalizedUsername,
            )
        }
        val parsed = runCatching { Uri.parse(trimmed) }.getOrNull()
        if (parsed != null) {
            val inviteToken = parsed.getQueryParameter("invite_token")?.trim().orEmpty().ifBlank {
                parsed.getQueryParameter("token")?.trim().orEmpty()
            }
            if (inviteToken.isNotBlank()) {
                val inviteServer = parsed.getQueryParameter("server")?.trim().orEmpty().ifBlank {
                    extractQueryParameterFallback(trimmed, "server")
                }
                val resolvedInviteServer = if (inviteServer.isBlank()) fallbackServerUrl else inviteServer
                return ComposeTarget(
                    peerUserId = "",
                    serverUrl = ApiClientFactory.normalizeBaseUrl(resolvedInviteServer),
                    inviteToken = inviteToken,
                )
            }
            val invitePeer = normalizePeerUserId(
                parsed.getQueryParameter("invite").orEmpty().ifBlank {
                    extractQueryParameterFallback(trimmed, "invite")
                },
            )
            if (invitePeer.isNotBlank()) {
                val inviteServer = parsed.getQueryParameter("server")?.trim().orEmpty().ifBlank {
                    extractQueryParameterFallback(trimmed, "server")
                }
                val resolvedInviteServer = if (inviteServer.isBlank()) fallbackServerUrl else inviteServer
                val normalizedUsername = invitePeer.takeIf {
                    parsed.getQueryParameter("invite")?.trim().orEmpty().startsWith("@") ||
                        extractQueryParameterFallback(trimmed, "invite").startsWith("@")
                }
                return ComposeTarget(
                    peerUserId = if (normalizedUsername == null) invitePeer else "",
                    serverUrl = ApiClientFactory.normalizeBaseUrl(resolvedInviteServer),
                    username = normalizedUsername,
                )
            }
        }
        if (parsed != null && parsed.scheme == "pqmsg") {
            val peer = normalizePeerUserId(parsed.getQueryParameter("user").orEmpty())
            val inviteToken = parsed.getQueryParameter("token")?.trim().orEmpty()
            val server = parsed.getQueryParameter("server")?.trim().orEmpty()
            require(peer.isNotBlank() || inviteToken.isNotBlank()) { "invite is missing target" }
            val resolvedServer = if (server.isBlank()) fallbackServerUrl else server
            return ComposeTarget(
                peerUserId = peer,
                serverUrl = ApiClientFactory.normalizeBaseUrl(resolvedServer),
                inviteToken = inviteToken.ifBlank { null },
            )
        }
        val normalizedUsername = trimmed.removePrefix("@").trim().takeIf {
            trimmed.startsWith("@") && it.isNotBlank()
        }
        val peerUserId = if (normalizedUsername == null) normalizePeerUserId(trimmed) else ""
        require(peerUserId.isNotBlank() || !normalizedUsername.isNullOrBlank()) {
            "username or invite is empty"
        }
        return ComposeTarget(
            peerUserId = peerUserId,
            serverUrl = ApiClientFactory.normalizeBaseUrl(fallbackServerUrl),
            username = normalizedUsername,
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
