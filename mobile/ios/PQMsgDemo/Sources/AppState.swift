import Foundation

@MainActor
final class AppState: ObservableObject {
    @Published var setup: SetupConfig
    @Published var progress: SetupProgress
    @Published var statusLine: String
    @Published var errorLine: String
    @Published var conversations: [ConversationSummary]
    @Published var selectedPeer: String
    @Published var chatLog: [String]
    @Published var draftMessage: String
    @Published var cryptoProfile: String
    @Published var serverCapabilitiesSummary: String
    @Published var pinnedIdentities: [IdentityPinRecord]
    @Published var managedDeviceId: String
    @Published var linkedDevices: [DeviceRecord]
    @Published var preparedOnboardingPackage: OnboardingPackageRecord?
    @Published var identityLogEvents: [IdentityLogItem]

    // MARK: - Extended Feature State
    @Published var groups: [GroupSummary]
    @Published var groupChatLog: [String]
    @Published var contacts: [ContactListItem]
    @Published var peerPresenceOnline: Bool
    @Published var peerIsTyping: Bool
    @Published var sealedSenderEnabled: Bool
    @Published var ephemeralTtlSeconds: Int
    @Published var pendingAttachment: PendingAttachmentSelection?

    // MARK: - Call State
    @Published var activeCallId: String?
    @Published var activeCallPeer: String?
    @Published var activeCallType: String?
    @Published var callStatus: String
    @Published var callElapsedSeconds: Int
    @Published var showCallView: Bool
    @Published var isIncomingCall: Bool
    @Published var incomingCallSdpBase64: String?

    private var callPollingTask: Task<Void, Never>?
    private var callTimerTask: Task<Void, Never>?
    private let maxAttachmentBytes = 128 * 1024

    private let store: LocalStateStore
    private var latestBundleByPeer: [String: BundleResponse]
    private var pendingAttachmentDraft: PendingAttachmentDraft?

    init(store: LocalStateStore = .shared) {
        self.store = store
        let loadedSetup = store.loadSetup()
        self.setup = loadedSetup
        self.progress = store.loadProgress(userId: loadedSetup.userId)
        self.statusLine = "Ready"
        self.errorLine = ""
        self.conversations = store.listConversations(userId: loadedSetup.userId)
        self.selectedPeer = loadedSetup.peerUserId
        self.chatLog = []
        self.draftMessage = ""
        self.cryptoProfile = ""
        self.serverCapabilitiesSummary = "Not checked"
        self.pinnedIdentities = store.listIdentityPins(userId: loadedSetup.userId)
        self.managedDeviceId = AppState.defaultManagedDeviceId(for: loadedSetup.userId)
        self.linkedDevices = []
        self.preparedOnboardingPackage = nil
        self.identityLogEvents = []
        self.latestBundleByPeer = [:]
        self.groups = store.listGroups(userId: loadedSetup.userId)
        self.groupChatLog = []
        self.contacts = []
        self.peerPresenceOnline = false
        self.peerIsTyping = false
        self.sealedSenderEnabled = false
        self.ephemeralTtlSeconds = 0
        self.pendingAttachment = nil
        self.activeCallId = nil
        self.activeCallPeer = nil
        self.activeCallType = nil
        self.callStatus = "Idle"
        self.callElapsedSeconds = 0
        self.showCallView = false
        self.isIncomingCall = false
        self.incomingCallSdpBase64 = nil
        self.pendingAttachmentDraft = nil
        refreshSecuritySnapshot()
    }

    func applyPreset(userId: String, peerId: String) {
        setup.userId = userId
        setup.peerUserId = peerId
        draftMessage = ""
        clearPendingAttachment()
        if setup.deviceId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            setup.deviceId = "\(userId)-ios-1"
        }
        progress = store.loadProgress(userId: setup.userId)
        managedDeviceId = Self.defaultManagedDeviceId(for: setup.userId)
        linkedDevices = []
        preparedOnboardingPackage = nil
        identityLogEvents = []
        persistSetup()
        refreshConversations()
        clearError()
    }

    func setServerURL(_ value: String) {
        setup.serverURL = value
        serverCapabilitiesSummary = "Not checked"
        linkedDevices = []
        preparedOnboardingPackage = nil
        identityLogEvents = []
        persistSetup()
    }

    func setUserId(_ value: String) {
        setup.userId = value
        draftMessage = ""
        clearPendingAttachment()
        progress = store.loadProgress(userId: value)
        managedDeviceId = Self.defaultManagedDeviceId(for: value)
        linkedDevices = []
        preparedOnboardingPackage = nil
        identityLogEvents = []
        refreshConversations()
        persistSetup()
    }

    func setDeviceId(_ value: String) {
        setup.deviceId = value
        persistSetup()
    }

    func setSuiteLabel(_ value: String) {
        setup.suiteLabel = value
        persistSetup()
    }

    func setPeerUserId(_ value: String) {
        setup.peerUserId = value
        selectedPeer = value
        persistSetup()
    }

    func generateKeys() async {
        await runSetupAction("Generate identity keys") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            if user.isEmpty {
                throw RustBridgeError.missingKeys("user id is empty")
            }
            let device = normalizedDeviceId(user: user, raw: setup.deviceId)
            let keysJson = try generateIdentityKeys(
                userId: user,
                deviceId: device,
                suite: parseSuite(setup.suiteLabel),
                oneTimeCount: 16
            )
            try store.writeKeys(userId: user, keysJson: keysJson)
            setup.userId = user
            setup.deviceId = device
            progress = progress.afterKeysGenerated()
            store.saveProgress(userId: user, progress: progress)
            persistSetup()
            refreshSecuritySnapshot()
            statusLine = "Generated keys for \(user)"
        }
    }

    func registerUser() async {
        await runSetupAction("Register user") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let payload = try buildRegisterPayload(keysJson: keys)
            let api = try ApiClient(serverURL: setup.serverURL)
            let capabilities = try await api.getCapabilities()
            try validateServerCapabilities(capabilities)
            _ = try await api.registerUser(
                RegisterUserRequest(
                    user_id: payload.userId,
                    identity_x25519_pub: payload.identityX25519Pub,
                    identity_sig_pub: payload.identitySigPub,
                    device_id: payload.deviceId
                )
            )
            progress = progress.afterUserRegistered()
            store.saveProgress(userId: user, progress: progress)
            statusLine = "Registered \(user)"
            clearError()
        }
    }

    func publishPrekeys() async {
        await runSetupAction("Publish prekeys") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let payload = try buildPublishPrekeysPayload(keysJson: keys)
            let authHeaders = try buildPrekeysAuthHeaders(keysJson: keys, userId: user).toHeaderMap()
            let api = try ApiClient(serverURL: setup.serverURL)
            let capabilities = try await api.getCapabilities()
            try validateServerCapabilities(capabilities)
            _ = try await api.publishPrekeys(
                userId: user,
                requestBody: PublishPrekeysRequest(
                    signed_prekey_x25519_pub: payload.signedPrekeyX25519Pub,
                    sig_over_spk: payload.sigOverSpk,
                    pq_signed_prekey_pub_mlkem768: payload.pqSignedPrekeyPubMlkem768,
                    sig_over_pqspk: payload.sigOverPqspk,
                    one_time_prekeys_x25519: payload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768: payload.oneTimePrekeysMlkem768
                ),
                headers: authHeaders
            )
            progress = progress.afterPrekeysPublished()
            store.saveProgress(userId: user, progress: progress)
            persistSetup()
            statusLine = "Published prekeys for \(user)"
            clearError()
        }
    }

    func verifyServer(pushToken: String) async {
        await runSetupAction("Verify server") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let capabilities = try await api.getCapabilities()
            try validateServerCapabilities(capabilities)
            let since = store.readCursor(userId: user)
            let inboxHeaders = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: since).toHeaderMap()
            _ = try await api.inbox(userId: user, since: since, headers: inboxHeaders)
            if !pushToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                let profile = try loadUserProfile(keysJson: keys)
                let pushHeaders = try buildPushTokenAuthHeaders(keysJson: keys, userId: user, fcmToken: pushToken).toHeaderMap()
                _ = try await api.registerPushToken(
                    userId: user,
                    headers: pushHeaders,
                    requestBody: RegisterPushTokenRequest(
                        device_id: profile.deviceId,
                        provider: "apns",
                        token: pushToken,
                        fcm_token: nil
                    )
                )
            }
            progress = progress.afterServerVerified()
            store.saveProgress(userId: user, progress: progress)
            serverCapabilitiesSummary = capabilitySummary(capabilities)
            statusLine = "Server verification completed for \(user)"
            clearError()
        }
    }

    func openConversation(peerUserId: String) {
        let peer = peerUserId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !peer.isEmpty else {
            errorLine = "peer user id is empty"
            return
        }
        if selectedPeer != peer {
            draftMessage = ""
            clearPendingAttachment()
        }
        selectedPeer = peer
        setup.peerUserId = peer
        persistSetup()
        store.markConversationRead(userId: setup.userId, peerUserId: peer)
        refreshConversations()
        clearError()
    }

    func fetchBundle(peerUserId: String) async {
        await runChatAction("Fetch bundle") {
            let peer = peerUserId.trimmingCharacters(in: .whitespacesAndNewlines)
            let api = try ApiClient(serverURL: setup.serverURL)
            let bundle = try await api.getBundle(userId: peer)
            latestBundleByPeer[peer] = bundle
            store.writeBundleFetchedAt(userId: setup.userId, peerUserId: peer, timestamp: bundle.bundle_generated_at)
            store.upsertConversation(
                userId: setup.userId,
                peerUserId: peer,
                lastPreview: "Bundle fetched for \(peer)",
                incrementUnread: false
            )
            refreshConversations()
            appendChatLog("bundle fetched for \(peer)")
            statusLine = "Bundle fetched for \(peer)"
        }
    }

    func sendMessage(peerUserId: String) async {
        await runChatAction("Send message") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let peer = peerUserId.trimmingCharacters(in: .whitespacesAndNewlines)
            let text = draftMessage.trimmingCharacters(in: .whitespacesAndNewlines)
            let outbound = try composeOutboundPayload(text: text)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let profile = try loadUserProfile(keysJson: keys)
            let session = store.readSession(userId: user, peerUserId: peer)

            let sendResult: SendResult
            if let session, !session.isEmpty {
                sendResult = try encryptWithSession(
                    sessionJson: session,
                    senderUserId: user,
                    peerUserId: peer,
                    plaintextUtf8: outbound.plaintext
                )
            } else {
                let bundle = try await loadBundleForPeer(api: api, peer: peer)
                try enforceIdentityPin(localUser: user, peerUser: peer, bundle: bundle)
                sendResult = try initiateSessionAndEncrypt(
                    keysJson: keys,
                    fromUserId: user,
                    peerUserId: peer,
                    peerBundle: bundle.toRustBundle(),
                    plaintextUtf8: outbound.plaintext,
                    suiteOverride: nil
                )
            }

            try store.writeSession(userId: user, peerUserId: peer, sessionJson: sendResult.sessionJson)
            let relayHeaders = try buildRelayAuthHeaders(
                keysJson: keys,
                senderUserId: user,
                recipientUserId: peer,
                messageBytesBase64: sendResult.messageBytesBase64
            ).toHeaderMap()
            let relayResponse = try await api.relay(
                recipientUserId: peer,
                headers: relayHeaders,
                requestBody: RelayRequest(
                    sender_user_id: profile.userId,
                    device_id: profile.deviceId,
                    message_bytes_base64: sendResult.messageBytesBase64
                )
            )
            appendChatLog("me->\(peer): \(outbound.preview) [message_id=\(relayResponse.message_id)]")
            store.upsertConversation(
                userId: user,
                peerUserId: peer,
                lastPreview: "You: \(outbound.preview)",
                incrementUnread: false
            )
            store.markConversationRead(userId: user, peerUserId: peer)
            refreshConversations()
            draftMessage = ""
            clearPendingAttachment()
            statusLine = "Encrypted message sent"
        }
    }

    func pollInbox() async {
        await runChatAction("Poll inbox") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let discoveredGroups = try await fetchAndPersistGroups(userId: user)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            var cursor = store.readCursor(userId: user)
            let inboxHeaders = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: cursor).toHeaderMap()
            let inbox = try await api.inbox(userId: user, since: cursor, headers: inboxHeaders)
            if inbox.messages.isEmpty {
                appendChatLog("inbox empty")
                statusLine = discoveredGroups > 0 ? "Synced \(discoveredGroups) group(s)" : "Inbox empty"
                return
            }
            for message in inbox.messages {
                let existing = store.readSession(userId: user, peerUserId: message.sender_user_id)
                do {
                    let result = try decryptMessage(
                        keysJson: keys,
                        recipientUserId: user,
                        senderUserId: message.sender_user_id,
                        messageBytesBase64: message.message_bytes_base64,
                        existingSessionJson: existing
                    )
                    try store.writeSession(
                        userId: user,
                        peerUserId: message.sender_user_id,
                        sessionJson: result.sessionJson
                    )
                    let preview = renderInboundPreview(result.plaintextUtf8)
                    appendChatLog("\(message.sender_user_id): \(preview)")
                    store.upsertConversation(
                        userId: user,
                        peerUserId: message.sender_user_id,
                        lastPreview: "\(message.sender_user_id): \(preview)",
                        incrementUnread: message.sender_user_id != selectedPeer
                    )
                } catch {
                    appendChatLog("decrypt failed for \(message.sender_user_id)")
                }
                cursor = max(cursor, message.message_id)
            }
            store.writeCursor(userId: user, cursor: cursor)
            refreshConversations()
            await replenishPrekeysIfNeeded(userId: user, keysJson: keys)
            statusLine = "Inbox polling completed"
        }
    }

    func syncGroups() async {
        let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !user.isEmpty else {
            return
        }
        do {
            let discoveredGroups = try await fetchAndPersistGroups(userId: user)
            if discoveredGroups > 0 {
                statusLine = "Synced \(discoveredGroups) group(s)"
            }
        } catch {
            // Best-effort hydration for invited groups.
        }
    }

    func refreshConversations() {
        conversations = store.listConversations(userId: setup.userId)
        pinnedIdentities = store.listIdentityPins(userId: setup.userId)
        groups = store.listGroups(userId: setup.userId)
    }

    private func fetchAndPersistGroups(userId: String) async throws -> Int {
        let keys = try requireKeys(userId)
        let api = try ApiClient(serverURL: setup.serverURL)
        let headers = try buildInboxAuthHeaders(keysJson: keys, userId: userId, since: 0).toHeaderMap()
        let response = try await api.listUserGroups(userId: userId, headers: headers)
        let existingGroupIds = Set(store.listGroups(userId: userId).map(\.groupId))
        var discoveredGroups = 0
        for group in response.groups where !existingGroupIds.contains(group.group_id) {
            let summary = GroupSummary(
                groupId: group.group_id,
                displayName: group.group_id,
                memberCount: group.member_count,
                lastPreview: group.owner_user_id == userId ? "Group created" : "You were added to a group",
                updatedAtMillis: Int64(Date().timeIntervalSince1970 * 1000),
                unreadCount: 0
            )
            store.upsertGroupConversation(userId: userId, group: summary)
            discoveredGroups += 1
        }
        if discoveredGroups > 0 {
            refreshConversations()
        }
        return discoveredGroups
    }

    private func replenishPrekeysIfNeeded(userId: String, keysJson: String) async {
        do {
            let api = try ApiClient(serverURL: setup.serverURL)
            let statusHeaders = try buildPrekeysStatusAuthHeaders(keysJson: keysJson, userId: userId).toHeaderMap()
            let status = try await api.prekeysStatus(userId: userId, headers: statusHeaders)
            guard status.low_one_time_prekeys else { return }
            let target = max(status.minimum_recommended_one_time_prekeys, 16)
            let refreshedKeysJson = try replenishOneTimePrekeys(keysJson: keysJson, oneTimeCount: UInt32(target))
            let payload = try buildPublishPrekeysPayload(keysJson: refreshedKeysJson)
            let headers = try buildPrekeysAuthHeaders(keysJson: refreshedKeysJson, userId: userId).toHeaderMap()
            _ = try await api.publishPrekeys(
                userId: userId,
                requestBody: PublishPrekeysRequest(
                    signed_prekey_x25519_pub: payload.signedPrekeyX25519Pub,
                    sig_over_spk: payload.sigOverSpk,
                    pq_signed_prekey_pub_mlkem768: payload.pqSignedPrekeyPubMlkem768,
                    sig_over_pqspk: payload.sigOverPqspk,
                    one_time_prekeys_x25519: payload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768: payload.oneTimePrekeysMlkem768
                ),
                headers: headers
            )
            try store.writeKeys(userId: userId, keysJson: refreshedKeysJson)
        } catch {
            // Best-effort: prekey replenishment failure is non-fatal
        }
    }

    func refreshSecuritySnapshot() {
        cryptoProfile = (try? activeCryptoProfile()) ?? "Unavailable"
        pinnedIdentities = store.listIdentityPins(userId: setup.userId)
        conversations = store.listConversations(userId: setup.userId)
    }

    func listDevices() async {
        await runSecurityAction("List devices") {
            let context = try await deviceManagementContext()
            let response = try await fetchDeviceSnapshot(context: context)
            statusLine = "Loaded \(response.devices.count) device record(s) for \(response.user_id)"
            clearError()
        }
    }

    func linkManagedDevice() async {
        await runSecurityAction("Link device") {
            let target = managedDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !target.isEmpty else {
                throw RustBridgeError.missingKeys("managed device id is empty")
            }
            let context = try await deviceManagementContext()
            guard target != context.profile.deviceId else {
                throw ApiClientError.transportPolicy("managed device id must differ from the authenticated device id")
            }
            let headers = try buildLinkDeviceAuthHeaders(
                keysJson: context.keysJson,
                userId: context.userId,
                newDeviceId: target
            ).toHeaderMap()
            let response = try await context.api.linkDevice(
                userId: context.userId,
                newDeviceId: target,
                headers: headers
            )
            guard response.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "link response user mismatch")
            }
            guard response.linked_device_id == target else {
                throw ApiClientError.requestFailed(-1, "link response device mismatch")
            }
            _ = try await fetchDeviceSnapshot(context: context)
            statusLine = "Linked device \(response.linked_device_id) for \(response.user_id)"
            clearError()
        }
    }

    func prepareSecondaryDeviceOnboarding(passphrase: String) async {
        preparedOnboardingPackage = nil
        await runSecurityAction("Prepare secondary onboarding") {
            let target = managedDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !target.isEmpty else {
                throw RustBridgeError.missingKeys("managed device id is empty")
            }
            guard !passphrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw RustBridgeError.missingKeys("onboarding passphrase is empty")
            }

            let context = try await deviceManagementContext()
            guard target != context.profile.deviceId else {
                throw ApiClientError.transportPolicy("managed device id must differ from the authenticated device id")
            }

            let headers = try buildLinkDeviceAuthHeaders(
                keysJson: context.keysJson,
                userId: context.userId,
                newDeviceId: target
            ).toHeaderMap()
            let response = try await context.api.linkDevice(
                userId: context.userId,
                newDeviceId: target,
                headers: headers
            )
            guard response.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "link response user mismatch")
            }
            guard response.linked_device_id == target else {
                throw ApiClientError.requestFailed(-1, "link response device mismatch")
            }

            let prepared = try prepareSecondaryDeviceOnboardingPackage(
                keysJson: context.keysJson,
                newDeviceId: target,
                serverUrl: setup.serverURL,
                passphrase: passphrase,
                oneTimeCount: 16
            )
            guard prepared.userId == context.userId else {
                throw ApiClientError.requestFailed(-1, "prepared onboarding package user mismatch")
            }
            guard prepared.deviceId == target else {
                throw ApiClientError.requestFailed(-1, "prepared onboarding package device mismatch")
            }
            _ = try await fetchDeviceSnapshot(context: context)
            preparedOnboardingPackage = OnboardingPackageRecord(
                userId: prepared.userId,
                deviceId: prepared.deviceId,
                linkedAt: response.linked_at,
                packageText: prepared.packageJson
            )
            statusLine = "Prepared onboarding package for \(prepared.deviceId)"
            clearError()
        }
    }

    func revokeManagedDevice() async {
        await runSecurityAction("Revoke device") {
            let target = managedDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !target.isEmpty else {
                throw RustBridgeError.missingKeys("managed device id is empty")
            }
            let context = try await deviceManagementContext()
            guard target != context.profile.deviceId else {
                throw ApiClientError.transportPolicy("managed device id matches the current device; use Reset Local State for self-retirement")
            }
            let headers = try buildRevokeDeviceAuthHeaders(
                keysJson: context.keysJson,
                userId: context.userId,
                targetDeviceId: target
            ).toHeaderMap()
            let response = try await context.api.revokeDevice(
                userId: context.userId,
                targetDeviceId: target,
                headers: headers
            )
            guard response.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "revoke response user mismatch")
            }
            guard response.revoked_device_id == target else {
                throw ApiClientError.requestFailed(-1, "revoke response device mismatch")
            }
            _ = try await fetchDeviceSnapshot(context: context)
            statusLine = "Revoked device \(response.revoked_device_id) for \(response.user_id)"
            clearError()
        }
    }

    func loadIdentityLog() async {
        await runSecurityAction("Load identity log") {
            let context = try await deviceManagementContext()
            let headers = try IdentityRotationSupport.buildIdentityLogHeaders(
                keysJson: context.keysJson,
                userId: context.userId
            )
            let response = try await context.api.identityLog(
                userId: context.userId,
                headers: headers
            )
            guard response.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "identity log response user mismatch")
            }
            identityLogEvents = response.events
            serverCapabilitiesSummary = capabilitySummary(context.capabilities)
            statusLine = "Loaded \(response.events.count) identity event(s) for \(response.user_id)"
            clearError()
        }
    }

    func rotateIdentity() async {
        await runSecurityAction("Rotate identity") {
            let target = managedDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !target.isEmpty else {
                throw RustBridgeError.missingKeys("managed device id is empty")
            }
            let context = try await deviceManagementContext()
            guard target != context.profile.deviceId else {
                throw ApiClientError.transportPolicy("managed device id must differ from the authenticated device id")
            }

            let nextKeysJson = try generateIdentityKeys(
                userId: context.userId,
                deviceId: target,
                suite: context.profile.suite,
                oneTimeCount: 16
            )
            let rotateInitRequest = try IdentityRotationSupport.buildRotateInitRequest(
                newKeysJson: nextKeysJson
            )
            let rotateInitHeaders = try IdentityRotationSupport.buildRotateInitHeaders(
                currentKeysJson: context.keysJson,
                userId: context.userId,
                request: rotateInitRequest
            )
            let rotateInitResponse = try await context.api.rotateInit(
                userId: context.userId,
                headers: rotateInitHeaders,
                requestBody: rotateInitRequest
            )
            guard rotateInitResponse.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "rotate-init response user mismatch")
            }

            let rotateConfirmRequest = try IdentityRotationSupport.buildRotateConfirmRequest(
                currentKeysJson: context.keysJson,
                newKeysJson: nextKeysJson,
                userId: context.userId,
                challengeId: rotateInitResponse.challenge_id,
                challengeNonceBase64: rotateInitResponse.challenge_nonce
            )
            let rotateConfirmHeaders = try IdentityRotationSupport.buildRotateConfirmHeaders(
                currentKeysJson: context.keysJson,
                userId: context.userId,
                request: rotateConfirmRequest
            )
            let rotateConfirmResponse = try await context.api.rotateConfirm(
                userId: context.userId,
                headers: rotateConfirmHeaders,
                requestBody: rotateConfirmRequest
            )
            guard rotateConfirmResponse.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "rotate-confirm response user mismatch")
            }

            let publishPayload = try buildPublishPrekeysPayload(keysJson: nextKeysJson)
            let publishHeaders = try buildPrekeysAuthHeaders(
                keysJson: nextKeysJson,
                userId: context.userId
            ).toHeaderMap()
            let publishResponse = try await context.api.publishPrekeys(
                userId: context.userId,
                requestBody: PublishPrekeysRequest(
                    signed_prekey_x25519_pub: publishPayload.signedPrekeyX25519Pub,
                    sig_over_spk: publishPayload.sigOverSpk,
                    pq_signed_prekey_pub_mlkem768: publishPayload.pqSignedPrekeyPubMlkem768,
                    sig_over_pqspk: publishPayload.sigOverPqspk,
                    one_time_prekeys_x25519: publishPayload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768: publishPayload.oneTimePrekeysMlkem768
                ),
                headers: publishHeaders
            )
            guard publishResponse.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "publish response user mismatch")
            }
            guard publishResponse.device_id == target else {
                throw ApiClientError.requestFailed(-1, "publish response device mismatch")
            }

            let priorPeer = setup.peerUserId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? SetupConfig.default.peerUserId
                : setup.peerUserId.trimmingCharacters(in: .whitespacesAndNewlines)

            store.wipeUserState(userId: context.userId)
            try store.writeKeys(userId: context.userId, keysJson: nextKeysJson)
            setup = SetupConfig(
                serverURL: setup.serverURL,
                userId: context.userId,
                deviceId: target,
                suiteLabel: suiteLabel(for: context.profile.suite),
                peerUserId: priorPeer
            )
            progress = SetupProgress.default.adoptLinkedDevice()
            persistSetup()
            store.saveProgress(userId: context.userId, progress: progress)

            let deviceHeaders = try buildListDevicesAuthHeaders(
                keysJson: nextKeysJson,
                userId: context.userId
            ).toHeaderMap()
            let deviceSnapshot = try await context.api.listDevices(
                userId: context.userId,
                headers: deviceHeaders
            )
            guard deviceSnapshot.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "device list response user mismatch")
            }
            let identityLogHeaders = try IdentityRotationSupport.buildIdentityLogHeaders(
                keysJson: nextKeysJson,
                userId: context.userId
            )
            let identityLogSnapshot = try await context.api.identityLog(
                userId: context.userId,
                headers: identityLogHeaders
            )
            guard identityLogSnapshot.user_id == context.userId else {
                throw ApiClientError.requestFailed(-1, "identity log response user mismatch")
            }

            linkedDevices = deviceSnapshot.devices
            identityLogEvents = identityLogSnapshot.events
            preparedOnboardingPackage = nil
            managedDeviceId = Self.defaultManagedDeviceId(for: context.userId)
            latestBundleByPeer = [:]
            conversations = store.listConversations(userId: context.userId)
            pinnedIdentities = store.listIdentityPins(userId: context.userId)
            selectedPeer = setup.peerUserId
            chatLog = []
            draftMessage = ""
            clearPendingAttachment()
            serverCapabilitiesSummary = capabilitySummary(context.capabilities)
            refreshSecuritySnapshot()
            statusLine = "Rotated identity to \(target) (version \(rotateConfirmResponse.identity_key_version)) and published new prekeys"
            clearError()
        }
    }

    func importLinkedDeviceOnboarding(packageText: String, passphrase: String) async {
        await runSetupAction("Import linked device package") {
            let normalizedPackage = packageText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !normalizedPackage.isEmpty else {
                throw RustBridgeError.missingKeys("onboarding package is empty")
            }
            guard !passphrase.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw RustBridgeError.missingKeys("onboarding passphrase is empty")
            }

            let opened = try openSecondaryDeviceOnboardingPackage(
                packageJson: normalizedPackage,
                passphrase: passphrase
            )
            let user = opened.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let device = opened.deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            let packageServerUrl = opened.serverUrl.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !user.isEmpty else {
                throw RustBridgeError.missingKeys("onboarding package user id is empty")
            }
            guard !device.isEmpty else {
                throw RustBridgeError.missingKeys("onboarding package device id is empty")
            }

            if !packageServerUrl.isEmpty {
                setup.serverURL = packageServerUrl
            }
            let api = try ApiClient(serverURL: setup.serverURL)
            let capabilities = try await api.getCapabilities()
            try validateServerCapabilities(capabilities)

            try store.writeKeys(userId: user, keysJson: opened.keysJson)
            setup.userId = user
            setup.deviceId = device
            setup.suiteLabel = suiteLabel(for: opened.suite)
            if setup.peerUserId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                setup.peerUserId = SetupConfig.default.peerUserId
            }

            let importedProgress = SetupProgress.default.afterKeysGenerated().afterUserRegistered()
            progress = importedProgress
            store.saveProgress(userId: user, progress: importedProgress)
            persistSetup()

            let payload = try buildPublishPrekeysPayload(keysJson: opened.keysJson)
            let headers = try buildPrekeysAuthHeaders(keysJson: opened.keysJson, userId: user).toHeaderMap()
            let publishResponse = try await api.publishPrekeys(
                userId: user,
                requestBody: PublishPrekeysRequest(
                    signed_prekey_x25519_pub: payload.signedPrekeyX25519Pub,
                    sig_over_spk: payload.sigOverSpk,
                    pq_signed_prekey_pub_mlkem768: payload.pqSignedPrekeyPubMlkem768,
                    sig_over_pqspk: payload.sigOverPqspk,
                    one_time_prekeys_x25519: payload.oneTimePrekeysX25519,
                    one_time_prekeys_mlkem768: payload.oneTimePrekeysMlkem768
                ),
                headers: headers
            )
            guard publishResponse.user_id == user else {
                throw ApiClientError.requestFailed(-1, "publish response user mismatch")
            }
            guard publishResponse.device_id == device else {
                throw ApiClientError.requestFailed(-1, "publish response device mismatch")
            }

            let deviceHeaders = try buildListDevicesAuthHeaders(keysJson: opened.keysJson, userId: user).toHeaderMap()
            let snapshot = try await api.listDevices(userId: user, headers: deviceHeaders)
            guard snapshot.user_id == user else {
                throw ApiClientError.requestFailed(-1, "device list response user mismatch")
            }

            progress = importedProgress.adoptLinkedDevice()
            store.saveProgress(userId: user, progress: progress)
            serverCapabilitiesSummary = capabilitySummary(capabilities)
            linkedDevices = snapshot.devices
            identityLogEvents = []
            managedDeviceId = Self.defaultManagedDeviceId(for: user)
            preparedOnboardingPackage = nil
            latestBundleByPeer = [:]
            conversations = store.listConversations(userId: user)
            pinnedIdentities = store.listIdentityPins(userId: user)
            selectedPeer = setup.peerUserId
            refreshSecuritySnapshot()
            statusLine = "Imported linked device \(device) for \(user)"
            clearError()
        }
    }

    // MARK: - Group Chat

    func createGroup(name: String, memberIds: [String]) async {
        await runChatAction("Create group") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            let response = try await api.createGroup(
                headers: headers,
                requestBody: CreateGroupRequest(group_id: name, member_user_ids: memberIds)
            )
            let allMembers = Set(memberIds).union([user])
            let summary = GroupSummary(
                groupId: response.group_id,
                displayName: response.group_id,
                memberCount: response.member_count,
                lastPreview: "Group created",
                updatedAtMillis: Int64(Date().timeIntervalSince1970 * 1000),
                unreadCount: 0
            )
            store.upsertGroupConversation(userId: user, group: summary)
            refreshConversations()
            statusLine = "Created group '\(response.group_id)' for \(allMembers.count) member(s)"
        }
    }

    func sendGroupMessage(groupId: String, text: String) async {
        await runChatAction("Send group message") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let profile = try loadUserProfile(keysJson: keys)

            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            let membersResponse = try await api.listGroupMembers(groupId: groupId, headers: headers)
            let otherMembers = membersResponse.members.filter { $0.user_id != user }

            var recipients: [GroupRelayRecipient] = []
            for member in otherMembers {
                let session = store.readSession(userId: user, peerUserId: member.user_id)
                let sendResult: SendResult
                if let session, !session.isEmpty {
                    sendResult = try encryptWithSession(
                        sessionJson: session,
                        senderUserId: user,
                        peerUserId: member.user_id,
                        plaintextUtf8: text
                    )
                } else {
                    let bundle = try await loadBundleForPeer(api: api, peer: member.user_id)
                    sendResult = try initiateSessionAndEncrypt(
                        keysJson: keys,
                        fromUserId: user,
                        peerUserId: member.user_id,
                        peerBundle: bundle.toRustBundle(),
                        plaintextUtf8: text,
                        suiteOverride: nil
                    )
                }
                try store.writeSession(userId: user, peerUserId: member.user_id, sessionJson: sendResult.sessionJson)
                recipients.append(GroupRelayRecipient(
                    recipient_user_id: member.user_id,
                    message_bytes_base64: sendResult.messageBytesBase64
                ))
            }

            let relayHeaders = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            _ = try await api.relayGroupMessage(
                groupId: groupId,
                headers: relayHeaders,
                requestBody: GroupRelayRequest(
                    sender_user_id: profile.userId,
                    device_id: profile.deviceId,
                    recipients: recipients
                )
            )

            let logLine = "me: \(text)"
            store.appendGroupThreadMessage(userId: user, groupId: groupId, line: logLine)
            groupChatLog = store.listGroupThreadMessages(userId: user, groupId: groupId)

            var g = store.listGroups(userId: user).first { $0.groupId == groupId }
                ?? GroupSummary(groupId: groupId, displayName: groupId, memberCount: 0, lastPreview: "", updatedAtMillis: 0, unreadCount: 0)
            g.lastPreview = "You: \(text)"
            store.upsertGroupConversation(userId: user, group: g)
            refreshConversations()
            statusLine = "Group message sent"
        }
    }

    func loadGroupChatLog(groupId: String) {
        groupChatLog = store.listGroupThreadMessages(userId: setup.userId, groupId: groupId)
    }

    func listGroupMembers(groupId: String) async -> [GroupMemberRecord] {
        do {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            let response = try await api.listGroupMembers(groupId: groupId, headers: headers)
            return response.members
        } catch {
            errorLine = "List members failed: \(error.localizedDescription)"
            return []
        }
    }

    func addGroupMember(groupId: String, memberId: String) async {
        await runChatAction("Add group member") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            _ = try await api.addGroupMember(groupId: groupId, headers: headers, userId: memberId)
            statusLine = "Added \(memberId) to group"
        }
    }

    // MARK: - Contacts

    func loadContacts() async {
        await runChatAction("Load contacts") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            let response = try await api.listContacts(userId: user, headers: headers)
            contacts = response.contacts
            statusLine = "Loaded \(contacts.count) contact(s)"
        }
    }

    func addContact(contactUserId: String, alias: String) async {
        await runChatAction("Add contact") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            _ = try await api.upsertContact(
                userId: user,
                headers: headers,
                requestBody: UpsertContactRequest(
                    contact_user_id: contactUserId,
                    alias: alias.isEmpty ? nil : alias,
                    verified: nil
                )
            )
            await loadContacts()
            statusLine = "Added contact \(contactUserId)"
        }
    }

    func removeContact(contactUserId: String) async {
        await runChatAction("Remove contact") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            _ = try await api.removeContact(userId: user, contactUserId: contactUserId, headers: headers)
            contacts.removeAll { $0.contact_user_id == contactUserId }
            statusLine = "Removed contact \(contactUserId)"
        }
    }

    // MARK: - Typing Indicators

    func notifyTyping(peerUserId: String, isTyping: Bool) async {
        do {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            _ = try await api.updateTyping(
                peerUserId: peerUserId,
                headers: headers,
                requestBody: TypingUpdateRequest(is_typing: isTyping)
            )
        } catch {
            // Typing indicator failures are non-fatal
        }
    }

    func pollTyping() async {
        do {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            let response = try await api.getTyping(userId: user, headers: headers)
            peerIsTyping = response.typing.contains { $0.sender_user_id == selectedPeer && $0.is_typing }
        } catch {
            // Non-fatal
        }
    }

    // MARK: - Presence

    func sendPresenceHeartbeat() async {
        do {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            _ = try await api.updatePresence(
                userId: user,
                headers: headers,
                requestBody: PresenceUpdateRequest(status: "online")
            )
        } catch {
            // Non-fatal
        }
    }

    func pollPresence(peerUserId: String) async {
        do {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: 0).toHeaderMap()
            let response = try await api.getPresence(userId: peerUserId, headers: headers)
            peerPresenceOnline = response.status == "online"
        } catch {
            peerPresenceOnline = false
        }
    }

    // MARK: - Read Receipts

    func sendReadReceipt(peerUserId: String, messageId: Int64) async {
        do {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let device = setup.deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            let api = try ApiClient(serverURL: setup.serverURL)
            let headers = try buildCallAuth(message: "receipt:\(user):\(device):\(messageId):read")
            _ = try await api.sendReceipt(
                userId: user,
                headers: headers,
                requestBody: SendReceiptRequest(message_id: messageId, receipt_type: "read")
            )
            store.updateMessageReceipt(userId: user, peerUserId: peerUserId, messageId: messageId, receiptType: "read")
        } catch {
            // Non-fatal
        }
    }

    // MARK: - Sealed Sender

    func toggleSealedSender() {
        sealedSenderEnabled.toggle()
        statusLine = sealedSenderEnabled ? "Sealed sender ON" : "Sealed sender OFF"
    }

    func sendSealedMessage(peerUserId: String) async {
        await runChatAction("Send sealed message") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let peer = peerUserId.trimmingCharacters(in: .whitespacesAndNewlines)
            let text = draftMessage.trimmingCharacters(in: .whitespacesAndNewlines)
            let outbound = try composeOutboundPayload(text: text)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let profile = try loadUserProfile(keysJson: keys)
            let session = store.readSession(userId: user, peerUserId: peer)

            let sendResult: SendResult
            if let session, !session.isEmpty {
                sendResult = try encryptWithSession(
                    sessionJson: session,
                    senderUserId: user,
                    peerUserId: peer,
                    plaintextUtf8: outbound.plaintext
                )
            } else {
                let bundle = try await loadBundleForPeer(api: api, peer: peer)
                try enforceIdentityPin(localUser: user, peerUser: peer, bundle: bundle)
                sendResult = try initiateSessionAndEncrypt(
                    keysJson: keys,
                    fromUserId: user,
                    peerUserId: peer,
                    peerBundle: bundle.toRustBundle(),
                    plaintextUtf8: outbound.plaintext,
                    suiteOverride: nil
                )
            }
            try store.writeSession(userId: user, peerUserId: peer, sessionJson: sendResult.sessionJson)
            let relayHeaders = try buildRelayAuthHeaders(
                keysJson: keys,
                senderUserId: user,
                recipientUserId: peer,
                messageBytesBase64: sendResult.messageBytesBase64
            ).toHeaderMap()
            _ = try await api.sealedRelay(
                recipientUserId: peer,
                headers: relayHeaders,
                requestBody: SealedRelayRequest(
                    sender_user_id: profile.userId,
                    device_id: profile.deviceId,
                    message_bytes_base64: sendResult.messageBytesBase64
                )
            )
            appendChatLog("me->\(peer) [sealed]: \(outbound.preview)")
            store.upsertConversation(userId: user, peerUserId: peer, lastPreview: "You [sealed]: \(outbound.preview)", incrementUnread: false)
            store.markConversationRead(userId: user, peerUserId: peer)
            refreshConversations()
            draftMessage = ""
            clearPendingAttachment()
            statusLine = "Sealed message sent"
        }
    }

    // MARK: - Ephemeral Messages

    func setEphemeralTtl(_ seconds: Int) {
        ephemeralTtlSeconds = seconds
        statusLine = seconds > 0 ? "Ephemeral TTL: \(seconds)s" : "Ephemeral OFF"
    }

    func sendEphemeralMessage(peerUserId: String) async {
        await runChatAction("Send ephemeral message") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let peer = peerUserId.trimmingCharacters(in: .whitespacesAndNewlines)
            let text = draftMessage.trimmingCharacters(in: .whitespacesAndNewlines)
            let outbound = try composeOutboundPayload(text: text)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            let profile = try loadUserProfile(keysJson: keys)
            let session = store.readSession(userId: user, peerUserId: peer)

            let sendResult: SendResult
            if let session, !session.isEmpty {
                sendResult = try encryptWithSession(
                    sessionJson: session,
                    senderUserId: user,
                    peerUserId: peer,
                    plaintextUtf8: outbound.plaintext
                )
            } else {
                let bundle = try await loadBundleForPeer(api: api, peer: peer)
                try enforceIdentityPin(localUser: user, peerUser: peer, bundle: bundle)
                sendResult = try initiateSessionAndEncrypt(
                    keysJson: keys,
                    fromUserId: user,
                    peerUserId: peer,
                    peerBundle: bundle.toRustBundle(),
                    plaintextUtf8: outbound.plaintext,
                    suiteOverride: nil
                )
            }
            try store.writeSession(userId: user, peerUserId: peer, sessionJson: sendResult.sessionJson)
            let relayHeaders = try buildRelayAuthHeaders(
                keysJson: keys,
                senderUserId: user,
                recipientUserId: peer,
                messageBytesBase64: sendResult.messageBytesBase64
            ).toHeaderMap()
            _ = try await api.relayEphemeralMessage(
                recipientUserId: peer,
                headers: relayHeaders,
                requestBody: RelayEphemeralRequest(
                    sender_user_id: profile.userId,
                    device_id: profile.deviceId,
                    message_bytes_base64: sendResult.messageBytesBase64,
                    ttl_seconds: ephemeralTtlSeconds
                )
            )
            appendChatLog("me->\(peer) [ephemeral \(ephemeralTtlSeconds)s]: \(outbound.preview)")
            store.upsertConversation(userId: user, peerUserId: peer, lastPreview: "You [ephemeral]: \(outbound.preview)", incrementUnread: false)
            store.markConversationRead(userId: user, peerUserId: peer)
            refreshConversations()
            draftMessage = ""
            clearPendingAttachment()
            statusLine = "Ephemeral message sent (TTL: \(ephemeralTtlSeconds)s)"
        }
    }

    func resetLocalState() async -> Bool {
        let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !user.isEmpty else {
            errorLine = "user id is empty"
            return false
        }
        do {
            var retiredRemotely = false
            if let keys = store.readKeys(userId: user),
               !keys.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                let profile = try loadUserProfile(keysJson: keys)
                guard profile.userId == user else {
                    throw RustBridgeError.missingKeys(
                        "user mismatch: current input '\(user)' vs stored keys '\(profile.userId)'"
                    )
                }
                let api = try ApiClient(serverURL: setup.serverURL)
                let capabilities = try await api.getCapabilities()
                try validateServerCapabilities(capabilities)
                let headers = try buildRetireDeviceAuthHeaders(keysJson: keys, userId: user).toHeaderMap()
                let response = try await api.retireCurrentDevice(userId: user, headers: headers)
                guard response.user_id == user else {
                    throw ApiClientError.requestFailed(-1, "retire response user mismatch")
                }
                guard response.retired_device_id == profile.deviceId else {
                    throw ApiClientError.requestFailed(-1, "retire response device mismatch")
                }
                serverCapabilitiesSummary = capabilitySummary(capabilities)
                retiredRemotely = true
            }
            store.wipeUserState(userId: user)
            setup = store.loadSetup()
            progress = store.loadProgress(userId: setup.userId)
            conversations = store.listConversations(userId: setup.userId)
            pinnedIdentities = store.listIdentityPins(userId: setup.userId)
            selectedPeer = setup.peerUserId
            chatLog = []
            draftMessage = ""
            clearPendingAttachment()
            latestBundleByPeer = [:]
            serverCapabilitiesSummary = "Not checked"
            linkedDevices = []
            identityLogEvents = []
            preparedOnboardingPackage = nil
            managedDeviceId = Self.defaultManagedDeviceId(for: setup.userId)
            statusLine = retiredRemotely
                ? "Retired current device and cleared local state for \(user)"
                : "Cleared local state for \(user)"
            clearError()
            refreshSecuritySnapshot()
            return true
        } catch {
            errorLine = "Reset local state failed: \(error.localizedDescription)"
            statusLine = "Reset local state failed"
            return false
        }
    }

    private func persistSetup() {
        store.saveSetup(setup)
    }

    private func normalizedDeviceId(user: String, raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return "\(user)-ios-1"
        }
        return trimmed
    }

    private func parseSuite(_ value: String) -> Suite {
        if value.lowercased() == "kyber768" {
            return .kyber768
        }
        return .mlKem768
    }

    private func suiteLabel(for suite: Suite) -> String {
        switch suite {
        case .kyber768:
            return "kyber768"
        case .mlKem768:
            return "ml-kem-768"
        }
    }

    private func suiteIdForSetup() -> Int {
        setup.suiteLabel.lowercased() == "kyber768" ? 2 : 1
    }

    private func validateServerCapabilities(_ capabilities: ServerCapabilitiesResponse) throws {
        guard capabilities.capability_schema_version == 1 else {
            throw ApiClientError.transportPolicy(
                "Unsupported server capability schema \(capabilities.capability_schema_version)"
            )
        }
        guard capabilities.supported_suite_ids.contains(suiteIdForSetup()) else {
            throw ApiClientError.transportPolicy(
                "Server does not support suite '\(setup.suiteLabel)'"
            )
        }
        guard !capabilities.tls_required || capabilities.tls_enabled else {
            throw ApiClientError.transportPolicy(
                "Server requires TLS but is not advertising an active TLS transport"
            )
        }
        guard capabilities.security_profile == "research" || capabilities.runtime_crypto_profile.pq_oqs_enabled else {
            throw ApiClientError.transportPolicy(
                "Server is not running a PQ-enabled crypto backend"
            )
        }
        guard capabilities.deployment_mode == "development" || capabilities.production_baseline_met else {
            throw ApiClientError.transportPolicy(
                "Server '\(capabilities.deployment_mode)' deployment is missing its production baseline"
            )
        }
    }

    private func capabilitySummary(_ capabilities: ServerCapabilitiesResponse) -> String {
        "\(capabilities.security_profile) / \(capabilities.deployment_mode) / suite \(capabilities.runtime_crypto_profile.suite_id)"
    }

    private func requireKeys(_ userId: String) throws -> String {
        guard let keys = store.readKeys(userId: userId), !keys.isEmpty else {
            throw RustBridgeError.missingKeys("missing keys for user '\(userId)'")
        }
        return keys
    }

    private func loadBundleForPeer(api: ApiClient, peer: String) async throws -> BundleResponse {
        if let cached = latestBundleByPeer[peer] {
            return cached
        }
        let fetched = try await api.getBundle(userId: peer)
        latestBundleByPeer[peer] = fetched
        return fetched
    }

    private func enforceIdentityPin(localUser: String, peerUser: String, bundle: BundleResponse) throws {
        let observedFingerprint = try bundle.identityFingerprint()
        let observedVersion = bundle.identity_key_version ?? 1
        let observedSigPub = bundle.identity_sig_pub
        let observedAt = bundle.bundle_generated_at
        let pin = IdentityPin(
            fingerprintSha256: observedFingerprint,
            identityKeyVersion: observedVersion,
            identitySigPub: observedSigPub,
            observedAt: observedAt
        )
        if let existing = store.readIdentityPin(userId: localUser, peerUserId: peerUser),
           existing.fingerprintSha256 != observedFingerprint {
            throw RustBridgeError.identityChanged(peerUser)
        }
        store.writeIdentityPin(userId: localUser, peerUserId: peerUser, pin: pin)
    }

    private func appendChatLog(_ line: String) {
        chatLog.append(line)
    }

    func stageAttachment(fileName: String, mimeType: String, data: Data) throws {
        let trimmedName = fileName.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedName = trimmedName.isEmpty ? "attachment.bin" : trimmedName
        guard data.count <= maxAttachmentBytes else {
            throw NSError(
                domain: "PQMsgAttachment",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "attachment exceeds \(maxAttachmentBytes) bytes"]
            )
        }
        let selection = PendingAttachmentSelection(
            fileName: normalizedName,
            mimeType: mimeType.isEmpty ? "application/octet-stream" : mimeType,
            byteLength: data.count
        )
        pendingAttachmentDraft = PendingAttachmentDraft(
            selection: selection,
            dataBase64: data.base64EncodedString()
        )
        pendingAttachment = selection
        statusLine = "Attachment ready"
        clearError()
    }

    func clearPendingAttachment() {
        pendingAttachmentDraft = nil
        pendingAttachment = nil
    }

    private func composeOutboundPayload(text: String) throws -> OutboundPayload {
        let trimmedText = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let attachment = pendingAttachmentDraft {
            let plaintext = MessageEnvelopeCodec.encodeMediaEnvelope(
                fileName: attachment.selection.fileName,
                mimeType: attachment.selection.mimeType,
                noteText: trimmedText,
                dataBase64: attachment.dataBase64
            )
            return OutboundPayload(
                plaintext: plaintext,
                preview: MessageEnvelopeCodec.renderPreview(
                    fileName: attachment.selection.fileName,
                    mimeType: attachment.selection.mimeType,
                    byteLength: attachment.selection.byteLength,
                    noteText: trimmedText
                )
            )
        }
        guard !trimmedText.isEmpty else {
            throw RustBridgeError.missingKeys("message is empty")
        }
        return OutboundPayload(plaintext: trimmedText, preview: trimmedText)
    }

    private func renderInboundPreview(_ plaintext: String) -> String {
        guard let envelope = MessageEnvelopeCodec.decodeMediaEnvelope(plaintext) else {
            return plaintext
        }
        return MessageEnvelopeCodec.renderPreview(for: envelope)
    }

    private func deviceManagementContext() async throws -> (
        userId: String,
        keysJson: String,
        profile: UserProfile,
        api: ApiClient,
        capabilities: ServerCapabilitiesResponse
    ) {
        let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !user.isEmpty else {
            throw RustBridgeError.missingKeys("user id is empty")
        }
        let keys = try requireKeys(user)
        let profile = try loadUserProfile(keysJson: keys)
        guard profile.userId == user else {
            throw RustBridgeError.missingKeys(
                "user mismatch: current input '\(user)' vs stored keys '\(profile.userId)'"
            )
        }
        let api = try ApiClient(serverURL: setup.serverURL)
        let capabilities = try await api.getCapabilities()
        try validateServerCapabilities(capabilities)
        return (user, keys, profile, api, capabilities)
    }

    private func fetchDeviceSnapshot(
        context: (
            userId: String,
            keysJson: String,
            profile: UserProfile,
            api: ApiClient,
            capabilities: ServerCapabilitiesResponse
        )
    ) async throws -> DeviceListResponse {
        let headers = try buildListDevicesAuthHeaders(
            keysJson: context.keysJson,
            userId: context.userId
        ).toHeaderMap()
        let response = try await context.api.listDevices(userId: context.userId, headers: headers)
        guard response.user_id == context.userId else {
            throw ApiClientError.requestFailed(-1, "device list response user mismatch")
        }
        linkedDevices = response.devices
        serverCapabilitiesSummary = capabilitySummary(context.capabilities)
        return response
    }

    private func runSetupAction(_ label: String, action: @escaping () async throws -> Void) async {
        do {
            try await action()
        } catch {
            errorLine = "\(label) failed: \(error.localizedDescription)"
            statusLine = "\(label) failed"
        }
    }

    private func runChatAction(_ label: String, action: @escaping () async throws -> Void) async {
        do {
            try await action()
        } catch {
            errorLine = "\(label) failed: \(error.localizedDescription)"
            statusLine = "\(label) failed"
        }
    }

    private func runSecurityAction(_ label: String, action: @escaping () async throws -> Void) async {
        do {
            try await action()
        } catch {
            errorLine = "\(label) failed: \(error.localizedDescription)"
            statusLine = "\(label) failed"
        }
    }

    private func clearError() {
        errorLine = ""
    }

    private static func defaultManagedDeviceId(for userId: String) -> String {
        let trimmed = userId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return ""
        }
        return "\(trimmed)-device-2"
    }

    // MARK: - Call Signaling

    private func buildCallAuth(message: String) throws -> [String: String] {
        let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
        let keys = try requireKeys(user)
        return try buildFormatStringAuthHeaders(keysJson: keys, message: message).toHeaderMap()
    }

    func startOutgoingCall(peerUserId: String, callType: String) async {
        await runChatAction("Start call") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let device = setup.deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            let peer = peerUserId.trimmingCharacters(in: .whitespacesAndNewlines)
            let api = try ApiClient(serverURL: setup.serverURL)

            let sdpOfferPlaceholder = Data("placeholder-sdp-offer".utf8).base64EncodedString()
            let authMessage = "call-offer:\(user):\(device):\(peer)"
            let headers = try buildCallAuth(message: authMessage)

            let response = try await api.callOffer(
                calleeUserId: peer,
                headers: headers,
                requestBody: CallOfferRequest(
                    caller_user_id: user,
                    device_id: device,
                    call_type: callType,
                    sdp_offer_base64: sdpOfferPlaceholder
                )
            )

            activeCallId = response.call_id
            activeCallPeer = peer
            activeCallType = callType
            callStatus = "Ringing..."
            callElapsedSeconds = 0
            isIncomingCall = false
            showCallView = true
            startCallSignalPolling()
        }
    }

    func acceptIncomingCall() async {
        await runChatAction("Accept call") {
            guard let callId = activeCallId,
                  let peer = activeCallPeer else { return }
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let device = setup.deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            let api = try ApiClient(serverURL: setup.serverURL)

            let sdpAnswerPlaceholder = Data("placeholder-sdp-answer".utf8).base64EncodedString()
            let authMessage = "call-answer:\(user):\(device):\(callId)"
            let headers = try buildCallAuth(message: authMessage)

            _ = try await api.callAnswer(
                callId: callId,
                headers: headers,
                requestBody: CallAnswerRequest(
                    callee_user_id: user,
                    device_id: device,
                    sdp_answer_base64: sdpAnswerPlaceholder
                )
            )

            callStatus = "Connected"
            startCallTimer()
            startCallSignalPolling()
        }
    }

    func hangupCall(reason: String = "user-hangup") async {
        callPollingTask?.cancel()
        callPollingTask = nil
        callTimerTask?.cancel()
        callTimerTask = nil

        if let callId = activeCallId {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let device = setup.deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
            do {
                let api = try ApiClient(serverURL: setup.serverURL)
                let authMessage = "call-hangup:\(user):\(device):\(callId)"
                let headers = try buildCallAuth(message: authMessage)
                _ = try await api.callHangup(
                    callId: callId,
                    headers: headers,
                    requestBody: CallHangupRequest(
                        user_id: user,
                        device_id: device,
                        reason: reason
                    )
                )
            } catch {
                // Best-effort hangup notification
            }
        }

        activeCallId = nil
        activeCallPeer = nil
        activeCallType = nil
        callStatus = "Ended"
        callElapsedSeconds = 0

        try? await Task.sleep(nanoseconds: 1_500_000_000)
        showCallView = false
        callStatus = "Idle"
    }

    func declineIncomingCall() async {
        await hangupCall(reason: "declined")
    }

    private func startCallSignalPolling() {
        callPollingTask?.cancel()
        callPollingTask = Task { [weak self] in
            var lastSignalId: Int64 = 0
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self, let callId = self.activeCallId else { break }

                do {
                    let user = self.setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
                    let device = self.setup.deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
                    let api = try ApiClient(serverURL: self.setup.serverURL)
                    let authMessage = "call-signals:\(user):\(device):\(callId)"
                    let headers = try self.buildCallAuth(message: authMessage)
                    let response = try await api.pollCallSignals(
                        callId: callId,
                        since: lastSignalId,
                        headers: headers
                    )
                    for signal in response.signals {
                        lastSignalId = max(lastSignalId, signal.signal_id)
                        await self.handleCallSignal(signal)
                    }
                } catch {
                    // Continue polling
                }
            }
        }
    }

    private func handleCallSignal(_ signal: CallSignal) async {
        switch signal.signal_type {
        case "answer":
            callStatus = "Connected"
            startCallTimer()
        case "hangup":
            callPollingTask?.cancel()
            callTimerTask?.cancel()
            callStatus = "Ended"
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            showCallView = false
            activeCallId = nil
            activeCallPeer = nil
            activeCallType = nil
            callStatus = "Idle"
        default:
            break
        }
    }

    private func startCallTimer() {
        callTimerTask?.cancel()
        callElapsedSeconds = 0
        callTimerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self else { break }
                self.callElapsedSeconds += 1
            }
        }
    }
}

private struct PendingAttachmentDraft {
    let selection: PendingAttachmentSelection
    let dataBase64: String
}

private struct OutboundPayload {
    let plaintext: String
    let preview: String
}
