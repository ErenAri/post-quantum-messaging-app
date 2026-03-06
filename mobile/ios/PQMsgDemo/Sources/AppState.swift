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

    private let store: LocalStateStore
    private var latestBundleByPeer: [String: BundleResponse]

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
        self.latestBundleByPeer = [:]
        refreshSecuritySnapshot()
    }

    func applyPreset(userId: String, peerId: String) {
        setup.userId = userId
        setup.peerUserId = peerId
        if setup.deviceId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            setup.deviceId = "\(userId)-ios-1"
        }
        progress = store.loadProgress(userId: setup.userId)
        managedDeviceId = Self.defaultManagedDeviceId(for: setup.userId)
        linkedDevices = []
        preparedOnboardingPackage = nil
        persistSetup()
        refreshConversations()
        clearError()
    }

    func setServerURL(_ value: String) {
        setup.serverURL = value
        serverCapabilitiesSummary = "Not checked"
        linkedDevices = []
        preparedOnboardingPackage = nil
        persistSetup()
    }

    func setUserId(_ value: String) {
        setup.userId = value
        progress = store.loadProgress(userId: value)
        managedDeviceId = Self.defaultManagedDeviceId(for: value)
        linkedDevices = []
        preparedOnboardingPackage = nil
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
            guard !text.isEmpty else {
                throw RustBridgeError.missingKeys("message is empty")
            }
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
                    plaintextUtf8: text
                )
            } else {
                let bundle = try await loadBundleForPeer(api: api, peer: peer)
                try enforceIdentityPin(localUser: user, peerUser: peer, bundle: bundle)
                sendResult = try initiateSessionAndEncrypt(
                    keysJson: keys,
                    fromUserId: user,
                    peerUserId: peer,
                    peerBundle: bundle.toRustBundle(),
                    plaintextUtf8: text,
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
            appendChatLog("me->\(peer): \(text) [message_id=\(relayResponse.message_id)]")
            store.upsertConversation(
                userId: user,
                peerUserId: peer,
                lastPreview: "You: \(text)",
                incrementUnread: false
            )
            store.markConversationRead(userId: user, peerUserId: peer)
            refreshConversations()
            draftMessage = ""
            statusLine = "Encrypted message sent"
        }
    }

    func pollInbox() async {
        await runChatAction("Poll inbox") {
            let user = setup.userId.trimmingCharacters(in: .whitespacesAndNewlines)
            let keys = try requireKeys(user)
            let api = try ApiClient(serverURL: setup.serverURL)
            var cursor = store.readCursor(userId: user)
            let inboxHeaders = try buildInboxAuthHeaders(keysJson: keys, userId: user, since: cursor).toHeaderMap()
            let inbox = try await api.inbox(userId: user, since: cursor, headers: inboxHeaders)
            if inbox.messages.isEmpty {
                appendChatLog("inbox empty")
                statusLine = "Inbox empty"
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
                    appendChatLog("\(message.sender_user_id): \(result.plaintextUtf8)")
                    store.upsertConversation(
                        userId: user,
                        peerUserId: message.sender_user_id,
                        lastPreview: "\(message.sender_user_id): \(result.plaintextUtf8)",
                        incrementUnread: message.sender_user_id != selectedPeer
                    )
                } catch {
                    appendChatLog("decrypt failed for \(message.sender_user_id)")
                }
                cursor = max(cursor, message.message_id)
            }
            store.writeCursor(userId: user, cursor: cursor)
            refreshConversations()
            statusLine = "Inbox polling completed"
        }
    }

    func refreshConversations() {
        conversations = store.listConversations(userId: setup.userId)
        pinnedIdentities = store.listIdentityPins(userId: setup.userId)
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
            guard !user.isEmpty else {
                throw RustBridgeError.missingKeys("onboarding package user id is empty")
            }
            guard !device.isEmpty else {
                throw RustBridgeError.missingKeys("onboarding package device id is empty")
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
            latestBundleByPeer = [:]
            serverCapabilitiesSummary = "Not checked"
            linkedDevices = []
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
}
