import Foundation

final class LocalStateStore {
    static let shared = LocalStateStore()

    private let defaults = UserDefaults.standard
    private let keychain = KeychainStore(service: "com.pqmsg.demo.ios")
    private let fileManager = FileManager.default
    private let protectedRoot: URL

    private init() {
        let appSupport =
            FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        self.protectedRoot = appSupport.appendingPathComponent("pqmsg-secure-state", isDirectory: true)
    }

    func loadSetup() -> SetupConfig {
        if let stored: SetupConfig = readProtectedCodable(at: setupURL()) {
            return stored
        }
        guard let data = defaults.data(forKey: "setup_config"),
              let config = try? JSONDecoder().decode(SetupConfig.self, from: data)
        else {
            return .default
        }
        persistProtected(config, at: setupURL())
        defaults.removeObject(forKey: "setup_config")
        return config
    }

    func saveSetup(_ config: SetupConfig) {
        persistProtected(config, at: setupURL())
        defaults.removeObject(forKey: "setup_config")
    }

    func loadProgress(userId: String) -> SetupProgress {
        let legacyKey = legacyProgressKey(userId: userId)
        let url = progressURL(userId: userId)
        if let stored: SetupProgress = readProtectedCodable(at: url) {
            return stored
        }
        guard let data = defaults.data(forKey: legacyKey),
              let progress = try? JSONDecoder().decode(SetupProgress.self, from: data)
        else {
            return .default
        }
        persistProtected(progress, at: url)
        defaults.removeObject(forKey: legacyKey)
        return progress
    }

    func saveProgress(userId: String, progress: SetupProgress) {
        persistProtected(progress, at: progressURL(userId: userId))
        defaults.removeObject(forKey: legacyProgressKey(userId: userId))
    }

    func writeKeys(userId: String, keysJson: String) throws {
        try keychain.setString(keysJson, account: "keys.\(userId)")
    }

    func readKeys(userId: String) -> String? {
        try? keychain.getString(account: "keys.\(userId)")
    }

    func writeSession(userId: String, peerUserId: String, sessionJson: String) throws {
        try keychain.setString(sessionJson, account: "session.\(userId).\(peerUserId)")
    }

    func readSession(userId: String, peerUserId: String) -> String? {
        try? keychain.getString(account: "session.\(userId).\(peerUserId)")
    }

    func readCursor(userId: String) -> Int64 {
        let legacyKey = "cursor.\(userId)"
        let url = cursorURL(userId: userId)
        if let stored: Int64 = readProtectedCodable(at: url) {
            return stored
        }
        guard let legacy = defaults.object(forKey: legacyKey) as? NSNumber else {
            return 0
        }
        let cursor = legacy.int64Value
        persistProtected(cursor, at: url)
        defaults.removeObject(forKey: legacyKey)
        return cursor
    }

    func writeCursor(userId: String, cursor: Int64) {
        persistProtected(cursor, at: cursorURL(userId: userId))
        defaults.removeObject(forKey: "cursor.\(userId)")
    }

    func writeBundleFetchedAt(userId: String, peerUserId: String, timestamp: String) {
        persistProtected(timestamp, at: bundleURL(userId: userId, peerUserId: peerUserId))
        defaults.removeObject(forKey: "bundle.\(userId).\(peerUserId)")
    }

    func readBundleFetchedAt(userId: String, peerUserId: String) -> String? {
        let legacyKey = "bundle.\(userId).\(peerUserId)"
        let url = bundleURL(userId: userId, peerUserId: peerUserId)
        if let stored: String = readProtectedCodable(at: url) {
            return stored
        }
        guard let timestamp = defaults.string(forKey: legacyKey) else {
            return nil
        }
        persistProtected(timestamp, at: url)
        defaults.removeObject(forKey: legacyKey)
        return timestamp
    }

    func readIdentityPin(userId: String, peerUserId: String) -> IdentityPin? {
        let url = pinURL(userId: userId, peerUserId: peerUserId)
        if let stored: IdentityPin = readProtectedCodable(at: url) {
            return stored
        }
        let legacyKey = "pin.\(userId).\(peerUserId)"
        guard let data = defaults.data(forKey: legacyKey),
              let pin = try? JSONDecoder().decode(IdentityPin.self, from: data)
        else {
            return nil
        }
        persistProtected(pin, at: url)
        defaults.removeObject(forKey: legacyKey)
        return pin
    }

    func writeIdentityPin(userId: String, peerUserId: String, pin: IdentityPin) {
        persistProtected(pin, at: pinURL(userId: userId, peerUserId: peerUserId))
        defaults.removeObject(forKey: "pin.\(userId).\(peerUserId)")
    }

    func listIdentityPins(userId: String) -> [IdentityPinRecord] {
        migrateLegacyIdentityPins(userId: userId)
        let dir = pinsDirectoryURL(userId: userId)
        guard let urls = try? fileManager.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }
        return urls
            .filter { $0.pathExtension == "json" }
            .compactMap { url -> IdentityPinRecord? in
                guard let pin: IdentityPin = readProtectedCodable(at: url) else {
                    return nil
                }
                let peer = url.deletingPathExtension().lastPathComponent.removingPercentEncoding
                    ?? url.deletingPathExtension().lastPathComponent
                return IdentityPinRecord(peerUserId: peer, pin: pin)
            }
            .sorted { $0.peerUserId < $1.peerUserId }
    }

    func upsertConversation(
        userId: String,
        peerUserId: String,
        lastPreview: String,
        incrementUnread: Bool
    ) {
        guard !userId.isEmpty, !peerUserId.isEmpty else {
            return
        }
        var items = listConversations(userId: userId)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let preview = normalizedPreview(lastPreview)
        if let idx = items.firstIndex(where: { $0.peerUserId == peerUserId }) {
            var current = items[idx]
            current.lastPreview = preview
            current.updatedAtMillis = now
            if incrementUnread {
                current.unreadCount += 1
            }
            items[idx] = current
        } else {
            items.append(
                ConversationSummary(
                    peerUserId: peerUserId,
                    lastPreview: preview,
                    updatedAtMillis: now,
                    unreadCount: incrementUnread ? 1 : 0
                )
            )
        }
        saveConversations(userId: userId, items: items)
    }

    func markConversationRead(userId: String, peerUserId: String) {
        var items = listConversations(userId: userId)
        guard let idx = items.firstIndex(where: { $0.peerUserId == peerUserId }) else {
            return
        }
        var current = items[idx]
        current.unreadCount = 0
        items[idx] = current
        saveConversations(userId: userId, items: items)
    }

    func listConversations(userId: String) -> [ConversationSummary] {
        let legacyKey = conversationsKey(userId: userId)
        let url = conversationsURL(userId: userId)
        if let stored: [ConversationSummary] = readProtectedCodable(at: url) {
            return sortedConversations(stored)
        }
        guard let data = defaults.data(forKey: legacyKey),
              let items = try? JSONDecoder().decode([ConversationSummary].self, from: data)
        else {
            return []
        }
        persistProtected(sortedConversations(items), at: url)
        defaults.removeObject(forKey: legacyKey)
        return sortedConversations(items)
    }

    func countSessions(userId: String, peers: [ConversationSummary]) -> Int {
        peers.filter { readSession(userId: userId, peerUserId: $0.peerUserId) != nil }.count
    }

    // MARK: - Groups

    func upsertGroupConversation(userId: String, group: GroupSummary) {
        var items = listGroups(userId: userId)
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        if let idx = items.firstIndex(where: { $0.groupId == group.groupId }) {
            var current = items[idx]
            current.displayName = group.displayName
            current.memberCount = group.memberCount
            current.lastPreview = group.lastPreview
            current.updatedAtMillis = now
            items[idx] = current
        } else {
            var g = group
            g.updatedAtMillis = now
            items.append(g)
        }
        persistProtected(items.sorted { $0.updatedAtMillis > $1.updatedAtMillis }, at: groupsURL(userId: userId))
    }

    func markGroupRead(userId: String, groupId: String) {
        var items = listGroups(userId: userId)
        guard let idx = items.firstIndex(where: { $0.groupId == groupId }) else { return }
        var current = items[idx]
        current.unreadCount = 0
        items[idx] = current
        persistProtected(items, at: groupsURL(userId: userId))
    }

    func listGroups(userId: String) -> [GroupSummary] {
        readProtectedCodable(at: groupsURL(userId: userId)) ?? []
    }

    func removeGroup(userId: String, groupId: String) {
        var items = listGroups(userId: userId)
        items.removeAll { $0.groupId == groupId }
        persistProtected(items, at: groupsURL(userId: userId))
    }

    // MARK: - Group Thread Messages

    func appendGroupThreadMessage(userId: String, groupId: String, line: String) {
        var lines: [String] = readProtectedCodable(at: groupThreadURL(userId: userId, groupId: groupId)) ?? []
        lines.append(line)
        if lines.count > 500 {
            lines = Array(lines.suffix(500))
        }
        persistProtected(lines, at: groupThreadURL(userId: userId, groupId: groupId))
    }

    func listGroupThreadMessages(userId: String, groupId: String) -> [String] {
        readProtectedCodable(at: groupThreadURL(userId: userId, groupId: groupId)) ?? []
    }

    // MARK: - Outbox Queue

    struct OutboxItem: Codable {
        let id: String
        let peerUserId: String
        let plaintext: String
        let createdAtMillis: Int64
        let ephemeralTtlSeconds: Int?
        let sealedSender: Bool
    }

    func enqueueOutbox(userId: String, item: OutboxItem) {
        var items: [OutboxItem] = readProtectedCodable(at: outboxURL(userId: userId)) ?? []
        items.append(item)
        persistProtected(items, at: outboxURL(userId: userId))
    }

    func listOutbox(userId: String) -> [OutboxItem] {
        readProtectedCodable(at: outboxURL(userId: userId)) ?? []
    }

    func removeOutboxItem(userId: String, itemId: String) {
        var items: [OutboxItem] = readProtectedCodable(at: outboxURL(userId: userId)) ?? []
        items.removeAll { $0.id == itemId }
        persistProtected(items, at: outboxURL(userId: userId))
    }

    func clearOutbox(userId: String) {
        removeProtectedItem(at: outboxURL(userId: userId))
    }

    // MARK: - Receipt Tracking

    func updateMessageReceipt(userId: String, peerUserId: String, messageId: Int64, receiptType: String) {
        let key = "receipt.\(userId).\(peerUserId).\(messageId)"
        let existing: String? = readProtectedCodable(at: receiptURL(key: key))
        let priority = ["sent": 0, "delivered": 1, "read": 2]
        let currentPriority = priority[existing ?? ""] ?? -1
        let newPriority = priority[receiptType] ?? -1
        if newPriority > currentPriority {
            persistProtected(receiptType, at: receiptURL(key: key))
        }
    }

    func wipeUserState(userId: String) {
        guard !userId.isEmpty else {
            return
        }
        let knownPeers = listConversations(userId: userId).map(\.peerUserId)
        removeProtectedItem(at: progressURL(userId: userId))
        removeProtectedItem(at: cursorURL(userId: userId))
        removeProtectedItem(at: conversationsURL(userId: userId))
        removeProtectedDirectory(at: bundleDirectoryURL(userId: userId))
        removeProtectedDirectory(at: pinsDirectoryURL(userId: userId))
        removeLegacyState(userId: userId)

        let keyPrefix = "keys.\(userId)"
        let sessionPrefix = "session.\(userId)."
        if let accounts = try? keychain.listAccounts() {
            for account in accounts where account == keyPrefix || account.hasPrefix(sessionPrefix) {
                try? keychain.delete(account: account)
            }
        } else {
            try? keychain.delete(account: keyPrefix)
            for peer in knownPeers {
                try? keychain.delete(account: "session.\(userId).\(peer)")
            }
        }

        let currentSetup = loadSetup()
        if currentSetup.userId == userId {
            saveSetup(
                SetupConfig(
                    serverURL: currentSetup.serverURL,
                    userId: "",
                    deviceId: "",
                    suiteLabel: currentSetup.suiteLabel,
                    peerUserId: SetupConfig.default.peerUserId
                )
            )
        }
    }

    private func saveConversations(userId: String, items: [ConversationSummary]) {
        persistProtected(sortedConversations(items), at: conversationsURL(userId: userId))
        defaults.removeObject(forKey: conversationsKey(userId: userId))
    }

    private func migrateLegacyIdentityPins(userId: String) {
        let prefix = "pin.\(userId)."
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix(prefix) {
            guard let data = defaults.data(forKey: key),
                  let pin = try? JSONDecoder().decode(IdentityPin.self, from: data)
            else {
                continue
            }
            let peer = String(key.dropFirst(prefix.count))
            persistProtected(pin, at: pinURL(userId: userId, peerUserId: peer))
            defaults.removeObject(forKey: key)
        }
    }

    private func readProtectedCodable<T: Decodable>(at url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else {
            return nil
        }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    private func persistProtected<T: Encodable>(_ value: T, at url: URL) {
        guard let data = try? JSONEncoder().encode(value) else {
            return
        }
        writeProtectedData(data, to: url)
    }

    // Use file protection that keeps metadata unavailable until first unlock
    // while still allowing normal app use after boot.
    private func writeProtectedData(_ data: Data, to url: URL) {
        let dir = url.deletingLastPathComponent()
        try? fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        if fileManager.fileExists(atPath: url.path) {
            try? data.write(to: url, options: .atomic)
        } else {
            fileManager.createFile(
                atPath: url.path,
                contents: data,
                attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
            )
        }
        try? fileManager.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: url.path
        )
    }

    private func setupURL() -> URL {
        protectedRoot.appendingPathComponent("setup.json")
    }

    private func progressURL(userId: String) -> URL {
        protectedRoot
            .appendingPathComponent("progress", isDirectory: true)
            .appendingPathComponent(safeComponent(userId.isEmpty ? "_" : userId))
            .appendingPathExtension("json")
    }

    private func cursorURL(userId: String) -> URL {
        protectedRoot
            .appendingPathComponent("cursors", isDirectory: true)
            .appendingPathComponent(safeComponent(userId))
            .appendingPathExtension("json")
    }

    private func bundleURL(userId: String, peerUserId: String) -> URL {
        bundleDirectoryURL(userId: userId)
            .appendingPathComponent(safeComponent(peerUserId))
            .appendingPathExtension("json")
    }

    private func bundleDirectoryURL(userId: String) -> URL {
        protectedRoot
            .appendingPathComponent("bundles", isDirectory: true)
            .appendingPathComponent(safeComponent(userId), isDirectory: true)
    }

    private func pinsDirectoryURL(userId: String) -> URL {
        protectedRoot
            .appendingPathComponent("pins", isDirectory: true)
            .appendingPathComponent(safeComponent(userId), isDirectory: true)
    }

    private func pinURL(userId: String, peerUserId: String) -> URL {
        pinsDirectoryURL(userId: userId)
            .appendingPathComponent(safeComponent(peerUserId))
            .appendingPathExtension("json")
    }

    private func conversationsURL(userId: String) -> URL {
        protectedRoot
            .appendingPathComponent("conversations", isDirectory: true)
            .appendingPathComponent(safeComponent(userId))
            .appendingPathExtension("json")
    }

    private func groupsURL(userId: String) -> URL {
        protectedRoot
            .appendingPathComponent("groups", isDirectory: true)
            .appendingPathComponent(safeComponent(userId))
            .appendingPathExtension("json")
    }

    private func groupThreadURL(userId: String, groupId: String) -> URL {
        protectedRoot
            .appendingPathComponent("group-threads", isDirectory: true)
            .appendingPathComponent(safeComponent(userId), isDirectory: true)
            .appendingPathComponent(safeComponent(groupId))
            .appendingPathExtension("json")
    }

    private func outboxURL(userId: String) -> URL {
        protectedRoot
            .appendingPathComponent("outbox", isDirectory: true)
            .appendingPathComponent(safeComponent(userId))
            .appendingPathExtension("json")
    }

    private func receiptURL(key: String) -> URL {
        protectedRoot
            .appendingPathComponent("receipts", isDirectory: true)
            .appendingPathComponent(safeComponent(key))
            .appendingPathExtension("json")
    }

    private func legacyProgressKey(userId: String) -> String {
        let normalized = userId.isEmpty ? "_" : userId
        return "progress.\(normalized)"
    }

    private func conversationsKey(userId: String) -> String {
        "conversations.\(userId)"
    }

    private func normalizedPreview(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let base = trimmed.isEmpty ? "No content" : trimmed
        if base.count <= 160 {
            return base
        }
        let index = base.index(base.startIndex, offsetBy: 157)
        return String(base[..<index]) + "..."
    }

    private func sortedConversations(_ items: [ConversationSummary]) -> [ConversationSummary] {
        items.sorted { lhs, rhs in
            if lhs.updatedAtMillis == rhs.updatedAtMillis {
                return lhs.peerUserId < rhs.peerUserId
            }
            return lhs.updatedAtMillis > rhs.updatedAtMillis
        }
    }

    private func removeLegacyState(userId: String) {
        defaults.removeObject(forKey: legacyProgressKey(userId: userId))
        defaults.removeObject(forKey: "cursor.\(userId)")
        defaults.removeObject(forKey: conversationsKey(userId: userId))
        let bundlePrefix = "bundle.\(userId)."
        let pinPrefix = "pin.\(userId)."
        for key in defaults.dictionaryRepresentation().keys {
            if key.hasPrefix(bundlePrefix) || key.hasPrefix(pinPrefix) {
                defaults.removeObject(forKey: key)
            }
        }
    }

    private func removeProtectedItem(at url: URL) {
        try? fileManager.removeItem(at: url)
    }

    private func removeProtectedDirectory(at url: URL) {
        guard fileManager.fileExists(atPath: url.path) else {
            return
        }
        try? fileManager.removeItem(at: url)
    }

    private func safeComponent(_ value: String) -> String {
        let raw = value.isEmpty ? "_" : value
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._")
        return raw.addingPercentEncoding(withAllowedCharacters: allowed) ?? raw
    }
}
