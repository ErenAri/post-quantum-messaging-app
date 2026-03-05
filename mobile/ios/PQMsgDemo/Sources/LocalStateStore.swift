import Foundation

final class LocalStateStore {
    static let shared = LocalStateStore()

    private let defaults = UserDefaults.standard
    private let keychain = KeychainStore(service: "com.pqmsg.demo.ios")

    private init() {}

    func loadSetup() -> SetupConfig {
        guard let data = defaults.data(forKey: "setup_config"),
              let config = try? JSONDecoder().decode(SetupConfig.self, from: data)
        else {
            return .default
        }
        return config
    }

    func saveSetup(_ config: SetupConfig) {
        guard let encoded = try? JSONEncoder().encode(config) else {
            return
        }
        defaults.set(encoded, forKey: "setup_config")
    }

    func loadProgress(userId: String) -> SetupProgress {
        let key = progressKey(userId: userId)
        guard let data = defaults.data(forKey: key),
              let progress = try? JSONDecoder().decode(SetupProgress.self, from: data)
        else {
            return .default
        }
        return progress
    }

    func saveProgress(userId: String, progress: SetupProgress) {
        let key = progressKey(userId: userId)
        guard let encoded = try? JSONEncoder().encode(progress) else {
            return
        }
        defaults.set(encoded, forKey: key)
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
        defaults.object(forKey: "cursor.\(userId)") as? Int64 ?? 0
    }

    func writeCursor(userId: String, cursor: Int64) {
        defaults.set(cursor, forKey: "cursor.\(userId)")
    }

    func writeBundleFetchedAt(userId: String, peerUserId: String, timestamp: String) {
        defaults.set(timestamp, forKey: "bundle.\(userId).\(peerUserId)")
    }

    func readBundleFetchedAt(userId: String, peerUserId: String) -> String? {
        defaults.string(forKey: "bundle.\(userId).\(peerUserId)")
    }

    func readIdentityPin(userId: String, peerUserId: String) -> IdentityPin? {
        let key = "pin.\(userId).\(peerUserId)"
        guard let data = defaults.data(forKey: key) else {
            return nil
        }
        return try? JSONDecoder().decode(IdentityPin.self, from: data)
    }

    func writeIdentityPin(userId: String, peerUserId: String, pin: IdentityPin) {
        let key = "pin.\(userId).\(peerUserId)"
        guard let encoded = try? JSONEncoder().encode(pin) else {
            return
        }
        defaults.set(encoded, forKey: key)
    }

    func listIdentityPins(userId: String) -> [IdentityPinRecord] {
        let prefix = "pin.\(userId)."
        return defaults.dictionaryRepresentation().keys
            .filter { $0.hasPrefix(prefix) }
            .compactMap { key -> IdentityPinRecord? in
                let peer = String(key.dropFirst(prefix.count))
                guard let pin = readIdentityPin(userId: userId, peerUserId: peer) else {
                    return nil
                }
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
        guard let data = defaults.data(forKey: conversationsKey(userId: userId)),
              let items = try? JSONDecoder().decode([ConversationSummary].self, from: data)
        else {
            return []
        }
        return items.sorted { lhs, rhs in
            if lhs.updatedAtMillis == rhs.updatedAtMillis {
                return lhs.peerUserId < rhs.peerUserId
            }
            return lhs.updatedAtMillis > rhs.updatedAtMillis
        }
    }

    func countSessions(userId: String, peers: [ConversationSummary]) -> Int {
        peers.filter { readSession(userId: userId, peerUserId: $0.peerUserId) != nil }.count
    }

    private func saveConversations(userId: String, items: [ConversationSummary]) {
        let sorted = items.sorted { lhs, rhs in
            if lhs.updatedAtMillis == rhs.updatedAtMillis {
                return lhs.peerUserId < rhs.peerUserId
            }
            return lhs.updatedAtMillis > rhs.updatedAtMillis
        }
        guard let encoded = try? JSONEncoder().encode(sorted) else {
            return
        }
        defaults.set(encoded, forKey: conversationsKey(userId: userId))
    }

    private func progressKey(userId: String) -> String {
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
}
