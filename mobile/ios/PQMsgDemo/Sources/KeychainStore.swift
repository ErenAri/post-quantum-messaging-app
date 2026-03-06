import Foundation
import Security

final class KeychainStore {
    private let service: String

    init(service: String) {
        self.service = service
    }

    func setString(_ value: String, account: String) throws {
        let encoded = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: encoded,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw KeychainStoreError.osStatus(updateStatus)
        }
        var insert = query
        attributes.forEach { insert[$0.key] = $0.value }
        let addStatus = SecItemAdd(insert as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainStoreError.osStatus(addStatus)
        }
    }

    func getString(account: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw KeychainStoreError.osStatus(status)
        }
        guard let data = result as? Data else {
            throw KeychainStoreError.invalidData
        }
        guard let value = String(data: data, encoding: .utf8) else {
            throw KeychainStoreError.invalidUtf8
        }
        return value
    }

    func delete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            return
        }
        throw KeychainStoreError.osStatus(status)
    }

    func listAccounts() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw KeychainStoreError.osStatus(status)
        }
        if let items = result as? [[String: Any]] {
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        }
        if let item = result as? [String: Any],
           let account = item[kSecAttrAccount as String] as? String {
            return [account]
        }
        return []
    }
}

enum KeychainStoreError: Error {
    case osStatus(OSStatus)
    case invalidData
    case invalidUtf8
}
