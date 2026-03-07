import CryptoKit
import Foundation
import Security

struct SetupConfig: Codable {
    var serverURL: String
    var userId: String
    var deviceId: String
    var suiteLabel: String
    var peerUserId: String

    static let `default` = SetupConfig(
        serverURL: "http://127.0.0.1:3000",
        userId: "",
        deviceId: "",
        suiteLabel: "ml-kem-768",
        peerUserId: "bob"
    )
}

struct SetupProgress: Codable {
    var keysGenerated: Bool
    var userRegistered: Bool
    var prekeysPublished: Bool
    var serverVerified: Bool

    static let `default` = SetupProgress(
        keysGenerated: false,
        userRegistered: false,
        prekeysPublished: false,
        serverVerified: false
    )

    func afterKeysGenerated() -> SetupProgress {
        SetupProgress(
            keysGenerated: true,
            userRegistered: false,
            prekeysPublished: false,
            serverVerified: false
        )
    }

    func afterUserRegistered() -> SetupProgress {
        SetupProgress(
            keysGenerated: keysGenerated,
            userRegistered: true,
            prekeysPublished: false,
            serverVerified: false
        )
    }

    func afterPrekeysPublished() -> SetupProgress {
        SetupProgress(
            keysGenerated: keysGenerated,
            userRegistered: userRegistered,
            prekeysPublished: true,
            serverVerified: false
        )
    }

    func afterServerVerified() -> SetupProgress {
        SetupProgress(
            keysGenerated: keysGenerated,
            userRegistered: userRegistered,
            prekeysPublished: prekeysPublished,
            serverVerified: true
        )
    }

    func adoptLinkedDevice() -> SetupProgress {
        SetupProgress(
            keysGenerated: true,
            userRegistered: true,
            prekeysPublished: true,
            serverVerified: false
        )
    }

    func isAdoptedLinkedDevice() -> Bool {
        keysGenerated && userRegistered && prekeysPublished && !serverVerified
    }

    func canRegister() -> Bool {
        keysGenerated && !userRegistered
    }

    func canPublishPrekeys() -> Bool {
        keysGenerated && userRegistered
    }

    func canVerifyServer() -> Bool {
        keysGenerated && userRegistered && prekeysPublished
    }

    func canOpenConversations() -> Bool {
        keysGenerated && userRegistered && prekeysPublished && serverVerified
    }
}

struct ConversationSummary: Codable, Identifiable, Hashable {
    var peerUserId: String
    var lastPreview: String
    var updatedAtMillis: Int64
    var unreadCount: Int

    var id: String { peerUserId }
}

struct IdentityPin: Codable, Hashable {
    var fingerprintSha256: String
    var identityKeyVersion: Int
    var identitySigPub: String
    var observedAt: String
}

struct IdentityPinRecord: Hashable {
    var peerUserId: String
    var pin: IdentityPin
}

struct RegisterUserRequest: Codable {
    let user_id: String
    let identity_x25519_pub: String
    let identity_sig_pub: String
    let device_id: String
}

struct RegisterUserResponse: Codable {
    let user_id: String
    let device_id: String
    let registered_at: String
}

struct PublishPrekeysRequest: Codable {
    let signed_prekey_x25519_pub: String
    let sig_over_spk: String
    let pq_signed_prekey_pub_mlkem768: String
    let sig_over_pqspk: String
    let one_time_prekeys_x25519: [String]
    let one_time_prekeys_mlkem768: [String]
}

struct PublishPrekeysResponse: Codable {
    let user_id: String
    let device_id: String
    let uploaded_one_time_prekeys_x25519: Int
    let uploaded_one_time_prekeys_mlkem768: Int
    let remaining_one_time_prekeys_x25519: Int
    let remaining_one_time_prekeys_mlkem768: Int
    let low_one_time_prekeys: Bool
    let minimum_recommended_one_time_prekeys: Int
    let updated_at: String
}

struct BundleResponse: Codable {
    let user_id: String
    let device_id: String
    let identity_x25519_pub: String
    let identity_sig_pub: String
    let signed_prekey_x25519_pub: String
    let sig_over_spk: String
    let pq_signed_prekey_pub_mlkem768: String
    let sig_over_pqspk: String
    let one_time_prekey_x25519: String?
    let one_time_prekey_mlkem768: String?
    let remaining_one_time_prekeys_x25519: Int?
    let remaining_one_time_prekeys_mlkem768: Int?
    let low_one_time_prekeys: Bool?
    let minimum_recommended_one_time_prekeys: Int?
    let last_resort_prekey_only: Bool?
    let identity_key_version: Int?
    let identity_fingerprint_sha256: String?
    let bundle_generated_at: String
}

struct RelayRequest: Codable {
    let sender_user_id: String
    let device_id: String
    let message_bytes_base64: String
}

struct RelayResponse: Codable {
    let message_id: Int64
    let received_at: String
}

struct InboxMessage: Codable, Hashable {
    let message_id: Int64
    let sender_user_id: String
    let message_bytes_base64: String
    let received_at: String
}

struct InboxResponse: Codable {
    let user_id: String
    let messages: [InboxMessage]
}

struct RegisterPushTokenRequest: Codable {
    let device_id: String
    let provider: String?
    let token: String?
    let fcm_token: String?
}

struct RegisterPushTokenResponse: Codable {
    let user_id: String
    let device_id: String
    let provider: String
    let registered_at: String
}

struct RetireCurrentDeviceResponse: Codable {
    let user_id: String
    let retired_device_id: String
    let retired_at: String
    let remaining_active_devices: Int
}

struct LinkDeviceResponse: Codable {
    let user_id: String
    let linked_device_id: String
    let linked_at: String
}

struct RevokeDeviceResponse: Codable {
    let user_id: String
    let revoked_device_id: String
    let revoked_at: String
}

struct DeviceRecord: Codable, Hashable, Identifiable {
    let device_id: String
    let active: Bool
    let linked_at: String
    let revoked_at: String?

    var id: String { device_id }
}

struct DeviceListResponse: Codable {
    let user_id: String
    let devices: [DeviceRecord]
}

struct RotateInitRequest: Codable {
    let new_identity_x25519_pub: String
    let new_identity_sig_pub: String
    let new_device_id: String
}

struct RotateInitResponse: Codable {
    let user_id: String
    let challenge_id: String
    let challenge_nonce: String
    let expires_at: String
}

struct RotateConfirmRequest: Codable {
    let challenge_id: String
    let sig_by_current_identity: String
    let sig_by_new_identity: String
}

struct RotateConfirmResponse: Codable {
    let user_id: String
    let identity_key_version: Int
    let identity_fingerprint_sha256: String
    let rotated_at: String
}

struct IdentityLogItem: Codable, Hashable, Identifiable {
    let version: Int
    let identity_x25519_pub: String
    let identity_sig_pub: String
    let device_id: String
    let event_type: String
    let changed_at: String
    let identity_fingerprint_sha256: String

    var id: Int { version }
}

struct IdentityLogResponse: Codable {
    let user_id: String
    let events: [IdentityLogItem]
}

struct OnboardingPackageRecord: Hashable {
    let userId: String
    let deviceId: String
    let linkedAt: String
    var packageText: String
}

struct RuntimeCryptoProfileResponse: Codable {
    let protocol_version: Int
    let suite_id: Int
    let kem: String
    let dh: String
    let kdf: String
    let aead: String
    let signature: String
    let pq_oqs_enabled: Bool
    let fips_mode: Bool
}

struct ServerCapabilitiesResponse: Codable {
    let capability_schema_version: Int
    let security_profile: String
    let deployment_mode: String
    let tls_required: Bool
    let tls_enabled: Bool
    let supported_suite_ids: [Int]
    let runtime_crypto_profile: RuntimeCryptoProfileResponse
    let production_baseline_met: Bool
    let registration_pow_bits: Int
    let prekey_bundle_reserve_count: Int
    let pq_ratchet_interval: Int
    let web_client_policy: String
}

enum IdentityRotationSupportError: LocalizedError {
    case invalidInput(String)

    var errorDescription: String? {
        switch self {
        case let .invalidInput(reason):
            return reason
        }
    }
}

private struct StoredIdentityKeys: Decodable {
    let user_id: String
    let device_id: String
    let identity_x25519_pub_b64: String
    let identity_sig_pub_b64: String
    let identity_sig_secret_b64: String
}

private struct TlvRecordData {
    let ty: UInt16
    let value: Data
}

enum IdentityRotationSupport {
    private static let authTagEndpoint: UInt16 = 0xB201
    private static let authTagUserId: UInt16 = 0xB202
    private static let authTagDeviceId: UInt16 = 0xB203
    private static let authTagTimestamp: UInt16 = 0xB204
    private static let authTagNonce: UInt16 = 0xB205
    private static let authTagRecipientId: UInt16 = 0xB206
    private static let authTagRotateNewX25519Hash: UInt16 = 0xB20B
    private static let authTagRotateNewSigHash: UInt16 = 0xB20C
    private static let authTagRotateChallengeId: UInt16 = 0xB20D
    private static let authTagRotateSigCurrentHash: UInt16 = 0xB20E
    private static let authTagRotateSigNewHash: UInt16 = 0xB20F
    private static let rotateSigTagUserId: UInt16 = 0xB101
    private static let rotateSigTagChallengeId: UInt16 = 0xB102
    private static let rotateSigTagChallengeNonce: UInt16 = 0xB103
    private static let rotateSigTagNewIdentityX25519: UInt16 = 0xB104
    private static let rotateSigTagNewIdentitySig: UInt16 = 0xB105
    private static let rotateSigTagNewDeviceId: UInt16 = 0xB106

    static func buildRotateInitRequest(newKeysJson: String) throws -> RotateInitRequest {
        let keys = try decodeKeys(newKeysJson)
        return RotateInitRequest(
            new_identity_x25519_pub: keys.identity_x25519_pub_b64,
            new_identity_sig_pub: keys.identity_sig_pub_b64,
            new_device_id: keys.device_id
        )
    }

    static func buildRotateInitHeaders(
        currentKeysJson: String,
        userId: String,
        request: RotateInitRequest
    ) throws -> [String: String] {
        let keys = try decodeKeys(currentKeysJson)
        try requireUser(userId, matches: keys.user_id, label: "keys")
        let signingKey = try loadSigningKey(keys)
        let timestamp = currentTimestamp()
        let nonce = try randomNonceBase64()
        var records = authCommonRecords(
            endpoint: "rotate-init",
            userId: userId,
            deviceId: keys.device_id,
            timestamp: timestamp,
            nonce: nonce
        )
        records.append(
            TlvRecordData(
                ty: authTagRotateNewX25519Hash,
                value: sha256(Data(request.new_identity_x25519_pub.utf8))
            )
        )
        records.append(
            TlvRecordData(
                ty: authTagRotateNewSigHash,
                value: sha256(Data(request.new_identity_sig_pub.utf8))
            )
        )
        let signature = try signingKey.signature(for: encodeTlv(records))
        return authHeaderMap(
            userId: userId,
            deviceId: keys.device_id,
            timestamp: timestamp,
            nonce: nonce,
            signature: signature
        )
    }

    static func buildRotateConfirmRequest(
        currentKeysJson: String,
        newKeysJson: String,
        userId: String,
        challengeId: String,
        challengeNonceBase64: String
    ) throws -> RotateConfirmRequest {
        let currentKeys = try decodeKeys(currentKeysJson)
        let newKeys = try decodeKeys(newKeysJson)
        try requireUser(userId, matches: currentKeys.user_id, label: "current keys")
        try requireUser(userId, matches: newKeys.user_id, label: "new keys")
        guard let challengeNonce = Data(base64Encoded: challengeNonceBase64) else {
            throw IdentityRotationSupportError.invalidInput("invalid base64 for challenge_nonce")
        }
        let currentSigningKey = try loadSigningKey(currentKeys)
        let newSigningKey = try loadSigningKey(newKeys)
        let message = try rotationSignatureMessage(
            userId: userId,
            challengeId: challengeId,
            challengeNonce: challengeNonce,
            newIdentityX25519Base64: newKeys.identity_x25519_pub_b64,
            newIdentitySigBase64: newKeys.identity_sig_pub_b64,
            newDeviceId: newKeys.device_id
        )
        return RotateConfirmRequest(
            challenge_id: challengeId,
            sig_by_current_identity: try currentSigningKey.signature(for: message).base64EncodedString(),
            sig_by_new_identity: try newSigningKey.signature(for: message).base64EncodedString()
        )
    }

    static func buildRotateConfirmHeaders(
        currentKeysJson: String,
        userId: String,
        request: RotateConfirmRequest
    ) throws -> [String: String] {
        let keys = try decodeKeys(currentKeysJson)
        try requireUser(userId, matches: keys.user_id, label: "keys")
        let signingKey = try loadSigningKey(keys)
        let timestamp = currentTimestamp()
        let nonce = try randomNonceBase64()
        var records = authCommonRecords(
            endpoint: "rotate-confirm",
            userId: userId,
            deviceId: keys.device_id,
            timestamp: timestamp,
            nonce: nonce
        )
        records.append(
            TlvRecordData(
                ty: authTagRotateChallengeId,
                value: Data(request.challenge_id.utf8)
            )
        )
        records.append(
            TlvRecordData(
                ty: authTagRotateSigCurrentHash,
                value: sha256(Data(request.sig_by_current_identity.utf8))
            )
        )
        records.append(
            TlvRecordData(
                ty: authTagRotateSigNewHash,
                value: sha256(Data(request.sig_by_new_identity.utf8))
            )
        )
        let signature = try signingKey.signature(for: encodeTlv(records))
        return authHeaderMap(
            userId: userId,
            deviceId: keys.device_id,
            timestamp: timestamp,
            nonce: nonce,
            signature: signature
        )
    }

    static func buildIdentityLogHeaders(
        keysJson: String,
        userId: String
    ) throws -> [String: String] {
        let keys = try decodeKeys(keysJson)
        try requireUser(userId, matches: keys.user_id, label: "keys")
        let signingKey = try loadSigningKey(keys)
        let timestamp = currentTimestamp()
        let nonce = try randomNonceBase64()
        let records = authCommonRecords(
            endpoint: "identity-log",
            userId: userId,
            deviceId: keys.device_id,
            timestamp: timestamp,
            nonce: nonce
        ) + [
            TlvRecordData(ty: authTagRecipientId, value: Data(userId.utf8)),
        ]
        let signature = try signingKey.signature(for: encodeTlv(records))
        return authHeaderMap(
            userId: userId,
            deviceId: keys.device_id,
            timestamp: timestamp,
            nonce: nonce,
            signature: signature
        )
    }

    private static func decodeKeys(_ keysJson: String) throws -> StoredIdentityKeys {
        let data = Data(keysJson.utf8)
        do {
            return try JSONDecoder().decode(StoredIdentityKeys.self, from: data)
        } catch {
            throw IdentityRotationSupportError.invalidInput("invalid keys JSON")
        }
    }

    private static func requireUser(_ userId: String, matches expected: String, label: String) throws {
        if userId != expected {
            throw IdentityRotationSupportError.invalidInput(
                "user_id '\(userId)' does not match \(label) user '\(expected)'"
            )
        }
    }

    private static func loadSigningKey(_ keys: StoredIdentityKeys) throws -> Curve25519.Signing.PrivateKey {
        guard let secret = Data(base64Encoded: keys.identity_sig_secret_b64) else {
            throw IdentityRotationSupportError.invalidInput("invalid base64 for identity_sig_secret_b64")
        }
        let signingKey: Curve25519.Signing.PrivateKey
        do {
            signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: secret)
        } catch {
            throw IdentityRotationSupportError.invalidInput("identity_sig_secret_b64 is not a valid Ed25519 private key")
        }
        let publicB64 = signingKey.publicKey.rawRepresentation.base64EncodedString()
        if publicB64 != keys.identity_sig_pub_b64 {
            throw IdentityRotationSupportError.invalidInput(
                "identity_sig_pub_b64 does not match identity_sig_secret_b64"
            )
        }
        return signingKey
    }

    private static func currentTimestamp() -> Int64 {
        Int64(Date().timeIntervalSince1970.rounded(.down))
    }

    private static func randomNonceBase64() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            throw IdentityRotationSupportError.invalidInput("failed to generate auth nonce")
        }
        return Data(bytes).base64EncodedString()
    }

    private static func authCommonRecords(
        endpoint: String,
        userId: String,
        deviceId: String,
        timestamp: Int64,
        nonce: String
    ) -> [TlvRecordData] {
        [
            TlvRecordData(ty: authTagEndpoint, value: Data(endpoint.utf8)),
            TlvRecordData(ty: authTagUserId, value: Data(userId.utf8)),
            TlvRecordData(ty: authTagDeviceId, value: Data(deviceId.utf8)),
            TlvRecordData(ty: authTagTimestamp, value: int64Data(timestamp)),
            TlvRecordData(ty: authTagNonce, value: Data(nonce.utf8)),
        ]
    }

    private static func rotationSignatureMessage(
        userId: String,
        challengeId: String,
        challengeNonce: Data,
        newIdentityX25519Base64: String,
        newIdentitySigBase64: String,
        newDeviceId: String
    ) throws -> Data {
        guard let newIdentityX25519 = Data(base64Encoded: newIdentityX25519Base64) else {
            throw IdentityRotationSupportError.invalidInput("invalid base64 for identity_x25519_pub_b64")
        }
        guard let newIdentitySig = Data(base64Encoded: newIdentitySigBase64) else {
            throw IdentityRotationSupportError.invalidInput("invalid base64 for identity_sig_pub_b64")
        }
        return encodeTlv([
            TlvRecordData(ty: rotateSigTagUserId, value: Data(userId.utf8)),
            TlvRecordData(ty: rotateSigTagChallengeId, value: Data(challengeId.utf8)),
            TlvRecordData(ty: rotateSigTagChallengeNonce, value: challengeNonce),
            TlvRecordData(ty: rotateSigTagNewIdentityX25519, value: newIdentityX25519),
            TlvRecordData(ty: rotateSigTagNewIdentitySig, value: newIdentitySig),
            TlvRecordData(ty: rotateSigTagNewDeviceId, value: Data(newDeviceId.utf8)),
        ])
    }

    private static func authHeaderMap(
        userId: String,
        deviceId: String,
        timestamp: Int64,
        nonce: String,
        signature: Data
    ) -> [String: String] {
        [
            "x-pqmsg-auth-user": userId,
            "x-pqmsg-auth-device": deviceId,
            "x-pqmsg-auth-timestamp": String(timestamp),
            "x-pqmsg-auth-nonce": nonce,
            "x-pqmsg-auth-signature": signature.base64EncodedString(),
        ]
    }

    private static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    private static func encodeTlv(_ records: [TlvRecordData]) -> Data {
        var output = Data()
        for record in records {
            output.append(uint16Data(record.ty))
            output.append(uint16Data(UInt16(record.value.count)))
            output.append(record.value)
        }
        return output
    }

    private static func uint16Data(_ value: UInt16) -> Data {
        var bigEndian = value.bigEndian
        return Data(bytes: &bigEndian, count: MemoryLayout<UInt16>.size)
    }

    private static func int64Data(_ value: Int64) -> Data {
        var bigEndian = value.bigEndian
        return Data(bytes: &bigEndian, count: MemoryLayout<Int64>.size)
    }
}
