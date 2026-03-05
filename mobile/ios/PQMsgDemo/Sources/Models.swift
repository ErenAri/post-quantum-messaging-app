import Foundation

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

    func canRegister() -> Bool {
        keysGenerated
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
    let fcm_token: String
}

struct RegisterPushTokenResponse: Codable {
    let user_id: String
    let device_id: String
    let provider: String
    let registered_at: String
}
