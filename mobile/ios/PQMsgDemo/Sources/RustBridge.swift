import CryptoKit
import Foundation

enum RustBridgeError: Error {
    case missingKeys(String)
    case invalidBundleIdentity
    case identityChanged(String)
}

extension RequestAuthHeaders {
    func toHeaderMap() -> [String: String] {
        [
            "x-pqmsg-auth-user": authUser,
            "x-pqmsg-auth-device": authDevice,
            "x-pqmsg-auth-timestamp": authTimestamp,
            "x-pqmsg-auth-nonce": authNonce,
            "x-pqmsg-auth-signature": authSignature,
        ]
    }
}

extension BundleResponse {
    func toRustBundle() -> ServerBundle {
        ServerBundle(
            userId: user_id,
            identityX25519Pub: identity_x25519_pub,
            identitySigPub: identity_sig_pub,
            signedPrekeyX25519Pub: signed_prekey_x25519_pub,
            sigOverSpk: sig_over_spk,
            pqSignedPrekeyPubMlkem768: pq_signed_prekey_pub_mlkem768,
            sigOverPqspk: sig_over_pqspk,
            oneTimePrekeyX25519: one_time_prekey_x25519,
            oneTimePrekeyMlkem768: one_time_prekey_mlkem768
        )
    }

    func identityFingerprint() throws -> String {
        if let existing = identity_fingerprint_sha256?.trimmingCharacters(in: .whitespacesAndNewlines),
           !existing.isEmpty {
            return existing.lowercased()
        }
        guard let keyData = Data(base64Encoded: identity_x25519_pub) else {
            throw RustBridgeError.invalidBundleIdentity
        }
        let digest = SHA256.hash(data: keyData)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
