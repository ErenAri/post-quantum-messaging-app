package com.pqmsg.demo

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class MessagingCoordinatorTest {
    private fun b64(length: Int, seed: Int): String {
        val bytes = ByteArray(length) { index -> (seed + index).toByte() }
        return Base64.getEncoder().encodeToString(bytes)
    }

    @Test
    fun parse_compose_target_normalizes_direct_usernames() {
        val target = MessagingCoordinator.parseComposeTarget(
            "  @TestUser  ",
            "http://10.0.2.2:3000",
        )

        assertEquals("TestUser", target.peerUserId)
        assertEquals("http://10.0.2.2:3000/", target.serverUrl)
    }

    @Test
    fun parse_compose_target_extracts_web_invite_links() {
        val target = MessagingCoordinator.parseComposeTarget(
            "https://app.test/chat?invite=InviteUser",
            "http://10.0.2.2:3000",
        )

        assertEquals("InviteUser", target.peerUserId)
        assertEquals("http://10.0.2.2:3000/", target.serverUrl)
    }

    @Test
    fun parse_compose_target_extracts_opaque_invite_tokens() {
        val target = MessagingCoordinator.parseComposeTarget(
            "https://app.test/chat?invite_token=opaque-token-123&server=https%3A%2F%2Frelay.example",
            "http://10.0.2.2:3000",
        )

        assertEquals("", target.peerUserId)
        assertEquals("opaque-token-123", target.inviteToken)
        assertEquals("https://relay.example/", target.serverUrl)
    }

    @Test
    fun normalized_device_id_defaults_from_user() {
        val deviceId = MessagingCoordinator.normalizedDeviceId("alice", "")

        assertEquals("alice-android-1", deviceId)
    }

    @Test
    fun normalize_suite_label_defaults_to_ml_kem() {
        assertEquals("ml-kem-768", MessagingCoordinator.normalizeSuiteLabel("   "))
        assertEquals("kyber768", MessagingCoordinator.normalizeSuiteLabel("KYBER768"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parse_compose_target_rejects_blank_input() {
        MessagingCoordinator.parseComposeTarget(
            "   ",
            "http://10.0.2.2:3000",
        )
    }

    @Test
    fun transparency_proof_matches_hybrid_identity_pin() {
        val proof = TransparencyProofResponse(
            user_id = "alice",
            leaf = TransparencyLeafRecord(
                user_id = "alice",
                version = 3,
                identity_x25519_pub = b64(32, 1),
                identity_sig_pub = b64(32, 40),
                identity_pq_sig_pub = b64(48, 80),
                timestamp = 1_700_000_000L,
            ),
            inclusion_proof = TransparencyInclusionProofResponse(
                leaf_index = 0L,
                path = emptyList(),
            ),
            signed_tree_head = TransparencySignedTreeHeadResponse(
                epoch = 3L,
                tree_size = 3L,
                root_hash = b64(32, 120),
                signature = b64(64, 160),
            ),
            consistency_proof = null,
        )
        val pin = IdentityPin(
            fingerprintSha256 = MessagingCoordinator.transparencyLeafFingerprint(proof.leaf),
            identityKeyVersion = 3,
            identityX25519Pub = proof.leaf.identity_x25519_pub,
            identitySigPub = proof.leaf.identity_sig_pub,
            identityPqSigPub = proof.leaf.identity_pq_sig_pub.orEmpty(),
            observedAt = "2026-03-12T00:00:00Z",
        )

        assertTrue(MessagingCoordinator.transparencyProofMatchesIdentityPin("alice", proof, pin))
    }

    @Test
    fun transparency_proof_rejects_mismatched_hybrid_identity_pin() {
        val proof = TransparencyProofResponse(
            user_id = "alice",
            leaf = TransparencyLeafRecord(
                user_id = "alice",
                version = 3,
                identity_x25519_pub = b64(32, 2),
                identity_sig_pub = b64(32, 41),
                identity_pq_sig_pub = b64(48, 81),
                timestamp = 1_700_000_000L,
            ),
            inclusion_proof = TransparencyInclusionProofResponse(
                leaf_index = 0L,
                path = emptyList(),
            ),
            signed_tree_head = TransparencySignedTreeHeadResponse(
                epoch = 3L,
                tree_size = 3L,
                root_hash = b64(32, 121),
                signature = b64(64, 161),
            ),
            consistency_proof = null,
        )
        val pin = IdentityPin(
            fingerprintSha256 = MessagingCoordinator.transparencyLeafFingerprint(proof.leaf),
            identityKeyVersion = 3,
            identityX25519Pub = b64(32, 99),
            identitySigPub = proof.leaf.identity_sig_pub,
            identityPqSigPub = proof.leaf.identity_pq_sig_pub.orEmpty(),
            observedAt = "2026-03-12T00:00:00Z",
        )

        assertFalse(MessagingCoordinator.transparencyProofMatchesIdentityPin("alice", proof, pin))
    }
}
