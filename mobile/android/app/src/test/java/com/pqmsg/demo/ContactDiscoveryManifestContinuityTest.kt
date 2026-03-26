package com.pqmsg.demo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContactDiscoveryManifestContinuityTest {
    private fun manifest(
        oprfPublicKey: String = "oprf-pub-1",
        attestationMode: String = "service_boundary_only",
    ) = ContactDiscoveryManifestResponse(
        service = "cdsi-preview",
        protocol_version = 1,
        attestation_mode = attestationMode,
        ticket_format = "ed25519-ticket-v1",
        ticket_issuer_ed25519_pub = "ticket-issuer-pub",
        ticket_max_ttl_seconds = 300,
        lookup_protocol = "blind_token_directory_preview",
        privacy_mode = "blind_evaluation_preview",
        match_result_format = "contact_invite_token",
        oprf_suite = "ristretto255-sha512-preview",
        oprf_public_key_ristretto255 = oprfPublicKey,
        signed_at = "2026-03-26T00:00:00Z",
        expires_at = "2026-03-26T00:05:00Z",
        manifest_issuer_ed25519_pub = "manifest-issuer-pub",
        manifest_signature_ed25519 = "sig",
    )

    @Test
    fun diffContactDiscoveryManifestCheckpoint_returnsEmptyForSameIdentityMaterial() {
        val previous = buildContactDiscoveryManifestCheckpoint(
            serviceOrigin = "https://cdsi.example",
            manifest = manifest(),
            observedAt = "2026-03-26T00:00:00Z",
        )
        val current = buildContactDiscoveryManifestCheckpoint(
            serviceOrigin = "https://cdsi.example",
            manifest = manifest(),
            observedAt = "2026-03-26T00:01:00Z",
        )

        assertTrue(diffContactDiscoveryManifestCheckpoint(previous, current).isEmpty())
    }

    @Test
    fun diffContactDiscoveryManifestCheckpoint_detectsIdentityDrift() {
        val previous = buildContactDiscoveryManifestCheckpoint(
            serviceOrigin = "https://cdsi.example",
            manifest = manifest(oprfPublicKey = "oprf-pub-1"),
            observedAt = "2026-03-26T00:00:00Z",
        )
        val current = buildContactDiscoveryManifestCheckpoint(
            serviceOrigin = "https://cdsi.example",
            manifest = manifest(oprfPublicKey = "oprf-pub-2", attestationMode = "sgx_preview"),
            observedAt = "2026-03-26T00:01:00Z",
        )

        assertEquals(
            listOf("oprf_public_key_ristretto255", "attestation_mode"),
            diffContactDiscoveryManifestCheckpoint(previous, current),
        )
    }
}
