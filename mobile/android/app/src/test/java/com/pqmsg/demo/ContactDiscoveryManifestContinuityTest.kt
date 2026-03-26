package com.pqmsg.demo

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class ContactDiscoveryManifestContinuityTest {
    private fun manifest(
        oprfPublicKey: String = "oprf-pub-1",
        attestationMode: String = "service_boundary_only",
        attestationVerifier: String? = null,
        enclaveMeasurementHex: String? = null,
    ) = ContactDiscoveryManifestResponse(
        service = "cdsi-preview",
        protocol_version = 1,
        attestation_mode = attestationMode,
        attestation_verifier = attestationVerifier,
        enclave_measurement_hex = enclaveMeasurementHex,
        attestation_document_format = if (attestationMode == "unattested_development") null else "opaque_b64_v1",
        attestation_document_sha256 = if (attestationMode == "unattested_development") null else "bb".repeat(32),
        ticket_format = "ed25519-ticket-v1",
        ticket_issuer_ed25519_pub = "ticket-issuer-pub",
        ticket_max_ttl_seconds = 300,
        lookup_protocol = "blind_token_directory_preview",
        privacy_mode = "blind_evaluation_preview",
        directory_backend = "simulated_enclave_preview",
        host_enclave_protocol_version = 1,
        match_result_format = "contact_invite_token",
        oprf_suite = "ristretto255-sha512-preview",
        evaluation_proof_mode = "dleq_per_element_preview",
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
            manifest = manifest(
                oprfPublicKey = "oprf-pub-2",
                attestationMode = "sgx_preview",
                attestationVerifier = "sgx-dcap-preview",
                enclaveMeasurementHex = "aa".repeat(32),
            ),
            observedAt = "2026-03-26T00:01:00Z",
        )

        assertEquals(
            listOf(
                "oprf_public_key_ristretto255",
                "attestation_mode",
                "attestation_verifier",
                "enclave_measurement_hex",
            ),
            diffContactDiscoveryManifestCheckpoint(previous, current),
        )
    }

    @Test
    fun verifyContactDiscoveryAttestationDocument_rejectsStaleEvidence() {
        val documentBytes = "{\"tee\":\"sgx\"}".toByteArray()
        val documentSha256 =
            MessageDigest
                .getInstance("SHA-256")
                .digest(documentBytes)
                .joinToString("") { "%02x".format(it) }
        val response = ContactDiscoveryAttestationResponse(
            attestation_mode = "sgx_preview",
            attestation_verifier = "sgx-dcap-preview",
            enclave_measurement_hex = "aa".repeat(32),
            directory_backend = "simulated_enclave_preview",
            host_enclave_protocol_version = 1,
            attested_oprf_public_key_ristretto255 = "oprf-pub-1",
            document_format = "opaque_b64_v1",
            document_base64 = Base64.getEncoder().encodeToString(documentBytes),
            document_sha256 = documentSha256,
            published_at = "2026-03-26T00:00:00Z",
        )

        assertThrows(IllegalArgumentException::class.java) {
            verifyContactDiscoveryAttestationDocument(
                response = response,
                expectedAttestationMode = "sgx_preview",
                expectedVerifier = "sgx-dcap-preview",
                expectedMeasurementHex = "aa".repeat(32),
                expectedOprfPublicKeyRistretto255 = "oprf-pub-1",
                expectedDocumentSha256 = documentSha256,
                expectedMaxAgeSeconds = 1,
            )
        }
    }

    @Test
    fun verifyContactDiscoveryAttestationDocument_rejectsOprfKeyMismatch() {
        val documentBytes = "{\"tee\":\"sgx\"}".toByteArray()
        val documentSha256 =
            MessageDigest
                .getInstance("SHA-256")
                .digest(documentBytes)
                .joinToString("") { "%02x".format(it) }
        val response = ContactDiscoveryAttestationResponse(
            attestation_mode = "sgx_preview",
            attestation_verifier = "sgx-dcap-preview",
            enclave_measurement_hex = "aa".repeat(32),
            directory_backend = "simulated_enclave_preview",
            host_enclave_protocol_version = 1,
            attested_oprf_public_key_ristretto255 = "wrong-oprf-pub",
            document_format = "opaque_b64_v1",
            document_base64 = Base64.getEncoder().encodeToString(documentBytes),
            document_sha256 = documentSha256,
            published_at = java.time.Instant.now().toString(),
        )

        assertThrows(IllegalArgumentException::class.java) {
            verifyContactDiscoveryAttestationDocument(
                response = response,
                expectedAttestationMode = "sgx_preview",
                expectedVerifier = "sgx-dcap-preview",
                expectedMeasurementHex = "aa".repeat(32),
                expectedOprfPublicKeyRistretto255 = "oprf-pub-1",
                expectedDocumentSha256 = documentSha256,
                expectedMaxAgeSeconds = 900,
            )
        }
    }
}
