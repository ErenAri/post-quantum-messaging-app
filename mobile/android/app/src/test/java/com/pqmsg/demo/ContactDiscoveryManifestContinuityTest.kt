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
        attestationMode: String = "attested_enclave_v1",
        attestationVerifier: String? = "aws-nitro-root-v1",
        enclaveMeasurementHex: String? = "aa".repeat(32),
        hostReleaseId: String = "attested-host-v1",
    ) = ContactDiscoveryManifestResponse(
        service = "pqmsg-discovery",
        protocol_version = 1,
        attestation_mode = attestationMode,
        attestation_verifier = attestationVerifier,
        enclave_measurement_hex = enclaveMeasurementHex,
        attestation_pcrs_sha384 = null,
        attestation_document_format = "opaque_b64_v1",
        attestation_document_sha256 = "bb".repeat(32),
        attestation_challenge_mode =
            "nonce_b64_required_v1",
        ticket_format = "ed25519-ticket-v1",
        ticket_issuer_ed25519_pub = "ticket-issuer-pub",
        ticket_max_ttl_seconds = 300,
        lookup_protocol = "attested_enclave_voprf_directory_v1",
        privacy_mode = "enclave_backed_private_discovery_v1",
        directory_backend = "attested_enclave_directory_v1",
        host_enclave_protocol_version = 1,
        host_release_id = hostReleaseId,
        enclave_release_id = "attested-enclave-v1",
        match_result_format = "contact_invite_token",
        oprf_suite = "ristretto255-sha512-v1",
        evaluation_proof_mode = "dleq_per_element_v1",
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
                attestationMode = "attested_enclave_v1",
                attestationVerifier = "aws-nitro-root-v1",
                enclaveMeasurementHex = "aa".repeat(32),
            ),
            observedAt = "2026-03-26T00:01:00Z",
        )

        assertEquals(
            listOf("oprf_public_key_ristretto255"),
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
            attestation_mode = "attested_enclave_v1",
            attestation_verifier = "aws-nitro-root-v1",
            enclave_measurement_hex = "aa".repeat(32),
            attested_pcrs_sha384 = null,
            directory_backend = "attested_enclave_directory_v1",
            host_enclave_protocol_version = 1,
            host_release_id = "attested-host-v1",
            enclave_release_id = "attested-enclave-v1",
            manifest_contract_sha256 = "11".repeat(32),
            attested_oprf_public_key_ristretto255 = "oprf-pub-1",
            document_format = "opaque_b64_v1",
            document_base64 = Base64.getEncoder().encodeToString(documentBytes),
            document_sha256 = documentSha256,
            published_at = "2026-03-26T00:00:00Z",
            challenge_nonce_base64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
            attestation_signature_ed25519 = "sig",
        )

        assertThrows(IllegalArgumentException::class.java) {
            verifyContactDiscoveryAttestationDocument(
                response = response,
                expectedAttestationMode = "attested_enclave_v1",
                expectedVerifier = "aws-nitro-root-v1",
                expectedMeasurementHex = "aa".repeat(32),
                expectedPcrsSha384 = null,
                expectedManifestIssuerEd25519Pub = "manifest-issuer-pub",
                expectedChallengeNonceBase64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
                expectedManifestContractSha256 = "11".repeat(32),
                expectedHostReleaseId = "attested-host-v1",
                expectedEnclaveReleaseId = "attested-enclave-v1",
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
            attestation_mode = "attested_enclave_v1",
            attestation_verifier = "aws-nitro-root-v1",
            enclave_measurement_hex = "aa".repeat(32),
            attested_pcrs_sha384 = null,
            directory_backend = "attested_enclave_directory_v1",
            host_enclave_protocol_version = 1,
            host_release_id = "attested-host-v1",
            enclave_release_id = "attested-enclave-v1",
            manifest_contract_sha256 = "11".repeat(32),
            attested_oprf_public_key_ristretto255 = "wrong-oprf-pub",
            document_format = "opaque_b64_v1",
            document_base64 = Base64.getEncoder().encodeToString(documentBytes),
            document_sha256 = documentSha256,
            published_at = java.time.Instant.now().toString(),
            challenge_nonce_base64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
            attestation_signature_ed25519 = "sig",
        )

        assertThrows(IllegalArgumentException::class.java) {
            verifyContactDiscoveryAttestationDocument(
                response = response,
                expectedAttestationMode = "attested_enclave_v1",
                expectedVerifier = "aws-nitro-root-v1",
                expectedMeasurementHex = "aa".repeat(32),
                expectedPcrsSha384 = null,
                expectedManifestIssuerEd25519Pub = "manifest-issuer-pub",
                expectedChallengeNonceBase64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
                expectedManifestContractSha256 = "11".repeat(32),
                expectedHostReleaseId = "attested-host-v1",
                expectedEnclaveReleaseId = "attested-enclave-v1",
                expectedOprfPublicKeyRistretto255 = "oprf-pub-1",
                expectedDocumentSha256 = documentSha256,
                expectedMaxAgeSeconds = 900,
            )
        }
    }

    @Test
    fun verifyContactDiscoveryAttestationDocument_rejectsPcrSetMismatch() {
        val documentBytes = "{\"tee\":\"sgx\"}".toByteArray()
        val documentSha256 =
            MessageDigest
                .getInstance("SHA-256")
                .digest(documentBytes)
                .joinToString("") { "%02x".format(it) }
        val response = ContactDiscoveryAttestationResponse(
            attestation_mode = "attested_enclave_v1",
            attestation_verifier = "aws-nitro-root-v1",
            enclave_measurement_hex = "aa".repeat(32),
            attested_pcrs_sha384 = mapOf("pcr0" to "ef".repeat(48)),
            directory_backend = "attested_enclave_directory_v1",
            host_enclave_protocol_version = 1,
            host_release_id = "attested-host-v1",
            enclave_release_id = "attested-enclave-v1",
            manifest_contract_sha256 = "11".repeat(32),
            attested_oprf_public_key_ristretto255 = "oprf-pub-1",
            document_format = "opaque_b64_v1",
            document_base64 = Base64.getEncoder().encodeToString(documentBytes),
            document_sha256 = documentSha256,
            published_at = java.time.Instant.now().toString(),
            challenge_nonce_base64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
            attestation_signature_ed25519 = "sig",
        )

        assertThrows(IllegalArgumentException::class.java) {
            verifyContactDiscoveryAttestationDocument(
                response = response,
                expectedAttestationMode = "attested_enclave_v1",
                expectedVerifier = "aws-nitro-root-v1",
                expectedMeasurementHex = "aa".repeat(32),
                expectedPcrsSha384 = mapOf("pcr0" to "12".repeat(48)),
                expectedManifestIssuerEd25519Pub = "manifest-issuer-pub",
                expectedChallengeNonceBase64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
                expectedManifestContractSha256 = "11".repeat(32),
                expectedHostReleaseId = "attested-host-v1",
                expectedEnclaveReleaseId = "attested-enclave-v1",
                expectedOprfPublicKeyRistretto255 = "oprf-pub-1",
                expectedDocumentSha256 = documentSha256,
                expectedMaxAgeSeconds = 900,
            )
        }
    }

    @Test
    fun verifyContactDiscoveryAttestationDocument_rejectsHostReleaseMismatch() {
        val documentBytes = "{\"tee\":\"sgx\"}".toByteArray()
        val documentSha256 =
            MessageDigest
                .getInstance("SHA-256")
                .digest(documentBytes)
                .joinToString("") { "%02x".format(it) }
        val response = ContactDiscoveryAttestationResponse(
            attestation_mode = "attested_enclave_v1",
            attestation_verifier = "aws-nitro-root-v1",
            enclave_measurement_hex = "aa".repeat(32),
            attested_pcrs_sha384 = null,
            directory_backend = "attested_enclave_directory_v1",
            host_enclave_protocol_version = 1,
            host_release_id = "attested-host-v1",
            enclave_release_id = "attested-enclave-v1",
            manifest_contract_sha256 = "11".repeat(32),
            attested_oprf_public_key_ristretto255 = "oprf-pub-1",
            document_format = "opaque_b64_v1",
            document_base64 = Base64.getEncoder().encodeToString(documentBytes),
            document_sha256 = documentSha256,
            published_at = java.time.Instant.now().toString(),
            challenge_nonce_base64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
            attestation_signature_ed25519 = "sig",
        )

        assertThrows(IllegalArgumentException::class.java) {
            verifyContactDiscoveryAttestationDocument(
                response = response,
                expectedAttestationMode = "attested_enclave_v1",
                expectedVerifier = "aws-nitro-root-v1",
                expectedMeasurementHex = "aa".repeat(32),
                expectedPcrsSha384 = null,
                expectedManifestIssuerEd25519Pub = "manifest-issuer-pub",
                expectedChallengeNonceBase64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
                expectedManifestContractSha256 = "11".repeat(32),
                expectedHostReleaseId = "wrong-host-preview",
                expectedEnclaveReleaseId = "attested-enclave-v1",
                expectedOprfPublicKeyRistretto255 = "oprf-pub-1",
                expectedDocumentSha256 = documentSha256,
                expectedMaxAgeSeconds = 900,
            )
        }
    }

    @Test
    fun verifyContactDiscoveryAttestationDocument_rejectsManifestContractMismatch() {
        val documentBytes = "{\"tee\":\"sgx\"}".toByteArray()
        val documentSha256 =
            MessageDigest
                .getInstance("SHA-256")
                .digest(documentBytes)
                .joinToString("") { "%02x".format(it) }
        val response = ContactDiscoveryAttestationResponse(
            attestation_mode = "attested_enclave_v1",
            attestation_verifier = "aws-nitro-root-v1",
            enclave_measurement_hex = "aa".repeat(32),
            attested_pcrs_sha384 = null,
            directory_backend = "attested_enclave_directory_v1",
            host_enclave_protocol_version = 1,
            host_release_id = "attested-host-v1",
            enclave_release_id = "attested-enclave-v1",
            manifest_contract_sha256 = "11".repeat(32),
            attested_oprf_public_key_ristretto255 = "oprf-pub-1",
            document_format = "opaque_b64_v1",
            document_base64 = Base64.getEncoder().encodeToString(documentBytes),
            document_sha256 = documentSha256,
            published_at = java.time.Instant.now().toString(),
            challenge_nonce_base64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
            attestation_signature_ed25519 = "sig",
        )

        assertThrows(IllegalArgumentException::class.java) {
            verifyContactDiscoveryAttestationDocument(
                response = response,
                expectedAttestationMode = "attested_enclave_v1",
                expectedVerifier = "aws-nitro-root-v1",
                expectedMeasurementHex = "aa".repeat(32),
                expectedPcrsSha384 = null,
                expectedManifestIssuerEd25519Pub = "manifest-issuer-pub",
                expectedChallengeNonceBase64 = "bm9uY2UxMjM0NTY3ODkwMTIzNA==",
                expectedManifestContractSha256 = "22".repeat(32),
                expectedHostReleaseId = "attested-host-v1",
                expectedEnclaveReleaseId = "attested-enclave-v1",
                expectedOprfPublicKeyRistretto255 = "oprf-pub-1",
                expectedDocumentSha256 = documentSha256,
                expectedMaxAgeSeconds = 900,
            )
        }
    }
}


