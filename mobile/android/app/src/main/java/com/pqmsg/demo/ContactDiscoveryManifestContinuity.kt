package com.pqmsg.demo

import com.google.gson.Gson
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import uniffi.pqmsg_android.verifyContactDiscoveryAttestationResponseSignature

private val contactDiscoveryManifestGson = Gson()

data class ContactDiscoveryManifestCheckpoint(
    val service_origin: String,
    val manifest_issuer_ed25519_pub: String,
    val ticket_issuer_ed25519_pub: String,
    val protocol_version: Int,
    val ticket_format: String,
    val lookup_protocol: String,
    val privacy_mode: String,
    val directory_backend: String,
    val host_enclave_protocol_version: Int,
    val enclave_release_id: String,
    val match_result_format: String,
    val oprf_suite: String,
    val evaluation_proof_mode: String,
    val oprf_public_key_ristretto255: String,
    val attestation_mode: String,
    val attestation_verifier: String?,
    val enclave_measurement_hex: String?,
    val attestation_document_format: String?,
    val attestation_document_sha256: String?,
    val attestation_challenge_mode: String?,
    val observed_at: String,
)

fun verifyContactDiscoveryAttestationDocument(
    response: ContactDiscoveryAttestationResponse,
    expectedAttestationMode: String,
    expectedVerifier: String,
    expectedMeasurementHex: String,
    expectedManifestIssuerEd25519Pub: String,
    expectedChallengeNonceBase64: String,
    expectedEnclaveReleaseId: String,
    expectedOprfPublicKeyRistretto255: String,
    expectedDocumentSha256: String,
    expectedMaxAgeSeconds: Int,
) {
    require(response.attestation_mode == expectedAttestationMode) {
        "Contact discovery attestation mode mismatch"
    }
    require(response.attestation_verifier == expectedVerifier) {
        "Contact discovery attestation verifier mismatch"
    }
    require(response.enclave_measurement_hex == expectedMeasurementHex) {
        "Contact discovery attestation measurement mismatch"
    }
    require(response.directory_backend == "simulated_enclave_preview") {
        "Unsupported contact discovery backend"
    }
    require(response.host_enclave_protocol_version == 1) {
        "Unsupported contact discovery host/enclave protocol version"
    }
    require(response.enclave_release_id == expectedEnclaveReleaseId) {
        "Contact discovery attestation enclave release mismatch"
    }
    require(response.attested_oprf_public_key_ristretto255 == expectedOprfPublicKeyRistretto255) {
        "Contact discovery attestation OPRF public key mismatch"
    }
    require(response.document_format == "opaque_b64_v1") {
        "Unsupported contact discovery attestation document format"
    }
    require(response.document_sha256.equals(expectedDocumentSha256, ignoreCase = true)) {
        "Contact discovery attestation document hash mismatch"
    }
    val documentBytes = Base64.getDecoder().decode(response.document_base64)
    val digest = MessageDigest.getInstance("SHA-256").digest(documentBytes)
    val computedHex = digest.joinToString("") { "%02x".format(it) }
    require(computedHex == expectedDocumentSha256.lowercase()) {
        "Contact discovery attestation document integrity check failed"
    }
    require(expectedMaxAgeSeconds > 0) {
        "Contact discovery attestation max age is invalid"
    }
    val publishedAt = Instant.parse(response.published_at)
    val now = Instant.now()
    require(!publishedAt.isAfter(now.plusSeconds(300))) {
        "Contact discovery attestation published_at is in the future"
    }
    require(!publishedAt.isBefore(now.minusSeconds(expectedMaxAgeSeconds.toLong()))) {
        "Contact discovery attestation document is stale"
    }
    verifyContactDiscoveryAttestationResponseSignature(
        contactDiscoveryManifestGson.toJson(response),
        expectedManifestIssuerEd25519Pub,
        expectedChallengeNonceBase64,
    )
}

fun buildContactDiscoveryManifestCheckpoint(
    serviceOrigin: String,
    manifest: ContactDiscoveryManifestResponse,
    observedAt: String,
): ContactDiscoveryManifestCheckpoint {
    return ContactDiscoveryManifestCheckpoint(
        service_origin = serviceOrigin,
        manifest_issuer_ed25519_pub = manifest.manifest_issuer_ed25519_pub,
        ticket_issuer_ed25519_pub = manifest.ticket_issuer_ed25519_pub,
        protocol_version = manifest.protocol_version,
        ticket_format = manifest.ticket_format,
        lookup_protocol = manifest.lookup_protocol,
        privacy_mode = manifest.privacy_mode,
        directory_backend = manifest.directory_backend,
        host_enclave_protocol_version = manifest.host_enclave_protocol_version,
        enclave_release_id = manifest.enclave_release_id,
        match_result_format = manifest.match_result_format,
        oprf_suite = manifest.oprf_suite,
        evaluation_proof_mode = manifest.evaluation_proof_mode,
        oprf_public_key_ristretto255 = manifest.oprf_public_key_ristretto255,
        attestation_mode = manifest.attestation_mode,
        attestation_verifier = manifest.attestation_verifier,
        enclave_measurement_hex = manifest.enclave_measurement_hex,
        attestation_document_format = manifest.attestation_document_format,
        attestation_document_sha256 = manifest.attestation_document_sha256,
        attestation_challenge_mode = manifest.attestation_challenge_mode,
        observed_at = observedAt,
    )
}

fun diffContactDiscoveryManifestCheckpoint(
    previous: ContactDiscoveryManifestCheckpoint,
    current: ContactDiscoveryManifestCheckpoint,
): List<String> {
    val changedFields = mutableListOf<String>()
    if (previous.service_origin != current.service_origin) changedFields += "service_origin"
    if (previous.manifest_issuer_ed25519_pub != current.manifest_issuer_ed25519_pub) {
        changedFields += "manifest_issuer_ed25519_pub"
    }
    if (previous.ticket_issuer_ed25519_pub != current.ticket_issuer_ed25519_pub) {
        changedFields += "ticket_issuer_ed25519_pub"
    }
    if (previous.protocol_version != current.protocol_version) changedFields += "protocol_version"
    if (previous.ticket_format != current.ticket_format) changedFields += "ticket_format"
    if (previous.lookup_protocol != current.lookup_protocol) changedFields += "lookup_protocol"
    if (previous.privacy_mode != current.privacy_mode) changedFields += "privacy_mode"
    if (previous.directory_backend != current.directory_backend) {
        changedFields += "directory_backend"
    }
    if (previous.host_enclave_protocol_version != current.host_enclave_protocol_version) {
        changedFields += "host_enclave_protocol_version"
    }
    if (previous.enclave_release_id != current.enclave_release_id) {
        changedFields += "enclave_release_id"
    }
    if (previous.match_result_format != current.match_result_format) {
        changedFields += "match_result_format"
    }
    if (previous.oprf_suite != current.oprf_suite) changedFields += "oprf_suite"
    if (previous.evaluation_proof_mode != current.evaluation_proof_mode) {
        changedFields += "evaluation_proof_mode"
    }
    if (previous.oprf_public_key_ristretto255 != current.oprf_public_key_ristretto255) {
        changedFields += "oprf_public_key_ristretto255"
    }
    if (previous.attestation_mode != current.attestation_mode) changedFields += "attestation_mode"
    if (previous.attestation_verifier != current.attestation_verifier) {
        changedFields += "attestation_verifier"
    }
    if (previous.enclave_measurement_hex != current.enclave_measurement_hex) {
        changedFields += "enclave_measurement_hex"
    }
    if (previous.attestation_document_format != current.attestation_document_format) {
        changedFields += "attestation_document_format"
    }
    if (previous.attestation_document_sha256 != current.attestation_document_sha256) {
        changedFields += "attestation_document_sha256"
    }
    if (previous.attestation_challenge_mode != current.attestation_challenge_mode) {
        changedFields += "attestation_challenge_mode"
    }
    return changedFields
}
