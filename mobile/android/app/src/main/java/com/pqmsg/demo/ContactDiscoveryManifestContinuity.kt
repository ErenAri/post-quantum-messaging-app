package com.pqmsg.demo

data class ContactDiscoveryManifestCheckpoint(
    val service_origin: String,
    val manifest_issuer_ed25519_pub: String,
    val ticket_issuer_ed25519_pub: String,
    val protocol_version: Int,
    val ticket_format: String,
    val lookup_protocol: String,
    val privacy_mode: String,
    val match_result_format: String,
    val oprf_suite: String,
    val oprf_public_key_ristretto255: String,
    val attestation_mode: String,
    val observed_at: String,
)

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
        match_result_format = manifest.match_result_format,
        oprf_suite = manifest.oprf_suite,
        oprf_public_key_ristretto255 = manifest.oprf_public_key_ristretto255,
        attestation_mode = manifest.attestation_mode,
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
    if (previous.match_result_format != current.match_result_format) {
        changedFields += "match_result_format"
    }
    if (previous.oprf_suite != current.oprf_suite) changedFields += "oprf_suite"
    if (previous.oprf_public_key_ristretto255 != current.oprf_public_key_ristretto255) {
        changedFields += "oprf_public_key_ristretto255"
    }
    if (previous.attestation_mode != current.attestation_mode) changedFields += "attestation_mode"
    return changedFields
}
