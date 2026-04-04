# Private Contact Discovery

## Status

Current product posture:

- Raw hash upload/match on the main server is disabled.
- Manual contacts, opaque invite links, and optional `@username` lookup remain the active contact bootstrap paths.
- The app server can now advertise `contact_discovery_mode` and, when configured, mint short-lived signed tickets for a separate private discovery service.
- The separate discovery service now publishes a signed manifest contract, and supported clients verify that manifest before using the attested private discovery service.
- A separate `pqmsg-discovery` service crate now exposes `/health`, `/v1/manifest`, `/v1/attestation`, `/v1/discovery/evaluate`, `/v1/discovery/handles`, and `/v1/discovery/match`.
- Supported web and Android clients can now request a discovery ticket from the app server and talk directly to the separate discovery service.

This document defines the next honest step beyond that groundwork: replacing the current service-boundary-only hashed-directory flow with a real privacy-preserving contact discovery subsystem instead of rebuilding a weaker server-side address-book lookup in `pqmsg-server`.

### Supported today

The currently implemented contract is narrower than the longer-term enclave rollout:

- The app server only advertises `contact_discovery_mode = "private_service"` when the full separate-service contract is configured end to end.
- Supported Android and web clients verify the signed discovery manifest against the app-server-advertised issuer keys and contract fields before they use the service.
- When the manifest advertises attestation evidence, supported Android and web clients also fetch `/v1/attestation?nonce_b64=...`, verify the signed attestation payload, require the echoed challenge nonce to match, require `manifest_contract_sha256`, host release, enclave release, attested OPRF key, and any PCR set to match the manifest/app-server contract, and reject stale evidence older than the app-server-advertised max age.
- Supported Android and web clients continuity-pin the discovery-service contract on the current device and fail closed if the manifest contract silently changes.
- Supported Android and web clients also reject `evaluate`, `handles`, and `match` responses if the echoed `manifest_contract_sha256` or `ticket_nonce` drift from the verified manifest contract and issued ticket.
- Raw-hash discovery on the main app server remains disabled. Manual contacts, invite links, and optional exact `@username` lookup remain the primary contact bootstrap paths.

### Not claimed today

The current separate-service path is still a preview, not a production claim of Signal-equivalent private discovery:

- it is not a claim of a completed enclave rollout or third-party-audited CDS deployment,
- it is not the default contact bootstrap path,
- it is not a public directory,
- and it is not currently exercised uniformly across every client surface in the repository.

## Research Baseline

This design direction follows Signal's published private-contact-discovery model:

- Signal support: private contact discovery keeps the service from learning your address book.
- Signal blog: private contact discovery uses a separate service boundary and reproducible enclave build/attestation posture.
- Signal open-source direction: `signalapp/ContactDiscoveryService`, `signalapp/ContactDiscoveryService-Icelake`.

## Goals

- Let a client learn which contacts are registered without revealing the full contact set to the main messaging server.
- Keep direct-message privacy posture aligned with the rest of the hardened Android/web path.
- Make the discovery service separately deployable and separately disableable.
- Preserve abuse controls and rate limits without turning the discovery service into a user-tracking oracle.

## Non-Goals

- No raw SHA-256 contact matching inside `pqmsg-server`.
- No discovery result persistence on the main app server.
- No "best effort" downgrade from private discovery back to raw-hash discovery.

## Architecture

### 1. App server

Responsibilities:

- Authenticate the user/device with the existing signed transport headers.
- Enforce rate limits and account/device policy.
- Mint a short-lived opaque discovery ticket.
- Advertise the discovery mode, service origin, and manifest-verification key in capabilities.

Already implemented:

- `contact_discovery_mode`
- `contact_discovery_ticket_supported`
- `contact_discovery_service_origin`
- `contact_discovery_manifest_issuer_ed25519_pub`
- `POST /v1/users/{user_id}/contact-discovery/ticket`

### 2. Private discovery service

Responsibilities:

- Accept only short-lived app-server-issued tickets.
- Verify the ticket signature and expiry.
- Perform the lookup over client-submitted identifiers without routing those queries through the main messaging server.
- Return only matched account references and minimal proof/metadata needed by the client.

The discovery service must be isolated from the main messaging server so the main server never receives the user's address-book query material.

Current implementation boundary:

- `pqmsg-discovery` verifies short-lived tickets, enforces a small signed per-ticket operation budget, publishes a signed manifest contract, and exposes the repo's current `attested_enclave_voprf_directory_v1` preview lookup mode.
- That manifest is signed by a dedicated Ed25519 manifest issuer key so clients can bind the service contract to the app-server capabilities document.
- The signed manifest now locks the current result contract to `match_result_format = contact_invite_token`, the current blind-evaluation primitive to `oprf_suite = ristretto255-sha512-v1`, the current proof contract to `evaluation_proof_mode = dleq_per_element_v1`, and, when configured, the attestation verifier + enclave measurement + attestation PCR set + attestation document hash expected by the app server.
- When attestation evidence is configured, the signed manifest now also pins `attestation_challenge_mode = nonce_b64_required_v1`, so supported clients can fail closed if the preview silently drops back to a static attestation fetch.
- The signed manifest now also locks the preview backend seam to `directory_backend = attested_enclave_directory_v1` and `host_enclave_protocol_version = 1`, so clients/app-server can pin the future host/enclave replacement boundary instead of treating the service as an opaque monolith.
- In that mode, clients keep SHA-256 handle hashes local, request blind evaluations from the discovery service, verify the returned DLEQ-style proofs against the manifest-pinned OPRF public key, finalize those evaluations into discovery tokens locally, and upload/search only the finalized token hashes.
- The current ticket embeds a dedicated opaque contact-bootstrap invite token plus a signed max-use budget, and the discovery service returns that token on match instead of a stable account ID.
- Tickets are now explicitly single-purpose: `upload` tickets are only valid for blind evaluation plus token upload, while `match` tickets are only valid for blind evaluation plus token match.
- The preview discovery registry now also purges expired bootstrap-invite-backed token rows instead of merely filtering them at match time, which reduces stale handle persistence on the separate service.
- When configured for an attested preview deployment, clients now also fetch `/v1/attestation?nonce_b64=...`, verify the returned attestation document hash against the signed manifest, require the attested blind-evaluation key to match the manifest-pinned OPRF public key, require any attested PCR set to match the manifest/app-server-pinned PCR set, require the echoed challenge nonce to match the per-request client nonce, verify the signed attestation payload under the manifest issuer key, reject stale evidence using the app-server-advertised max age, and continuity-pin that document contract locally.
- This is intentionally marked `privacy_mode = "enclave_backed_private_discovery_v1"` and is still not a production claim of Signal-style private discovery.
- `pqmsg-server` now only advertises that separate discovery path when the full attested enclave-style contract is configured. If any required contract field is missing, capabilities fall back to `manual_only` instead of partially exposing discovery.

### 3. Client

Responsibilities:

- Normalize contact handles locally.
- Submit discovery input directly to the discovery service instead of the main app server.
- Present results as optional contact suggestions, not automatic server-side graph mutation.
- Cache only the minimal local result set needed for UX.

## Proposed Flow

1. Client fetches `/v1/capabilities`.
2. If `contact_discovery_mode == "private_service"`, client fetches `/v1/manifest` from `contact_discovery_service_origin`, verifies the signed manifest against `contact_discovery_manifest_issuer_ed25519_pub`, checks any pinned `contact_discovery_attestation_verifier` / `contact_discovery_expected_measurement_hex` / `contact_discovery_expected_pcrs_sha384` / `contact_discovery_attestation_document_sha256` / `contact_discovery_attestation_max_age_seconds` from capabilities, and compares the service identity/protocol contract, including `host_release_id`, against a local continuity checkpoint for that account.
3. If the manifest advertises `attestation_document_sha256`, client fetches `/v1/attestation?nonce_b64=...`, verifies the returned attestation document bytes/hash and attestation metadata, requires the echoed nonce to match the per-request challenge, verifies the attestation payload signature under the manifest issuer key, requires the attested `host_release_id`, `manifest_contract_sha256`, blind-evaluation key, and any advertised PCR set to match the manifest-pinned contract, rejects stale evidence older than `contact_discovery_attestation_max_age_seconds`, and only then continues to the lookup flow.
4. Client requests `/v1/users/{user_id}/contact-discovery/ticket` with purpose `upload` or `match`; the signed ticket is now also bound to the app-server-pinned manifest contract hash and carries a per-ticket nonce.
5. Client performs the current blind-evaluation preview directly against `contact_discovery_service_origin`.
6. Discovery service echoes both `manifest_contract_sha256` and the validated `ticket_nonce` on blind-evaluation, upload, and match responses; client rejects any response whose contract hash drifts from the already-verified signed manifest contract or whose nonce does not match the exact issued ticket.
7. Discovery service accepts only the purpose-appropriate follow-on operation (`handles` for `upload`, `match` for `match`) and returns matched opaque bootstrap invite references.
8. Client converts selected results into local/manual contacts.

## Required Security Properties

- The app server must not see raw or directly reversible contact handles.
- Tickets must be short-lived, single-purpose, and bound to user/device identity.
- Discovery queries must be unlinkable across runs as much as the chosen primitive allows.
- The discovery service must expose an auditable identity/attestation story before production claims are made.
- There must be no silent fallback to raw-hash discovery.

## Chosen Direction

The next real implementation phase is no longer "pick any private-discovery idea." The repo now chooses one direction, based on Signal's published CDS/CDSI model:

- a separate enclave-backed discovery service
- a host/enclave split with separate release cadence and measurement tracking
- client-side attestation verification against a published/verifiable measurement
- opaque bootstrap results instead of stable account identifiers

That means the current `attested_enclave_voprf_directory_v1` / `enclave_backed_private_discovery_v1` flow is explicitly a supported preview bridge, not the intended final protocol.

### Why this direction

Signal's own current open-source/private-discovery direction still centers on an attested dedicated service, not a generic blind-directory service. The relevant public signals are:

- the original private contact discovery design and SGX rationale
- the current `ContactDiscoveryService-Icelake` host/enclave split
- reproducible enclave release and measurement handling

For this repo, the practical consequence is: do not keep widening the preview. The next substantial engineering work should replace it.

## Remaining Design Choices

### Final discovery primitive details

The concrete direction is now fixed to an enclave-backed service, but several details still need to be specified before implementation:

- client-to-enclave request/response shape
- host/enclave key separation and release cadence
- exact attestation evidence format and verifier contract
- enclave-side directory representation and update stream model

### Account identifier returned from discovery

The discovery service should return the minimum handle needed to bootstrap contact creation. The current attested flow uses opaque contact-invite bootstrap tokens instead of returning stable account IDs directly:

- stable `user_id`
- or opaque invite/bootstrap token
- or username-like share token

The choice affects metadata leakage and should be reviewed with the invite and username flows.

### Abuse controls

Need explicit policy for:

- per-device ticket issuance rate
- per-ticket query count and max input size
  Note: the current preview now enforces a small signed max-use budget per ticket, but that is still an abuse-control stopgap rather than a final production policy.
- abuse logging that does not recreate a contact graph

## Recommended Implementation Order

1. Define the final host/enclave discovery protocol and attestation contract around an enclave-backed service.
2. Replace the current `attested_enclave_voprf_directory_v1` flow with that enclave-backed primitive.
3. Wire account ingestion/update flow into the enclave-backed directory.
4. Keep opaque bootstrap invite results instead of stable account identifiers.
5. Subject the discovery service to separate review before enabling it in hardened deployments.
6. Keep the main app server raw-hash routes disabled.

## Current Repo Boundary

Until the separate service lookup protocol exists, the correct server/client posture is:

- `contact_discovery_supported = true` only when a separate discovery service is configured and the app server is running in `development`
- `contact_discovery_mode = "private_service"` only when the full attested separate-service contract is configured end to end
- `contact_discovery_manifest_issuer_ed25519_pub` must be present, and clients verify the signed discovery manifest before using the service
- development clients now also pin a local continuity checkpoint for the discovery service contract and fail closed if `service_origin`, issuer keys, protocol fields, `directory_backend`, `host_enclave_protocol_version`, `host_release_id`, `enclave_release_id`, attestation verifier, enclave measurement, attestation PCR set, attestation document hash/format, or the OPRF public key change silently on the same device
- the current manifest commits to `lookup_protocol = attested_enclave_voprf_directory_v1`, `privacy_mode = enclave_backed_private_discovery_v1`, `directory_backend = attested_enclave_directory_v1`, `host_enclave_protocol_version = 1`, `host_release_id = attested-host-v1`, `match_result_format = contact_invite_token`, `oprf_suite = ristretto255-sha512-v1`, and `evaluation_proof_mode = dleq_per_element_v1`; it can also carry a signed attestation verifier + enclave measurement + attestation PCR set + attestation document hash contract plus `attestation_challenge_mode = nonce_b64_required_v1` for stricter deployments
- raw-hash upload/match routes on the main app server remain disabled
- manual contacts, invite links, and optional `@username` lookup remain the supported bootstrap paths outside the discovery service

## Research Basis

Primary sources driving this decision:

- Signal blog: private contact discovery
- Signal support: private contact discovery
- `signalapp/ContactDiscoveryService`
- `signalapp/ContactDiscoveryService-Icelake`
- RFC 9497 for the current preview OPRF background




