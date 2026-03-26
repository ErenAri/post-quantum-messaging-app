# Private Contact Discovery

## Status

Current product posture:

- Raw hash upload/match on the main server is disabled.
- Manual contacts, opaque invite links, and optional `@username` lookup remain the active contact bootstrap paths.
- The app server can now advertise `contact_discovery_mode` and, when configured, mint short-lived signed tickets for a separate private discovery service.
- The separate discovery service now publishes a signed manifest contract, and supported clients verify that manifest before using the development-only service.
- A separate `pqmsg-discovery` service crate now exposes `/health`, `/v1/manifest`, `/v1/attestation`, `/v1/discovery/evaluate`, `/v1/discovery/handles`, and `/v1/discovery/match`.
- Supported web and Android clients can now request a discovery ticket from the app server and talk directly to the separate discovery service.

This document defines the next honest step beyond that groundwork: replacing the current service-boundary-only hashed-directory flow with a real privacy-preserving contact discovery subsystem instead of rebuilding a weaker server-side address-book lookup in `pqmsg-server`.

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

- `pqmsg-discovery` verifies short-lived tickets, enforces a small signed per-ticket operation budget, publishes a signed manifest contract, and exposes a development-only `blind_token_directory_preview` lookup mode.
- That manifest is signed by a dedicated Ed25519 manifest issuer key so clients can bind the service contract to the app-server capabilities document.
- The signed manifest now locks the current result contract to `match_result_format = contact_invite_token`, the current blind-evaluation primitive to `oprf_suite = ristretto255-sha512-preview`, the current proof contract to `evaluation_proof_mode = dleq_per_element_preview`, and, when configured, the attestation verifier + enclave measurement + attestation document hash expected by the app server.
- In that mode, clients keep SHA-256 handle hashes local, request blind evaluations from the discovery service, verify the returned DLEQ-style proofs against the manifest-pinned OPRF public key, finalize those evaluations into discovery tokens locally, and upload/search only the finalized token hashes.
- The current ticket embeds a dedicated opaque contact-bootstrap invite token plus a signed max-use budget, and the discovery service returns that token on match instead of a stable account ID.
- When configured for an attested preview deployment, clients now also fetch `/v1/attestation`, verify the returned attestation document hash against the signed manifest, reject stale evidence using the app-server-advertised max age, and continuity-pin that document contract locally.
- This is intentionally marked `privacy_mode = "blind_evaluation_preview"` and is still not a production claim of Signal-style private discovery.
- `pqmsg-server` now only advertises that separate discovery path in `development` deployments. `pilot` and `production` stay on `manual_only`, and server boot now rejects `PQMSG_CONTACT_DISCOVERY_*` preview configuration entirely outside `development`, until a real private-discovery protocol and attestation story exist.

### 3. Client

Responsibilities:

- Normalize contact handles locally.
- Submit discovery input directly to the discovery service instead of the main app server.
- Present results as optional contact suggestions, not automatic server-side graph mutation.
- Cache only the minimal local result set needed for UX.

## Proposed Flow

1. Client fetches `/v1/capabilities`.
2. If `contact_discovery_mode == "private_service"`, client fetches `/v1/manifest` from `contact_discovery_service_origin`, verifies the signed manifest against `contact_discovery_manifest_issuer_ed25519_pub`, checks any pinned `contact_discovery_attestation_verifier` / `contact_discovery_expected_measurement_hex` / `contact_discovery_attestation_document_sha256` / `contact_discovery_attestation_max_age_seconds` from capabilities, and compares the service identity/protocol contract against a local continuity checkpoint for that account.
3. If the manifest advertises `attestation_document_sha256`, client fetches `/v1/attestation`, verifies the returned attestation document bytes/hash and attestation metadata, rejects stale evidence older than `contact_discovery_attestation_max_age_seconds`, and only then continues to the lookup flow.
4. Client requests `/v1/users/{user_id}/contact-discovery/ticket`.
5. Client performs the current blind-evaluation preview directly against `contact_discovery_service_origin`.
6. Discovery service returns matched opaque bootstrap invite references.
7. Client converts selected results into local/manual contacts.

## Required Security Properties

- The app server must not see raw or directly reversible contact handles.
- Tickets must be short-lived, single-purpose, and bound to user/device identity.
- Discovery queries must be unlinkable across runs as much as the chosen primitive allows.
- The discovery service must expose an auditable identity/attestation story before production claims are made.
- There must be no silent fallback to raw-hash discovery.

## Open Design Choices

### Discovery primitive

The repo should not invent a new private-discovery cryptosystem ad hoc. The next implementation phase should choose one concrete design and commit to it:

- enclave-backed lookup service
- OPRF/PSI-based design
- another audited/private-set-membership approach

### Account identifier returned from discovery

The discovery service should return the minimum handle needed to bootstrap contact creation. The current development-only flow now uses opaque contact-invite bootstrap tokens instead of returning stable account IDs directly:

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

1. Replace the current `blind_token_directory_preview` flow with one concrete audited private-discovery primitive.
2. Add attestation / manifest verification strong enough for hardened deployments.
3. Limit or eliminate service-side handle persistence once the final primitive is chosen.
4. Subject the discovery service to separate review before enabling it in hardened deployments.
5. Keep the main app server raw-hash routes disabled.

## Current Repo Boundary

Until the separate service lookup protocol exists, the correct server/client posture is:

- `contact_discovery_supported = true` only when a separate discovery service is configured and the app server is running in `development`
- `contact_discovery_mode = "private_service"` only for that development-only separate-service ticket flow
- `contact_discovery_manifest_issuer_ed25519_pub` must be present, and clients verify the signed discovery manifest before using the service
- development clients now also pin a local continuity checkpoint for the discovery service contract and fail closed if `service_origin`, issuer keys, protocol fields, attestation verifier, enclave measurement, attestation document hash/format, or the OPRF public key change silently on the same device
- the current manifest commits to `lookup_protocol = blind_token_directory_preview`, `privacy_mode = blind_evaluation_preview`, `match_result_format = contact_invite_token`, `oprf_suite = ristretto255-sha512-preview`, and `evaluation_proof_mode = dleq_per_element_preview`; it can also carry a signed attestation verifier + enclave measurement + attestation document hash contract for stricter deployments
- raw-hash upload/match routes on the main app server remain disabled
- manual contacts, invite links, and optional `@username` lookup remain the supported bootstrap paths outside the discovery service



