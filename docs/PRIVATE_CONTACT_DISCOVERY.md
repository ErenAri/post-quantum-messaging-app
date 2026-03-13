# Private Contact Discovery

## Status

Current product posture:

- Raw hash upload/match on the main server is disabled.
- Manual contacts, opaque invite links, and optional `@username` lookup remain the active contact bootstrap paths.
- The app server can now advertise `contact_discovery_mode` and, when configured, mint short-lived signed tickets for a separate private discovery service.

This document defines the next honest step beyond that groundwork: a dedicated private contact discovery subsystem instead of rebuilding a weaker server-side address-book lookup in `pqmsg-server`.

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
- Advertise the discovery mode and service origin in capabilities.

Already implemented:

- `contact_discovery_mode`
- `contact_discovery_ticket_supported`
- `contact_discovery_service_origin`
- `POST /v1/users/{user_id}/contact-discovery/ticket`

### 2. Private discovery service

Responsibilities:

- Accept only short-lived app-server-issued tickets.
- Verify the ticket signature and expiry.
- Perform the privacy-preserving lookup over blinded/encrypted identifiers.
- Return only matched account references and minimal proof/metadata needed by the client.

The discovery service must be isolated from the main messaging server so the main server never receives the user's address-book query material.

### 3. Client

Responsibilities:

- Normalize contact handles locally.
- Blind/encrypt inputs before submitting to the discovery service.
- Present results as optional contact suggestions, not automatic server-side graph mutation.
- Cache only the minimal local result set needed for UX.

## Proposed Flow

1. Client fetches `/v1/capabilities`.
2. If `contact_discovery_mode == "private_service"`, client requests `/v1/users/{user_id}/contact-discovery/ticket`.
3. Client performs the privacy-preserving discovery protocol directly against `contact_discovery_service_origin`.
4. Discovery service returns matched account references.
5. Client converts selected results into local/manual contacts.

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

The discovery service should return the minimum handle needed to bootstrap contact creation:

- stable `user_id`
- or opaque invite/bootstrap token
- or username-like share token

The choice affects metadata leakage and should be reviewed with the invite and username flows.

### Abuse controls

Need explicit policy for:

- per-device ticket issuance rate
- per-ticket query count and max input size
- abuse logging that does not recreate a contact graph

## Recommended Implementation Order

1. Add a dedicated discovery-service manifest/attestation contract.
2. Implement a separate `pqmsg-discovery` service crate or sibling service.
3. Add client-side private-discovery transport and local result handling on Android and web.
4. Remove any remaining product text that implies discovery is available before the new service ships.
5. Subject the discovery service to separate review before enabling it in hardened deployments.

## Current Repo Boundary

Until the separate service exists, the correct server/client posture is:

- `contact_discovery_supported = false`
- `contact_discovery_mode = "manual_only"` unless a separate service is actually configured
- manual contacts, invite links, and optional `@username` lookup remain the only supported discovery/bootstrap paths
