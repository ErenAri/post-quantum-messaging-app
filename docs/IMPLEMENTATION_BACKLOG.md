# Implementation Backlog

This backlog converts `docs/REALISTIC_ROADMAP.md` into concrete work items for
this repository.

The priorities below are intentionally biased toward protocol correctness,
state-lifecycle safety, and implementation/document alignment before any major
infrastructure expansion.

## Phase 1: Protocol Contract And State Invariants

- [x] Add snapshot recovery coverage for skipped-message keys and document the
  current session recovery guarantee.
- [x] Audit `docs/SPEC.md`, `docs/WIRE_FORMAT.md`, and `docs/THREAT_MODEL.md`
  against the current `pqmsg-core` handshake and session implementation.
- [x] Add a focused invariant test for replay rejection across consumed OTPK /
  initial-message flows at the server boundary.
- [x] Add explicit tests for suite continuity and wire-version continuity across
  session snapshot restore.
- [x] Add tests covering identity rotation interaction with existing session and
  trust-pin state.
- [x] Document which PCS guarantees are currently implemented, which are bounded,
  and which are still aspirational.

## Phase 2: Multi-Device And Local-Key Lifecycle

- [x] Write a single device-lifecycle contract covering registration, linked
  device import, device retirement, and local reset.
- [x] Add cross-client tests for stale-local-key recovery and same-username
  re-registration behavior in supported development flows.
- [x] Make local reset semantics consistent across Android, web, desktop, and
  CLI for keys, sessions, cursors, and trust pins.
- [x] Add explicit server/client tests for current-device retirement clearing the
  correct device-scoped state and nothing broader.

## Phase 3: Transparency And Discovery Maturity

- [x] Align discovery/transparency docs with the actual manifest, attestation,
  and client verification behavior.
- [x] Add client coverage for stale transparency checkpoint recovery plus
  fail-closed checks for manifest drift, attestation drift, and ticket/contract
  drift in supported clients.
- [x] Split "supported today" discovery behavior from the longer-term
  enclave-backed target in the docs so the contract is unambiguous.

## Phase 4: Private Group Maturity

- [ ] Define a clear private-group availability contract for local state,
  history, epoch sync, and unavailable-state handling.
- [ ] Add tests for private-group state refresh and attachment/reply/search
  behavior when local state is missing or stale.
- [ ] Tighten cross-client parity for private-group unavailable states so they
  fail consistently and intentionally.

## Phase 5: Client Hardening And UX Reliability

- [ ] Normalize security-critical recovery copy across Android, web, desktop,
  and CLI.
- [ ] Add a small supported-flow validation matrix that is exercised manually or
  automatically before release screenshots are refreshed.
- [ ] Reduce prototype-only surfaces that contradict `docs/SUPPORT_MATRIX.json`
  or current server capability policy.

## Phase 6: Operational Hardening

- [ ] Review deployment-profile guardrails against the actual supported beta
  paths and remove stale or purely aspirational checks.
- [ ] Add privacy-safe observability for the most common sync, transparency, and
  local-state recovery failures.

## Explicitly Deferred

These are intentionally not in the near-term backlog:

- FoundationDB migration
- Java/Go microservice split
- SFU / full calling stack
- SGX / Nitro / enclave rollout
- censorship-circumvention infrastructure
- enterprise biometric / quorum workflows
- compliance-first product expansion
