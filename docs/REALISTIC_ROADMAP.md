# Realistic Roadmap For This Repo

This roadmap is a repo-specific response to the external comparison memo in
`C:/Users/erena/Downloads/Post-Quantum Messaging App Comparison.md`.

The memo is directionally useful, but it frequently analyzes an imagined
`FastAPI + Python + PostgreSQL` system rather than the code that actually
exists here.

This repository today is primarily:

- a Rust workspace rooted in `Cargo.toml`
- a Rust cryptographic core in `crates/pqmsg-core`
- an Axum-based Rust server in `crates/pqmsg-server`
- Android, iOS, web, and desktop clients around that Rust core
- a mixed SQLite / PostgreSQL operational story, not a pure Postgres backend

The goal of this document is to turn the broad external memo into a practical,
sequenced roadmap for this codebase.

## Current Reality

The current project is best understood as:

- a research-grade hybrid post-quantum messaging prototype
- with a real protocol core, real clients, and real server behavior
- but not yet a production-ready Signal competitor

That is consistent with the repo's own positioning in `README.md`.

Important current strengths:

- hybrid cryptographic core already exists
- multiple client surfaces already exist
- explicit security profiles and deployment modes already exist
- private discovery, private groups, support matrix, threat model, and audit docs
  already exist in `docs/`
- CI, coverage, and verification discipline already exist

Important current limits:

- beta scope is still intentionally narrow
- some product flows are still prototype-grade
- discovery and private-group maturity are incomplete
- operational hardening is partial, not full production posture
- the codebase still has open questions around multi-device semantics,
  transparency behavior, and long-term protocol guarantees

## What The External Memo Gets Wrong

These are the main corrections that matter for planning:

1. The server architecture is not primarily FastAPI/Python.
   The core server here is Rust + Axum in `crates/pqmsg-server`.

2. PostgreSQL is not the whole persistence story.
   The repo deliberately supports SQLite and SQLCipher-oriented local and server
   flows, alongside PostgreSQL support and policy gates.

3. The project is not missing all structure.
   Many of the things the memo treats as absent already exist in partial form:
   threat-model docs, support matrix, deployment profiles, audit readiness,
   private discovery contract work, and opaque private-group work.

4. The memo mixes two different products.
   A privacy-focused Signal-like messenger and an enterprise-managed regulated
   communications platform are not the same roadmap.

5. The memo over-prescribes late-stage infrastructure.
   FoundationDB migration, SFU rollout, SGX/Nitro, biometrics, censorship
   circumvention, and enterprise governance are not the next steps for this repo.

## Product Decision Gate

Before more architecture expansion, the project should explicitly choose one
primary direction.

### Recommended Primary Direction

Build a Signal-like privacy-first messaging system first.

That means:

- optimize for protocol correctness, privacy properties, and multi-device safety
- treat enterprise controls as secondary or later
- avoid prematurely designing around compliance-heavy central administration

### What To Defer

Defer these unless the product direction changes:

- enterprise quorum / approval workflows
- biometric identity services
- heavy compliance packaging as a core product driver
- full calling stack and SFU work
- censorship-circumvention infrastructure
- storage-engine replacement purely for theoretical future scale

## Priority Order

## Phase 0: Freeze Scope

Before adding more major features, freeze the target scope for the next tranche:

- direct messaging
- multi-device identity and recovery semantics
- private groups
- transparency verification
- basic web + Android + iOS + desktop interoperability

Success criteria:

- no major new product surfaces added until these are coherent
- documentation in `docs/SPEC.md`, `docs/WIRE_FORMAT.md`, `docs/THREAT_MODEL.md`,
  and `docs/SUPPORT_MATRIX.json` agrees with the actual implementation

## Phase 1: Protocol Contract And State Invariants

This is the highest-value work.

Tasks:

- write down the exact current handshake, ratchet, session snapshot, and replay
  model as implemented in `crates/pqmsg-core`
- document what is currently guaranteed versus aspirational
- add invariant tests around:
  - session healing behavior
  - skipped-key handling
  - replay rejection
  - suite continuity
  - sender certificate validation
  - identity rotation edge cases

Why this matters:

- this repo is already strongest at protocol engineering
- getting the contract exact matters more than adding new infrastructure
- later audits and formal work depend on implementation/document alignment

Success criteria:

- protocol docs match implementation
- new tests cover the risky state transitions, not just happy paths
- threat model explicitly names what PCS and recovery guarantees are real today

## Phase 2: Multi-Device And Local-Key Lifecycle

This is the next practical risk area after core protocol correctness.

Tasks:

- define authoritative server/device identity lifecycle
- define what linked devices can and cannot do
- tighten local reset, recovery, and re-registration behavior across Android,
  iOS, web, and desktop
- make stale-local-key recovery consistent across clients
- ensure device retirement clears exactly the right state server-side and locally

Why this matters:

- real messaging products fail on lifecycle semantics more often than on raw
  primitive choice
- recent web repair/reset work shows this is already an active risk area

Success criteria:

- same-username recovery paths are deterministic in development and principled in
  hardened modes
- linked-device and local reset behavior is documented and tested
- no client keeps silently poisoned identity state

## Phase 3: Transparency And Discovery Maturity

The repo already has substantial discovery and transparency work. The next step
is to make the guarantees crisp and implementation-complete.

Tasks:

- align `docs/PRIVATE_CONTACT_DISCOVERY.md`, `docs/SPEC.md`, and server/client
  behavior exactly
- make continuity pinning and proof validation behavior explicit and tested
- verify client failure behavior under:
  - stale tree sizes
  - manifest drift
  - attestation drift
  - contract hash drift
- keep discovery clearly secondary to direct manual bootstrap until it is mature

Why this matters:

- the memo is right that key distribution and transparency are critical
- this repo is already investing here, so this is a realistic next step

Success criteria:

- supported clients fail closed on drift conditions already described in docs
- transparency/discovery behavior is reproducible in tests, not just prose

## Phase 4: Private Group Maturity

Private groups already exist conceptually and in code. They need product and
protocol tightening, not a fresh redesign.

Tasks:

- define group-state availability and recovery semantics clearly
- harden epoch rotation, membership updates, and local state refresh behavior
- tighten unavailable-state handling across clients
- ensure attachment, reply, search, and local history behavior are coherent in
  private-group contexts

Why this matters:

- private groups are already one of the most complex parts of the repo
- they are also one of the easiest places for client/server drift

Success criteria:

- group state is never ambiguously "kind of there"
- group unavailable states are intentional and documented
- Android/web/iOS/desktop behavior matches supported scope

## Phase 5: Client Hardening And UX Reliability

UI work should now be in service of reliability, not redesign churn.

Tasks:

- unify security-critical status messaging across clients
- reduce recovery confusion around identity mismatch, stale local state, and
  unsupported surfaces
- tighten local storage guarantees and failure messaging
- make support posture visible but not noisy

Why this matters:

- the app now has a solid Signal-inspired UI pass
- the next value is trustworthy behavior under failure, not another visual cycle

Success criteria:

- users can recover from local-state problems without guesswork
- unsupported flows fail clearly and consistently
- screenshots and product copy match the actual support matrix

## Phase 6: Operational Hardening

Do this after correctness and lifecycle work, not before.

Tasks:

- continue strengthening deployment-profile enforcement
- keep audit logging, structured logging, and policy gates aligned
- expand release verification only where it directly protects supported paths
- improve observability for protocol and sync failures without leaking metadata

Why this matters:

- the repo already has meaningful operational scaffolding
- this should be a hardening pass on current systems, not an infrastructure rewrite

Success criteria:

- supported deployment modes have explicit, test-backed guardrails
- operational telemetry helps debug sync and protocol failures without violating
  privacy posture

## Explicitly Deferred

These are not the next roadmap items for this repo:

- FoundationDB migration
- Java or Go microservice split for its own sake
- full voice/video/SFU system
- enterprise biometric identity integration
- SGX/Nitro enclave rollout
- censorship-circumvention infrastructure
- broad compliance-program work as a primary product driver

Those may become relevant later, but they are not the leverage point today.

## Recommended Next Three Milestones

If this repo needs a concrete sequence, it should be:

1. Protocol alignment milestone
   - implementation/docs/test alignment for handshake, ratchet, replay, and
     recovery invariants

2. Device lifecycle milestone
   - linked-device semantics, local reset, same-identity recovery, and
     cross-client state correctness

3. Transparency/private-group milestone
   - mature fail-closed discovery/transparency behavior and more coherent
     private-group state handling

## Bottom Line

The external comparison memo is best used as a pressure-test checklist, not as a
literal implementation plan.

The right next step for this repo is not "become Signal's backend architecture."
The right next step is:

- finish the protocol contract
- finish lifecycle correctness
- finish discovery/transparency and private-group maturity
- then harden operations around what is actually supported

That path is realistic for this codebase, and it directly builds on the project
it already is instead of the one the memo imagined.
