# Post-Quantum Messaging Prototype

## Abstract

This repository is a research-grade prototype for hybrid post-quantum
asynchronous messaging.

The design combines:

- X25519 classical Diffie-Hellman
- ML-KEM-family encapsulation in a PQXDH-style initiation path
- one-time prekey (DH4) consumption for replay resistance
- hybrid identity authentication with Ed25519 + ML-DSA-65
- a minimal ratcheting channel with explicit suite and wire-version continuity

The goal is not product completeness. The goal is measurable protocol
engineering with reproducible tests, strict parsers, explicit failure modes, and
clear support boundaries.

## Current Beta Scope

As of March 9, 2026, the supported beta path is **Android private beta for messaging only**.

- Web remains a demo surface and is not part of the supported beta.
- Outbound web direct messaging and private-group messaging stay blocked whenever the server advertises `web_client_policy = demo_only`.
- The server exposes `supported_beta_clients` so the beta support matrix is machine-readable instead of only documented prose.
- Canonical machine-readable support posture now lives in `docs/SUPPORT_MATRIX.json`.
- Calling remains out of scope for the beta on every client.
- Manual contact bootstrap on the hardened Android/web path is `@username` or opaque invite only.
- Private discovery is still not fully implemented.
- The longer-term intended private-discovery direction remains a separate enclave-backed service rather than a permanently widened blind-directory preview.
- Legacy clear-roster groups remain disabled; the opaque private-group path is advertised separately through `private_group_messaging_supported`.

## Research Positioning

The project is best interpreted as a:

**Hybrid Post-Quantum Messaging Protocol Prototype with Security Verification
Harness**

Its strongest contributions are:

- explicit protocol and wire-format documentation
- deterministic KAT and interop coverage
- strict parser behavior and fuzz targets
- hybrid handshake and session-state modeling
- authenticated, fail-closed client behavior
- cross-surface experimentation across CLI, Android, iOS, web, and desktop

## System Architecture

```mermaid
flowchart LR
    C["CLI / Android / iOS / Web / Desktop"] -->|HTTP JSON + TLS| S["pqmsg-server"]
    S -->|Sealed inbox sync / realtime relay| C
    A["Android bridge"] --> CORE["pqmsg-core"]
    I["iOS bridge"] --> CORE
    W["Web WASM bridge"] --> CORE
    D["Desktop wrapper"] --> W
    S --> DB["PostgreSQL / SQLite"]
    S --> RD["Redis rate limiter"]
    PV["ProVerif model"] -.-> V["CI verification gate"]
    TM["Tamarin model"] -.-> V
```

## Security-Critical Design Decisions

- immutable user identity registration after first successful bind
- authenticated prekey publication and identity rotation flows
- strict TLV/wire parsing with fail-closed decode behavior
- suite, version, and ratchet metadata authenticated in AEAD associated data
- DH4 one-time prekey consumption as a replay-resistance control
- PQ backend runtime checks with fail-closed client behavior
- peer identity pinning and explicit trust decisions on key changes
- sealed-sender transport, sender certificates, and transparency-aware identity checks
- dedicated formal-verification and fuzzing gates

## Repository Layout

| Path | Role |
|---|---|
| `crates/pqmsg-core` | Cryptographic primitives, handshake, TLV, wire format, ratchet/session state |
| `crates/pqmsg-server` | Prekey publication and opaque ciphertext relay service |
| `crates/pqmsg-cli` | Local operator workflow |
| `crates/pqmsg-android` | UniFFI-facing Rust bridge for Android |
| `crates/pqmsg-ios` | UniFFI-facing Rust bridge for iOS |
| `mobile/android` | Kotlin Android demo client |
| `mobile/ios` | SwiftUI iOS demo client |
| `mobile/web` | Web demo shell with WASM PQ crypto and browser gating |
| `desktop` | Tauri desktop app wrapping the web shell |
| `deploy` | Container, Kubernetes, and Helm deployment assets |
| `observability` | Prometheus, Grafana, Loki, and Alertmanager assets |
| `docs` | Normative, operational, and security documentation |
| `verification` | Formal protocol models |
| `scripts/security` | Verification, validation, and audit helper scripts |

## Verification

High-signal local verification:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The broader verification story includes:

- coverage enforcement in CI
- dependency-policy checks
- ProVerif and Tamarin gates
- Android and web build validation
- interop tests
- support-matrix validation
- signed release and artifact-attestation workflows

## Getting Started

README stays high-level. Installation, local setup, emulator flow, and local app
builds live in [INSTALLATION](docs/INSTALLATION.md).

Operational deployment and release workflows live in:

- [DEPLOYMENT](docs/DEPLOYMENT.md)
- [OBSERVABILITY](docs/OBSERVABILITY.md)
- [OPERATIONS](docs/OPERATIONS.md)
- [RELEASE_GOVERNANCE](docs/RELEASE_GOVERNANCE.md)

## Documentation Index

| Document | Description |
|---|---|
| [INSTALLATION](docs/INSTALLATION.md) | Local installation, builds, and first-run setup |
| [SPEC](docs/SPEC.md) | Protocol specification |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | Threat model and mitigations |
| [WIRE_FORMAT](docs/WIRE_FORMAT.md) | Binary wire encoding reference |
| [CRYPTO_AGILITY](docs/CRYPTO_AGILITY.md) | Algorithm suite agility design |
| [API](docs/API.md) | Server REST and WebSocket API reference |
| [SECURITY_GATES](docs/SECURITY_GATES.md) | Security quality gates policy |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | Container and Kubernetes deployment guidance |
| [OBSERVABILITY](docs/OBSERVABILITY.md) | Metrics, logs, tracing, and alerting |
| [OPERATIONS](docs/OPERATIONS.md) | Operational runbooks |
| [RELEASE_GOVERNANCE](docs/RELEASE_GOVERNANCE.md) | Release gate pipeline |
| [FORMAL_AUDIT](docs/FORMAL_AUDIT.md) | Formal verification status |
| [PENETRATION_TESTING](docs/PENETRATION_TESTING.md) | Penetration test methodology |
| [ANDROID](docs/ANDROID.md) | Android architecture and integration guide |
| [IOS](docs/IOS.md) | iOS architecture and integration guide |
| [WEB](docs/WEB.md) | Web demo client and policy gating |
| [PRIVATE_GROUPS](docs/PRIVATE_GROUPS.md) | Private-group availability and fail-closed behavior |
| [PRIVATE_CONTACT_DISCOVERY](docs/PRIVATE_CONTACT_DISCOVERY.md) | Discovery contract and client verification model |
| [DEVICE_LIFECYCLE](docs/DEVICE_LIFECYCLE.md) | Registration, linking, reset, and retirement contract |
| [VALIDATION_MATRIX](docs/VALIDATION_MATRIX.md) | Supported-flow validation contract |
| [AUDIT_READINESS](docs/AUDIT_READINESS.md) | Audit readiness package |
| [SECURITY](SECURITY.md) | Vulnerability disclosure policy |
| [CONTRIBUTING](CONTRIBUTING.md) | Contributor guide and code conventions |
