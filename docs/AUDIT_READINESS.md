# Audit Readiness Package

> **Version:** 1.0  
> **Last updated:** 2025  
> **Scope:** pqmsg — Post-Quantum Messaging Application

This document indexes all security-relevant artifacts in the repository and maps them
to industry audit frameworks. It is intended as the primary entry-point for an external
security auditor performing a Tier 3.5 (high-assurance) software security assessment.

To materialize the current document set as a reproducible handoff package, run:

```bash
python scripts/security/build_audit_readiness_bundle.py --output-dir /tmp/pqmsg-audit-bundle
```

That bundle copies the core audit documents, selected governance workflows, and manifest/policy validators into a single directory and writes `audit-bundle-manifest.json` with SHA-256 digests for each included artifact.

To verify a generated bundle locally, run:

```bash
python scripts/security/verify_audit_readiness_bundle.py --bundle-dir /tmp/pqmsg-audit-bundle
```

To turn that verified bundle into an external-review handoff archive with checksum, machine-readable descriptor, and a human-readable finding summary, run:

```bash
python scripts/security/prepare_external_audit_handoff.py --bundle-dir /tmp/pqmsg-audit-bundle --output-dir /tmp/pqmsg-audit-handoff
```

To add or update a concrete finding in the registry, run:

```bash
python scripts/security/upsert_audit_finding.py \
  --finding-id AUD-2026-001 \
  --source external_audit \
  --title "Example finding title" \
  --severity high \
  --affected-component crates/pqmsg-core/src/session.rs \
  --exploit-path "Describe the concrete exploit path" \
  --mitigation-plan "Describe the remediation plan" \
  --verification-test "Describe the verification test" \
  --status open
```

To render the current registry as a standalone Markdown summary, run:

```bash
python scripts/security/render_audit_findings_report.py --output /tmp/audit-findings-summary.md
```

To record a real audit engagement and later mark it complete, run:

```bash
python scripts/security/upsert_audit_engagement.py \
  --engagement-id EXT-AUDIT-2026-01 \
  --type external_audit \
  --auditor-name "Example Security Lab" \
  --scope "Protocol, server, Android beta path" \
  --status in_progress
```

When the engagement is complete and its report is in hand, the final closeout check is:

```bash
python scripts/security/validate_final_audit_closeout.py
```

CI also validates that repository paths referenced in this document still exist via:

```bash
python scripts/security/validate_audit_readiness_index.py
```

The CI `audit-readiness-bundle` job now builds the full bundle, verifies it, uploads it as an artifact, prepares a zipped external handoff package, writes `audit-findings-summary.md`, and attests both the bundle manifest and handoff archive provenance.

The current beta support boundary is also frozen as a machine-readable artifact in `docs/SUPPORT_MATRIX.json`, with CI drift checks in `scripts/security/validate_support_matrix.py`.

External findings now also have a machine-readable registry in `docs/AUDIT_FINDINGS.json`,
validated by `scripts/security/validate_audit_findings.py` and mirrored by the GitHub issue
template `.github/ISSUE_TEMPLATE/security-audit-finding.yml`.
The registry can be maintained locally with `scripts/security/upsert_audit_finding.py`, and a
human-readable summary can be rendered on demand with
`scripts/security/render_audit_findings_report.py`.
External audit engagements themselves are now tracked separately in
`docs/AUDIT_ENGAGEMENTS.json`, validated by `scripts/security/validate_audit_engagements.py`
and maintained with `scripts/security/upsert_audit_engagement.py`.
Tagged releases additionally fail closed on unresolved `critical` / `high` findings via
`scripts/security/validate_release_audit_gate.py`.
Release publication also emits `dist/release-security-posture.json` so the published artifact set
records the exact support boundary and audit-gate state used for go/no-go.
Applied promotion and rollback verification now compares the live `/v1/capabilities` support
boundary against that frozen release posture before the bundle is accepted as green evidence.
For the actual final human release decision after an external review,
`scripts/security/validate_final_audit_closeout.py` checks both the findings gate and the
presence of at least one completed `external_audit` engagement.

---

## 1. Repository Layout

| Area | Path | Description |
|------|------|-------------|
| Core crypto | `crates/pqmsg-core/` | PQXDH handshake, Double Ratchet, PQ ratchet, TLV encoding, ML-KEM, X25519 |
| Server | `crates/pqmsg-server/` | Axum-based directory/relay server, auth, audit logging |
| CLI | `crates/pqmsg-cli/` | Command-line client |
| Android | `crates/pqmsg-android/`, `mobile/android/` | UniFFI bindings + Kotlin demo |
| iOS | `crates/pqmsg-ios/`, `mobile/ios/` | UniFFI bindings + Swift demo |
| Web | `mobile/web/` | PWA client (WebCrypto) |
| Formal verification | `verification/proverif/`, `verification/tamarin/` | Symbolic models |
| Observability | `observability/` | Prometheus, Grafana, Loki, Alertmanager configs |
| CI | `.github/workflows/ci.yml` | Full CI pipeline with security gates |
| Deployment | `deploy/` | Kubernetes manifests, Helm chart |

---

## 2. Documentation Index

| Document | Path | Audit Relevance |
|----------|------|-----------------|
| Protocol Specification | `docs/SPEC.md` | Cryptographic construction, session model, ratcheting |
| Device Lifecycle Contract | `docs/DEVICE_LIFECYCLE.md` | Registration, linked-device import, retirement, reset semantics |
| Threat Model | `docs/THREAT_MODEL.md` | Adversary classes, controls, residual risks |
| Wire Format | `docs/WIRE_FORMAT.md` | Binary encoding, TLV, AEAD binding |
| Crypto Agility | `docs/CRYPTO_AGILITY.md` | Suite registry, FIPS mode, downgrade resistance |
| Security Gates | `docs/SECURITY_GATES.md` | Mandatory quality gates (zeroize, constant-time, parsing) |
| Formal Audit Scope | `docs/FORMAL_AUDIT.md` | External audit engagement plan |
| Audit Findings Registry | `docs/AUDIT_FINDINGS.json` | Canonical finding/remediation tracker |
| Audit Engagement Registry | `docs/AUDIT_ENGAGEMENTS.json` | Canonical external-audit engagement tracker |
| Audit Release Gate | `scripts/security/validate_release_audit_gate.py` | Fails release on unresolved critical/high findings |
| Final Audit Closeout Gate | `scripts/security/validate_final_audit_closeout.py` | Requires a completed external audit plus a clean blocking-findings gate |
| Audit Engagement Upsert Tool | `scripts/security/upsert_audit_engagement.py` | Deterministic local maintenance of the engagement registry |
| Audit Finding Upsert Tool | `scripts/security/upsert_audit_finding.py` | Deterministic local maintenance of the findings registry |
| Audit Findings Report Renderer | `scripts/security/render_audit_findings_report.py` | Reusable Markdown summary of tracked findings |
| Penetration Testing | `docs/PENETRATION_TESTING.md` | Repeatable pentest runbooks |
| Release Governance | `docs/RELEASE_GOVERNANCE.md` | Change control, dual-reviewer, rollback |
| Operations Runbook | `docs/OPERATIONS.md` | SLOs, incident response, DR drills |
| TLS Rotation | `docs/TLS_ROTATION.md` | Certificate lifecycle, pin rotation |
| Observability | `docs/OBSERVABILITY.md` | Metrics, alerting, logging architecture |
| API Reference | `docs/API.md` | HTTP API, auth headers, replay controls |
| Support Matrix | `docs/SUPPORT_MATRIX.json` | Canonical beta support boundary and holdbacks |
| Deployment Guide | `docs/DEPLOYMENT.md` | Container build, K8s, Helm, autoscaling |
| Audit Finding Intake Template | `.github/ISSUE_TEMPLATE/security-audit-finding.yml` | Structured GitHub intake for external findings |

---

## 3. Cryptographic Inventory

| Primitive | Algorithm | Library | Notes |
|-----------|-----------|---------|-------|
| Key agreement (classical) | X25519 | `x25519-dalek` | ECDH component of PQXDH |
| Key agreement (PQ) | ML-KEM-768 (FIPS 203) | `oqs` 0.11 (liboqs) | Default PQ KEM |
| Digital signature | Ed25519 | `ed25519-dalek` | Identity keys, prekey signatures |
| AEAD | ChaCha20-Poly1305 | `chacha20poly1305` | Session encryption |
| KDF | HKDF-SHA-256 | `hkdf`, `sha2` | Key schedule |
| Password hash | Argon2id | `argon2` | Client-side key stretching |
| Hash | SHA-256 | `sha2` | PII scrubbing, various |

### Feature Flags

| Flag | Effect |
|------|--------|
| `pq-oqs` | Explicitly enables the liboqs-backed ML-KEM-768 / ML-DSA-65 backend |
| `pq-rust` | Explicitly enables the pure-Rust ML-KEM-768 / ML-DSA-65 backend |
| `fips` | Restricts to FIPS-approved suites only; adds `FipsKemWrapper` with extra key validation and implies `pq-oqs` |
| `classical-only-INSECURE` | Disables PQ primitives (testing only; compile-error with `fips`) |

`pqmsg-core` does not select a PQ backend implicitly; consumers and CI lanes must
opt into `pq-oqs` or `pq-rust` explicitly.

### Suite Registry

Defined in `crates/pqmsg-core/src/alg.rs`:

| Suite ID | Name | Status |
|----------|------|--------|
| 0x0001 | ML-KEM-768 + X25519 | Default, FIPS-approved |
| 0x0002 | Kyber768 Alias | Non-FIPS (blocked under `fips` feature) |
| 0xFF01 | X25519-Only (INSECURE) | Research only |

---

## 4. Security Controls Matrix

### 4.1 Authentication & Access Control

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Request authentication | Ed25519 HMAC over request body with timestamp + nonce | `crates/pqmsg-server/src/auth.rs` |
| Nonce replay prevention | Distributed cache (Redis or in-memory) with TTL | `crates/pqmsg-server/src/lib.rs` — `AuthReplayCache` |
| Timestamp skew rejection | ±300 second window | `crates/pqmsg-server/src/auth.rs` |
| Rate limiting | Per-key sliding window | `crates/pqmsg-server/src/lib.rs` — `RateLimiter` |
| DoS hardening | Request body limits, PoW for registration | `crates/pqmsg-server/src/lib.rs` — `DosHardeningPolicy` |

### 4.2 Cryptographic Controls

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Hybrid key agreement | PQXDH = X25519 + ML-KEM-768 | `crates/pqmsg-core/src/handshake.rs` |
| PQ ratchet re-keying | Configurable interval (supported default: every message) | `crates/pqmsg-core/src/ratchet/pq.rs` |
| Signed prekey expiry | Server rejects stale prekeys (>30 day default) | `crates/pqmsg-server/src/handlers/prekeys.rs` |
| ML-KEM key validation | Encapsulation key length + decapsulation round-trip check | `crates/pqmsg-core/src/kem.rs` |
| FIPS mode | Compile-time gate restricting to FIPS-approved suites | `crates/pqmsg-core/src/alg.rs`, `kem.rs` |
| Algorithm downgrade prevention | Fail-closed suite negotiation | `crates/pqmsg-core/src/wire.rs` — `SupportedSuites::negotiate()` |
| Bounded skipped-key cache | Hard limit prevents memory exhaustion | `crates/pqmsg-core/src/ratchet/mod.rs` |
| KAT test vectors | Known-answer tests for PQXDH handshake | `crates/pqmsg-core/src/handshake.rs` tests |

### 4.3 Operational Security

| Control | Implementation | Evidence |
|---------|---------------|----------|
| Mandatory audit logging | Required for non-Research security profiles | `crates/pqmsg-server/src/main.rs` |
| PII scrubbing | SHA-256 prefix hash in structured logs | `crates/pqmsg-server/src/lib.rs` — `scrub_pii()` |
| Push circuit breaker | Per-provider (FCM/APNs) with threshold + cooldown | `crates/pqmsg-server/src/lib.rs` — `CircuitBreakerState` |
| Graceful shutdown | SIGTERM handler with connection drain | `crates/pqmsg-server/src/main.rs` |
| Request timeout | Tower middleware, configurable | `crates/pqmsg-server/src/main.rs` |
| Health checks | Deep health endpoint (DB, Redis, disk, latency) | `crates/pqmsg-server/src/handlers/mod.rs` |

### 4.4 Monitoring & Alerting

| Alert | Severity | Trigger |
|-------|----------|---------|
| High 5xx error rate | Critical | >2% sustained for 10m |
| Auth reject spike | High | >5/s for 5m |
| Nonce replay burst | Critical | >10/s for 2m |
| Push circuit breaker open | Critical | Any provider circuit open |
| Signed prekey staleness | High | Stale prekeys served for 15m |
| PQ prekey depletion | High | Last-resort keys served for 5m |
| Device revocation spike | High | >3/s for 5m |
| PQ ratchet stall | High | No re-key steps for 30m while messages flow |
| Registration spike | Medium | >10/s for 5m |
| Rate limit reject spike | Medium | >20/s for 10m |
| High in-flight requests | Medium | >200 for 10m |

Full rules: `observability/prometheus/alert-rules.yml`

---

### 4.5 Storage At-Rest Matrix

| Surface | At-rest posture | Evidence |
|---------|-----------------|----------|
| Android local message DB | SQLCipher full-page encryption with a device-local random passphrase wrapped in encrypted preferences; message bodies remain app-layer encrypted inside the DB; SQLCipher `cipher_memory_security` is enabled during DB configuration | `mobile/android/app/src/main/java/com/pqmsg/demo/LocalMessageDatabase.kt` |
| Android backup policy | Auto Backup and device-to-device backup transfer are disabled for app state; device moves require explicit re-link / reprovision flow instead of raw state restore | `mobile/android/app/src/main/AndroidManifest.xml`, `mobile/android/app/src/main/res/xml/backup_rules.xml`, `mobile/android/app/src/main/res/xml/data_extraction_rules.xml` |
| Android storage regression evidence | Plaintext-to-SQLCipher migration, encrypted cold-reopen coverage, and fail-closed bad-restore coverage when the wrapped SQLCipher passphrase is missing | `mobile/android/app/src/androidTest/java/com/pqmsg/demo/LocalMessageDatabaseMigrationInstrumentationTest.kt` |
| Server SQLite | SQLCipher page encryption with fail-closed keyed startup, explicit one-way plaintext migration, explicit startup key rotation, offline key-rotation tooling, and migration/rotation guard coverage | `crates/pqmsg-server/src/db.rs`, `crates/pqmsg-server/src/main.rs`, `crates/pqmsg-server/src/bin/sqlite_rotate_key.rs` |
| Server SQLite Windows path | Vendored-OpenSSL SQLCipher build with repo prerequisite wrapper, CI lane, and locally verified targeted migration tests | `scripts/dev/check_sqlcipher_server_prereqs.ps1`, `scripts/dev/run_sqlcipher_server_tests_windows.ps1`, `.github/workflows/ci.yml`, `crates/pqmsg-server/src/db.rs` |
| Postgres production profile | Platform/storage-level encryption required by deployment contract; encrypted backups required in hardened modes | `crates/pqmsg-server/src/main.rs`, `docs/DEPLOYMENT.md`, `docs/FULL_PAGE_ENCRYPTION_PLAN.md` |
| Web local state | No trustworthy page-encryption layer; sensitive state relies on app-layer encryption and hardened storage policy | `mobile/web/src/storage.ts`, `docs/FULL_PAGE_ENCRYPTION_PLAN.md` |
| Web browser boundary | Hosted web messaging fails closed without secure context and cross-origin isolation, and the service worker does not cache cross-origin or `/v1/*` messaging traffic | `mobile/web/src/webEnvironment.ts`, `mobile/web/public/sw.js`, `mobile/web/vite.config.ts` |

---

## 5. Formal Verification

### 5.1 ProVerif (Symbolic)

**Model:** `verification/proverif/pqxdh_hybrid_model.pv`

| Query | Property |
|-------|----------|
| `attacker(plaintext0)` | Plaintext secrecy |
| `AliceComplete ==> not attacker(k)` | Session key secrecy |
| `BobComplete ==> AliceComplete` | Authentication |
| `BobComplete ==> AliceAcceptedBundle` | Bundle integrity |
| `attacker(plaintext_fs)` | Forward secrecy (post ephemeral reveal) |
| `SessionBound identity agreement` | Identity misbinding resistance |

**CI gate:** `proverif-gate` job runs on every push/PR (blocking).

### 5.2 Tamarin (Multiset Rewriting)

**Model:** `verification/tamarin/pqxdh_hybrid.spthy`

| Lemma | Property |
|-------|----------|
| `session_key_secrecy` | Key secrecy under honest parties |
| `authentication` | Injective agreement |
| `forward_secrecy` | Key secrecy under post-session compromise |
| `no_key_reuse` | Session key uniqueness |

---

## 6. Testing Coverage

| Category | Tool | Location |
|----------|------|----------|
| Unit tests | `cargo test` | All crates |
| Integration tests | `cargo test -p pqmsg-server` | `crates/pqmsg-server/tests/` |
| Fuzz targets | `cargo-fuzz` | `crates/pqmsg-core/fuzz/` — TLV, wire, handshake, sealed, algorithm dispatch |
| KAT vectors | In-source tests | `crates/pqmsg-core/src/handshake.rs` |
| Coverage gate | `cargo-llvm-cov` | CI enforces ≥50% line coverage |
| Penetration smoke | Shell script | `scripts/security/pentest_smoke.sh` |
| FIPS build gate | CI job | `cargo test -p pqmsg-core --features fips` |

---

## 7. Supply Chain

| Control | Tool | CI Job |
|---------|------|--------|
| Advisory audit | `cargo-audit` | `dependency-policy` |
| License/ban/source audit | `cargo-deny` | `dependency-policy` |
| SBOM generation | `cargo-cyclonedx` (CycloneDX JSON) | `sbom` |
| Release provenance | GitHub artifact attestations + signed checksum manifest + `release-manifest.json` including published GHCR image digest + deployment-ready image reference artifacts + container provenance attestation + promotion path that consumes the signed bundle + rollback mapping artifacts + post-deploy verification evidence + rollback execution evidence + pre-apply cluster contract validation + classified pre/post drift evidence + live post-apply policy verification + live Service/Ingress routing verification + incident-ready failure handoff records used as a blocking workflow gate + optional Alertmanager incident payload submission from workflow governance failures with recorded delivery evidence + optional GitHub issue publication for durable incident tracking, structured `pqmsg-*` issue labels, later scope-based resolution, per-bundle SHA-256 evidence manifests, issue-thread publication of the final bundle-manifest digest, GitHub artifact attestations for promotion/rollback bundle manifests, and consumer-side workflow-bundle verification before rollback | `release`, `promote`, `rollback` |
| Deny policy | `deny.toml` | Bans, advisories, licenses, sources |

---

## 8. Deployment Security

| Control | Evidence |
|---------|----------|
| Non-root container | `Dockerfile` — `USER nonroot` |
| Distroless base image | `gcr.io/distroless/cc-debian12` |
| TLS termination | Rustls with certificate files |
| Secret management | Kubernetes Secrets (base64) |
| Postgres at-rest declaration | Hardened deployments require `PQMSG_POSTGRES_STORAGE_ENCRYPTION` and `PQMSG_POSTGRES_BACKUP_ENCRYPTION=true` |
| Pod hardening | CI-enforced `automountServiceAccountToken: false`, `enableServiceLinks: false`, `seccompProfile.type: RuntimeDefault`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` |
| Network isolation | CI-enforced `NetworkPolicy` parity across raw K8s and Helm renders |
| Namespace admission baseline | Raw namespace pins Pod Security Admission `restricted` labels at `v1.34`; Helm target namespaces must match operationally |
| Immutable deployment image | CI-enforced digest pinning for raw K8s and rendered Helm manifests |
| Horizontal autoscaling | HPA with CPU/memory targets |
| Network policy | Ingress annotations for rate limiting |

---

## 9. Compliance Mapping

### NIST SP 800-207 (Zero Trust)

| Principle | Status |
|-----------|--------|
| Per-request authentication | ✅ Ed25519 signed requests |
| Least privilege | ✅ Device-scoped access |
| Encryption in transit | ✅ TLS 1.3 (Rustls) |
| Continuous monitoring | ✅ Prometheus + Alertmanager |

### NIST SP 800-208 (PQC Transition)

| Requirement | Status |
|-------------|--------|
| Hybrid key agreement | ✅ X25519 + ML-KEM-768 |
| Algorithm agility | ✅ Suite registry with negotiation |
| FIPS 203 compliance | ✅ `fips` feature gate |
| Crypto inventory | ✅ Section 3 above |

### OWASP Top 10 (2021)

| Category | Status |
|----------|--------|
| A01 Broken Access Control | ✅ Per-request auth, device-scoped |
| A02 Cryptographic Failures | ✅ Hybrid PQ, no weak ciphers |
| A03 Injection | ✅ Parameterized SQL (SQLx), strict parsing |
| A04 Insecure Design | ✅ Formal verification, threat model |
| A05 Security Misconfiguration | ✅ Security profiles, mandatory audit logging |
| A06 Vulnerable Components | ✅ cargo-audit, cargo-deny, SBOM |
| A07 Auth Failures | ✅ Replay cache, timestamp validation |
| A08 Data Integrity | ✅ AEAD binding, signature verification |
| A09 Logging/Monitoring | ✅ Structured audit logs, PII scrubbing, alerts |
| A10 SSRF | ✅ No server-side URL fetching |

---

## 10. Auditor Quickstart

```bash
# 1. Run all tests
cargo test --workspace --all-targets

# 2. Run FIPS-mode tests
cargo test -p pqmsg-core --features fips

# 3. Run fuzz targets (20s each)
cd crates/pqmsg-core
cargo +nightly fuzz run fuzz_tlv_decode -- -max_total_time=20
cargo +nightly fuzz run fuzz_wire_decode -- -max_total_time=20
cargo +nightly fuzz run fuzz_handshake_decode -- -max_total_time=20

# 4. Formal verification (requires proverif)
proverif verification/proverif/pqxdh_hybrid_model.pv

# 5. Formal verification (requires tamarin-prover)
tamarin-prover verification/tamarin/pqxdh_hybrid.spthy --prove

# 6. Supply chain audit
cargo audit
cargo deny check advisories licenses bans sources

# 7. Generate SBOM
cargo cyclonedx --manifest-path Cargo.toml --format json --all

# 8. Windows SQLCipher SQLite check
.\scripts\dev\run_sqlcipher_server_tests_windows.ps1

# 9. Coverage report
cargo llvm-cov --workspace --exclude pqmsg-android --exclude pqmsg-ios --html
```

---

## 11. Known Limitations & Residual Risks

| Risk | Mitigation | Status |
|------|-----------|--------|
| Endpoint malware | Out of scope; mitigated by platform security | Accepted |
| Traffic analysis | Constant-size padding not yet implemented | Open |
| HSM integration | PKCS#11 stub present, not production-tested | In progress |
| ML-KEM standardization | Tracking NIST FIPS 203 final | Monitoring |
| Browser PQ gap | Web client uses WebCrypto (no PQ); envelope mode only | Documented |
