# Audit Readiness Package

> **Version:** 1.0  
> **Last updated:** 2025  
> **Scope:** pqmsg — Post-Quantum Messaging Application

This document indexes all security-relevant artifacts in the repository and maps them
to industry audit frameworks. It is intended as the primary entry-point for an external
security auditor performing a Tier 3.5 (high-assurance) software security assessment.

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
| Threat Model | `docs/THREAT_MODEL.md` | Adversary classes, controls, residual risks |
| Wire Format | `docs/WIRE_FORMAT.md` | Binary encoding, TLV, AEAD binding |
| Crypto Agility | `docs/CRYPTO_AGILITY.md` | Suite registry, FIPS mode, downgrade resistance |
| Security Gates | `docs/SECURITY_GATES.md` | Mandatory quality gates (zeroize, constant-time, parsing) |
| Formal Audit Scope | `docs/FORMAL_AUDIT.md` | External audit engagement plan |
| Penetration Testing | `docs/PENETRATION_TESTING.md` | Repeatable pentest runbooks |
| Release Governance | `docs/RELEASE_GOVERNANCE.md` | Change control, dual-reviewer, rollback |
| Operations Runbook | `docs/OPERATIONS.md` | SLOs, incident response, DR drills |
| TLS Rotation | `docs/TLS_ROTATION.md` | Certificate lifecycle, pin rotation |
| Observability | `docs/OBSERVABILITY.md` | Metrics, alerting, logging architecture |
| API Reference | `docs/API.md` | HTTP API, auth headers, replay controls |
| Deployment Guide | `docs/DEPLOYMENT.md` | Container build, K8s, Helm, autoscaling |

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
| `pq-oqs` (default) | Enables ML-KEM-768 via liboqs |
| `fips` | Restricts to FIPS-approved suites only; adds `FipsKemWrapper` with extra key validation |
| `classical-only-INSECURE` | Disables PQ primitives (testing only; compile-error with `fips`) |

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
| Bounded skipped-key cache | Hard limit prevents memory exhaustion | `crates/pqmsg-core/src/ratchet/double.rs` |
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
