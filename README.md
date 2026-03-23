# Post-Quantum Messaging Prototype

## Abstract

This repository presents a research-grade prototype for hybrid post-quantum asynchronous messaging.  
The design composes X25519-based classical Diffie-Hellman with ML-KEM-family encapsulation in a PQXDH-style initiation path (including DH4 one-time prekey consumption for replay protection), followed by a minimal ratcheting channel. Identity authentication uses hybrid dual signatures (Ed25519 + ML-DSA-65) for quantum-resistant bundle verification.

The implementation objective is not product completeness; it is security-measurable protocol engineering with reproducible tests, strict parsers, and explicit failure modes.

## Current Beta Scope

As of March 9, 2026, the supported beta path is **Android private beta for messaging only**.

- Web remains a demo surface and is not part of the supported beta.
- Outbound web messaging stays blocked whenever the server advertises `web_client_policy = demo_only`.
- Calling remains out of scope for the beta on every client.
- Manual contact bootstrap on the hardened Android/web path is `@username` or opaque invite only; private discovery and private groups are still not implemented.

## Research Positioning

The project is best interpreted as a:

**Hybrid Post-Quantum Messaging Protocol Prototype with Security Verification Harness**

The strongest contributions are:

- explicit protocol specification and wire framing,
- deterministic KAT coverage for handshake transcripts,
- strict TLV/wire parsing behavior and fuzz targets,
- hybrid handshake and ratchet state model suitable for further formalization,
- DH4 one-time prekey consumption preventing replay of captured `InitialMessage` payloads,
- hybrid dual-signature authentication (Ed25519 + ML-DSA-65) for quantum-resistant identity and prekey verification,
- experimental call-signaling and media-encryption prototypes that remain out of beta scope,
- five-platform reach: CLI, Android, iOS, Web PWA, and Desktop (Tauri),
- stories (24h ephemeral broadcasts) and channels (admin-only broadcast groups).

## System Architecture

```mermaid
flowchart LR
    C[pqmsg-cli / Android / iOS / Web / Desktop] -->|HTTP JSON + TLS| S[pqmsg-server]
    S -->|WebSocket inbox stream| C
    S -->|Call signaling REST| C
    C -->|UniFFI bridge| A[pqmsg-android]
    C -->|UniFFI bridge| I[pqmsg-ios]
    D[Desktop Tauri] -->|wraps Web SPA| W[Web PWA]
    A --> CORE[pqmsg-core]
    I --> CORE
    C --> CORE
    W -->|WASM bridge| CORE
    CORE -.->|optional| HSM[PKCS#11 HSM]
    S --> DB[(PostgreSQL / SQLite)]
    S --> RD[(Redis rate limiter)]
    S --> OBS[Prometheus + Loki + Alertmanager]
    S -.->|optional| OTLP[OpenTelemetry Collector]
    PV[ProVerif model] -.-> V{CI verification gate}
    TM[Tamarin model] -.-> V
```

## Security-Critical Design Decisions

```mermaid
flowchart TD
    R1[Immutable user identity registration] --> G[Identity takeover resistance]
    R2[Ed25519 prekey signature verification] --> G
    R3[Version + suite + ratchet metadata in AEAD AD] --> H[Downgrade and tamper resistance]
    R4[Strict TLV decoding, unknown critical rejection] --> P[Parser safety]
    R5[Runtime PQ backend profile check] --> Q[Fail-closed operational posture]
    R6[FIPS feature gate: ML-KEM-768 only] --> H
    R7[Zeroize on drop for all secret-bearing structs] --> M[Memory safety]
    R8[PKCS#11 HSM signing abstraction] --> M
    R9[Sealed sender IP rate limiting] --> D[Anonymous abuse resistance]
    R10[Push circuit breaker + audit events] --> D
    R11[PII scrubbing in structured logs] --> L[Operational data hygiene]
    R12[ProVerif + Tamarin CI gate] --> V[Verified protocol correctness]
    R13[DH4 one-time prekey consumption] --> G
    R14[ML-DSA-65 dual signatures on prekey bundles] --> Q
    R15[PQ key exchange for call media encryption] --> M
```

- DH4 one-time prekey (OTPK) consumption in handshake key schedule prevents replay of captured `InitialMessage` payloads; consumed OTPKs are marked used in the server database.
- Hybrid dual-signature authentication (Ed25519 + ML-DSA-65) on prekey bundles; verifiers check BOTH signatures (security holds if EITHER scheme is secure).
- Experimental calling research path: PQ key exchange and media-encryption prototypes exist in the repo, but calling is not included in the current beta scope.
- FIPS feature gate (`--features fips`) restricts algorithm suite to ML-KEM-768 only; compile-time conflict with `classical-only-INSECURE`.
- PKCS#11 HSM signing abstraction in `pqmsg-core::hsm` supports software and hardware-backed key handles; real PKCS#11 implementation via `cryptoki` crate gated behind `hsm-pkcs11` feature.
- All secret key material is zeroized on drop via explicit `Drop` implementations (`DhKeyPair`, `SessionState`, `SessionSnapshot`, `RootStepOutput`, `PqStepOutput`, `SkippedMessageKeys`).
- Sealed sender relay enforces IP-based rate limiting extracted from `X-Forwarded-For`/`X-Real-IP` headers alongside per-recipient rate limiting.
- Push notification dispatch uses circuit-breaker pattern; circuit-open events emit security audit events.
- Structured logs undergo PII scrubbing (user IDs and device IDs replaced with SHA-256 hash prefixes).
- Server auto-migrates database schema on startup.
- Server registration is identity-immutable after first successful bind.
- Server enforces CORS (configurable via `PQMSG_CORS_ALLOWED_ORIGINS`) and security response headers (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy, Permissions-Policy, Cache-Control).
- Server supports OpenTelemetry OTLP trace export (set `PQMSG_OTLP_ENDPOINT` for gRPC collector).
- Server provides delivery/read receipt endpoints (`/v1/users/{user_id}/receipts`, `/v1/users/{user_id}/receipts/poll`).
- Server supports ephemeral (disappearing) messages with TTL (`/v1/ephemeral-relay/{recipient_user_id}`) and automatic background reaper.
- Server audit log supports size-based rotation (configurable `PQMSG_AUDIT_LOG_MAX_BYTES`, `PQMSG_AUDIT_LOG_MAX_FILES`).
- Server prekey uploads require valid Ed25519 signatures under registered identity signature keys.
- Server provides authenticated identity rotation challenge/confirm endpoints and a versioned identity event log.
- Server relay/inbox/identity-log endpoints require signed request-auth headers bound to user/device identity keys.
- Server exposes authenticated prekey inventory status (`/v1/users/{user_id}/prekeys/status`) with low-inventory signaling.
- Server WebSocket inbox stream (`/v1/ws/inbox/{user_id}`) uses the same signed request-auth model for real-time relay delivery.
- Server enforces monotonic inbox cursors per authenticated user/device session and rejects cursor regression.
- Server performs TTL-bounded relay ciphertext deduplication to reduce replay delivery risk.
- Session decryption enforces suite continuity and authenticates ratchet metadata, including `pq_step_ct` on PQ-step messages.
- PQ ratchet support is always compiled in `pqmsg-core`; runtime behavior is configured by session state and interval policy.
- Clients expose active crypto profile and fail closed when PQ backend is not available.
- Clients pin peer identity fingerprints and require explicit trust on key changes.
- Android applies screen security (`FLAG_SECURE`) across the app to block screenshots and recent-app previews by default.
- Clients track seen ciphertext blobs and reject replayed transport message IDs per peer.
- CLI, Android, and iOS clients auto-replenish one-time prekeys when server low-inventory signals are observed.
- CLI persists keys, sessions, and message archives encrypted at rest; Android persists keys/sessions in keystore-backed encrypted files and metadata in encrypted preferences; iOS persists keys/sessions in Keychain and metadata in file-protected application support storage.
- CLI maintains an encrypted local message archive with retention TTL enforcement and supports authenticated remote inbox deletion requests.
- CLI and client security surfaces expose a deterministic local reset path to purge per-user keys, sessions, pins, cursors, and conversation metadata from the device/browser.

## Repository Layout

| Path | Role |
|---|---|
| `crates/pqmsg-core` | Cryptographic primitives, handshake, TLV, wire format, ratchet/session state |
| `crates/pqmsg-server` | Prekey publication and opaque ciphertext relay service |
| `crates/pqmsg-cli` | Local operator workflow (keygen, register, publish, send, poll) |
| `crates/pqmsg-android` | UniFFI-facing Rust bridge for Android clients |
| `crates/pqmsg-ios` | UniFFI-facing Rust bridge for iOS clients |
| `mobile/android` | Minimal Kotlin demo UI and transport layer |
| `mobile/ios` | Minimal SwiftUI demo UI and iOS build scripts |
| `mobile/web` | Progressive web app shell with WebCrypto fallback mode |
| `desktop` | Tauri desktop app wrapping web SPA with native Rust crypto |
| `deploy` | Container, Kubernetes, and Helm deployment assets |
| `observability` | Prometheus, Grafana, Loki, and Promtail stack assets |
| `docs` | Normative and security documentation corpus |
| `verification/proverif` | Symbolic protocol verification model (ProVerif) |
| `verification/tamarin` | Multiset rewriting protocol model (Tamarin Prover) |
| `scripts/security` | Formal-verification and penetration smoke helper scripts |

## Build and Verification

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI/CD quality gates additionally enforce:

- **SAST**: `cargo-audit` and `cargo-deny` on every push/PR (advisories, licenses, bans, sources),
- **Coverage**: `cargo-llvm-cov` with a minimum 50% line-coverage threshold,
- **SBOM**: CycloneDX JSON bill-of-materials generated and uploaded as artifact,
- **Benchmarks**: Criterion performance benchmarks for crypto primitives and server hot-path endpoints (results as CI artifact),
- **ProVerif gate**: blocking CI job verifying all symbolic protocol queries pass on every push/PR (DH4 + dual-signature model),
- **Tamarin gate**: complementary Tamarin prover verification with OTPK single-use and hybrid-signature lemmas,
- **FIPS build gate**: CI job confirming the `fips` feature flag compiles cleanly,
- **Android build**: full APK assembly,
- **Fuzz smoke** (nightly): 5 libFuzzer targets covering TLV, wire, handshake, sealed-sender, and algorithm dispatch,
- **Interop tests**: 16 cross-platform protocol interoperability tests (wire format, snapshot persistence, bidirectional exchange, AD mismatch, suite tampering),
- **Signed releases**: cosign-signed checksums with SBOM attached.

### Security Profile Runtime Controls

`pqmsg-core` now enforces profile-aware runtime checks:

- `research`: allows local HTTP demo workflows,
- `high_assurance`: requires PQ backend and HTTPS transport in clients,
- `nss_aligned`: stricter suite allowlist plus high-assurance requirements.

CLI default profile is `research`.  
For local demo-only runs over HTTP, pass `--security-profile research`.

For non-research profiles, local CLI key/session files should be accessed with:

```powershell
--state-passphrase "<strong-passphrase>"
```

Optional message archive retention window (days):

```powershell
--message-retention-days 30
```

Legacy plaintext local files are blocked unless explicitly allowed with `--allow-plaintext-state`.

CLI key backup and restore:

```powershell
cargo run -p pqmsg-cli -- backup-keys --keys ./devkeys/alice.json --out ./backups/alice.backup.json --backup-passphrase "<backup-passphrase>"
cargo run -p pqmsg-cli -- restore-keys --input ./backups/alice.backup.json --out ./devkeys/alice-restored.json --backup-passphrase "<backup-passphrase>"
```

CLI message archive deletion (local and optional remote inbox delete request):

```powershell
cargo run -p pqmsg-cli -- delete-messages --user alice --keys ./devkeys/alice.json --peer bob --before-message-id 250
cargo run -p pqmsg-cli -- delete-messages --user alice --keys ./devkeys/alice.json --before-message-id 250 --remote
```

CLI local-state reset (optionally delete the local identity key file too):

```powershell
cargo run -p pqmsg-cli -- reset-local-state --user alice
cargo run -p pqmsg-cli -- reset-local-state --user alice --keys ./devkeys/alice.json --wipe-keys
cargo run -p pqmsg-cli -- reset-local-state --user alice --keys ./devkeys/alice.json --remote-retire --wipe-keys
```

CLI linked-device management:

```powershell
cargo run -p pqmsg-cli -- devices-list --user alice --keys ./devkeys/alice.json
cargo run -p pqmsg-cli -- devices-link --user alice --keys ./devkeys/alice.json --new-device-id alice-device-2
cargo run -p pqmsg-cli -- devices-revoke --user alice --keys ./devkeys/alice.json --target-device-id alice-device-2
```

CLI discovery, contacts, and group fan-out relay:

```powershell
cargo run -p pqmsg-cli -- discovery-upload --user alice --keys ./devkeys/alice.json --phone-hash <sha256hex> --email-hash <sha256hex>
cargo run -p pqmsg-cli -- discovery-match --user alice --keys ./devkeys/alice.json --hash <sha256hex>
cargo run -p pqmsg-cli -- contacts-add --user alice --keys ./devkeys/alice.json --peer bob --alias "Bobby"
cargo run -p pqmsg-cli -- contacts-list --user alice --keys ./devkeys/alice.json
cargo run -p pqmsg-cli -- groups-create --user alice --keys ./devkeys/alice.json --group alpha --member bob --member carol
cargo run -p pqmsg-cli -- groups-members --user alice --keys ./devkeys/alice.json --group alpha
cargo run -p pqmsg-cli -- groups-send --user alice --keys ./devkeys/alice.json --group alpha --text "group-ciphertext-placeholder"
cargo run -p pqmsg-cli -- send-sealed --from alice --to bob --text "sealed-ciphertext-placeholder"
cargo run -p pqmsg-cli -- poll-sealed --user bob --keys ./devkeys/bob.json
```

### PQ Backend Build (required for high-assurance/NSS runs)

```powershell
cargo run -p pqmsg-cli --features pqmsg-core/pq-oqs -- --help
```

The CLI performs an active runtime profile check and aborts when the PQ backend is not enabled.
`pqmsg-android` now fails closed if `pq-oqs` is not available.
`pqmsg-cli register` automatically solves registration PoW when the server advertises `registration_pow_bits > 0` via `/v1/capabilities`.

## 15-Minute Quickstart (Windows + Android Emulator)

1. Start the relay server in one terminal:

```powershell
$env:PQMSG_DATABASE_URL='sqlite://./pqmsg-server.db?mode=rwc'
$env:PQMSG_BIND='127.0.0.1:3000'
$env:PQMSG_SECURITY_PROFILE='research'
cargo run -p pqmsg-server
```

For an encrypted SQLite server database:

```powershell
$rawKey = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($rawKey)
$env:PQMSG_SQLITE_ENCRYPTION_KEY_B64 = [Convert]::ToBase64String($rawKey)
$env:PQMSG_SQLITE_MIGRATE_PLAINTEXT = 'true' # only needed once for a legacy plaintext DB
$env:PQMSG_DATABASE_URL='sqlite://./pqmsg-server.db?mode=rwc'
$env:PQMSG_BIND='127.0.0.1:3000'
$env:PQMSG_SECURITY_PROFILE='research'
cargo run -p pqmsg-server
```

On Windows source builds, `pqmsg-server` now uses the vendored-OpenSSL SQLCipher path by
default. Install Strawberry Perl if you do not already have a usable `perl.exe`
(Git for Windows also works), keep the standard MSVC build tools available, and run
`.\scripts\dev\run_sqlcipher_server_tests_windows.ps1`. Existing plaintext SQLite server
databases still require explicit one-way migration via
`PQMSG_SQLITE_MIGRATE_PLAINTEXT=true`.

To rotate an existing SQLCipher SQLite key in place at startup:

```powershell
$oldRawKey = [Convert]::FromBase64String($env:OLD_SQLITE_KEY_B64)
$newRawKey = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($newRawKey)
$env:PQMSG_SQLITE_ROTATE_KEY = 'true'
$env:PQMSG_SQLITE_ROTATE_FROM_KEY_B64 = [Convert]::ToBase64String($oldRawKey)
$env:PQMSG_SQLITE_ENCRYPTION_KEY_B64 = [Convert]::ToBase64String($newRawKey)
cargo run -p pqmsg-server
```

That rotation path preserves the existing SQLCipher compatibility and page-size settings.
If you need to change cipher format settings instead of only rotating the raw key, use
the export/migration path rather than `PRAGMA rekey`.

For hardened Postgres deployments, declare the storage profile with
`PQMSG_POSTGRES_STORAGE_ENCRYPTION=managed_service|filesystem|block|tde_extension`
and set `PQMSG_POSTGRES_BACKUP_ENCRYPTION=true` only after encrypted backups are enabled.

Metrics and health can be inspected with:

```powershell
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:3000/metrics
```

Formal verification and penetration smoke commands:

```powershell
./scripts/security/run_proverif.ps1
./scripts/security/pentest_smoke.ps1 -Server http://127.0.0.1:3000
./scripts/security/alert_drill.ps1 -Alertmanager http://127.0.0.1:9093
```

For PostgreSQL-backed server startup:

```powershell
$env:PQMSG_DATABASE_URL='postgres://pqmsg:pqmsg@localhost:5432/pqmsg'
$env:PQMSG_BIND='127.0.0.1:3000'
$env:PQMSG_SECURITY_PROFILE='high_assurance'
$env:PQMSG_DEPLOYMENT_MODE='pilot'
$env:PQMSG_DB_MAX_CONNECTIONS='30'
$env:PQMSG_DB_MIN_CONNECTIONS='5'
$env:PQMSG_DB_ACQUIRE_TIMEOUT_SECS='5'
$env:PQMSG_DB_IDLE_TIMEOUT_SECS='300'
$env:PQMSG_FCM_SERVER_KEY='<optional-fcm-legacy-server-key>'
$env:PQMSG_FCM_ENDPOINT='https://fcm.googleapis.com/fcm/send'
$env:PQMSG_APNS_BEARER_TOKEN='<optional-apns-bearer-token>'
$env:PQMSG_APNS_TOPIC='com.example.pqmsgdemo'
$env:PQMSG_APNS_ENDPOINT='https://api.push.apple.com'
$env:PQMSG_TLS_CERT_PATH='C:\certs\server.crt'
$env:PQMSG_TLS_KEY_PATH='C:\certs\server.key'
$env:PQMSG_RATE_LIMIT_REDIS_URL='redis://127.0.0.1:6379/'
$env:PQMSG_REGISTRATION_POW_BITS='18'
$env:PQMSG_PREKEY_PUBLISH_MIN_INTERVAL_SECONDS='30'
$env:PQMSG_PREKEY_BUNDLE_RESERVE_COUNT='2'
$env:PQMSG_LOG_FORMAT='json'
$env:PQMSG_AUDIT_LOG_PATH='C:\logs\pqmsg-audit.jsonl'
$env:PQMSG_AUDIT_LOG_MAX_BYTES='52428800'
$env:PQMSG_AUDIT_LOG_MAX_FILES='5'
$env:PQMSG_CORS_ALLOWED_ORIGINS='https://app.example.com'
$env:PQMSG_OTLP_ENDPOINT='http://otel-collector:4317'
cargo run -p pqmsg-server
```

2. Build Android Rust bridge and APK from repository root:

```powershell
cargo build -p pqmsg-android --features pqmsg-core/pq-oqs
cargo run -p pqmsg-android --bin uniffi-bindgen -- generate --library target/debug/pqmsg_android.dll --language kotlin --out-dir mobile/android/app/build/generated/uniffi/kotlin
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o mobile/android/app/src/main/jniLibs build -p pqmsg-android --release --features pqmsg-core/pq-oqs
cd mobile/android
.\gradlew.bat :app:assembleDebug
```

Optional iOS bridge + Xcode project generation (macOS):

```bash
cd mobile/ios
./scripts/build_rust_ios.sh
./scripts/generate_project.sh
open PQMsgDemo.xcodeproj
```

Web client fallback mode:

```bash
cd mobile/web
npm install
npm run dev
```

Desktop app (Tauri — wraps web client with native window):

```bash
cd desktop
npm install
npm run dev
```

3. In Android Studio:

- open `mobile/android`,
- run configuration `app`,
- launch two emulators for Alice and Bob.

4. On each emulator Setup screen:

- use preset button (`Alice` or `Bob`),
- keep server URL as `http://10.0.2.2:3000`,
- execute steps in order:
  `Generate Identity Keys` -> `Register User` -> `Publish Prekeys` -> `Verify Server` -> `Open Chat`.

5. In Chat screen:

- Alice fetches Bob bundle and sends message,
- Bob polls inbox and decrypts (HTTP fallback),
- real-time clients can also subscribe to `/v1/ws/inbox/{user_id}?since=<message_id>` with signed auth headers.

Optional push-token registration endpoint for Android devices:

`POST /v1/users/{user_id}/push-token`

The server sends wake-only FCM/APNs payloads and never includes plaintext message content in push transport.

## Production Transport Note

The Android emulator endpoint pattern (`http://10.0.2.2:...`) is demonstration-only.  
Operational deployment requires TLS and should include certificate pinning.  
Set `PQMSG_SECURITY_PROFILE=high_assurance` (or `nss_aligned`) with `PQMSG_TLS_CERT_PATH` and `PQMSG_TLS_KEY_PATH` on the server. For pilot/production deployments, also set `PQMSG_DEPLOYMENT_MODE=pilot` (or `production`) so the server refuses SQLite, local-only rate limiting, missing audit logs, wildcard CORS, non-PQ runtimes, and undeclared Postgres at-rest encryption. `production` also requires `PQMSG_SENTRY_DSN`.

## Containerization and Kubernetes

Production artifacts now include:

- root multi-stage `Dockerfile`,
- raw Kubernetes manifests under `deploy/k8s`,
- Helm chart under `deploy/helm/pqmsg-server`,
- autoscaling policy via HPA (`min=2`, `max=10`, CPU and memory targets).

Quick commands:

```bash
docker build -t pqmsg-server:0.1.0 .
kubectl create namespace pqmsg
kubectl create secret generic pqmsg-server-secrets --namespace pqmsg \
  --from-literal=PQMSG_DATABASE_URL='postgres://pqmsg:change-me@postgres.pqmsg.svc.cluster.local:5432/pqmsg' \
  --from-literal=PQMSG_RATE_LIMIT_REDIS_URL='redis://redis.pqmsg.svc.cluster.local:6379/'
kubectl create secret tls pqmsg-server-tls --namespace pqmsg --cert=server.crt --key=server.key
kubectl apply -k deploy/k8s
helm upgrade --install pqmsg-server deploy/helm/pqmsg-server --namespace pqmsg --create-namespace
docker compose -f docker-compose.observability.yml up -d --build
```

Observability endpoints:

- Prometheus: `http://localhost:9090`
- Alertmanager: `http://localhost:9093`
- Mailpit: `http://localhost:8025`
- Grafana: `http://localhost:3001`

Alert email settings are read from `.env.alerting` (use `.env.alerting.example` for real SMTP template).

## SQLite to PostgreSQL Data Migration

```powershell
cargo run -p pqmsg-server --bin migrate_sqlite_to_postgres -- --sqlite-url "sqlite://./pqmsg-server.db?mode=ro" --postgres-url "postgres://pqmsg:pqmsg@localhost:5432/pqmsg"
```

## Documentation Index

| Document | Description |
|---|---|
| [SPEC](docs/SPEC.md) | Protocol specification |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | Threat model and mitigations |
| [WIRE_FORMAT](docs/WIRE_FORMAT.md) | Binary wire encoding reference |
| [CRYPTO_AGILITY](docs/CRYPTO_AGILITY.md) | Algorithm suite agility design |
| [API](docs/API.md) | Server REST/WebSocket API reference |
| [SECURITY_GATES](docs/SECURITY_GATES.md) | Security quality gates policy |
| [DEPLOYMENT](docs/DEPLOYMENT.md) | Container and Kubernetes deployment |
| [OBSERVABILITY](docs/OBSERVABILITY.md) | Prometheus, Grafana, Loki stack |
| [OPERATIONS](docs/OPERATIONS.md) | Operational runbooks |
| [RELEASE_GOVERNANCE](docs/RELEASE_GOVERNANCE.md) | Release gate pipeline |
| [FORMAL_AUDIT](docs/FORMAL_AUDIT.md) | Formal verification status |
| [PENETRATION_TESTING](docs/PENETRATION_TESTING.md) | Penetration test methodology |
| [ANDROID](docs/ANDROID.md) | Android build and integration guide |
| [IOS](docs/IOS.md) | iOS build and integration guide |
| [WEB](docs/WEB.md) | Web demo client with beta holdbacks and server-policy gating |
| [TLS_ROTATION](docs/TLS_ROTATION.md) | TLS certificate rotation procedures |
| [AUDIT_READINESS](docs/AUDIT_READINESS.md) | Comprehensive audit readiness package |
| [SECURITY](SECURITY.md) | Vulnerability disclosure policy |
| [CONTRIBUTING](CONTRIBUTING.md) | Contributor guide and code conventions |
