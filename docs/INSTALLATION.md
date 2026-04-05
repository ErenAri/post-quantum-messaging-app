# INSTALLATION

## 1. Scope

This document covers local installation, build, and first-run setup for the
current research and beta surfaces:

- local relay server,
- Android demo client,
- web demo shell,
- desktop wrapper,
- optional iOS local build path.

Operational deployment, Kubernetes, observability, and release workflows stay in
[DEPLOYMENT](DEPLOYMENT.md), [OBSERVABILITY](OBSERVABILITY.md), and
[RELEASE_GOVERNANCE](RELEASE_GOVERNANCE.md).

## 2. Prerequisites

Minimum local toolchain:

- Rust stable toolchain
- PowerShell on Windows or a POSIX shell on macOS/Linux
- Node.js and npm for the web and desktop shells
- Android Studio with SDK and NDK if building Android
- `cargo-ndk` for Android Rust library builds
- `xcodegen` and Xcode on macOS if building iOS

Windows SQLCipher source builds additionally need:

- Strawberry Perl or another usable `perl.exe`
- standard MSVC build tools
- optional `nasm` for faster OpenSSL assembly builds

Useful helper:

```powershell
.\scripts\dev\run_sqlcipher_server_tests_windows.ps1
```

## 3. Local Relay Server

Research-profile local server:

```powershell
$env:PQMSG_DATABASE_URL='sqlite://./pqmsg-server.db?mode=rwc'
$env:PQMSG_BIND='127.0.0.1:3000'
$env:PQMSG_SECURITY_PROFILE='research'
cargo run -p pqmsg-server
```

Encrypted SQLite server database:

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

Rotate an existing SQLCipher SQLite key in place at startup:

```powershell
$oldRawKey = [Convert]::FromBase64String($env:OLD_SQLITE_KEY_B64)
$newRawKey = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($newRawKey)
$env:PQMSG_SQLITE_ROTATE_KEY = 'true'
$env:PQMSG_SQLITE_ROTATE_FROM_KEY_B64 = [Convert]::ToBase64String($oldRawKey)
$env:PQMSG_SQLITE_ENCRYPTION_KEY_B64 = [Convert]::ToBase64String($newRawKey)
cargo run -p pqmsg-server
```

Health and metrics:

```powershell
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:3000/metrics
```

Hardened PostgreSQL-backed startup:

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

For deployment-specific guardrails, storage profiles, and cluster rollout, use
[DEPLOYMENT](DEPLOYMENT.md).

## 4. Android Local Build

Build the Android Rust bridge and APK from repository root:

```powershell
cargo build -p pqmsg-android
cargo run -p pqmsg-android --bin uniffi-bindgen -- generate --library target/debug/pqmsg_android.dll --language kotlin --out-dir mobile/android/app/build/generated/uniffi/kotlin
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o mobile/android/app/src/main/jniLibs build -p pqmsg-android --release
cd mobile/android
.\gradlew.bat :app:assembleDebug
```

Android Studio run path:

1. Open `mobile/android`.
2. Run configuration `app`.
3. Launch two emulators for Alice and Bob.
4. On each setup screen, use the preset button, keep the server URL as
   `http://10.0.2.2:3000`, and complete the guided setup flow.

For Android architecture, persistence, troubleshooting, and deeper build notes,
use [ANDROID](ANDROID.md).

## 5. Web Demo Shell

```bash
cd mobile/web
npm install
npm run dev
```

Production bundle:

```bash
cd mobile/web
npm install
npm run build
npm run preview
```

Web remains a demo surface unless the server advertises a hardened web policy.
See [WEB](WEB.md) for capability
gating and browser constraints.

## 6. Desktop Wrapper

```bash
cd desktop
npm install
npm run dev
```

The desktop app wraps the web SPA with a native shell.

## 7. Optional iOS Local Build

```bash
cd mobile/ios
./scripts/build_rust_ios.sh
./scripts/generate_project.sh
open PQMsgDemo.xcodeproj
```

For iOS details, use [IOS](IOS.md).

## 8. CLI Notes

CLI help:

```powershell
cargo run -p pqmsg-cli -- --help
```

The CLI requires an explicit PQ backend through `pqmsg-core` feature selection.
For usage workflows, lifecycle semantics, and reset behavior, see:

- [DEVICE_LIFECYCLE](DEVICE_LIFECYCLE.md)
- [SPEC](SPEC.md)

## 9. Validation Before Screenshots Or Demos

Run the support-aware validation matrix first:

```powershell
py -3 scripts/dev/validate_supported_client_flows.py --surface web
py -3 scripts/dev/validate_supported_client_flows.py --surface android
```

The validation contract is documented in
[VALIDATION_MATRIX](VALIDATION_MATRIX.md).
