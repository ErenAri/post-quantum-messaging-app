# Contributing to pqmsg

## Development Setup

### Prerequisites

- **Rust** stable toolchain (1.75+): [rustup.rs](https://rustup.rs/)
- **SQLite** (bundled via `sqlx`) — no external install needed for development
- **CMake** and a C compiler — required by the `oqs` (liboqs) PQ backend

### Build and Test

```bash
# Format check
cargo fmt --all --check

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Run all tests (unit + integration)
cargo test --workspace --all-targets

# Run only server integration tests
cargo test -p pqmsg-server --test api

# Run server property tests (proptest)
cargo test -p pqmsg-server --lib proptests

# Run benchmarks
cargo bench -p pqmsg-core --bench crypto_benchmarks
cargo bench -p pqmsg-server --bench server_load
```

### Optional: Android Build

Requires Android NDK 26+, JDK 17+, and `cargo-ndk`. See [docs/ANDROID.md](docs/ANDROID.md).

### Optional: Fuzz Testing

Requires the nightly toolchain and `cargo-fuzz`:

```bash
rustup install nightly
cargo install cargo-fuzz
cd crates/pqmsg-core
cargo +nightly fuzz run fuzz_tlv_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_wire_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_handshake_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_sealed_decode -- -max_total_time=60
cargo +nightly fuzz run fuzz_algorithm_dispatch -- -max_total_time=60
```

## Project Structure

| Crate | Purpose |
|---|---|
| `pqmsg-core` | Cryptographic primitives, handshake, ratchet, TLV/wire codec |
| `pqmsg-server` | Axum-based relay server with SQLite/Postgres, Redis rate limiting |
| `pqmsg-cli` | Command-line client for keygen, registration, messaging |
| `pqmsg-android` | UniFFI bridge exposing core to Kotlin |
| `pqmsg-ios` | UniFFI bridge exposing core to Swift |

Server source is organized into modules under `crates/pqmsg-server/src/`:

| Module | Responsibility |
|---|---|
| `lib.rs` | App state, middleware, router construction, constants |
| `handlers.rs` | All HTTP and WebSocket handler functions |
| `auth.rs` | Request authentication (TLV transcript + Ed25519 signatures) |
| `validation.rs` | Input validation and base64/hex/key parsing |
| `types.rs` | Request/response DTOs |
| `db.rs` | Database abstraction layer |
| `error.rs` | Error types and HTTP response mapping |

## Code Conventions

### Security

- **No ad hoc cryptography.** All secret-dependent operations must use vetted libraries.
- **Zeroize secrets.** Use `SecretBytes` or `Zeroizing<T>` for key material.
- **Strict parsing.** All wire parsers must be length-delimited and fallible. No panics on adversarial input.
- **Validate at boundaries.** Server endpoints validate all input; internal code trusts validated types.
- See [docs/SECURITY_GATES.md](docs/SECURITY_GATES.md) for the full policy.

### Style

- Run `cargo fmt` before committing.
- All public items in library crates should have doc comments.
- Server-internal functions use `pub(crate)` visibility.
- Test helper functions use descriptive names and unique `signing_key` seeds to avoid collisions.

### Tests

- Integration tests live in `crates/pqmsg-server/tests/api.rs`.
- End-to-end tests live in `crates/pqmsg-server/tests/e2e.rs` (call signaling, ephemeral messages, receipts, multi-device fan-out).
- Property tests (proptest) live in `#[cfg(test)] mod proptests` inside source modules.
- Each test should use unique user/device IDs to avoid cross-test interference.
- Signing key seeds: check existing allocations before choosing new ones (existing: 1–251).

### Commits

- Use conventional commit messages: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `ci:`, `chore:`.
- Security-impacting changes must update relevant docs (`SPEC.md`, `THREAT_MODEL.md`, `SECURITY_GATES.md`).

## CI Pipeline

Every push and PR runs:

| Job | What it checks |
|---|---|
| `rust-checks` | `cargo fmt`, `clippy`, `cargo test` |
| `fips-build-gate` | `pqmsg-core` compiles and passes tests with `--features fips` |
| `classical-only-build-gate` | `pqmsg-core` compiles with `--features classical-only-INSECURE` |
| `hsm-pkcs11-build-gate` | `pqmsg-core` compiles with `--features hsm-pkcs11` (SoftHSM2) |
| `postgres-integration` | Server tests against PostgreSQL 16 service container |
| `dependency-policy` | `cargo audit` + `cargo deny` (advisories, licenses, bans, sources) |
| `coverage` | `cargo llvm-cov` with minimum 50% line coverage |
| `benchmarks` | Criterion benchmarks for crypto primitives and server load (results uploaded as artifacts) |
| `sbom` | CycloneDX SBOM generation |
| `android-build` | Full Android APK assembly |
| `web-tests` | Web client npm test suite |
| `proverif-gate` | ProVerif symbolic protocol verification (all queries must pass) |

Nightly/manual jobs: `fuzz-smoke`, `pentest-smoke`, `alertmanager-config-smoke`.

## Pull Request Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace --all-targets` passes (all tests green)
- [ ] New code has test coverage
- [ ] Security-impacting changes have updated threat model / security gates docs
- [ ] No new `unsafe` blocks without justification
- [ ] No new cryptographic primitives without security review
