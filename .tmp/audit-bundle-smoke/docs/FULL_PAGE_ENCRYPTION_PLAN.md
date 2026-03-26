# Full-Page Encryption Plan

## 1. Objective

Add true database-at-rest encryption where the platform can support it, while keeping
end-to-end encryption and app-layer secret wrapping in place.

This plan treats "full-page encryption" as protection for the database file, indexes,
WAL/journal files, and other on-disk pages, not just selective field encryption.

## 2. Current State

- Android now uses SQLCipher for the local message database in
  `mobile/android/app/src/main/java/com/pqmsg/demo/LocalMessageDatabase.kt`.
- Android still keeps the existing per-record AES-GCM message-body encryption as
  defense in depth on top of SQLCipher page encryption.
- Android now enables SQLCipher `PRAGMA cipher_memory_security = ON` during database
  configuration as additional in-process hardening.
- Android now treats unreadable device-local SQLCipher state as an explicit reprovision
  event and surfaces a linked-device/full-reprovision recovery message instead of
  silently proceeding with incompatible local storage.
- Web cannot provide trustworthy SQLCipher-style page encryption; it must continue to
  rely on app-layer encryption for sensitive local state.
- Server SQLite now has a first SQLCipher-backed connection path gated by
  `PQMSG_SQLITE_ENCRYPTION_KEY_B64`, optional SQLCipher compatibility/page-size
  settings, and fail-closed key verification on connect.
- Existing plaintext server SQLite files can now be migrated explicitly with
  `PQMSG_SQLITE_MIGRATE_PLAINTEXT=true` during a keyed startup.
- Existing encrypted server SQLite files can now rotate to a new SQLCipher raw key
  explicitly at startup with `PQMSG_SQLITE_ROTATE_KEY=true` plus
  `PQMSG_SQLITE_ROTATE_FROM_KEY_B64`.
- A dedicated offline rotation binary and wrapper scripts now exist for the preferred
  operational path:
  - `cargo run -p pqmsg-server --bin sqlite_rotate_key -- ...`
  - `scripts/dev/rotate_sqlcipher_server_key.ps1`
  - `scripts/dev/rotate_sqlcipher_server_key.sh`
- Postgres still relies on engine/storage-layer encryption choices outside the
  application.

## 3. Principles

1. End-to-end message content encryption remains the primary confidentiality control.
2. Full-page encryption is an at-rest control, not a substitute for minimizing server
   metadata.
3. Keys for page encryption must live outside the database file itself.
4. Migration must be one-way, explicit, and tested against live legacy data.
5. Development and production server storage can use different at-rest strategies.

## 4. Phase 1: Android Local Database

Status: implemented with SQLCipher migration and encrypted cold-start regression coverage.

- Use SQLCipher for the local SQLite message store.
- Generate a random 32-byte database passphrase on first run.
- Store that passphrase in Android `EncryptedSharedPreferences` protected by a
  `MasterKey`.
- Keep message-body and outbox plaintext encrypted at the application layer inside the
  SQLCipher database.
- Migrate the legacy plaintext SQLite file to the encrypted database on first open.
- Remove legacy plaintext database, WAL, and SHM files after a successful migration.

Remaining Android follow-up:

- Validate upgrade behavior with backups disabled and document the re-link/re-provision expectation for device transfers.

## 5. Phase 2: Server SQLite Storage Profile

Goal: support encrypted single-node or development SQLite deployments.

Status: implemented with explicit plaintext migration and rollback-oriented regression
coverage.

Recommended direction:

- Keep the current plain-SQLite path available for local development and tests until
  migration is complete.
- Use an external database key source:
  - environment variable for local development,
  - KMS/secret manager injection for deployment.
- Fail closed if the configured SQLCipher key is missing for an encrypted profile.
- Ensure migrations run against the encrypted database and cover WAL/journal files.
- Document Windows build prerequisites clearly: either OpenSSL development headers/libs
  or a vendored-OpenSSL build toolchain.

Implementation notes:

- The current implementation keeps `pqmsg-server` on `sqlx::AnyPool` and injects the
  SQLCipher pragmas in an `after_connect` hook for SQLite connections.
- Wrong keys or plaintext legacy files fail on connect because the hook performs an
  immediate schema read after `PRAGMA key`.
- The standard Windows source-build path now uses vendored OpenSSL, with CI coverage and
  repo helper scripts to validate Perl/MSVC prerequisites before running the server tests.
- The same Windows prerequisite wrapper is now locally verified against the targeted
  SQLCipher migration test suite.
- Remaining work is operational runbook/documentation for key rotation execution in
  deployed environments.

## 6. Phase 3: Postgres Production Storage

Goal: production-grade at-rest encryption for the main server deployment profile.

Recommended direction:

- Prefer storage-engine or platform-managed encryption first:
  - managed Postgres TDE / encrypted storage,
  - self-managed disk/volume encryption with strict key handling,
  - or a vetted Postgres TDE extension/profile if operationally acceptable.
- Do not attempt to build custom page encryption in the application layer for Postgres.
- Keep especially sensitive blobs opaque at the application layer even when TDE exists.

Operational requirements:

- key rotation procedure,
- backup encryption,
- replica/restore validation,
- documented recovery and break-glass process,
- audit evidence that encrypted storage is actually enabled in each environment.

Implementation status:

- `pqmsg-server` now fails closed in hardened deployment modes unless Postgres at-rest
  storage encryption is explicitly declared with `PQMSG_POSTGRES_STORAGE_ENCRYPTION`
  and encrypted backups are attested with `PQMSG_POSTGRES_BACKUP_ENCRYPTION=true`.
- This is a deployment-contract control, not engine-level TDE inside PostgreSQL.

## 7. Phase 4: Key Management

- Android:
  - keep DB passphrase random and device-local,
  - wrap it with Android keystore-backed storage,
  - wipe it on destructive local reset.
- Server SQLite:
  - load the SQLCipher key from environment or KMS,
  - never persist it in the repo or database file,
  - document rotation and restart behavior.
- Postgres:
  - rely on the platform or cluster key hierarchy,
  - document ownership and rotation boundaries.

## 8. Phase 5: Verification

- Android:
  - unit/instrumentation migration test,
  - open/create/read/write regression,
  - destructive reset regression,
  - cold-start regression with existing encrypted database.
- Server SQLite:
  - startup failure when encrypted profile has no key,
  - successful migration path,
  - WAL/journal file inspection in test fixtures,
  - backup/restore roundtrip.
- Postgres:
  - deployment checklist proving storage encryption is enabled,
  - restore drill against encrypted backups,
  - documented audit evidence for each production environment.

## 9. Rollout Order

1. Validate Android backup/restore behavior across upgrades and device transfer flows.
2. Standardize production Postgres at-rest encryption through platform/storage policy.
3. Re-run audit-readiness documentation with the final storage matrix.
4. Document and rehearse server SQLite operational key rotation.
