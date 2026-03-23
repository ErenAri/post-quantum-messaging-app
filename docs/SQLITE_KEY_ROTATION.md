# SQLite SQLCipher Key Rotation

## 1. Scope

This runbook covers offline rotation of the SQLCipher raw key for `pqmsg-server` when
`PQMSG_DATABASE_URL` points to SQLite.

The supported rotation model is:

1. stop all writers,
2. take a backup,
3. run the offline rotation tool with the current key and the target key,
4. update the deployed secret/config to the target key only,
5. restart the server and validate health.

This runbook does **not** change SQLCipher compatibility mode or page size. If you need
to change those settings, use the export/migration path instead of key rotation.

## 2. Preconditions

1. The deployment uses SQLite, not PostgreSQL.
2. You have the current SQLCipher key.
3. You have generated the target 32-byte raw key.
4. You have a current backup or filesystem snapshot of the SQLite DB file and sidecars.
5. All server writers are stopped. Rotation is offline and must not race active writers.

## 3. Windows Local / Single-Node Procedure

1. Stop `pqmsg-server`.
2. Back up the SQLite DB file and any `-wal`, `-shm`, or `-journal` sidecars.
3. Run:

```powershell
.\scripts\dev\rotate_sqlcipher_server_key.ps1 `
  -DatabaseUrl 'sqlite://./pqmsg-server.db?mode=rwc' `
  -FromKeyB64 '<current-base64-key>' `
  -GenerateTargetKey `
  -CipherPageSize 4096
```

Or provide `-ToKeyB64 '<target-base64-key>'` if the target key already exists.

4. Record the printed `PQMSG_SQLITE_ENCRYPTION_KEY_B64=<new-key>` value into the server
   secret/config store.
5. Unset any temporary rotation env vars. The normal server startup should use only:
   - `PQMSG_SQLITE_ENCRYPTION_KEY_B64=<new-key>`
   - optional `PQMSG_SQLITE_CIPHER_COMPATIBILITY`
   - optional `PQMSG_SQLITE_CIPHER_PAGE_SIZE`
6. Start `pqmsg-server`.
7. Validate:
   - `/health` succeeds,
   - the server can read existing state,
   - startup logs no SQLite encryption errors.

## 4. Linux / macOS Local Procedure

1. Stop `pqmsg-server`.
2. Back up the SQLite DB file and sidecars.
3. Run:

```bash
./scripts/dev/rotate_sqlcipher_server_key.sh \
  --database-url 'sqlite://./pqmsg-server.db?mode=rwc' \
  --from-key-b64 '<current-base64-key>' \
  --generate-target-key \
  --cipher-page-size 4096
```

4. Record the printed `PQMSG_SQLITE_ENCRYPTION_KEY_B64=<new-key>` value.
5. Start the server with the new key only and validate health.

## 5. Kubernetes / Managed Host Procedure

1. Scale `pqmsg-server` to zero or otherwise guarantee no writers are active.
2. Snapshot the persistent volume or make a file-level copy of the SQLite DB and sidecars.
3. Start a one-shot maintenance pod or host shell with access to:
   - the SQLite file,
   - the current key,
   - the new target key.
4. Run the offline rotation tool there.
5. Update the secret/configmap to the new key only.
6. Bring the service back up.
7. Validate health, logs, and a sample authenticated read path.

## 6. Rollback

If rotation fails before the secret/config is updated:

1. restore the SQLite backup,
2. keep using the old key,
3. investigate the failure,
4. retry only after the cause is understood.

If rotation succeeds but restart fails:

1. stop the server,
2. restore the pre-rotation DB backup,
3. restore the old key in config,
4. bring the service back up on the original key,
5. capture logs and rerun rotation in a maintenance window.

## 7. Notes

- The offline tool is `cargo run -p pqmsg-server --bin sqlite_rotate_key -- ...`.
- The wrapper scripts are:
  - `scripts/dev/rotate_sqlcipher_server_key.ps1`
  - `scripts/dev/rotate_sqlcipher_server_key.sh`
- The startup-only rotation path still exists via:
  - `PQMSG_SQLITE_ROTATE_KEY=true`
  - `PQMSG_SQLITE_ROTATE_FROM_KEY_B64`
  - `PQMSG_SQLITE_ENCRYPTION_KEY_B64`

The offline tool is preferred for operations because it rotates and exits instead of
booting the full service process.
