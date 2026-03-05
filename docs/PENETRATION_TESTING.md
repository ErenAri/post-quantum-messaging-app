# PENETRATION_TESTING

## 1. Purpose

This runbook defines repeatable penetration-testing activities for `pqmsg-server` and supporting clients.

## 2. Test Modes

1. in-process adversarial integration tests:
   - `cargo test -p pqmsg-server --test api`
2. full workspace regression:
   - `cargo test --workspace`
3. manual API probing against live server:
   - request replay attempts,
   - authentication transcript mismatch attempts,
   - oversized payload attempts,
   - rate-limit and anti-abuse behavior validation.

## 3. Manual Probe Baseline

Start server:

```powershell
$env:PQMSG_DATABASE_URL='sqlite://./pqmsg-server.db?mode=rwc'
$env:PQMSG_BIND='127.0.0.1:3000'
$env:PQMSG_SECURITY_PROFILE='research'
cargo run -p pqmsg-server
```

Probe endpoints:

```powershell
curl http://127.0.0.1:3000/health
curl http://127.0.0.1:3000/metrics
```

Run helper:

```powershell
./scripts/security/pentest_smoke.ps1 -Server http://127.0.0.1:3000
```

Linux/macOS:

```bash
./scripts/security/pentest_smoke.sh http://127.0.0.1:3000
```

## 4. Required Evidence

Capture:

1. command transcript,
2. returned status codes and response bodies for reject paths,
3. audit log records when `PQMSG_AUDIT_LOG_PATH` is configured,
4. metrics delta snapshots before/after probes.

## 5. Minimum Reject Cases

1. missing auth headers on authenticated endpoints,
2. nonce replay on signed requests,
3. malformed or oversized payloads,
4. signature transcript mismatch,
5. anti-abuse controls:
   - rate-limit reject,
   - registration PoW reject when enabled,
   - prekey publish cooldown reject when enabled.
