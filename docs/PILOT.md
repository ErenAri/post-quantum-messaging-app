# Android Messaging Pilot

## 1. Objective

This runbook defines the first supported pilot for `pqmsg`.

The pilot is intentionally narrow:

- Android is the only supported pilot client.
- Web remains demo-only.
- Calling remains out of scope.
- Supported messaging scope is direct messaging plus opaque private groups.
- Manual bootstrap remains `@username` or opaque invite only.

The canonical frozen support contract remains:

- [docs/SUPPORT_MATRIX.json](SUPPORT_MATRIX.json)

The live pilot environment must keep `/v1/capabilities` aligned with that file.

## 2. Frozen Support Contract

Do not widen product scope during pilot preparation.

Pilot contract:

- `supported_beta_clients = ["android"]`
- `web_client_policy = "demo_only"`
- `calling_supported = false`
- `private_group_messaging_supported = true`
- legacy clear-roster groups remain disabled

If any of those values must change, stop the pilot rollout and update the support contract first.

## 3. Pilot Defaults

Unless a release owner explicitly overrides them, use these defaults:

- GitHub Environment: `pilot`
- Kubernetes namespace: `pqmsg-pilot`
- Helm release name: `pqmsg-server`
- deployment mode: `pilot`
- security profile: `high_assurance`
- cohort size: `5-10` Android users
- operator group: `2` maintainers/on-call operators
- first pilot window: `7 days`

## 4. Release Candidate Freeze

Before cutting a pilot candidate, run the candidate gate:

```powershell
py -3 scripts/release/validate_pilot_readiness.py `
  --phase candidate `
  --output dist/pilot-candidate-readiness.json
```

That gate must leave all required checks green:

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --features pqmsg-core/pq-rust -- -D warnings`
- `cargo test --workspace --all-targets --features pqmsg-core/pq-rust`
- `cargo audit`
- `cargo deny check advisories licenses bans sources`
- support-matrix and audit validators
- release-governance workflow validator
- release-governance helper smoke
- pilot helper smoke
- supported Android/web validation matrix

The candidate gate is necessary but not sufficient for launch. The launch phase below adds fuzz, formal, pentest, and escalation-drill evidence.

After the candidate gate is green, prepare a fail-closed pilot release tag:

```powershell
py -3 scripts/release/prepare_pilot_release_candidate.py `
  --tag v0.1.0-rc1 `
  --candidate-readiness dist/pilot-candidate-readiness.json
```

That helper refuses to proceed if the candidate report is not green, the git worktree is dirty, or the tag already exists. Add `--create-tag` only when you are ready to cut the annotated tag.

## 5. Hardened Pilot Environment

Use the existing Kubernetes + Helm promotion path. Do not hand-apply mutable manifests for the pilot environment.

Minimum pilot server posture:

- `PQMSG_DEPLOYMENT_MODE=pilot`
- `PQMSG_SECURITY_PROFILE=high_assurance`
- HTTPS/TLS only
- PostgreSQL with explicit at-rest encryption declaration
- encrypted backups enabled and tested
- Redis-backed rate limiting
- explicit non-wildcard `PQMSG_CORS_ALLOWED_ORIGINS`
- structured JSON logs
- `PQMSG_AUDIT_LOG_PATH` configured

Required GitHub Environment inputs for promotion:

- secrets:
  - `KUBECONFIG_B64`
  - `PQMSG_DATABASE_URL`
  - `PQMSG_RATE_LIMIT_REDIS_URL`
  - `PQMSG_SENDER_CERT_SIGNING_KEY`
  - optional push credentials and optional telemetry DSN
  - optional `PQMSG_ALERTMANAGER_API_URL`
- vars:
  - `PQMSG_POSTGRES_STORAGE_ENCRYPTION`
  - `PQMSG_POSTGRES_BACKUP_ENCRYPTION`
  - `PQMSG_CORS_ALLOWED_ORIGINS`
  - `PQMSG_AUDIT_LOG_PATH`
  - optional `PQMSG_INCIDENT_ISSUE_REPO`

Bootstrap or re-check the GitHub Environment before promotion:

```powershell
py -3 scripts/release/bootstrap_pilot_environment.py `
  --environment-name pilot `
  --create `
  --output dist/pilot-environment-readiness.json
```

That helper creates the empty `pilot` environment if needed, lists the required secrets and vars that are still missing, and marks `ready_for_promotion=true` only when the environment inputs are complete.

Use the existing `promote` workflow twice:

1. `apply=false` to validate the release bundle, render the chart, and confirm the cluster contract.
2. `apply=true` only after the dry run and rollout owner review are complete.

### Strictly free pilot path

If cloud spend must stay at zero, run the pilot on the local `kind` cluster and dispatch `promote` or `rollback` through the self-hosted GitHub Actions runner on the same machine.

- keep the Kubernetes namespace as `pqmsg-pilot`
- keep the GitHub Environment as `pilot`
- register the runner with the label `pqmsg-pilot`
- use `runner_profile=pilot_local` when dispatching `promote` or `rollback`

For this free path, `KUBECONFIG_B64` intentionally points at the local cluster endpoint and is only valid from that self-hosted runner. It will not work from GitHub-hosted runners.

Pre-apply cluster prerequisites for the free local pilot are intentionally narrow:

- namespace `pqmsg-pilot` must carry the required pod-security labels
- secret `pqmsg-server-tls` must already exist in that namespace

The chart-generated release secret and configmap are created during `helm upgrade --install`; they are not a pre-apply requirement for the first pilot install.

## 6. Launch Validation

Before onboarding pilot users, run the full launch gate against the pilot environment:

```powershell
py -3 scripts/release/validate_pilot_readiness.py `
  --phase launch `
  --server https://your-pilot-hostname `
  --output dist/pilot-launch-readiness.json
```

The launch gate adds:

- live `/health` verification against the hardened pilot contract
- live `/v1/capabilities` verification against [docs/SUPPORT_MATRIX.json](SUPPORT_MATRIX.json)
- parser fuzz smoke
- ProVerif smoke
- penetration smoke against the running pilot server
- alert escalation drill against the configured observability stack

After the launch gate passes, run a manual two-device Android smoke on the pilot environment:

1. provision two fresh Android users
2. exchange direct messages in both directions
3. create one private group and exchange messages
4. send one attachment in DM and one in private group
5. restart both apps and verify inbox sync continuity
6. verify fail-closed trust-change behavior
7. verify fail-closed stale private-group-state behavior

The release owner must also confirm:

- the rollback path is executable and documented

Record the manual Android smoke result in the launch handoff with one line per step:

- pass/fail
- tester initials
- timestamp
- incident or bug reference if the step failed

Use the provided template:

- [docs/PILOT_ANDROID_SMOKE_TEMPLATE.json](PILOT_ANDROID_SMOKE_TEMPLATE.json)

After the launch gate and manual Android smoke both pass, write the final cohort-launch handoff:

```powershell
py -3 scripts/release/write_pilot_launch_handoff.py `
  --candidate-readiness dist/pilot-candidate-readiness.json `
  --launch-readiness dist/pilot-launch-readiness.json `
  --manual-smoke docs/PILOT_ANDROID_SMOKE_TEMPLATE.json `
  --promotion-record dist/promotion-record.json `
  --release-owner initials-or-name `
  --rollback-owner initials-or-name `
  --output dist/pilot-launch-handoff.json
```

That handoff fails closed if:

- candidate readiness is not green
- launch readiness is not green
- live runtime verification is missing or failed
- any required Android smoke step is still `pending` or marked `fail`

## 7. Cohort Launch

Launch only to a trusted small cohort.

Allowed pilot flows:

- new account provisioning on Android
- direct message send/receive
- private-group create/join/send/receive
- Android attachment send/receive
- trust-change handling on peer identity rotation
- local reset, repair, and reprovision behavior

Explicitly unsupported during this pilot:

- web messaging
- calling
- legacy clear-roster group messaging
- discovery-dependent onboarding as a required path

## 8. Daily Operations

Review these signals at least once per day:

- 5xx rate
- auth reject spikes
- rate-limit spikes
- push circuit breaker state
- signed-prekey staleness
- PQ prekey depletion
- device revocation spikes
- nonce replay bursts

Classify every user-reported issue as one of:

- rollout blocker
- protocol/correctness bug
- UX bug
- non-pilot backlog

Immediate rollback triggers:

- sustained 5xx breach
- auth reject spike attributable to the candidate build
- integrity or policy violation
- any Sev-1 confidentiality or integrity concern

## 9. Pilot Success Criteria

The pilot is successful only if all of the following hold:

- no Sev-1 incidents during the `7-day` pilot window
- no unresolved Sev-2 incident older than `24h`
- onboarding, direct messaging, private groups, and reset/recovery remain usable for the whole cohort
- the support contract remains unchanged during the pilot
- daily operational review and incident ownership actually happen

If those criteria are not met:

- stop expansion
- keep scope unchanged
- convert failures into a targeted remediation backlog before a broader rollout
