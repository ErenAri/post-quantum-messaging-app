# Validation Matrix

This repo keeps one small supported-flow validation matrix that must pass before
release screenshots are refreshed.

The goal is modest on purpose: confirm the current support posture still
matches the docs, and confirm the actually supported or intentionally-demo
client surfaces still build and pass their high-signal tests.

## Current Matrix

The current validator lives in:

- [scripts/dev/validate_supported_client_flows.py](../scripts/dev/validate_supported_client_flows.py)

It always runs:

- support-matrix contract validation via
  [scripts/security/validate_support_matrix.py](../scripts/security/validate_support_matrix.py)

It then runs the relevant client surface checks:

- `--surface web`
  - `npm test -- src/app.flow.test.ts`
  - `npm run build`
- `--surface android`
  - `.\gradlew.bat :app:assembleDebug app:testDebugUnitTest`
- `--surface all`
  - both web and Android checks above

## Usage

Validate the current web demo shell before refreshing web screenshots:

```powershell
py -3 scripts/dev/validate_supported_client_flows.py --surface web
```

Validate the Android beta client before refreshing Android screenshots:

```powershell
py -3 scripts/dev/validate_supported_client_flows.py --surface android
```

Validate both surfaces before a broader screenshot or release refresh:

```powershell
py -3 scripts/dev/validate_supported_client_flows.py --surface all
```

## Scope

This matrix does not attempt to prove every protocol property or every
cross-client feature. It is only the pre-screenshot/pre-beta guardrail for the
currently supported product surface:

- docs and machine-readable support policy still agree
- web demo shell still passes its main flow/build checks
- Android beta messaging client still assembles and passes unit tests

Anything deeper belongs in CI, protocol tests, or release-specific governance
checks.
