# FORMAL_AUDIT

## 1. Objective

This document defines the Tier 3.5 security-audit execution package for the `pqmsg` prototype:

1. independent third-party review readiness,
2. symbolic protocol verification artifacts,
3. repeatable penetration-testing evidence collection.

## 2. External Auditor Engagement Package

The following artifacts are expected to be delivered to an external assessor at kickoff:

1. protocol specification: `docs/SPEC.md`,
2. wire format: `docs/WIRE_FORMAT.md`,
3. threat model: `docs/THREAT_MODEL.md`,
4. security gate policy: `docs/SECURITY_GATES.md`,
5. API contract: `docs/API.md`,
6. formal verification model: `verification/proverif/pqxdh_hybrid_model.pv`,
7. Tamarin Prover model: `verification/tamarin/pqxdh_hybrid.spthy`,
8. audit readiness package: `docs/AUDIT_READINESS.md`,
9. reproducible handoff archive:
   - `python scripts/security/build_audit_readiness_bundle.py --output-dir /tmp/pqmsg-audit-bundle`,
   - `python scripts/security/verify_audit_readiness_bundle.py --bundle-dir /tmp/pqmsg-audit-bundle`,
   - `python scripts/security/prepare_external_audit_handoff.py --bundle-dir /tmp/pqmsg-audit-bundle --output-dir /tmp/pqmsg-audit-handoff`,
10. test evidence:
   - `cargo test --workspace`,
   - `cargo clippy --workspace --all-targets -- -D warnings`,
   - fuzz smoke outputs from CI.

## 3. Audit Scope

Mandatory scope:

1. hybrid handshake key schedule and authentication logic in `crates/pqmsg-core/src/handshake.rs`,
2. ratchet and session processing in:
   - `crates/pqmsg-core/src/session.rs`,
   - `crates/pqmsg-core/src/ratchet/mod.rs`,
   - `crates/pqmsg-core/src/ratchet/pq.rs`,
3. server-side identity/prekey directory controls and relay handling in `crates/pqmsg-server/src/lib.rs`,
4. client identity pinning and local secret storage flows in:
   - `crates/pqmsg-cli/src/main.rs`,
   - `crates/pqmsg-core/src/storage.rs`,
5. Android binding boundary in `crates/pqmsg-android`.

## 3A. Formal Verification CI Gate

The `proverif-gate` CI job runs on every push and pull request. It installs ProVerif, executes the symbolic model, and blocks merge if any query returns `false`. The Tamarin model (`verification/tamarin/pqxdh_hybrid.spthy`) provides complementary verification with compromise rules (`RevealLtk`, `RevealEph`, `RevealPQSigLtk`) and six security lemmas: session key secrecy, authentication, forward secrecy, no key reuse, OTPK single-use, and hybrid-signature security.

Both models now verify:

- **DH4 one-time prekey**: the key schedule includes `DH4(EK_A, OTPK_B)` and the Tamarin model enforces single-use via linear fact consumption,
- **Hybrid dual signatures**: Alice verifies both Ed25519 and ML-DSA-65 signatures on Bob's prekey bundle,
- **OTPK consumption**: Bob checks the consumed OTPK matches and emits a tracking event,
- **PQ signature unforgeability**: the ProVerif model includes `pqsig_sign`/`pqsig_verify` equations for ML-DSA-65.

## 4. Acceptance Criteria

Audit completion is accepted only when:

1. all critical/high findings are closed or formally risk-accepted,
2. symbolic model queries are reproducible by reviewer tooling,
3. penetration testing report includes:
   - exploitability classification,
   - proof-of-concept details,
   - remediation verification evidence,
4. post-audit hardening deltas are merged and CI green.

## 5. Tracking Template

Use the following issue schema for each external finding:

1. `finding_id` (stable external reference),
2. `severity`,
3. `affected_component`,
4. `exploit_path`,
5. `mitigation_plan`,
6. `verification_test`,
7. `status`.
