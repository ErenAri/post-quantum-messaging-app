# ProVerif Model

This directory contains a symbolic model for the hybrid PQXDH-style handshake used in `pqmsg-core`.

## Files

- `pqxdh_hybrid_model.pv`: symbolic model with secrecy and authentication queries.

## Scope

The model encodes:

- signed Bob prekey bundle publication with dual signatures (Ed25519 + ML-DSA-65),
- Alice bundle dual-signature validation (hybrid: secure if EITHER holds),
- X25519-style DH terms including DH4 (one-time prekey),
- ML-KEM-style encapsulation/decapsulation abstraction,
- ML-DSA-65 PQ signature sign/verify abstraction,
- HKDF key schedule abstraction with 5-term input (DH1-4 + ss_pq),
- AEAD payload abstraction with associated data inputs,
- OTPK consumption tracking.

## Security Queries

The model asks ProVerif to evaluate:

1. **Plaintext secrecy** — application plaintext is never leaked to the Dolev–Yao attacker.
2. **Authentication (Alice → Bob)** — Bob's completion event implies a matching Alice completion.
3. **Bundle acceptance** — Bob's completion event implies Alice accepted the published bundle.
4. **Forward secrecy** — a second plaintext (`plaintext_fs`) remains secret even after the ephemeral DH key is revealed to the attacker post-session.
5. **Identity misbinding resistance** — if two `SessionBound` events share the same session key, they must agree on the identity key pair.
6. **OTPK consumption** — the `OTPKConsumed` event is reachable, confirming DH4 one-time prekey participation in the handshake.

## Run

If ProVerif is installed locally:

```bash
proverif verification/proverif/pqxdh_hybrid_model.pv
```

Windows PowerShell:

```powershell
proverif verification/proverif/pqxdh_hybrid_model.pv
```

Repository helper scripts:

- `scripts/security/run_proverif.sh`
- `scripts/security/run_proverif.ps1`
