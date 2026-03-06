# ProVerif Model

This directory contains a symbolic model for the hybrid PQXDH-style handshake used in `pqmsg-core`.

## Files

- `pqxdh_hybrid_model.pv`: symbolic model with secrecy and authentication queries.

## Scope

The model encodes:

- signed Bob prekey bundle publication,
- Alice bundle signature validation,
- X25519-style DH terms,
- ML-KEM-style encapsulation/decapsulation abstraction,
- HKDF key schedule abstraction,
- AEAD payload abstraction with associated data inputs.

## Security Queries

The model asks ProVerif to evaluate:

1. **Plaintext secrecy** — application plaintext is never leaked to the Dolev–Yao attacker.
2. **Session key secrecy** — the derived handshake key for completed Alice sessions cannot be recovered by the attacker.
3. **Authentication (Alice → Bob)** — Bob's completion event implies a matching Alice completion.
4. **Bundle acceptance** — Bob's completion event implies Alice accepted the published bundle.
5. **Forward secrecy** — a second plaintext (`plaintext_fs`) remains secret even after the ephemeral DH key is revealed to the attacker post-session.
6. **Identity misbinding resistance** — if two `SessionBound` events share the same session key, they must agree on the identity key pair.

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
