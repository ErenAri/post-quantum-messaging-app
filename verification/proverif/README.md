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

1. secrecy of application plaintext,
2. secrecy of the derived handshake key for completed Alice sessions,
3. authentication correspondence between Bob and Alice completion events.

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
