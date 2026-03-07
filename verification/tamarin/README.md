# Tamarin Prover Model

This directory contains a Tamarin prover model for the PQXDH hybrid handshake used in `pqmsg-core`.

## Files

- `pqxdh_hybrid.spthy`: multiset rewriting model with security lemmas.

## Relationship to ProVerif

The ProVerif model in `../proverif/` gives fast symbolic verification of secrecy and authentication.
The Tamarin model complements it with:

- **State-based reasoning** via multiset rewriting rules.
- **Compromise rules** (`RevealLtk`, `RevealEph`, `RevealPQSigLtk`) for explicit forward-secrecy and hybrid-signature proofs.
- **Injective agreement** for authentication.
- **Key uniqueness** across sessions.
- **OTPK single-use** via linear fact consumption (one-time prekeys cannot be reused).
- **Hybrid signature security** — authentication holds even if the PQ signing key is compromised (and vice versa).

## Security Lemmas

1. **Session key secrecy** — the attacker cannot learn the session key unless a long-term key is compromised.
2. **Authentication** — injective agreement; Bob's commit implies a prior Alice running action.
3. **Forward secrecy** — a compromised long-term key only affects sessions established after the compromise.
4. **No key reuse** — distinct sessions produce distinct session keys.
5. **OTPK single-use** — each one-time prekey can only be consumed once (guaranteed by linear fact).
6. **Hybrid signature security** — authentication holds even if classical OR PQ signing key is compromised (not both).

## Run

```bash
tamarin-prover verification/tamarin/pqxdh_hybrid.spthy --prove
```

Interactive mode:

```bash
tamarin-prover interactive verification/tamarin/pqxdh_hybrid.spthy
```

Then open `http://localhost:3001` in a browser.
