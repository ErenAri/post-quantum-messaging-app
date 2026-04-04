# THREAT_MODEL

## 1. Purpose

This document defines the adversary model and trust assumptions for the current prototype.

## 2. Assets

Primary assets:

1. client identity private keys,
2. signed/one-time prekey private material,
3. ratchet state (root, chain, skipped keys),
4. ciphertext payloads and protocol metadata,
5. directory bindings between `user_id` and identity keys.

## 3. Adversary Classes

- passive network observer,
- active network manipulator,
- compromised or malicious relay/directory server,
- replay/tamper adversary,
- endpoint compromise adversary.

## 4. Trust Boundaries

```mermaid
flowchart LR
    A[Client A] -->|Ciphertext + protocol headers| R[Relay / Prekey Server]
    B[Client B] -->|Ciphertext + protocol headers| R
    A -->|Local secrets| SA[(Client Storage A)]
    B -->|Local secrets| SB[(Client Storage B)]
    A -.->|optional| HSM[PKCS#11 HSM]
    B -.->|optional| HSM
    R --> DB[(PostgreSQL / SQLite)]
    R --> RD[(Redis: rate limits)]
    R --> AL[Audit Log + PII Scrubbing]
    R -->|circuit breaker| PN[FCM / APNS Push]
```

The server is explicitly not trusted with plaintext.

## 5. Explicit Threats and Controls

| Threat | Control |
|---|---|
| Identity takeover via re-registration | Immutable `user_id` identity binding (`409` on mutation) |
| Unauthorized identity key rotation | Challenge-confirm rotation signed by both current and new identity keys |
| Unauthorized prekey publication | Ed25519 signature verification on uploaded `SPK`/`PQSPK` |
| Unauthenticated inbox access / relay spoofing | Signed transport auth headers (`x-pqmsg-auth-*`) with device binding and nonce replay checks |
| Silent peer key substitution after first contact | Client-side peer identity fingerprint pinning with explicit trust prompt on key change |
| Suite/version downgrade | AD binding plus strict suite continuity checks |
| Ratchet metadata tampering (`pq_step_ct`, counters) | Ratchet header fields included in AEAD associated data |
| Parser-driven DoS | Strict TLV decode, critical-tag rejection, fuzz targets |
| Secret retention in memory | `zeroize` and zeroizing containers for keying material; explicit `Drop` implementations on all secret-bearing structs |
| Secret leakage from local state files | Encrypted-at-rest key/session persistence in CLI and Android client stores |
| Sealed sender anonymous abuse | IP-based rate limiting via `X-Forwarded-For`/`X-Real-IP` alongside per-recipient rate limiting |
| Push provider outage cascade | Circuit-breaker pattern on FCM/APNS dispatch; emits security audit events on circuit open |
| PII leakage in structured logs | Runtime PII scrubbing replaces user/device IDs with SHA-256 hash prefixes in log output |
| Algorithm downgrade via FIPS bypass | `fips` feature gate restricts suite to ML-KEM-768 only; compile-time conflict with `classical-only-INSECURE` |
| Replay of captured InitialMessage | DH4 one-time prekey consumption; server marks OTPKs as used and rejects replayed `otpk_id` references |
| Quantum forgery of identity signatures | Hybrid dual-signature verification (Ed25519 + ML-DSA-65); security holds if EITHER scheme is secure |
| Silent discovery-service contract drift | Supported Android/web clients verify signed discovery manifests, optional attestation evidence, per-device continuity checkpoints, and echoed `manifest_contract_sha256` / `ticket_nonce` values on discovery operations |
| Stale transparency checkpoint after local reset or log compaction | Supported clients retry once without `previous_tree_size` only when the server explicitly rejects that checkpoint as out of range, then still require the refreshed proof to match the pinned identity |
| Call media eavesdropping | PQ key exchange before WebRTC SDP; Insertable Streams encrypt RTP payloads with `media_key` + ChaCha20-Poly1305 |
| Unauthorized call signaling | Format-string authenticated endpoints; call offer/answer/ICE/hangup require Ed25519 signature |

## 6. Current PCS Posture

Current implemented recovery properties:

- direct-message sessions continuously mix fresh PQ material into the root key
  on the supported path (default PQ ratchet interval: every message),
- classical DH ratchet and chain-key advancement continue to rotate future
  message keys within one active session,
- bounded skipped-key continuity and bounded PQ key-history continuity survive
  snapshot restore for already-derivable out-of-order traffic.

Current bounds and non-claims:

- this is not a claim of full production-grade post-compromise security across
  multiple devices or independently diverged local snapshots,
- identity rotation authenticates server-side replacement of the current
  identity/device, but does not automatically repair stale trust pins or
  transparently upgrade already-open client sessions,
- supported clients are expected to fail closed on peer identity change until
  the new fingerprint/transparency state is explicitly accepted and a fresh
  session is established,
- active endpoint compromise still defeats transport/session cryptography.

## 7. Residual Risk

Residual risk remains substantial in:

- endpoint malware compromise,
- replay policy beyond current minimal semantics,
- snapshot restore and skipped-key continuity are covered for the current session model, but this is not a claim of full production-grade multi-device state convergence,
- global traffic analysis and social-graph extraction,
- trust-on-first-use UX and large-scale key lifecycle management.

## 8. Transport Security Assumption

Plain HTTP transport is accepted only for local demonstration environments.  
Operational deployments MUST use TLS and SHOULD implement certificate pinning to reduce key-directory substitution risk.
