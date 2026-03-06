# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest `main` | Yes |
| tagged releases (`v*`) | Yes |
| older tags | Best-effort |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

To report a vulnerability, please email **security@pqmsg.example.com** with:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce or a proof-of-concept (if available).
3. The affected component(s) (e.g., `pqmsg-core`, `pqmsg-server`, wire format).
4. Your suggested severity (Critical / High / Medium / Low).

We aim to acknowledge reports within **48 hours** and provide an initial assessment within **5 business days**.

## Disclosure Policy

- We follow **coordinated disclosure**. We ask reporters to allow up to **90 days** for a fix before public disclosure.
- Security advisories will be published via GitHub Security Advisories once a fix is available.
- Credit will be given to reporters in the advisory (unless anonymity is requested).

## Security Expectations

This project is a **research-grade prototype**. While we apply production-quality security practices (see below), it has not undergone a formal third-party audit and should not be used for real-world sensitive communications without independent review.

### Security practices in place

- **Dependency auditing**: `cargo audit` and `cargo deny` run on every CI push.
- **SBOM generation**: CycloneDX SBOMs are generated for every build and attached to releases.
- **Fuzz testing**: libFuzzer targets cover TLV, wire, handshake, sealed-sender, and algorithm parsers; proptest covers all server input validators.
- **Signed releases**: Release artifacts include cosign-signed SHA-256 checksums.
- **Formal verification**: ProVerif symbolic model for the PQXDH hybrid handshake.
- **Penetration testing**: Automated smoke scripts for common attack vectors.
- **Runtime security profiles**: `high_assurance` and `nss_aligned` profiles enforce PQ backend availability and TLS transport.

## Scope

The following components are in scope for security reports:

- `pqmsg-core` — cryptographic primitives, handshake, ratchet, TLV/wire parsing
- `pqmsg-server` — relay server, authentication, rate limiting, input validation
- `pqmsg-cli` — key management, encrypted storage, message archive
- `pqmsg-android` / `pqmsg-ios` — mobile UniFFI bindings
- Wire format and protocol specification (`docs/WIRE_FORMAT.md`, `docs/SPEC.md`)
- Deployment configurations (`deploy/`, `Dockerfile`, Helm charts)

## PGP Key

_(Optional: add a PGP public key for encrypted vulnerability reports.)_
