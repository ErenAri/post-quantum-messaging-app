# TLS_ROTATION

## 1. Objective

This runbook defines a certificate and pin rotation process for `pqmsg-server` and Android clients in high-assurance deployments.

## 2. Preconditions

- active TLS deployment with `PQMSG_TLS_CERT_PATH` and `PQMSG_TLS_KEY_PATH`,
- Android clients using HTTPS with `BuildConfig.TLS_PIN_SHA256`,
- staged environment matching production hostnames.

## 3. Rotation Model

Use overlapping validity and staged pin rollout:

1. provision a new certificate for the existing hostname,
2. compute the new SPKI SHA-256 pin,
3. ship a client update that trusts both old and new pins during transition,
4. deploy new server certificate,
5. verify clients across supported versions,
6. remove old pin in a subsequent client release.

## 4. Pin Computation

For an X.509 certificate file:

```powershell
openssl x509 -in server.crt -pubkey -noout `
| openssl pkey -pubin -outform der `
| openssl dgst -sha256 -binary `
| openssl base64 -A
```

Prefix output with `sha256/` for Android pin format.

## 5. Server Rotation Procedure

1. Place new certificate and key files on host with restricted permissions.
2. Validate key pair consistency before cutover:

```powershell
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa  -noout -modulus -in server.key | openssl md5
```

3. Restart `pqmsg-server` with:
   - `PQMSG_SECURITY_PROFILE=high_assurance`,
   - updated `PQMSG_TLS_CERT_PATH`,
   - updated `PQMSG_TLS_KEY_PATH`.
4. Verify `/health` responds and `strict-transport-security` header is present.
5. Monitor error rates and failed TLS handshakes during rollout window.

## 6. Android Rotation Procedure

1. Build release with both active and next pins accepted by transport policy.
2. Roll out client update before server cutover.
3. Deploy server certificate.
4. Observe successful app connectivity and handshake continuity.
5. Remove legacy pin in next release after overlap window closes.

## 7. Emergency Rollback

If post-cutover failures exceed threshold:

1. revert server to previous certificate/key pair,
2. keep both pins in client configuration until incident closure,
3. publish incident note and revised rotation window.

## 8. Rotation Cadence

- routine renewal target: every 60-90 days,
- pre-expiry alert threshold: 21 days,
- dry-run in staging before every production cutover.
