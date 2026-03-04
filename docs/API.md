# API

## 1. Scope

This document specifies the HTTP/JSON interface for `pqmsg-server` under `/v1`.  
The service is intentionally minimal and stores only public key material plus opaque ciphertext blobs.

- Content type: `application/json`
- Error type: `application/problem+json`
- Request body limit: `1,048,576` bytes

## 2. Service Lifecycle

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>S: POST /users/register
    C->>S: POST /users/{id}/devices/link
    C->>S: GET /users/{id}/devices
    C->>S: POST /users/{id}/devices/{device_id}/revoke
    C->>S: POST /users/{id}/prekeys
    C->>S: GET /users/{id}/prekeys/status
    C->>S: POST /users/{id}/push-token
    C->>S: GET /users/{peer}/bundle
    C->>S: POST /users/{id}/rotate/init
    C->>S: POST /users/{id}/rotate/confirm
    C->>S: GET /users/{id}/identity-log
    C->>S: POST /relay/{peer}
    C->>S: GET /inbox/{id}?since=n
    C->>S: GET /ws/inbox/{id}?since=n (WebSocket)
```

## 2.1 Security Profile Configuration

Server startup is controlled by environment variables:

- `PQMSG_SECURITY_PROFILE`: `research` | `high_assurance` | `nss_aligned` (default: `high_assurance`)
- `PQMSG_DATABASE_URL`: `sqlite://...` or `postgres://...`
- `PQMSG_TLS_CERT_PATH`: PEM certificate path
- `PQMSG_TLS_KEY_PATH`: PEM private key path
- `PQMSG_DB_MAX_CONNECTIONS`: pool max connections (default: `20`)
- `PQMSG_DB_MIN_CONNECTIONS`: pool min connections (default: `1`)
- `PQMSG_DB_ACQUIRE_TIMEOUT_SECS`: connection acquisition timeout seconds (default: `5`)
- `PQMSG_DB_IDLE_TIMEOUT_SECS`: idle connection timeout seconds (default: `300`)
- `PQMSG_FCM_SERVER_KEY`: optional FCM legacy server key for wake-signal dispatch
- `PQMSG_FCM_ENDPOINT`: optional override (default: `https://fcm.googleapis.com/fcm/send`)

In `high_assurance` and `nss_aligned`, server startup fails unless both TLS paths are provided.

## 3. Identity and Prekey Security Semantics

```mermaid
flowchart TD
    A[First registration] --> B[Identity bound to user_id]
    B --> C[Subsequent register with changed key => 409 Conflict]
    D[Prekey upload] --> E[Server reconstructs SPK/PQSPK signature transcripts]
    E --> F[Ed25519 verify under registered identity_sig_pub]
    F --> G[Accept only valid ownership proof]
```

- `user_id` identity bindings are immutable after first successful registration.
- Re-registration with changed identity material is rejected (`409 Conflict`).
- Prekey signatures are verified using Ed25519 before persistence.

## 3.1 Authenticated Transport Headers

The following endpoints require request authentication headers:

- `GET /v1/users/{user_id}/identity-log`
- `GET /v1/users/{user_id}/prekeys/status`
- `GET /v1/users/{user_id}/devices`
- `POST /v1/users/{user_id}/devices/link`
- `POST /v1/users/{user_id}/devices/{target_device_id}/revoke`
- `POST /v1/users/{user_id}/prekeys`
- `POST /v1/relay/{recipient_user_id}`
- `GET /v1/inbox/{user_id}`
- `GET /v1/ws/inbox/{user_id}`
- `POST /v1/users/{user_id}/push-token`

Required headers:

- `x-pqmsg-auth-user`
- `x-pqmsg-auth-device`
- `x-pqmsg-auth-timestamp` (unix seconds)
- `x-pqmsg-auth-nonce` (single-use)
- `x-pqmsg-auth-signature` (`base64(64-byte Ed25519 signature)`)

The server verifies signatures under registered `identity_sig_pub`, enforces authenticated device binding against active `user_devices` records, applies timestamp skew checks, rejects nonce replay, enforces monotonic inbox cursors per authenticated `user_id` + `device_id`, and applies relay ciphertext deduplication with TTL.

## 4. Endpoint Definitions

### 4.1 Register User

`POST /v1/users/register`

Request:

```json
{
  "user_id": "alice",
  "identity_x25519_pub": "base64(32 bytes)",
  "identity_sig_pub": "base64(32-byte Ed25519 public key)",
  "device_id": "alice-device-1"
}
```

Success response:

```json
{
  "user_id": "alice",
  "device_id": "alice-device-1",
  "registered_at": "2026-03-04T12:00:00Z"
}
```

Conflict response (`identity_x25519_pub`, `identity_sig_pub`, or `device_id` changed for existing `user_id`):

```json
{
  "type": "about:blank",
  "title": "Conflict",
  "status": 409,
  "detail": "user_id is already registered with an immutable identity"
}
```

### 4.2 Publish Prekeys

`POST /v1/users/{user_id}/prekeys`

Request:

```json
{
  "signed_prekey_x25519_pub": "base64(32 bytes)",
  "sig_over_spk": "base64(64-byte Ed25519 signature)",
  "pq_signed_prekey_pub_mlkem768": "base64(variable)",
  "sig_over_pqspk": "base64(64-byte Ed25519 signature)",
  "one_time_prekeys_x25519": ["base64(32 bytes)"],
  "one_time_prekeys_mlkem768": ["base64(variable)"]
}
```

The server verifies:

1. `sig_over_spk` over protocol transcript for `SPK`,
2. `sig_over_pqspk` over protocol transcript for `PQSPK`,
3. both under registered `identity_sig_pub`.

Success response fields also include remaining one-time prekey counts and low-inventory advisory flags.

### 4.2A Device Management

`GET /v1/users/{user_id}/devices`

Returns all linked devices with active/revoked state:

```json
{
  "user_id": "alice",
  "devices": [
    {
      "device_id": "alice-device-1",
      "active": true,
      "linked_at": "2026-03-04T12:00:00Z",
      "revoked_at": null
    }
  ]
}
```

`POST /v1/users/{user_id}/devices/link`

Request:

```json
{
  "new_device_id": "alice-device-2"
}
```

Response:

```json
{
  "user_id": "alice",
  "linked_device_id": "alice-device-2",
  "linked_at": "2026-03-04T12:10:00Z"
}
```

`POST /v1/users/{user_id}/devices/{target_device_id}/revoke`

Response:

```json
{
  "user_id": "alice",
  "revoked_device_id": "alice-device-2",
  "revoked_at": "2026-03-04T12:20:00Z"
}
```

Device-link auth signature transcript fields:

1. endpoint label (`devices-link`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. target user id,
7. linked device id.

Device-revoke auth signature transcript fields:

1. endpoint label (`devices-revoke`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. target user id,
7. revoked device id.

### 4.3 Prekey Inventory Status

`GET /v1/users/{user_id}/prekeys/status`

Requires authenticated transport headers (Section 3.1).

Prekeys-status auth signature transcript fields:

1. endpoint label (`prekeys-status`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. target user id.

Response:

```json
{
  "user_id": "alice",
  "device_id": "alice-device-1",
  "remaining_one_time_prekeys_x25519": 12,
  "remaining_one_time_prekeys_mlkem768": 12,
  "low_one_time_prekeys": false,
  "minimum_recommended_one_time_prekeys": 16,
  "checked_at": "2026-03-04T12:00:00Z"
}
```

### 4.4 Fetch Bundle

`GET /v1/users/{user_id}/bundle[?device_id=<device_id>]`

If `device_id` is omitted, the server selects the earliest active linked device with published prekeys.
If `device_id` is present, the server returns a bundle only for that active device.

Response:

```json
{
  "user_id": "alice",
  "device_id": "alice-device-1",
  "identity_x25519_pub": "base64...",
  "identity_sig_pub": "base64...",
  "signed_prekey_x25519_pub": "base64...",
  "sig_over_spk": "base64...",
  "pq_signed_prekey_pub_mlkem768": "base64...",
  "sig_over_pqspk": "base64...",
  "one_time_prekey_x25519": "base64 or null",
  "one_time_prekey_mlkem768": "base64 or null",
  "remaining_one_time_prekeys_x25519": 11,
  "remaining_one_time_prekeys_mlkem768": 11,
  "low_one_time_prekeys": false,
  "minimum_recommended_one_time_prekeys": 16,
  "last_resort_prekey_only": false,
  "identity_key_version": 1,
  "identity_fingerprint_sha256": "hex(sha256(identity_x25519_pub))",
  "bundle_generated_at": "2026-03-04T12:00:00Z"
}
```

When `PQMSG_FCM_SERVER_KEY` is configured, relay delivery triggers an FCM wake-only push payload (`data: {"wake":"1","v":"1"}`) to registered recipient tokens.

### 4.5 Register Push Token

`POST /v1/users/{user_id}/push-token`

Requires authenticated transport headers (Section 3.1).

Request:

```json
{
  "device_id": "alice-device-1",
  "fcm_token": "fcm-registration-token"
}
```

Push-token auth signature transcript fields:

1. endpoint label (`push-token`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. target user id,
7. device id,
8. SHA-256 hash of `fcm_token` bytes.

Response:

```json
{
  "user_id": "alice",
  "device_id": "alice-device-1",
  "provider": "fcm",
  "registered_at": "2026-03-04T12:00:00Z"
}
```

### 4.6 Initiate Identity Rotation

`POST /v1/users/{user_id}/rotate/init`

Request:

```json
{
  "new_identity_x25519_pub": "base64(32 bytes)",
  "new_identity_sig_pub": "base64(32-byte Ed25519 public key)",
  "new_device_id": "alice-device-2"
}
```

Response:

```json
{
  "user_id": "alice",
  "challenge_id": "uuid-v4",
  "challenge_nonce": "base64(32 bytes)",
  "expires_at": "2026-03-04T12:10:00Z"
}
```

### 4.7 Confirm Identity Rotation

`POST /v1/users/{user_id}/rotate/confirm`

Request:

```json
{
  "challenge_id": "uuid-v4",
  "sig_by_current_identity": "base64(64-byte Ed25519 signature)",
  "sig_by_new_identity": "base64(64-byte Ed25519 signature)"
}
```

The signatures are computed over a server-defined rotation transcript containing:

1. `user_id`,
2. `challenge_id`,
3. `challenge_nonce`,
4. `new_identity_x25519_pub`,
5. `new_identity_sig_pub`,
6. `new_device_id`.

Response:

```json
{
  "user_id": "alice",
  "identity_key_version": 2,
  "identity_fingerprint_sha256": "hex(sha256(new_identity_x25519_pub))",
  "rotated_at": "2026-03-04T12:01:00Z"
}
```

### 4.8 Identity Event Log

`GET /v1/users/{user_id}/identity-log`

Requires authenticated transport headers (Section 3.1).

Identity-log auth signature transcript fields:

1. endpoint label (`identity-log`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. target user id.

Response:

```json
{
  "user_id": "alice",
  "events": [
    {
      "version": 2,
      "identity_x25519_pub": "base64...",
      "identity_sig_pub": "base64...",
      "device_id": "alice-device-2",
      "event_type": "rotation",
      "changed_at": "2026-03-04T12:01:00Z",
      "identity_fingerprint_sha256": "hex..."
    }
  ]
}
```

### 4.9 Relay Message

`POST /v1/relay/{recipient_user_id}`

Requires authenticated transport headers (Section 3.1).

Request:

```json
{
  "sender_user_id": "alice",
  "device_id": "alice-device-1",
  "message_bytes_base64": "base64(ciphertext bytes)"
}
```

The payload is treated as opaque and persisted without server-side plaintext processing.
The server computes a deduplication key over `sender_user_id || recipient_user_id || message_blob` and rejects duplicates while the relay dedup window remains active.
Relay storage and delivery are performed per active recipient device.

Relay auth signature transcript fields:

1. endpoint label (`relay`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. recipient user id,
7. decoded relay message blob bytes.

Duplicate relay submissions within the dedup window are rejected with `409 Conflict`.

Success response:

```json
{
  "message_id": 42,
  "delivered_device_count": 2,
  "received_at": "2026-03-04T12:00:00Z"
}
```

### 4.10 Poll Inbox

`GET /v1/inbox/{user_id}?since=<message_id>`

Requires authenticated transport headers (Section 3.1).

Inbox auth signature transcript fields:

1. endpoint label (`inbox`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. target user id,
7. `since` value.

Inbox views are device-scoped: the authenticated `x-pqmsg-auth-device` selects the recipient device mailbox.
`since` is monotonic per authenticated `(user_id, device_id)` session.  
If `since` regresses below the stored server cursor for that session, the request is rejected with `409 Conflict`.

Response:

```json
{
  "user_id": "alice",
  "messages": [
    {
      "message_id": 42,
      "sender_user_id": "bob",
      "message_bytes_base64": "base64(...)",
      "received_at": "2026-03-04T12:00:00Z"
    }
  ]
}
```

### 4.11 WebSocket Inbox

`GET /v1/ws/inbox/{user_id}?since=<message_id>`

Requires authenticated transport headers (Section 3.1) and a standard WebSocket handshake.

WebSocket auth signature transcript fields:

1. endpoint label (`ws-inbox`),
2. auth user id,
3. auth device id,
4. auth timestamp,
5. auth nonce,
6. target user id,
7. `since` value.

The same monotonic `since` rule is enforced for WebSocket session establishment per authenticated `(user_id, device_id)`.

Server messages are JSON text frames:

```json
{
  "event": "sync",
  "user_id": "bob",
  "messages": [
    {
      "message_id": 42,
      "sender_user_id": "alice",
      "message_bytes_base64": "base64(...)",
      "received_at": "2026-03-04T12:00:00Z"
    }
  ]
}
```

- `event = "sync"` carries the initial catch-up window from `since`.
- `event = "relay"` carries newly relayed ciphertexts in near real time.
- Clients should still keep HTTP polling (`GET /v1/inbox/{user_id}`) as degraded/offline fallback.

### 4.12 Health

`GET /health`

Response:

```json
{
  "status": "ok",
  "security_profile": "research",
  "db_backend": "sqlite",
  "db_ready": true,
  "db_pool_size": 1,
  "db_pool_idle": 1,
  "push_enabled": false
}
```

## 5. Validation and Limits

- one-time prekey family maximum: `256` entries each,
- relay decoded blob maximum: `1,000,000` bytes,
- inbox page maximum: `200` messages,
- relay ciphertext dedup window: `900` seconds,
- endpoint-level in-memory token bucket rate limiting.

## 6. Transport Requirement

Plain HTTP is acceptable only for local demonstration.  
Operational deployments must terminate TLS and should enforce certificate pinning at clients.
