# Device Lifecycle Contract

This document is the single lifecycle contract for device-bound identity state
in this repository. It consolidates the currently implemented behavior across
the server, CLI, Android, iOS, and web clients.

It is intentionally narrower than a full product spec. It covers only:

- first registration,
- linked-device import,
- device retirement and revoke,
- local reset,
- the boundary between linked-device adoption and identity rotation.

When this document conflicts with older client-specific prose, this document is
the lifecycle source of truth.

## 1. Scope And Terms

### 1.1 Scope

This contract applies to:

- `pqmsg-server` account and device records,
- the authenticated direct-message clients in this repo,
- client local key/session state,
- reset and reprovision behavior.

This contract does not define:

- account deletion,
- automatic multi-device state convergence,
- automatic healing of stale trust pins after peer rotation,
- discovery/contact semantics,
- calling,
- development-only repair helpers as hardened behavior.

### 1.2 Terms

- **Account**: the immutable `user_id` registration on the server.
- **Identity keys**: the long-lived account identity keys bound to that
  `user_id`.
- **Device id**: the per-device identifier used for auth headers, prekeys, and
  server-side device state.
- **Linked device**: another active device id under the same account identity.
- **Current device**: the authenticated device performing an action.
- **Local state**: device/browser-local keys, sessions, pins, cursors,
  conversation metadata, and related caches.

## 2. Registration Contract

Registration is the first authoritative binding of an account identity on the
server.

### 2.1 Server Contract

- `POST /v1/users/register` creates the account binding for `user_id`,
  `device_id`, and the advertised identity keys.
- After a successful first registration, that account identity is immutable at
  the same `user_id`; later device additions are not new registrations.
- A registered device is not ready for inbound bundle-based initiation until it
  publishes prekeys with `POST /v1/users/{user_id}/prekeys`.
- The server is authoritative for whether a device id is active or revoked.

### 2.2 Client Contract

- Fresh setup generates local keys before registration.
- After registration, clients persist local identity state and provisioning
  progress.
- Clients must not treat "same username, new local keys" as a normal recovery
  path in hardened behavior. That is a reset/reprovision event, not a silent
  overwrite.

## 3. Linked-Device Contract

Linked-device onboarding adds another device id under the same account
identity. It is not identity rotation.

### 3.1 Authoritative Semantics

- The authenticated existing device links the target device id with
  `POST /v1/users/{user_id}/devices/link`.
- The onboarding package is a client-side artifact. The server only tracks the
  linked device id and later the prekeys published for it.
- A linked device inherits the existing account identity keys and adopts a new
  device id.
- The linked device must publish fresh prekeys for that device id after import.
- Linked-device import must not call `POST /v1/users/register` again for the
  same account identity.

### 3.2 Client Requirements

- Secondary-device packages are local-passphrase-protected client artifacts.
- Import may apply the embedded server URL and adopted device keys locally.
- Import finishes only after the adopted device publishes its fresh prekeys and
  enters the provisioned state.
- Import is allowed to replace existing local state only after explicit user
  confirmation on clients that surface a preview.

### 3.3 What Linked-Device Import Does Not Mean

- It does not rotate the account identity version.
- It does not bless stale peer trust pins on other clients.
- It does not merge arbitrary prior local state from the destination device.
- It does not imply account-wide session continuity across devices.

## 4. Identity Rotation Is A Different Lifecycle Event

Identity rotation is distinct from linked-device onboarding and must remain so.

- `POST /v1/users/{user_id}/rotate/init` and
  `POST /v1/users/{user_id}/rotate/confirm` replace the server-advertised
  identity and move the authenticated account to a fresh device id.
- Rotation changes the identity event log and invalidates the old authenticated
  device for new server-authenticated actions.
- Existing local DM sessions and saved trust pins are not automatically migrated
  or re-approved by rotation alone.
- Supported clients must re-check the identity log, transparency state, and
  local trust pins after peer identity rotation before continuing normal send
  flows.

In short: linked-device onboarding preserves the account identity; rotation
replaces it.

## 5. Device Retirement And Revoke Contract

### 5.1 Current-Device Retirement

`POST /v1/users/{user_id}/devices/current/retire` is the self-retirement path
for the authenticated device.

Implemented contract:

- the authenticated current device can retire only itself,
- retirement clears device-scoped relay, prekey, inbox cursor, push-token, and
  presence state on the server,
- retirement marks that device inactive and returns the remaining active device
  count,
- retirement does not delete the account,
- retirement does not revoke other active linked devices,
- retirement does not delete account-level identity history.

### 5.2 Non-Current Device Revoke

`POST /v1/users/{user_id}/devices/{target_device_id}/revoke` is the management
path for another device under the same account.

Implemented contract:

- the authenticated current device may revoke another device id,
- clients must not use revoke as self-retirement,
- revoked devices stop being valid active devices for later auth and delivery.

### 5.3 Verified Behavior

Current server tests already lock down the important boundary:

- retiring the current device removes its fetchable bundle and inbox access,
- its device-scoped queued relay state is cleared,
- retirement does not clear surviving linked-device bundle, prekey-status, or
  inbox state,
- re-registering the same device id after retirement does not resurrect the old
  queued messages,
- identity rotation also revokes old-device authenticated access.

## 6. Local Reset Contract

Local reset is the client-side purge path. It is allowed to be best-effort on
remote retirement, but it must be explicit about what is and is not removed.

### 6.1 Common Rules

All clients should follow this sequence when possible:

1. If local keys for the current account still exist, attempt authenticated
   current-device retirement against the server.
2. Regardless of whether remote retirement was possible, purge the local state
   for that account from the device/browser.
3. Return to an unprovisioned or re-verify setup state instead of silently
   reusing stale identity material.

### 6.2 CLI

`reset-local-state` removes local user state from the CLI state directory and,
by default, removes the key file too.

- `--remote-retire` performs current-device retirement first.
- `--keep-keys` is the explicit opt-out when an operator intentionally wants to
  preserve the key file while wiping the state directory.

### 6.3 Desktop

The current desktop app is a thin Tauri wrapper around the web client.

- It does not define a separate native reset contract today.
- Its effective local reset semantics therefore inherit the web client reset and
  forget flows until a desktop-specific local key store exists.

### 6.4 Android

The Security Center reset action:

- attempts current-device retirement when keys are still present,
- then wipes per-user keys, sessions, pins, cursors, and conversation metadata,
- returns the UI to a fresh local setup state for that user.

Android local encrypted storage is device-local security state. Reset is the
supported escape hatch when local state is stale, unreadable, or intentionally
being retired.

### 6.5 iOS

The Security tab reset action:

- attempts current-device retirement when keys are still present,
- then removes per-user keys, sessions, pins, cursors, conversation metadata,
  and the stored APNs token,
- returns the app to a fresh local setup/provisioning state.

### 6.6 Web

Web has two different local purge paths and they must not be conflated:

- **Forget local profile**: local-only cleanup of a saved browser profile. This
  is for stale browser-local keys and does not imply remote retirement.
- **Account deletion/reset flow**: best-effort current-device retirement first,
  then local wipe of the saved key record, sessions, pins, conversation and
  group metadata, checkpoints, and related browser-local messaging state.

The hardened expectation is that poisoned browser state is removed explicitly,
not silently patched over by continuing with mismatched saved keys.

### 6.7 Development-Only Same-Username Repair

Research/development relays may expose an explicit reset path for same-username
re-registration and stale-local-key repair.

- This is an opt-in development escape hatch, not hardened behavior.
- It requires explicit user or operator action before the existing relay-side
  identity binding is reset.
- Supported use is limited to development recovery flows such as re-registering
  the same username from a browser after an immutable-identity conflict or
  repairing mismatched saved browser keys.

### 6.8 Recovery Terminology

Use the following terms consistently across clients and docs:

- **Forget local profile**: web/desktop local-only cleanup of one saved browser
  profile. This does not imply remote retirement.
- **Repair saved keys**: development-relay-only same-username recovery that
  resets the relay record and re-publishes the keys already saved on the local
  browser profile.
- **Reset local state** / **Reset this device**: destructive local wipe that
  removes the client-local account state and may attempt current-device
  retirement first when keys are still available.

## 7. Bounded Guarantees And Non-Goals

This repo currently guarantees less than a production multi-device messenger.
The contract is deliberately bounded:

- device retirement is device-scoped, not account deletion,
- linked-device import is explicit and package-based, not automatic sync,
- local reset is destructive and may be local-only when the server is
  unreachable,
- rotation, linked-device import, and local reset are separate flows with
  different trust implications,
- stale trust-pin or stale-session repair is not automatic across all clients,
- development-only "repair account" flows on local research relays are not part
  of the hardened contract.

## 8. Operator And Audit Checklist

When reviewing a lifecycle change, verify all of the following:

- does it preserve the distinction between linked-device import and identity
  rotation?
- does current-device retirement clear only device-scoped server state?
- does local reset clearly state whether remote retirement was attempted?
- does the client return to an unprovisioned/re-verify state after reset?
- does any same-username recovery path require explicit operator/user action?
- do docs and tests still agree on what is removed locally vs remotely?

## 9. Source Of Truth Map

This contract is derived from the currently implemented and documented behavior
in:

- [API.md](./API.md)
- [ANDROID.md](./ANDROID.md)
- [IOS.md](./IOS.md)
- [SPEC.md](./SPEC.md)
- `crates/pqmsg-server/tests/api.rs`
- `crates/pqmsg-cli/src/main.rs`
- `mobile/android/app/src/main/java/com/pqmsg/demo/SecurityInfoActivity.kt`
- `mobile/ios/PQMsgDemo/Sources/AppState.swift`
- `mobile/web/src/app.ts`
- `mobile/web/src/storage.ts`
