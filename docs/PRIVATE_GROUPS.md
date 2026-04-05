# Private Groups

## Status

Current product posture:

- The legacy clear-roster `group_messaging_supported` API remains disabled in the hardened Android/web profile.
- The newer opaque private-group path has a separate capability flag: `private_group_messaging_supported`.
- The existing server-side group model is too metadata-visible for a Signal-class privacy claim.
- `pqmsg-core` now contains the first shared opaque-state primitive: a client-managed private-group state object, an encrypted snapshot format, invite-package roundtrips, a join-package primitive, an initial opaque member-credential primitive, and a share-link invite envelope where the decryption secret stays client-side.
- `pqmsg-server` now exposes the first opaque private-group storage contract: state publish/fetch backed by encrypted snapshots plus hashed membership handles and derived fetch/publish capabilities.
- Dedicated opaque private-group message publish/fetch is now live on the Android/web supported path. The server no longer needs the old clear-roster recipient fanout for private-group transport.
- This document defines the next honest implementation boundary before private groups are treated as fully supported product surface.

## Research Baseline

This design direction follows Signal's published private-group posture:

- Signal support says the service has no record of group memberships, titles, avatars, or other group attributes.
- Signal's published private group system and `zkgroup` work point toward server-issued membership credentials instead of clear server-side membership lists.

## Goals

- Re-enable groups without restoring clear server-side membership graphs.
- Keep membership changes, invites, and removals authenticated without leaking more metadata than necessary.
- Preserve the current hybrid identity, sender-authentication, and transparency posture across group updates and group messages.
- Keep the design compatible with the existing hybrid PQ identity and transparency model.

## Non-Goals

- No return to the old clear membership list / explicit fan-out design.
- No server-side plaintext group titles, avatars, or member rosters in the hardened profile.
- No partial "private-ish" group mode that quietly falls back to the old metadata-heavy routes.

## Current Gap

The legacy group implementation assumes the server can:

- store clear member rosters,
- resolve recipients for each group send,
- observe group management mutations directly,
- and expose group membership/device state to normal clients.

That is why groups remain disabled today.
That is why legacy clear-roster groups remain disabled today.

## Target Architecture

### 1. Group root secret and state

Each group should have a client-managed root secret that derives:

- membership state authenticity,
- encrypted group attributes,
- sender keys or equivalent group-message secrets,
- invite / join material,
- epoch transitions after membership changes.

The server should store only opaque group-state blobs and delivery metadata that is strictly required for transport.

### 2. Membership credentials

The design should prefer server-issued membership credentials or opaque capability tokens over clear roster checks.

Properties we want:

- the server can authorize a device to fetch/post group state,
- without exposing the full membership graph to normal API consumers,
- and with rotation on joins, leaves, removals, and key changes.

### 3. Group state distribution

Clients should distribute encrypted group state updates to current members:

- initial create,
- invite accept,
- member add/remove,
- admin change,
- epoch/key rotation.

The app server should relay opaque state updates, not interpret them.

### 4. Group message transport

Group messages should use a dedicated group sender-key layer or equivalent group encryption primitive:

- per-group epoch keys,
- replay protection,
- membership-bound decryption,
- sender authentication tied back to the existing device identity / sender-certificate model.

### 5. Transparency and safety UX

Group membership and epoch transitions need user-visible trust surfaces:

- who changed membership,
- whether a peer identity changed before a group update,
- whether local group state is in sync with the latest accepted epoch.

## Recommended Implementation Order

1. Define the opaque group-state object in `pqmsg-core`.
   Status: implemented as the current `PrivateGroupState`, `PrivateGroupEncryptedSnapshot`, and `PrivateGroupInvitePackage` primitives.
2. Define the membership-credential model and server storage contract.
   Status: partially implemented in `pqmsg-core` as `PrivateGroupMemberCredential`, and partially implemented on the server as opaque `private-groups/state/publish` and `private-groups/state/fetch` endpoints backed by encrypted state blobs. Invite/join/remove flows still need to be built on top of that storage layer.
3. Implement create / invite / join / remove / epoch-rotate flows using opaque state updates.
   Status: mostly implemented on the server and supported Android/web client path with opaque invite issuance/resolution bound to the latest group epoch and current publish capability. The shared core now also has a share-link invite envelope (`PrivateGroupLinkInviteMaterial`) that keeps the join secret outside the server-stored ciphertext. Further trust UX and transport hardening still remain.
4. Add encrypted group message transport on top of that state model.
   Status: implemented as a dedicated opaque `private-groups/messages/publish` + `private-groups/messages/fetch` transport on the current Android/web path. Messages are encrypted/authenticated in `pqmsg-core` and the server no longer computes clear recipient fanout. Publish/fetch no longer carry clear `sender_user_id`, and stored group-message rows no longer persist sender identifiers; supported clients recover the sender locally from the signed group envelope plus the current member set. This is still not the final low-metadata design, because the server still sees access patterns through membership-handle-based publish/fetch authorization.
5. Add Android/web trust UX for group membership and epoch changes.
   Status: partially implemented. The Android and web group-info surfaces now show owner/role/epoch state and local trust summaries based on identity pins, safety-number verification where available, and transparency checkpoints. Richer epoch-change history and conflict UX still remain.
6. Only then re-enable `group_messaging_supported`.

## Suggested Server Contract Changes

- Keep `group_messaging_supported = false` until the opaque-state flow exists end to end.
- Advertise `private_group_messaging_supported = true` only when the opaque state, invite, and client transport path are available together.
- Replace clear roster endpoints with:
  - opaque state publish/fetch,
  - invite issuance and acceptance,
  - membership-credential refresh,
  - encrypted group message publish/fetch.
- Treat legacy `/groups` routes as disabled compatibility surface, not supported product API.

## Suggested Client Contract Changes

- Group creation should output an encrypted group-state package, not a clear server-side roster mutation.
- Joining a group should require invite material plus a current epoch state package.
- For shareable group links, the server-visible invite token should identify only the opaque ciphertext record; the join secret should remain in the client-shared link fragment or QR payload.
- Clients must reject stale or unauthenticated epoch transitions.
- Android and web should share one serialized group-state format from `pqmsg-core`.

## Current Availability Contract

The current Android/web private-group surface is intentionally fail-closed.

### A private group is available on a client only when all of the following are true

- a local opaque private-group record exists for the current user and `group_id`
- the saved `stateJson` parses into a `PrivateGroupState`
- the saved `memberCredentialJson` parses into a `PrivateGroupMemberCredential`
- the saved state and saved credential both belong to the requested `group_id`
- the saved credential belongs to the current local user
- the saved credential epoch matches the saved state epoch
- the saved state still lists the local user as a current member

### What does not block availability

- missing local message history does not block the thread from opening
- a zero local cursor does not block the thread from opening
- an empty thread still renders as an available private group and then syncs from the current local cursor

### When any availability prerequisite fails

- clients do not open the thread as partially usable
- clients do not send, attach, reply, search, or manage membership from that thread
- clients do not silently fall back to the old direct-message-wrapped private-group payload path
- clients show an explicit unavailable state and direct the user back to inbox or to a device/invite flow that can restore the latest epoch state

### State refresh boundary

- message fetch and other epoch-bound private-group operations require a valid current local member credential
- clients may keep older local history rows for storage or preview purposes, but that history is not treated as proof that the current epoch is usable
- if local state or credential is missing or stale, the client waits for a real private-group state restore path instead of attempting partial recovery from message transport alone

## Open Design Choices

### Membership primitive

Need to choose one concrete approach:

- a `zkgroup`-style credential system,
- a simpler opaque-token model for an intermediate release,
- or another reviewed private-group construction.

### Delivery model

Need to choose between:

- server fan-out over opaque per-member ciphertexts,
- a sender-key style distribution model,
- or a hybrid with opaque state updates plus sender-key message transport.

### Admin model

Need a concrete policy for:

- creator vs admin privileges,
- multi-admin conflict resolution,
- recovery after a removed or rotated admin device,
- how transparency proof failures affect group updates.

## Current Repo Boundary

- `group_messaging_supported = false`
- `private_group_messaging_supported` is the dedicated capability for the opaque private-group path
- legacy group routes remain disabled in the hardened profile
- the current Android/web path uses opaque state, opaque invites, and dedicated opaque group-message transport, not the old clear-roster API
- on supported clients, legacy direct-message-wrapped private-group payloads are compatibility-only and are ignored once dedicated private-group transport is enabled
- direct messaging, invites, usernames, and manual contacts remain the base social graph
