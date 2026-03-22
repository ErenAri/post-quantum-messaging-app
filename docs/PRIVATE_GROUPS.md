# Private Groups

## Status

Current product posture:

- Group messaging is disabled in the hardened Android/web profile.
- The existing server-side group model is too metadata-visible for a Signal-class privacy claim.
- `pqmsg-core` now contains the first shared opaque-state primitive: a client-managed private-group state object, an encrypted snapshot format, invite-package roundtrips, a join-package primitive, and an initial opaque member-credential primitive.
- `pqmsg-server` now exposes the first opaque private-group storage contract: state publish/fetch backed by encrypted snapshots plus hashed membership handles and derived fetch/publish capabilities.
- This document defines the next honest implementation boundary before groups are re-enabled.

## Research Baseline

This design direction follows Signal's published private-group posture:

- Signal support says the service has no record of group memberships, titles, avatars, or other group attributes.
- Signal's published private group system and `zkgroup` work point toward server-issued membership credentials instead of clear server-side membership lists.

## Goals

- Re-enable groups without restoring clear server-side membership graphs.
- Keep membership changes, invites, and removals authenticated without leaking more metadata than necessary.
- Preserve the current sealed direct-message posture for group payload transport where possible.
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
   Status: partially implemented on the server with opaque invite issuance/resolution bound to the latest group epoch and current publish capability. Join, remove, and full client flows are still pending.
4. Add encrypted group message transport on top of that state model.
5. Add Android/web trust UX for group membership and epoch changes.
6. Only then re-enable `group_messaging_supported`.

## Suggested Server Contract Changes

- Keep `group_messaging_supported = false` until the opaque-state flow exists end to end.
- Replace clear roster endpoints with:
  - opaque state publish/fetch,
  - invite issuance and acceptance,
  - membership-credential refresh,
  - encrypted group message relay.
- Treat legacy `/groups` routes as disabled compatibility surface, not supported product API.

## Suggested Client Contract Changes

- Group creation should output an encrypted group-state package, not a clear server-side roster mutation.
- Joining a group should require invite material plus a current epoch state package.
- Clients must reject stale or unauthenticated epoch transitions.
- Android and web should share one serialized group-state format from `pqmsg-core`.

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

Until the opaque-state private-group protocol exists:

- `group_messaging_supported = false`
- legacy group routes remain disabled in the hardened profile
- direct messaging, invites, usernames, and manual contacts remain the supported social graph
