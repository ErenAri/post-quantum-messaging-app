# Privacy Policy

Last updated: 2026-04-08

## Developer and Contact

This privacy policy applies to the PQMsg Android pilot client and related relay services in this repository.

Privacy inquiries may be sent through the project issue tracker:

- https://github.com/ErenAri/post-quantum-messaging-app/issues

## Scope

PQMsg is currently operated as an Android secure-messaging pilot. The supported scope is direct messaging plus opaque private groups. Web messaging is demo-only, and calling is out of scope for the supported Android pilot.

## Data We Process

Depending on the feature you use, the app and relay may process:

- account identifiers such as `@username` and device IDs,
- cryptographic public keys, key versions, transparency proofs, and trust-pin state,
- optional profile fields such as display name, shareable username, and avatar data,
- encrypted message payloads, encrypted attachment blobs, and delivery metadata,
- contact and invite metadata that you explicitly create,
- push token registration data when notifications are configured,
- local encrypted client state such as keys, sessions, pinned identities, cached conversations, and private-group state,
- operational, audit, rate-limit, and security-event records needed to run the service safely.

The supported Android pilot path does not require phone-number registration.

## How We Use Data

We use this data to:

- create and manage accounts and linked devices,
- deliver direct messages, private-group messages, and attachments,
- validate identity changes, trust state, and transparency state,
- operate the pilot environment, investigate abuse, and preserve service integrity.

## Sharing

Data may be processed by the pilot operator and the infrastructure providers used for hosting, storage, backups, logging, and monitoring. This project is not presented as an advertising or cross-service tracking platform.

## Retention and Deletion

- Local encrypted state remains on the Android device until the user resets local state or deletes the account.
- In-app account deletion is intended to remove the account record and associated user data from the relay.
- Limited records may be retained where necessary for security, abuse prevention, fraud handling, backup windows, audit integrity, or legal compliance.

## Security

- Local Android state is stored using encrypted local storage and platform-backed key protection.
- Release builds are intended to use HTTPS and configured certificate pinning.

## Your Choices

- You can reset local state on the device from `Privacy & account` without deleting the remote account.
- You can request full account deletion from within the Android app.
- If you cannot access the app, use the public account-deletion page:
  https://github.com/ErenAri/post-quantum-messaging-app/blob/main/docs/ACCOUNT_DELETION.md
