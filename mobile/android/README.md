# Android Demo

Guided demo client that uses:

- Retrofit/OkHttp for server transport
- Rust `libpqmsg_android.so` for cryptography via UniFFI
- Two screens: Setup and Chat

Current pilot scope is Android messaging only. Calling remains out of scope for this release.

## Flows

- Setup wizard with ordered steps: generate keys, register, publish prekeys, verify server
- Chat flow: fetch peer bundle, send encrypted handshake/session messages, poll and decrypt
- Two-level error surfacing: concise action hint with optional technical details

Detailed Android build steps are in [`docs/ANDROID.md`](../../docs/ANDROID.md).
