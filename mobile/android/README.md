# Android Demo

Thin demo client that uses:

- Retrofit/OkHttp for server transport
- Rust `libpqmsg_android.so` for cryptography via UniFFI
- Two screens: Setup and Chat

## Flows

- Generate identity keys in Rust
- Register user and publish prekeys
- Fetch peer bundle
- Send encrypted handshake/session messages
- Poll inbox and decrypt in Rust

Detailed Android build steps are in [`docs/ANDROID.md`](../../docs/ANDROID.md).
