#![forbid(unsafe_code)]

mod error;

pub mod ad;
pub mod aead;
pub mod alg;
pub mod dh;
pub mod groups;
pub mod handshake;
pub mod hsm;
pub mod kdf;
pub mod kem;
pub mod key_transparency;
pub mod keys;
pub mod pq_sig;
pub mod ratchet;
pub mod safety_number;
pub mod sealed;
pub mod session;
pub mod storage;
pub mod tlv;
pub mod wire;

#[cfg(any(feature = "wasm", feature = "wasm-pq"))]
pub mod wasm_bindings;

pub use alg as algorithms;
pub use error::CoreError;
