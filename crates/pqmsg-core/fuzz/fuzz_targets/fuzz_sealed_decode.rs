#![no_main]

use libfuzzer_sys::fuzz_target;
use pqmsg_core::sealed::SealedEnvelope;

fuzz_target!(|data: &[u8]| {
    // Fuzz the sealed-sender envelope TLV decoder.
    // Exercises version/suite_id u16 extraction, UTF-8 recipient_user_id,
    // fixed-size nonce extraction, and variable-length ciphertext.
    if let Ok(env) = SealedEnvelope::decode(data) {
        // Round-trip: a successful decode must re-encode without panic.
        let encoded = env.encode().expect("re-encode must succeed");
        let env2 = SealedEnvelope::decode(&encoded).expect("round-trip decode must succeed");
        assert_eq!(env.recipient_user_id, env2.recipient_user_id);
        assert_eq!(env.ciphertext, env2.ciphertext);
    }
});
