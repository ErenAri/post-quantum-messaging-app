#![no_main]

use libfuzzer_sys::fuzz_target;
use pqmsg_core::handshake::InitialMessage;

fuzz_target!(|data: &[u8]| {
    // Fuzz the X3DH initial-message TLV decoder.
    // This exercises UTF-8 string extraction, fixed-size key parsing,
    // and multi-field TLV record validation — all on untrusted input.
    if let Ok(msg) = InitialMessage::decode(data) {
        // Round-trip: a successful decode must re-encode without panic.
        let encoded = msg.encode().expect("re-encode must succeed");
        let msg2 = InitialMessage::decode(&encoded).expect("round-trip decode must succeed");
        assert_eq!(msg.sender_id, msg2.sender_id);
        assert_eq!(msg.recipient_id, msg2.recipient_id);
        assert_eq!(msg.ciphertext, msg2.ciphertext);
    }
});
