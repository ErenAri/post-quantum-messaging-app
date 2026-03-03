#![no_main]

use libfuzzer_sys::fuzz_target;
use pqmsg_core::tlv::{critical_type, decode_strict, decode_with_policy, DecodePolicy};

fuzz_target!(|data: &[u8]| {
    let known_types = [
        critical_type(0x0001),
        critical_type(0x0002),
        critical_type(0x1001),
        0x0004,
    ];
    let _ = decode_strict(data, &known_types);
    let _ = decode_with_policy(
        data,
        &known_types,
        DecodePolicy {
            reject_unknown_critical: false,
            reject_duplicates: false,
        },
    );
});
