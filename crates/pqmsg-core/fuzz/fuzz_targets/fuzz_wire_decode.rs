#![no_main]

use libfuzzer_sys::fuzz_target;
use pqmsg_core::wire::WireMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = WireMessage::decode(data) {
        let _ = message.encode();
    }
});
