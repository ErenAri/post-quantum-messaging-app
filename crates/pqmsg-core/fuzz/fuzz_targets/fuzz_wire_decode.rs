#![no_main]

use libfuzzer_sys::fuzz_target;
use pqmsg_core::wire::{decode_wire_message, WireMessage, WireMessageV2};

fuzz_target!(|data: &[u8]| {
    // Try version-dispatching decode
    if let Ok(decoded) = decode_wire_message(data) {
        match decoded {
            pqmsg_core::wire::DecodedWireMessage::V1(msg) => {
                let _ = msg.encode();
            }
            pqmsg_core::wire::DecodedWireMessage::V2(msg) => {
                let _ = msg.encode();
            }
        }
    }
    // Also try individual decoders directly
    if let Ok(message) = WireMessage::decode(data) {
        let _ = message.encode();
    }
    if let Ok(message) = WireMessageV2::decode(data) {
        let _ = message.encode();
    }
});
