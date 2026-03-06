#![no_main]

use libfuzzer_sys::fuzz_target;
use pqmsg_core::alg::{AlgorithmSuite, SecurityProfile};

fuzz_target!(|data: &[u8]| {
    // Fuzz algorithm suite dispatch and security-profile string parsing.
    // These take untrusted identifiers and must never panic.

    // Fuzz suite_id resolution from arbitrary u16 values.
    if data.len() >= 2 {
        let suite_id = u16::from_be_bytes([data[0], data[1]]);
        if let Ok(suite) = AlgorithmSuite::from_suite_id(suite_id) {
            // A valid suite must round-trip back to the same id.
            let rt_id = suite.suite_id().expect("suite_id round-trip");
            assert_eq!(suite_id, rt_id);
        }
    }

    // Fuzz SecurityProfile::parse from arbitrary UTF-8 strings.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = SecurityProfile::parse(s);
    }
});
