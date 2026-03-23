use crate::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const CRITICAL_BIT: u16 = 0x8000;

/// Maximum allowed size for a single TLV record value (64 KiB minus header).
/// This is the natural limit given the u16 length field, but we enforce it
/// explicitly to prevent allocation of oversized buffers from malformed input.
pub const MAX_TLV_VALUE_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TlvRecord {
    pub ty: u16,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodePolicy {
    pub reject_unknown_critical: bool,
    pub reject_duplicates: bool,
}

impl Default for DecodePolicy {
    fn default() -> Self {
        Self {
            reject_unknown_critical: true,
            reject_duplicates: true,
        }
    }
}

pub const fn critical_type(base: u16) -> u16 {
    base | CRITICAL_BIT
}

pub const fn is_critical(ty: u16) -> bool {
    (ty & CRITICAL_BIT) == CRITICAL_BIT
}

pub fn encode(records: &[TlvRecord]) -> Result<Vec<u8>, CoreError> {
    let mut out = Vec::new();
    for record in records {
        if record.value.len() > u16::MAX as usize {
            return Err(CoreError::InvalidLength {
                field: "tlv.value",
                expected: u16::MAX as usize,
                actual: record.value.len(),
            });
        }
        out.extend_from_slice(&record.ty.to_be_bytes());
        out.extend_from_slice(&(record.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&record.value);
    }
    Ok(out)
}

pub fn decode_strict(input: &[u8], known_types: &[u16]) -> Result<Vec<TlvRecord>, CoreError> {
    decode_with_policy(input, known_types, DecodePolicy::default())
}

pub fn decode_with_policy(
    input: &[u8],
    known_types: &[u16],
    policy: DecodePolicy,
) -> Result<Vec<TlvRecord>, CoreError> {
    let mut cursor = 0usize;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    while cursor < input.len() {
        if input.len() - cursor < 4 {
            return Err(CoreError::InvalidTlv("truncated header"));
        }
        let ty = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
        let len = u16::from_be_bytes([input[cursor + 2], input[cursor + 3]]) as usize;
        cursor += 4;

        if input.len() - cursor < len {
            return Err(CoreError::InvalidTlv("declared length exceeds input"));
        }
        if policy.reject_unknown_critical && !known_types.contains(&ty) && is_critical(ty) {
            return Err(CoreError::UnknownCriticalTlv(ty));
        }
        if policy.reject_duplicates && !seen.insert(ty) {
            return Err(CoreError::DuplicateTlv(ty));
        }

        let value = input[cursor..cursor + len].to_vec();
        cursor += len;
        records.push(TlvRecord { ty, value });
    }
    Ok(records)
}

pub fn require<'a>(
    records: &'a [TlvRecord],
    ty: u16,
    field: &'static str,
) -> Result<&'a [u8], CoreError> {
    records
        .iter()
        .find(|record| record.ty == ty)
        .map(|record| record.value.as_slice())
        .ok_or(CoreError::MissingField(field))
}

/// Build a lookup map from decoded records for efficient field extraction.
pub fn build_record_map(records: &[TlvRecord]) -> HashMap<u16, &[u8]> {
    records.iter().map(|r| (r.ty, r.value.as_slice())).collect()
}

pub fn require_from_map<'a>(
    map: &'a HashMap<u16, &'a [u8]>,
    ty: u16,
    field: &'static str,
) -> Result<&'a [u8], CoreError> {
    map.get(&ty).copied().ok_or(CoreError::MissingField(field))
}

#[cfg(test)]
mod tests {
    use super::{
        critical_type, decode_strict, decode_with_policy, encode, DecodePolicy, TlvRecord,
    };

    #[test]
    fn tlv_roundtrip() {
        let records = vec![
            TlvRecord {
                ty: critical_type(0x0001),
                value: vec![1, 2, 3],
            },
            TlvRecord {
                ty: 0x0004,
                value: b"pqmsg".to_vec(),
            },
        ];
        let encoded = encode(&records).expect("encode");
        let decoded = decode_strict(&encoded, &[critical_type(0x0001), 0x0004]).expect("decode");
        assert_eq!(records, decoded);
    }

    #[test]
    fn fuzz_like_invalid_inputs_rejected() {
        let known = [critical_type(0x0001)];
        let invalid_inputs = [
            vec![],
            vec![0x80, 0x01, 0x00],
            vec![0x80, 0x01, 0x00, 0x02, 0xaa],
            vec![0x80, 0x02, 0x00, 0x01, 0xaa],
            vec![0x80, 0x01, 0x00, 0x01, 0xaa, 0x80, 0x01, 0x00, 0x01, 0xbb],
        ];

        for (idx, input) in invalid_inputs.iter().enumerate() {
            if idx == 0 {
                let out = decode_with_policy(
                    input,
                    &known,
                    DecodePolicy {
                        reject_unknown_critical: true,
                        reject_duplicates: true,
                    },
                )
                .expect("empty input is valid");
                assert!(out.is_empty());
                continue;
            }

            let result = decode_strict(input, &known);
            assert!(result.is_err(), "expected error for case {idx}");
        }
    }
}
