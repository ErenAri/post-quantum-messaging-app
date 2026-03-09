use crate::alg::{AlgorithmSuite, SecurityProfile};
use crate::tlv::{critical_type, decode_strict, encode, build_record_map, require_from_map, TlvRecord};
use crate::CoreError;

pub const WIRE_VERSION: u16 = 1;
pub const DEFAULT_SUITE_ID: u16 = crate::alg::SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305;

const TAG_VERSION: u16 = critical_type(0x1001);
const TAG_SUITE_ID: u16 = critical_type(0x1002);
const TAG_SENDER_DH_PUB: u16 = critical_type(0x1003);
const TAG_MSG_NUM: u16 = critical_type(0x1004);
const TAG_PREV_CHAIN_LEN: u16 = critical_type(0x1005);
const TAG_PQ_STEP_CT: u16 = critical_type(0x1006);
const TAG_AEAD_NONCE: u16 = critical_type(0x1007);
const TAG_CIPHERTEXT: u16 = critical_type(0x1008);

/// Advertised suite list for algorithm negotiation in bundle metadata.
/// Encoded as a sequence of big-endian `u16` suite IDs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedSuites {
    pub suite_ids: Vec<u16>,
}

impl SupportedSuites {
    /// Build a `SupportedSuites` containing all suites allowed by the given profile.
    pub fn for_profile(profile: SecurityProfile) -> Self {
        let all_known = [
            crate::alg::SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
            crate::alg::SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
        ];
        let suite_ids: Vec<u16> = all_known
            .iter()
            .copied()
            .filter(|&id| profile.allows_suite_id(id))
            .collect();
        Self { suite_ids }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.suite_ids
            .iter()
            .flat_map(|id| id.to_be_bytes())
            .collect()
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        if input.len() % 2 != 0 {
            return Err(CoreError::InvalidLength {
                field: "supported_suites",
                expected: 0,
                actual: input.len(),
            });
        }
        let suite_ids: Vec<u16> = input
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        // Validate each suite ID is recognized.
        for &id in &suite_ids {
            AlgorithmSuite::from_suite_id(id)?;
        }
        Ok(Self { suite_ids })
    }

    /// Select the best mutually-supported suite between local and remote.
    /// Returns the first local preference that also appears in `remote`.
    pub fn negotiate(&self, remote: &SupportedSuites) -> Option<u16> {
        self.suite_ids
            .iter()
            .find(|id| remote.suite_ids.contains(id))
            .copied()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireMessage {
    pub version: u16,
    pub suite_id: u16,
    pub sender_dh_pub: [u8; 32],
    pub msg_num: u32,
    pub prev_chain_len: u32,
    pub pq_step_ct: Option<Vec<u8>>,
    pub aead_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl WireMessage {
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let mut records = vec![
            TlvRecord {
                ty: TAG_VERSION,
                value: self.version.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: TAG_SUITE_ID,
                value: self.suite_id.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: TAG_SENDER_DH_PUB,
                value: self.sender_dh_pub.to_vec(),
            },
            TlvRecord {
                ty: TAG_MSG_NUM,
                value: self.msg_num.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: TAG_PREV_CHAIN_LEN,
                value: self.prev_chain_len.to_be_bytes().to_vec(),
            },
        ];
        if let Some(ct) = &self.pq_step_ct {
            records.push(TlvRecord {
                ty: TAG_PQ_STEP_CT,
                value: ct.clone(),
            });
        }
        records.push(TlvRecord {
            ty: TAG_AEAD_NONCE,
            value: self.aead_nonce.to_vec(),
        });
        records.push(TlvRecord {
            ty: TAG_CIPHERTEXT,
            value: self.ciphertext.clone(),
        });
        encode(&records)
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        let known_types = [
            TAG_VERSION,
            TAG_SUITE_ID,
            TAG_SENDER_DH_PUB,
            TAG_MSG_NUM,
            TAG_PREV_CHAIN_LEN,
            TAG_PQ_STEP_CT,
            TAG_AEAD_NONCE,
            TAG_CIPHERTEXT,
        ];
        let records = decode_strict(input, &known_types)?;
        let map = build_record_map(&records);
        let version = parse_u16(
            require_from_map(&map, TAG_VERSION, "wire.version")?,
            "wire.version",
        )?;
        let suite_id = parse_u16(
            require_from_map(&map, TAG_SUITE_ID, "wire.suite_id")?,
            "wire.suite_id",
        )?;
        let sender_dh_pub = parse_32(
            require_from_map(&map, TAG_SENDER_DH_PUB, "wire.sender_dh_pub")?,
            "wire.sender_dh_pub",
        )?;
        let msg_num = parse_u32(
            require_from_map(&map, TAG_MSG_NUM, "wire.msg_num")?,
            "wire.msg_num",
        )?;
        let prev_chain_len = parse_u32(
            require_from_map(&map, TAG_PREV_CHAIN_LEN, "wire.prev_chain_len")?,
            "wire.prev_chain_len",
        )?;
        let pq_step_ct = map.get(&TAG_PQ_STEP_CT).map(|v| v.to_vec());
        let aead_nonce = parse_12(
            require_from_map(&map, TAG_AEAD_NONCE, "wire.aead_nonce")?,
            "wire.aead_nonce",
        )?;
        let ciphertext = require_from_map(&map, TAG_CIPHERTEXT, "wire.ciphertext")?.to_vec();

        Ok(Self {
            version,
            suite_id,
            sender_dh_pub,
            msg_num,
            prev_chain_len,
            pq_step_ct,
            aead_nonce,
            ciphertext,
        })
    }

    /// Validate the message's suite_id against a security profile (fail-closed).
    pub fn validate_suite(&self, profile: SecurityProfile) -> Result<(), CoreError> {
        profile.enforce_suite_id(self.suite_id)
    }
}

fn parse_u16(input: &[u8], field: &'static str) -> Result<u16, CoreError> {
    if input.len() != 2 {
        return Err(CoreError::InvalidLength {
            field,
            expected: 2,
            actual: input.len(),
        });
    }
    Ok(u16::from_be_bytes([input[0], input[1]]))
}

fn parse_u32(input: &[u8], field: &'static str) -> Result<u32, CoreError> {
    if input.len() != 4 {
        return Err(CoreError::InvalidLength {
            field,
            expected: 4,
            actual: input.len(),
        });
    }
    Ok(u32::from_be_bytes([input[0], input[1], input[2], input[3]]))
}

fn parse_32(input: &[u8], field: &'static str) -> Result<[u8; 32], CoreError> {
    if input.len() != 32 {
        return Err(CoreError::InvalidLength {
            field,
            expected: 32,
            actual: input.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(input);
    Ok(out)
}

fn parse_12(input: &[u8], field: &'static str) -> Result<[u8; 12], CoreError> {
    if input.len() != 12 {
        return Err(CoreError::InvalidLength {
            field,
            expected: 12,
            actual: input.len(),
        });
    }
    let mut out = [0u8; 12];
    out.copy_from_slice(input);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::{
        SecurityProfile, SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
        SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    };

    fn sample_message(suite_id: u16) -> WireMessage {
        WireMessage {
            version: WIRE_VERSION,
            suite_id,
            sender_dh_pub: [0xAA; 32],
            msg_num: 1,
            prev_chain_len: 0,
            pq_step_ct: None,
            aead_nonce: [0xBB; 12],
            ciphertext: vec![0xCC; 48],
        }
    }

    #[test]
    fn wire_message_roundtrip() {
        let msg = sample_message(DEFAULT_SUITE_ID);
        let encoded = msg.encode().expect("encode");
        let decoded = WireMessage::decode(&encoded).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn wire_message_validate_suite_pass() {
        let msg = sample_message(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305);
        assert!(msg.validate_suite(SecurityProfile::HighAssurance).is_ok());
        assert!(msg.validate_suite(SecurityProfile::NssAligned).is_ok());
    }

    #[test]
    fn wire_message_validate_suite_reject() {
        let msg = sample_message(SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305);
        assert!(msg.validate_suite(SecurityProfile::NssAligned).is_err());
    }

    #[test]
    fn supported_suites_encode_decode_roundtrip() {
        let suites = SupportedSuites {
            suite_ids: vec![
                SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
                SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
            ],
        };
        let encoded = suites.encode();
        assert_eq!(encoded.len(), 4); // 2 suite IDs * 2 bytes each
        let decoded = SupportedSuites::decode(&encoded).expect("decode");
        assert_eq!(suites, decoded);
    }

    #[test]
    fn supported_suites_for_nss_profile() {
        let suites = SupportedSuites::for_profile(SecurityProfile::NssAligned);
        assert_eq!(suites.suite_ids.len(), 1);
        assert_eq!(
            suites.suite_ids[0],
            SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305
        );
    }

    #[test]
    fn supported_suites_negotiate_finds_common() {
        let local = SupportedSuites {
            suite_ids: vec![SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305],
        };
        let remote = SupportedSuites {
            suite_ids: vec![
                SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
                SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
            ],
        };
        assert_eq!(
            local.negotiate(&remote),
            Some(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305)
        );
    }

    #[test]
    fn supported_suites_negotiate_no_common() {
        let local = SupportedSuites {
            suite_ids: vec![SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305],
        };
        let remote = SupportedSuites {
            suite_ids: vec![SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305],
        };
        assert_eq!(local.negotiate(&remote), None);
    }

    #[test]
    fn supported_suites_decode_rejects_odd_length() {
        assert!(SupportedSuites::decode(&[0x00, 0x01, 0x00]).is_err());
    }

    #[test]
    fn supported_suites_decode_rejects_unknown_suite() {
        let bad = 0xFFFFu16.to_be_bytes();
        assert!(SupportedSuites::decode(&bad).is_err());
    }
}
