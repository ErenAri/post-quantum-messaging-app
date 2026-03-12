use crate::alg::{AlgorithmSuite, SecurityProfile};
use crate::tlv::{
    build_record_map, critical_type, decode_strict, encode, require_from_map, TlvRecord,
};
use crate::CoreError;
use aes::cipher::{KeyIvInit, StreamCipher};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

pub const WIRE_VERSION: u16 = 1;
pub const WIRE_VERSION_V2: u16 = 2;
pub const DEFAULT_SUITE_ID: u16 = crate::alg::SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305;

// V1 wire message TLV tags
const TAG_VERSION: u16 = critical_type(0x1001);
const TAG_SUITE_ID: u16 = critical_type(0x1002);
const TAG_SENDER_DH_PUB: u16 = critical_type(0x1003);
const TAG_MSG_NUM: u16 = critical_type(0x1004);
const TAG_PREV_CHAIN_LEN: u16 = critical_type(0x1005);
const TAG_PQ_STEP_CT: u16 = critical_type(0x1006);
const TAG_AEAD_NONCE: u16 = critical_type(0x1007);
const TAG_CIPHERTEXT: u16 = critical_type(0x1008);
const TAG_PQ_TARGET_PUB_HASH: u16 = critical_type(0x1009);
const TAG_PQ_NEXT_PUB: u16 = critical_type(0x100A);

// V2 wire message TLV tags (header encrypted, padding applied)
const TAG_V2_VERSION: u16 = critical_type(0x1101);
const TAG_V2_SUITE_ID: u16 = critical_type(0x1102);
const TAG_V2_ENCRYPTED_HEADER: u16 = critical_type(0x1103);
const TAG_V2_AEAD_NONCE: u16 = critical_type(0x1104);
const TAG_V2_CIPHERTEXT: u16 = critical_type(0x1105);

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
    pub pq_target_pub_hash: Option<Vec<u8>>,
    pub pq_next_public_key: Option<Vec<u8>>,
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
        if let Some(target_pub_hash) = &self.pq_target_pub_hash {
            records.push(TlvRecord {
                ty: TAG_PQ_TARGET_PUB_HASH,
                value: target_pub_hash.clone(),
            });
        }
        if let Some(next_pub) = &self.pq_next_public_key {
            records.push(TlvRecord {
                ty: TAG_PQ_NEXT_PUB,
                value: next_pub.clone(),
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
            TAG_PQ_TARGET_PUB_HASH,
            TAG_PQ_NEXT_PUB,
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
        let pq_target_pub_hash = map.get(&TAG_PQ_TARGET_PUB_HASH).map(|v| v.to_vec());
        let pq_next_public_key = map.get(&TAG_PQ_NEXT_PUB).map(|v| v.to_vec());
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
            pq_target_pub_hash,
            pq_next_public_key,
            aead_nonce,
            ciphertext,
        })
    }

    /// Validate the message's suite_id against a security profile (fail-closed).
    pub fn validate_suite(&self, profile: SecurityProfile) -> Result<(), CoreError> {
        profile.enforce_suite_id(self.suite_id)
    }
}

/// Plaintext header fields that are encrypted in V2 wire messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderPlaintext {
    pub sender_dh_pub: [u8; 32],
    pub msg_num: u32,
    pub prev_chain_len: u32,
    pub pq_step_ct: Option<Vec<u8>>,
    pub pq_target_pub_hash: Option<Vec<u8>>,
    pub pq_next_public_key: Option<Vec<u8>>,
}

impl HeaderPlaintext {
    /// Serialize header fields to bytes for encryption.
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let mut records = vec![
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
        if let Some(target_pub_hash) = &self.pq_target_pub_hash {
            records.push(TlvRecord {
                ty: TAG_PQ_TARGET_PUB_HASH,
                value: target_pub_hash.clone(),
            });
        }
        if let Some(next_pub) = &self.pq_next_public_key {
            records.push(TlvRecord {
                ty: TAG_PQ_NEXT_PUB,
                value: next_pub.clone(),
            });
        }
        encode(&records)
    }

    /// Deserialize header fields from decrypted bytes.
    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        let known_types = [
            TAG_SENDER_DH_PUB,
            TAG_MSG_NUM,
            TAG_PREV_CHAIN_LEN,
            TAG_PQ_STEP_CT,
            TAG_PQ_TARGET_PUB_HASH,
            TAG_PQ_NEXT_PUB,
        ];
        let records = decode_strict(input, &known_types)?;
        let map = build_record_map(&records);
        let sender_dh_pub = parse_32(
            require_from_map(&map, TAG_SENDER_DH_PUB, "header.sender_dh_pub")?,
            "header.sender_dh_pub",
        )?;
        let msg_num = parse_u32(
            require_from_map(&map, TAG_MSG_NUM, "header.msg_num")?,
            "header.msg_num",
        )?;
        let prev_chain_len = parse_u32(
            require_from_map(&map, TAG_PREV_CHAIN_LEN, "header.prev_chain_len")?,
            "header.prev_chain_len",
        )?;
        let pq_step_ct = map.get(&TAG_PQ_STEP_CT).map(|v| v.to_vec());
        let pq_target_pub_hash = map.get(&TAG_PQ_TARGET_PUB_HASH).map(|v| v.to_vec());
        let pq_next_public_key = map.get(&TAG_PQ_NEXT_PUB).map(|v| v.to_vec());
        Ok(Self {
            sender_dh_pub,
            msg_num,
            prev_chain_len,
            pq_step_ct,
            pq_target_pub_hash,
            pq_next_public_key,
        })
    }
}

/// AES-256-CTR nonce: all zeros. Safe because the header key is unique per
/// ratchet step (never reused).
const HEADER_CTR_IV: [u8; 16] = [0u8; 16];

/// Encrypt serialized header plaintext with AES-256-CTR.
///
/// The header key is derived uniquely for each DH ratchet step, so using
/// a fixed nonce is cryptographically safe (key is never reused).
pub fn encrypt_header(hk: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = plaintext.to_vec();
    let mut cipher = Aes256Ctr::new(hk.into(), &HEADER_CTR_IV.into());
    cipher.apply_keystream(&mut buf);
    buf
}

/// Decrypt encrypted header with AES-256-CTR. Returns raw bytes that should
/// be parsed via `HeaderPlaintext::decode`.
pub fn decrypt_header(hk: &[u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    // AES-256-CTR is symmetric: encrypt == decrypt
    encrypt_header(hk, ciphertext)
}

/// Try to decrypt a header with the given key and parse it.
/// Returns `Ok(Some(header))` on success, `Ok(None)` if decryption produced
/// unparseable data, `Err` only on structural TLV errors.
pub fn try_decrypt_header(hk: &[u8; 32], ciphertext: &[u8]) -> Option<HeaderPlaintext> {
    let decrypted = decrypt_header(hk, ciphertext);
    HeaderPlaintext::decode(&decrypted).ok()
}

/// V2 wire message with encrypted header blob.
/// The header (sender DH pub, msg_num, prev_chain_len, pq_step_ct) is encrypted
/// with a header key derived during each DH ratchet step, preventing metadata leakage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireMessageV2 {
    pub version: u16,
    pub suite_id: u16,
    pub encrypted_header: Vec<u8>,
    pub aead_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl WireMessageV2 {
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let records = vec![
            TlvRecord {
                ty: TAG_V2_VERSION,
                value: self.version.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: TAG_V2_SUITE_ID,
                value: self.suite_id.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: TAG_V2_ENCRYPTED_HEADER,
                value: self.encrypted_header.clone(),
            },
            TlvRecord {
                ty: TAG_V2_AEAD_NONCE,
                value: self.aead_nonce.to_vec(),
            },
            TlvRecord {
                ty: TAG_V2_CIPHERTEXT,
                value: self.ciphertext.clone(),
            },
        ];
        encode(&records)
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        let known_types = [
            TAG_V2_VERSION,
            TAG_V2_SUITE_ID,
            TAG_V2_ENCRYPTED_HEADER,
            TAG_V2_AEAD_NONCE,
            TAG_V2_CIPHERTEXT,
        ];
        let records = decode_strict(input, &known_types)?;
        let map = build_record_map(&records);
        let version = parse_u16(
            require_from_map(&map, TAG_V2_VERSION, "wire_v2.version")?,
            "wire_v2.version",
        )?;
        let suite_id = parse_u16(
            require_from_map(&map, TAG_V2_SUITE_ID, "wire_v2.suite_id")?,
            "wire_v2.suite_id",
        )?;
        let encrypted_header =
            require_from_map(&map, TAG_V2_ENCRYPTED_HEADER, "wire_v2.encrypted_header")?.to_vec();
        let aead_nonce = parse_12(
            require_from_map(&map, TAG_V2_AEAD_NONCE, "wire_v2.aead_nonce")?,
            "wire_v2.aead_nonce",
        )?;
        let ciphertext = require_from_map(&map, TAG_V2_CIPHERTEXT, "wire_v2.ciphertext")?.to_vec();
        Ok(Self {
            version,
            suite_id,
            encrypted_header,
            aead_nonce,
            ciphertext,
        })
    }

    /// Validate the message's suite_id against a security profile (fail-closed).
    pub fn validate_suite(&self, profile: SecurityProfile) -> Result<(), CoreError> {
        profile.enforce_suite_id(self.suite_id)
    }
}

/// Version-dispatching decode: sniffs the first TLV tag to determine whether
/// the message is V1 or V2, then delegates to the appropriate decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedWireMessage {
    V1(WireMessage),
    V2(WireMessageV2),
}

impl DecodedWireMessage {
    pub fn version(&self) -> u16 {
        match self {
            Self::V1(m) => m.version,
            Self::V2(m) => m.version,
        }
    }

    pub fn suite_id(&self) -> u16 {
        match self {
            Self::V1(m) => m.suite_id,
            Self::V2(m) => m.suite_id,
        }
    }

    pub fn validate_suite(&self, profile: SecurityProfile) -> Result<(), CoreError> {
        match self {
            Self::V1(m) => m.validate_suite(profile),
            Self::V2(m) => m.validate_suite(profile),
        }
    }
}

/// Decode a wire message, dispatching by version tag.
/// V1 messages use TAG_VERSION (0x9001), V2 messages use TAG_V2_VERSION (0x9101).
/// The first 2 bytes of the TLV stream determine the tag type.
pub fn decode_wire_message(input: &[u8]) -> Result<DecodedWireMessage, CoreError> {
    if input.len() < 4 {
        return Err(CoreError::InvalidTlv("wire message too short"));
    }
    let first_tag = u16::from_be_bytes([input[0], input[1]]);
    match first_tag {
        TAG_VERSION => Ok(DecodedWireMessage::V1(WireMessage::decode(input)?)),
        TAG_V2_VERSION => Ok(DecodedWireMessage::V2(WireMessageV2::decode(input)?)),
        _ => Err(CoreError::UnsupportedAlgorithm("wire.version_tag")),
    }
}

/// Preference-ordered list of supported wire versions for negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupportedWireVersions {
    pub versions: Vec<u16>,
}

impl SupportedWireVersions {
    pub fn v1_only() -> Self {
        Self {
            versions: vec![WIRE_VERSION],
        }
    }

    pub fn v1_and_v2() -> Self {
        Self {
            versions: vec![WIRE_VERSION_V2, WIRE_VERSION],
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.versions.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        if input.len() % 2 != 0 {
            return Err(CoreError::InvalidLength {
                field: "supported_wire_versions",
                expected: 0,
                actual: input.len(),
            });
        }
        let versions: Vec<u16> = input
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        for &v in &versions {
            if v != WIRE_VERSION && v != WIRE_VERSION_V2 {
                return Err(CoreError::UnsupportedAlgorithm("wire.version"));
            }
        }
        Ok(Self { versions })
    }

    /// Select the highest mutually-supported wire version.
    pub fn negotiate(&self, remote: &SupportedWireVersions) -> Option<u16> {
        self.versions
            .iter()
            .find(|v| remote.versions.contains(v))
            .copied()
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
            pq_target_pub_hash: None,
            pq_next_public_key: None,
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

    // --- V2 wire message tests ---

    fn sample_v2_message(suite_id: u16) -> WireMessageV2 {
        WireMessageV2 {
            version: WIRE_VERSION_V2,
            suite_id,
            encrypted_header: vec![0xDD; 96],
            aead_nonce: [0xBB; 12],
            ciphertext: vec![0xCC; 48],
        }
    }

    #[test]
    fn wire_message_v2_roundtrip() {
        let msg = sample_v2_message(DEFAULT_SUITE_ID);
        let encoded = msg.encode().expect("encode v2");
        let decoded = WireMessageV2::decode(&encoded).expect("decode v2");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn wire_message_v2_validate_suite_pass() {
        let msg = sample_v2_message(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305);
        assert!(msg.validate_suite(SecurityProfile::HighAssurance).is_ok());
    }

    #[test]
    fn wire_message_v2_validate_suite_reject() {
        let msg = sample_v2_message(SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305);
        assert!(msg.validate_suite(SecurityProfile::NssAligned).is_err());
    }

    #[test]
    fn header_plaintext_roundtrip() {
        let header = HeaderPlaintext {
            sender_dh_pub: [0xAA; 32],
            msg_num: 42,
            prev_chain_len: 10,
            pq_step_ct: Some(vec![0xFF; 64]),
            pq_target_pub_hash: None,
            pq_next_public_key: None,
        };
        let encoded = header.encode().expect("encode header");
        let decoded = HeaderPlaintext::decode(&encoded).expect("decode header");
        assert_eq!(header, decoded);
    }

    #[test]
    fn header_plaintext_roundtrip_no_pq() {
        let header = HeaderPlaintext {
            sender_dh_pub: [0xBB; 32],
            msg_num: 0,
            prev_chain_len: 0,
            pq_step_ct: None,
            pq_target_pub_hash: None,
            pq_next_public_key: None,
        };
        let encoded = header.encode().expect("encode header");
        let decoded = HeaderPlaintext::decode(&encoded).expect("decode header");
        assert_eq!(header, decoded);
    }

    #[test]
    fn decode_wire_message_dispatches_v1() {
        let msg = sample_message(DEFAULT_SUITE_ID);
        let encoded = msg.encode().expect("encode v1");
        let decoded = decode_wire_message(&encoded).expect("dispatch v1");
        assert!(matches!(decoded, DecodedWireMessage::V1(_)));
        assert_eq!(decoded.version(), WIRE_VERSION);
    }

    #[test]
    fn decode_wire_message_dispatches_v2() {
        let msg = sample_v2_message(DEFAULT_SUITE_ID);
        let encoded = msg.encode().expect("encode v2");
        let decoded = decode_wire_message(&encoded).expect("dispatch v2");
        assert!(matches!(decoded, DecodedWireMessage::V2(_)));
        assert_eq!(decoded.version(), WIRE_VERSION_V2);
    }

    #[test]
    fn decode_wire_message_rejects_truncated() {
        assert!(decode_wire_message(&[0x00]).is_err());
    }

    #[test]
    fn decode_wire_message_rejects_unknown_tag() {
        // A message starting with an unknown critical tag
        let bad = vec![0xFF, 0xFF, 0x00, 0x02, 0x00, 0x01];
        assert!(decode_wire_message(&bad).is_err());
    }

    // --- SupportedWireVersions tests ---

    #[test]
    fn supported_wire_versions_encode_decode_roundtrip() {
        let versions = SupportedWireVersions::v1_and_v2();
        let encoded = versions.encode();
        assert_eq!(encoded.len(), 4);
        let decoded = SupportedWireVersions::decode(&encoded).expect("decode");
        assert_eq!(versions, decoded);
    }

    #[test]
    fn supported_wire_versions_negotiate_prefers_v2() {
        let local = SupportedWireVersions::v1_and_v2();
        let remote = SupportedWireVersions::v1_and_v2();
        assert_eq!(local.negotiate(&remote), Some(WIRE_VERSION_V2));
    }

    #[test]
    fn supported_wire_versions_negotiate_falls_back_to_v1() {
        let local = SupportedWireVersions::v1_and_v2();
        let remote = SupportedWireVersions::v1_only();
        assert_eq!(local.negotiate(&remote), Some(WIRE_VERSION));
    }

    #[test]
    fn supported_wire_versions_decode_rejects_unknown() {
        let bad = 99u16.to_be_bytes();
        assert!(SupportedWireVersions::decode(&bad).is_err());
    }

    #[test]
    fn supported_wire_versions_decode_rejects_odd_length() {
        assert!(SupportedWireVersions::decode(&[0x00, 0x01, 0x00]).is_err());
    }

    // --- Header encryption tests ---

    #[test]
    fn header_encrypt_decrypt_roundtrip() {
        let hk = [0x42u8; 32];
        let header = HeaderPlaintext {
            sender_dh_pub: [0xAA; 32],
            msg_num: 7,
            prev_chain_len: 3,
            pq_step_ct: Some(vec![0xBB; 16]),
            pq_target_pub_hash: None,
            pq_next_public_key: None,
        };
        let plaintext = header.encode().expect("encode header");
        let encrypted = encrypt_header(&hk, &plaintext);
        assert_ne!(
            encrypted, plaintext,
            "encrypted should differ from plaintext"
        );
        let decrypted = decrypt_header(&hk, &encrypted);
        assert_eq!(decrypted, plaintext);
        let parsed = HeaderPlaintext::decode(&decrypted).expect("parse decrypted header");
        assert_eq!(parsed, header);
    }

    #[test]
    fn header_wrong_key_produces_unparseable_output() {
        let hk = [0x42u8; 32];
        let wrong_hk = [0x99u8; 32];
        let header = HeaderPlaintext {
            sender_dh_pub: [0xAA; 32],
            msg_num: 0,
            prev_chain_len: 0,
            pq_step_ct: None,
            pq_target_pub_hash: None,
            pq_next_public_key: None,
        };
        let plaintext = header.encode().expect("encode");
        let encrypted = encrypt_header(&hk, &plaintext);
        let bad_decrypt = decrypt_header(&wrong_hk, &encrypted);
        // With the wrong key, the TLV structure will be corrupted
        assert!(HeaderPlaintext::decode(&bad_decrypt).is_err());
    }

    #[test]
    fn try_decrypt_header_returns_none_on_wrong_key() {
        let hk = [0x42u8; 32];
        let wrong_hk = [0x99u8; 32];
        let header = HeaderPlaintext {
            sender_dh_pub: [0xAA; 32],
            msg_num: 5,
            prev_chain_len: 2,
            pq_step_ct: None,
            pq_target_pub_hash: None,
            pq_next_public_key: None,
        };
        let plaintext = header.encode().expect("encode");
        let encrypted = encrypt_header(&hk, &plaintext);
        assert!(try_decrypt_header(&wrong_hk, &encrypted).is_none());
        assert_eq!(try_decrypt_header(&hk, &encrypted), Some(header));
    }
}
