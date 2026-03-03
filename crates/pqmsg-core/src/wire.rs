use crate::tlv::{critical_type, decode_strict, encode, require, TlvRecord};
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
        let version = parse_u16(
            require(&records, TAG_VERSION, "wire.version")?,
            "wire.version",
        )?;
        let suite_id = parse_u16(
            require(&records, TAG_SUITE_ID, "wire.suite_id")?,
            "wire.suite_id",
        )?;
        let sender_dh_pub = parse_32(
            require(&records, TAG_SENDER_DH_PUB, "wire.sender_dh_pub")?,
            "wire.sender_dh_pub",
        )?;
        let msg_num = parse_u32(
            require(&records, TAG_MSG_NUM, "wire.msg_num")?,
            "wire.msg_num",
        )?;
        let prev_chain_len = parse_u32(
            require(&records, TAG_PREV_CHAIN_LEN, "wire.prev_chain_len")?,
            "wire.prev_chain_len",
        )?;
        let pq_step_ct = records
            .iter()
            .find(|record| record.ty == TAG_PQ_STEP_CT)
            .map(|record| record.value.clone());
        let aead_nonce = parse_12(
            require(&records, TAG_AEAD_NONCE, "wire.aead_nonce")?,
            "wire.aead_nonce",
        )?;
        let ciphertext = require(&records, TAG_CIPHERTEXT, "wire.ciphertext")?.to_vec();

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
