use crate::dh::{diffie_hellman, DhPublicKey, DhSecretKey};
use crate::kdf::hkdf_sha256;
use crate::CoreError;
use std::collections::{HashMap, VecDeque};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod pq;

const INFO_CHAIN_STEP: &[u8] = b"pqmsg-ratchet-chain-step";
const INFO_ROOT_STEP: &[u8] = b"pqmsg-ratchet-root-step";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainState {
    chain_key: [u8; 32],
    next_msg_num: u32,
}

impl ChainState {
    pub fn new(chain_key: [u8; 32]) -> Self {
        Self {
            chain_key,
            next_msg_num: 0,
        }
    }

    pub fn next_msg_num(&self) -> u32 {
        self.next_msg_num
    }

    pub fn reset(&mut self, chain_key: [u8; 32]) {
        self.chain_key = chain_key;
        self.next_msg_num = 0;
    }

    pub fn from_parts(chain_key: [u8; 32], next_msg_num: u32) -> Self {
        Self {
            chain_key,
            next_msg_num,
        }
    }

    pub fn chain_key(&self) -> [u8; 32] {
        self.chain_key
    }

    pub fn next_message_key(&mut self) -> Result<(u32, [u8; 32]), CoreError> {
        let okm = Zeroizing::new(hkdf_sha256(&self.chain_key, None, INFO_CHAIN_STEP, 64)?);

        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&okm[..32]);
        let mut next_chain_key = [0u8; 32];
        next_chain_key.copy_from_slice(&okm[32..]);

        let msg_num = self.next_msg_num;
        self.next_msg_num = self.next_msg_num.saturating_add(1);
        self.chain_key = next_chain_key;
        Ok((msg_num, message_key))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkippedKeyId {
    pub dh_pub: [u8; 32],
    pub msg_num: u32,
}

pub struct SkippedMessageKeys {
    max_entries: usize,
    order: VecDeque<SkippedKeyId>,
    map: HashMap<SkippedKeyId, [u8; 32]>,
}

impl SkippedMessageKeys {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            order: VecDeque::new(),
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key_id: SkippedKeyId, key: [u8; 32]) {
        if self.max_entries == 0 {
            return;
        }
        if self.map.contains_key(&key_id) {
            return;
        }
        if self.order.len() >= self.max_entries {
            if let Some(evicted) = self.order.pop_front() {
                if let Some(mut removed_key) = self.map.remove(&evicted) {
                    removed_key.zeroize();
                }
            }
        }
        self.order.push_back(key_id);
        self.map.insert(key_id, key);
    }

    pub fn take(&mut self, key_id: SkippedKeyId) -> Option<[u8; 32]> {
        if let Some(pos) = self.order.iter().position(|entry| *entry == key_id) {
            self.order.remove(pos);
        }
        self.map.remove(&key_id)
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn entries(&self) -> Vec<(SkippedKeyId, [u8; 32])> {
        let mut out = Vec::with_capacity(self.order.len());
        for key_id in &self.order {
            if let Some(value) = self.map.get(key_id) {
                out.push((*key_id, *value));
            }
        }
        out
    }

    pub fn from_entries(max_entries: usize, entries: Vec<(SkippedKeyId, [u8; 32])>) -> Self {
        let mut state = Self::new(max_entries);
        for (key_id, key) in entries {
            state.insert(key_id, key);
        }
        state
    }
}

#[derive(Clone, Copy)]
pub struct RootStepOutput {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
}

pub fn kdf_root_step(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
) -> Result<RootStepOutput, CoreError> {
    let okm = Zeroizing::new(hkdf_sha256(dh_output, Some(root_key), INFO_ROOT_STEP, 64)?);
    let mut next_root = [0u8; 32];
    next_root.copy_from_slice(&okm[..32]);
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&okm[32..]);
    Ok(RootStepOutput {
        root_key: next_root,
        chain_key,
    })
}

pub fn dh_root_step(
    root_key: &[u8; 32],
    local_secret: &DhSecretKey,
    remote_public: &DhPublicKey,
) -> Result<RootStepOutput, CoreError> {
    let dh_output = diffie_hellman(local_secret, remote_public);
    kdf_root_step(root_key, &dh_output)
}
