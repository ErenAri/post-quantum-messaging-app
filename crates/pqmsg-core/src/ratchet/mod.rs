use crate::dh::{diffie_hellman, DhPublicKey, DhSecretKey};
use crate::kdf::hkdf_sha256;
use crate::CoreError;
use std::collections::{HashMap, VecDeque};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub mod pq;

const INFO_CHAIN_STEP: &[u8] = b"pqmsg-ratchet-chain-step";
const INFO_ROOT_STEP: &[u8] = b"pqmsg-ratchet-root-step";

/// Hard upper bound on skipped message key cache entries.
/// Prevents unbounded memory growth from adversarial out-of-order delivery.
pub const MAX_SKIPPED_KEYS_UPPER_BOUND: usize = 2048;

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
        if msg_num == u32::MAX {
            return Err(CoreError::PolicyViolation(
                "chain exhausted: message counter overflow",
            ));
        }
        self.next_msg_num = msg_num + 1;
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
        let clamped = max_entries.min(MAX_SKIPPED_KEYS_UPPER_BOUND);
        Self {
            max_entries: clamped,
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

impl Drop for SkippedMessageKeys {
    fn drop(&mut self) {
        for key in self.map.values_mut() {
            key.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct RootStepOutput {
    pub root_key: [u8; 32],
    pub chain_key: [u8; 32],
    /// Header encryption key derived alongside the chain key. Used to encrypt
    /// ratchet header metadata (sender DH pub, message number, etc.) in V2.
    pub header_key: [u8; 32],
}

impl Drop for RootStepOutput {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.chain_key.zeroize();
        self.header_key.zeroize();
    }
}

pub fn kdf_root_step(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
) -> Result<RootStepOutput, CoreError> {
    // Expand to 96 bytes: root_key(32) || chain_key(32) || header_key(32)
    let okm = Zeroizing::new(hkdf_sha256(dh_output, Some(root_key), INFO_ROOT_STEP, 96)?);
    let mut next_root = [0u8; 32];
    next_root.copy_from_slice(&okm[..32]);
    let mut chain_key = [0u8; 32];
    chain_key.copy_from_slice(&okm[32..64]);
    let mut header_key = [0u8; 32];
    header_key.copy_from_slice(&okm[64..96]);
    Ok(RootStepOutput {
        root_key: next_root,
        chain_key,
        header_key,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_keys_clamps_to_upper_bound() {
        let cache = SkippedMessageKeys::new(999_999);
        assert_eq!(cache.max_entries(), MAX_SKIPPED_KEYS_UPPER_BOUND);
    }

    #[test]
    fn skipped_keys_evicts_oldest_first() {
        let mut cache = SkippedMessageKeys::new(2);
        let k1 = SkippedKeyId {
            dh_pub: [1u8; 32],
            msg_num: 0,
        };
        let k2 = SkippedKeyId {
            dh_pub: [1u8; 32],
            msg_num: 1,
        };
        let k3 = SkippedKeyId {
            dh_pub: [1u8; 32],
            msg_num: 2,
        };

        cache.insert(k1, [0xAA; 32]);
        cache.insert(k2, [0xBB; 32]);
        cache.insert(k3, [0xCC; 32]);

        // k1 should have been evicted
        assert!(cache.take(k1).is_none());
        assert!(cache.take(k2).is_some());
        assert!(cache.take(k3).is_some());
    }

    #[test]
    fn skipped_keys_zero_max_entries_drops_all() {
        let mut cache = SkippedMessageKeys::new(0);
        let key_id = SkippedKeyId {
            dh_pub: [1u8; 32],
            msg_num: 0,
        };
        cache.insert(key_id, [0xAA; 32]);
        assert!(cache.take(key_id).is_none());
    }
}
