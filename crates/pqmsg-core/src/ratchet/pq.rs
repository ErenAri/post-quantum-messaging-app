use crate::kdf::hkdf_sha256_32;
use crate::kem::{KemKeyPair, KemProvider};
use crate::keys::SecretBytes;
use crate::CoreError;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const INFO_PQ_STEP: &[u8] = b"pqmsg-ratchet-pq-step";

/// Default PQ ratchet step interval: every message performs a KEM re-key.
/// This keeps PQ mixing continuously active on the supported direct-message path.
pub const DEFAULT_PQ_RATCHET_INTERVAL: u32 = 1;
pub const DEFAULT_PQ_RATCHET_KEY_HISTORY: usize = 4;

#[derive(Clone, Debug)]
pub struct PqLocalKeyRecord {
    pub public_key: Vec<u8>,
    pub secret_key: SecretBytes,
}

#[derive(Clone, Debug)]
pub struct PqRatchetState {
    pub interval: u32,
    pub local_public_key: Vec<u8>,
    pub local_secret_key: SecretBytes,
    pub remote_public_key: Vec<u8>,
    pub local_key_history: Vec<PqLocalKeyRecord>,
    pub max_key_history: usize,
    pub last_remote_update_msg_num: u32,
}

pub struct PqStepOutput {
    pub ciphertext: Vec<u8>,
    pub root_key: [u8; 32],
    pub target_public_key_hash: Vec<u8>,
    pub next_local_keypair: KemKeyPair,
}

impl Drop for PqStepOutput {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.next_local_keypair.secret_key.zeroize();
    }
}

impl PqRatchetState {
    pub fn should_step(&self, msg_num: u32) -> bool {
        self.interval > 0 && ((msg_num + 1) % self.interval == 0)
    }

    pub fn local_public_key_hash(&self) -> Vec<u8> {
        hash_public_key(&self.local_public_key)
    }

    pub fn commit_local_key_rotation(&mut self, next_local_keypair: KemKeyPair) {
        self.local_key_history.insert(
            0,
            PqLocalKeyRecord {
                public_key: std::mem::take(&mut self.local_public_key),
                secret_key: std::mem::replace(
                    &mut self.local_secret_key,
                    SecretBytes::from(Vec::new()),
                ),
            },
        );
        while self.local_key_history.len() > self.max_key_history {
            self.local_key_history.pop();
        }
        self.local_public_key = next_local_keypair.public_key;
        self.local_secret_key = next_local_keypair.secret_key;
    }

    pub fn apply_remote_public_key_update(&mut self, next_remote_public_key: &[u8], msg_num: u32) {
        if msg_num >= self.last_remote_update_msg_num {
            self.remote_public_key = next_remote_public_key.to_vec();
            self.last_remote_update_msg_num = msg_num;
        }
    }

    pub fn reset_remote_update_tracking(&mut self) {
        self.last_remote_update_msg_num = 0;
    }

    pub fn select_local_secret_key(
        &self,
        target_public_key_hash: Option<&[u8]>,
    ) -> Result<&[u8], CoreError> {
        let Some(target_public_key_hash) = target_public_key_hash else {
            return Ok(self.local_secret_key.as_slice());
        };
        if self.local_public_key_hash().as_slice() == target_public_key_hash {
            return Ok(self.local_secret_key.as_slice());
        }
        for record in &self.local_key_history {
            if hash_public_key(&record.public_key).as_slice() == target_public_key_hash {
                return Ok(record.secret_key.as_slice());
            }
        }
        Err(CoreError::MessageParsing(
            "pq ratchet target key unavailable",
        ))
    }
}

pub fn hash_public_key(public_key: &[u8]) -> Vec<u8> {
    Sha256::digest(public_key).to_vec()
}

pub fn mix_root_with_pq(root_key: &[u8; 32], ss_pq: &[u8]) -> Result<[u8; 32], CoreError> {
    hkdf_sha256_32(ss_pq, Some(root_key), INFO_PQ_STEP)
}

pub fn sender_step<K: KemProvider + ?Sized>(
    state: &PqRatchetState,
    kem: &K,
    root_key: &[u8; 32],
    msg_num: u32,
) -> Result<Option<PqStepOutput>, CoreError> {
    if !state.should_step(msg_num) {
        return Ok(None);
    }
    let encapsulated = kem.encapsulate(&state.remote_public_key)?;
    let next_root = mix_root_with_pq(root_key, &encapsulated.shared_secret)?;
    let next_local_keypair = kem.keypair()?;
    Ok(Some(PqStepOutput {
        ciphertext: encapsulated.ciphertext,
        root_key: next_root,
        target_public_key_hash: hash_public_key(&state.remote_public_key),
        next_local_keypair,
    }))
}

pub fn receiver_step<K: KemProvider + ?Sized>(
    state: &mut PqRatchetState,
    kem: &K,
    root_key: &[u8; 32],
    ciphertext: &[u8],
    target_public_key_hash: Option<&[u8]>,
    next_remote_public_key: Option<&[u8]>,
    msg_num: u32,
) -> Result<[u8; 32], CoreError> {
    let secret_key = state.select_local_secret_key(target_public_key_hash)?;
    let ss_pq = kem.decapsulate(secret_key, ciphertext)?;
    let next_root = mix_root_with_pq(root_key, &ss_pq)?;
    if let Some(next_remote_public_key) = next_remote_public_key {
        state.apply_remote_public_key_update(next_remote_public_key, msg_num);
    }
    Ok(next_root)
}
