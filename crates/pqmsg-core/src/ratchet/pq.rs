use crate::kdf::hkdf_sha256_32;
use crate::kem::KemProvider;
use crate::keys::SecretBytes;
use crate::CoreError;

const INFO_PQ_STEP: &[u8] = b"pqmsg-ratchet-pq-step";

#[derive(Clone, Debug)]
pub struct PqRatchetState {
    pub interval: u32,
    pub local_public_key: Vec<u8>,
    pub local_secret_key: SecretBytes,
    pub remote_public_key: Vec<u8>,
}

pub struct PqStepOutput {
    pub ciphertext: Vec<u8>,
    pub root_key: [u8; 32],
}

impl PqRatchetState {
    pub fn should_step(&self, msg_num: u32) -> bool {
        self.interval > 0 && ((msg_num + 1) % self.interval == 0)
    }
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
    Ok(Some(PqStepOutput {
        ciphertext: encapsulated.ciphertext,
        root_key: next_root,
    }))
}

pub fn receiver_step<K: KemProvider + ?Sized>(
    state: &PqRatchetState,
    kem: &K,
    root_key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<[u8; 32], CoreError> {
    let ss_pq = kem.decapsulate(state.local_secret_key.as_slice(), ciphertext)?;
    mix_root_with_pq(root_key, &ss_pq)
}
