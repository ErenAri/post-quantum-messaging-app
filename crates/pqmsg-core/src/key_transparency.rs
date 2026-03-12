//! Client-side key transparency verification (simplified CONIKS).
//!
//! The server maintains an append-only Merkle tree where each leaf binds a
//! user's identity keys to their user_id. The server publishes signed tree
//! heads (STH) every epoch. Clients verify:
//!
//! 1. **Inclusion proofs**: "My key (or my contact's key) is in the tree."
//! 2. **Consistency proofs**: "The tree only grew since the last epoch I saw."

use ed25519_dalek::Verifier;
use sha2::{Digest, Sha256};

use crate::CoreError;

/// Domain separation prefix for leaf hashes (prevents second-preimage attacks
/// where an internal node could be confused with a leaf).
const LEAF_PREFIX: u8 = 0x00;
/// Domain separation prefix for internal node hashes.
const NODE_PREFIX: u8 = 0x01;

/// A leaf in the transparency log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransparencyLeaf {
    pub user_id: String,
    /// Monotonically increasing version for this user's key record.
    pub version: u64,
    /// X25519 identity public key (32 bytes).
    pub identity_x25519_pub: [u8; 32],
    /// ML-DSA-65 (or external) signature public key.
    pub identity_sig_pub: Vec<u8>,
    /// Unix timestamp (seconds) when this key record was published.
    pub timestamp: u64,
}

impl TransparencyLeaf {
    /// Compute the leaf hash: `SHA256(0x00 || user_id || version || x25519_pub || sig_pub || timestamp)`.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([LEAF_PREFIX]);
        h.update(self.user_id.as_bytes());
        h.update(self.version.to_be_bytes());
        h.update(self.identity_x25519_pub);
        h.update(&self.identity_sig_pub);
        h.update(self.timestamp.to_be_bytes());
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Compute the hash of an internal Merkle tree node.
/// `SHA256(0x01 || left || right)`.
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// A signed tree head published by the server each epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTreeHead {
    /// Epoch number (monotonically increasing).
    pub epoch: u64,
    /// Number of leaves in the tree at this epoch.
    pub tree_size: u64,
    /// Root hash of the Merkle tree.
    pub root_hash: [u8; 32],
    /// Ed25519 signature over `epoch || tree_size || root_hash`.
    pub signature: Vec<u8>,
}

impl SignedTreeHead {
    /// The message that the server signs.
    pub fn signing_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(8 + 8 + 32);
        body.extend_from_slice(&self.epoch.to_be_bytes());
        body.extend_from_slice(&self.tree_size.to_be_bytes());
        body.extend_from_slice(&self.root_hash);
        body
    }

    /// Verify the STH signature against the server's transparency log key.
    pub fn verify(&self, server_pub_key: &ed25519_dalek::VerifyingKey) -> Result<(), CoreError> {
        let body = self.signing_body();
        let sig = ed25519_dalek::Signature::from_slice(&self.signature)
            .map_err(|_| CoreError::SignatureVerificationFailed)?;
        server_pub_key
            .verify(&body, &sig)
            .map_err(|_| CoreError::SignatureVerificationFailed)
    }
}

/// An inclusion proof for a leaf in the Merkle tree.
///
/// The proof is a list of sibling hashes from the leaf up to the root.
/// Each entry also indicates whether the sibling is on the left (true) or
/// right (false) side.
#[derive(Clone, Debug)]
pub struct InclusionProof {
    /// Index of the leaf in the tree (0-based).
    pub leaf_index: u64,
    /// Sibling hashes along the path from leaf to root.
    /// Each tuple is `(hash, is_left)` — `is_left` means the sibling is on the left.
    pub path: Vec<([u8; 32], bool)>,
}

/// Verify that a leaf is included in a tree with the given root hash.
pub fn verify_inclusion_proof(
    leaf_hash: &[u8; 32],
    proof: &InclusionProof,
    sth: &SignedTreeHead,
    server_pub_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), CoreError> {
    // First verify the STH signature
    sth.verify(server_pub_key)?;

    // Walk up the tree
    let mut current = *leaf_hash;
    for (sibling, is_left) in &proof.path {
        current = if *is_left {
            hash_node(sibling, &current)
        } else {
            hash_node(&current, sibling)
        };
    }

    if current != sth.root_hash {
        return Err(CoreError::PolicyViolation(
            "key_transparency.inclusion_proof_invalid",
        ));
    }
    Ok(())
}

/// A consistency proof between two tree heads.
///
/// Proves that the tree at `old_size` is a prefix of the tree at `new_size`.
#[derive(Clone, Debug)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    /// Intermediate hashes that prove the old tree is a prefix of the new tree.
    pub proof_hashes: Vec<[u8; 32]>,
}

/// Verify that `old_sth` is consistent with `new_sth` — i.e., the tree only grew.
pub fn verify_consistency_proof(
    old_sth: &SignedTreeHead,
    new_sth: &SignedTreeHead,
    proof: &ConsistencyProof,
    server_pub_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), CoreError> {
    // Verify both STH signatures
    old_sth.verify(server_pub_key)?;
    new_sth.verify(server_pub_key)?;

    // Basic sanity checks
    if new_sth.epoch < old_sth.epoch {
        return Err(CoreError::PolicyViolation(
            "key_transparency.epoch_regression",
        ));
    }
    if new_sth.tree_size < old_sth.tree_size {
        return Err(CoreError::PolicyViolation("key_transparency.tree_shrunk"));
    }
    if proof.old_size != old_sth.tree_size || proof.new_size != new_sth.tree_size {
        return Err(CoreError::PolicyViolation(
            "key_transparency.proof_size_mismatch",
        ));
    }

    // If the tree didn't grow, the roots must match directly
    if old_sth.tree_size == new_sth.tree_size {
        if old_sth.root_hash != new_sth.root_hash {
            return Err(CoreError::PolicyViolation(
                "key_transparency.root_hash_mismatch",
            ));
        }
        return Ok(());
    }

    // For non-trivial consistency proofs, we verify by reconstructing both
    // old and new roots from the proof hashes. This implements RFC 6962 §2.1.2
    // consistency proof verification.
    let (old_root, new_root) =
        evaluate_consistency_proof(old_sth.tree_size, new_sth.tree_size, &proof.proof_hashes)?;

    if old_root != old_sth.root_hash {
        return Err(CoreError::PolicyViolation(
            "key_transparency.old_root_mismatch",
        ));
    }
    if new_root != new_sth.root_hash {
        return Err(CoreError::PolicyViolation(
            "key_transparency.new_root_mismatch",
        ));
    }

    Ok(())
}

/// Evaluate a consistency proof to recover the old and new root hashes.
/// This follows the RFC 6962 §2.1.2 algorithm.
fn evaluate_consistency_proof(
    old_size: u64,
    new_size: u64,
    proof_hashes: &[[u8; 32]],
) -> Result<([u8; 32], [u8; 32]), CoreError> {
    if old_size == 0 || old_size > new_size || proof_hashes.is_empty() {
        return Err(CoreError::PolicyViolation(
            "key_transparency.invalid_consistency_params",
        ));
    }

    // The first proof hash seeds both old and new root reconstruction.
    let mut old_node = proof_hashes[0];
    let mut new_node = proof_hashes[0];
    let mut idx = 1;

    // Walk up the tree combining proof hashes
    let mut level_old = old_size;
    let mut level_new = new_size;

    while idx < proof_hashes.len() {
        let h = proof_hashes[idx];
        idx += 1;

        if level_old > 0 && (level_old & 1 == 1 || level_old == level_new) {
            // This proof hash is a right sibling
            old_node = hash_node(&h, &old_node);
            new_node = hash_node(&h, &new_node);
        } else {
            // This proof hash is a new right subtree
            new_node = hash_node(&new_node, &h);
        }

        level_old >>= 1;
        level_new >>= 1;
    }

    Ok((old_node, new_node))
}

/// Build a Merkle tree from a list of leaf hashes and return the root.
///
/// This is a utility for testing and for server-side tree construction.
pub fn build_tree_root(leaf_hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaf_hashes.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaf_hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(hash_node(&pair[0], &pair[1]));
            } else {
                // Odd node: promote to next level
                next.push(pair[0]);
            }
        }
        level = next;
    }
    Some(level[0])
}

/// Build an inclusion proof for the leaf at `leaf_index` in a tree of `leaf_hashes`.
///
/// Utility for testing and server-side proof generation.
pub fn build_inclusion_proof(
    leaf_hashes: &[[u8; 32]],
    leaf_index: usize,
) -> Option<InclusionProof> {
    if leaf_index >= leaf_hashes.len() || leaf_hashes.is_empty() {
        return None;
    }

    let mut path = Vec::new();
    let mut level: Vec<[u8; 32]> = leaf_hashes.to_vec();
    let mut idx = leaf_index;

    while level.len() > 1 {
        let sibling_idx = idx ^ 1;
        if sibling_idx < level.len() {
            let is_left = sibling_idx < idx;
            path.push((level[sibling_idx], is_left));
        }
        // Build the next level
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                next.push(hash_node(&pair[0], &pair[1]));
            } else {
                next.push(pair[0]);
            }
        }
        idx /= 2;
        level = next;
    }

    Some(InclusionProof {
        leaf_index: leaf_index as u64,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn make_leaf(user_id: &str, version: u64) -> TransparencyLeaf {
        TransparencyLeaf {
            user_id: user_id.to_string(),
            version,
            identity_x25519_pub: [version as u8; 32],
            identity_sig_pub: vec![version as u8; 64],
            timestamp: 1700000000 + version,
        }
    }

    fn sign_sth(
        key: &SigningKey,
        epoch: u64,
        tree_size: u64,
        root_hash: [u8; 32],
    ) -> SignedTreeHead {
        let mut sth = SignedTreeHead {
            epoch,
            tree_size,
            root_hash,
            signature: vec![],
        };
        let body = sth.signing_body();
        sth.signature = key.sign(&body).to_bytes().to_vec();
        sth
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let leaf = make_leaf("alice", 1);
        assert_eq!(leaf.hash(), leaf.hash());
    }

    #[test]
    fn different_leaves_have_different_hashes() {
        let leaf_a = make_leaf("alice", 1);
        let leaf_b = make_leaf("bob", 1);
        assert_ne!(leaf_a.hash(), leaf_b.hash());
    }

    #[test]
    fn different_versions_have_different_hashes() {
        let leaf_v1 = make_leaf("alice", 1);
        let leaf_v2 = make_leaf("alice", 2);
        assert_ne!(leaf_v1.hash(), leaf_v2.hash());
    }

    #[test]
    fn hash_node_is_order_dependent() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        assert_ne!(hash_node(&a, &b), hash_node(&b, &a));
    }

    #[test]
    fn signed_tree_head_verifies() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let sth = sign_sth(&key, 1, 4, [0xAA; 32]);
        sth.verify(&key.verifying_key()).expect("should verify");
    }

    #[test]
    fn signed_tree_head_rejects_wrong_key() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);
        let sth = sign_sth(&key, 1, 4, [0xAA; 32]);
        assert!(sth.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn build_tree_root_single_leaf() {
        let leaf = make_leaf("alice", 1);
        let root = build_tree_root(&[leaf.hash()]);
        assert_eq!(root, Some(leaf.hash()));
    }

    #[test]
    fn build_tree_root_two_leaves() {
        let a = make_leaf("alice", 1).hash();
        let b = make_leaf("bob", 1).hash();
        let root = build_tree_root(&[a, b]).unwrap();
        assert_eq!(root, hash_node(&a, &b));
    }

    #[test]
    fn build_tree_root_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| make_leaf(&format!("u{i}"), i as u64).hash())
            .collect();
        let root = build_tree_root(&leaves).unwrap();
        let left = hash_node(&leaves[0], &leaves[1]);
        let right = hash_node(&leaves[2], &leaves[3]);
        assert_eq!(root, hash_node(&left, &right));
    }

    #[test]
    fn inclusion_proof_verifies_for_all_leaves() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let leaves: Vec<[u8; 32]> = (0..8)
            .map(|i| make_leaf(&format!("u{i}"), i as u64).hash())
            .collect();
        let root = build_tree_root(&leaves).unwrap();
        let sth = sign_sth(&key, 1, leaves.len() as u64, root);

        for i in 0..leaves.len() {
            let proof = build_inclusion_proof(&leaves, i).unwrap();
            verify_inclusion_proof(&leaves[i], &proof, &sth, &key.verifying_key())
                .unwrap_or_else(|e| panic!("inclusion proof failed for leaf {i}: {e}"));
        }
    }

    #[test]
    fn inclusion_proof_fails_for_wrong_leaf() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| make_leaf(&format!("u{i}"), i as u64).hash())
            .collect();
        let root = build_tree_root(&leaves).unwrap();
        let sth = sign_sth(&key, 1, 4, root);

        let proof = build_inclusion_proof(&leaves, 0).unwrap();
        // Use a different leaf hash — should fail
        let fake_leaf = [0xFF; 32];
        assert!(verify_inclusion_proof(&fake_leaf, &proof, &sth, &key.verifying_key()).is_err());
    }

    #[test]
    fn inclusion_proof_odd_tree_size() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        // 5 leaves (not a power of 2)
        let leaves: Vec<[u8; 32]> = (0..5)
            .map(|i| make_leaf(&format!("u{i}"), i as u64).hash())
            .collect();
        let root = build_tree_root(&leaves).unwrap();
        let sth = sign_sth(&key, 1, 5, root);

        for i in 0..leaves.len() {
            let proof = build_inclusion_proof(&leaves, i).unwrap();
            verify_inclusion_proof(&leaves[i], &proof, &sth, &key.verifying_key())
                .unwrap_or_else(|e| panic!("inclusion proof failed for leaf {i}: {e}"));
        }
    }

    #[test]
    fn tree_mutation_invalidates_proof() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let mut leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| make_leaf(&format!("u{i}"), i as u64).hash())
            .collect();
        let root = build_tree_root(&leaves).unwrap();
        let sth = sign_sth(&key, 1, 4, root);
        let proof = build_inclusion_proof(&leaves, 2).unwrap();

        // Verify proof works before mutation
        verify_inclusion_proof(&leaves[2], &proof, &sth, &key.verifying_key())
            .expect("should work");

        // Mutate a leaf — the old proof should now fail against the new tree
        leaves[0] = [0xFF; 32];
        let new_root = build_tree_root(&leaves).unwrap();
        let new_sth = sign_sth(&key, 2, 4, new_root);
        // Old proof against new STH should fail
        assert!(
            verify_inclusion_proof(&leaves[2], &proof, &new_sth, &key.verifying_key()).is_err()
        );
    }

    #[test]
    fn consistency_same_tree() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| make_leaf(&format!("u{i}"), i as u64).hash())
            .collect();
        let root = build_tree_root(&leaves).unwrap();
        let sth = sign_sth(&key, 1, 4, root);

        let proof = ConsistencyProof {
            old_size: 4,
            new_size: 4,
            proof_hashes: vec![],
        };
        verify_consistency_proof(&sth, &sth, &proof, &key.verifying_key())
            .expect("same tree should be consistent");
    }

    #[test]
    fn consistency_rejects_shrinking_tree() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let sth_big = sign_sth(&key, 2, 8, [0xBB; 32]);
        let sth_small = sign_sth(&key, 1, 4, [0xAA; 32]);

        let proof = ConsistencyProof {
            old_size: 8,
            new_size: 4,
            proof_hashes: vec![],
        };
        assert!(
            verify_consistency_proof(&sth_big, &sth_small, &proof, &key.verifying_key()).is_err()
        );
    }

    #[test]
    fn consistency_rejects_epoch_regression() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let sth_new = sign_sth(&key, 1, 4, [0xAA; 32]);
        let sth_old = sign_sth(&key, 2, 8, [0xBB; 32]);

        let proof = ConsistencyProof {
            old_size: 8,
            new_size: 4,
            proof_hashes: vec![],
        };
        assert!(
            verify_consistency_proof(&sth_old, &sth_new, &proof, &key.verifying_key()).is_err()
        );
    }

    #[test]
    fn build_tree_root_empty() {
        assert!(build_tree_root(&[]).is_none());
    }

    #[test]
    fn build_inclusion_proof_out_of_bounds() {
        let leaves = vec![[0x01; 32]];
        assert!(build_inclusion_proof(&leaves, 1).is_none());
        assert!(build_inclusion_proof(&[], 0).is_none());
    }
}
