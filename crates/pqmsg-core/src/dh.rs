use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DhPublicKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DhSecretKey(pub [u8; 32]);

#[derive(Clone)]
pub struct DhKeyPair {
    pub public: DhPublicKey,
    pub secret: DhSecretKey,
}

impl Drop for DhKeyPair {
    fn drop(&mut self) {
        self.secret.0.zeroize();
    }
}

pub fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> DhKeyPair {
    let secret = StaticSecret::random_from_rng(rng);
    let public = PublicKey::from(&secret);
    DhKeyPair {
        public: DhPublicKey(public.to_bytes()),
        secret: DhSecretKey(secret.to_bytes()),
    }
}

pub fn diffie_hellman(secret: &DhSecretKey, remote_public: &DhPublicKey) -> [u8; 32] {
    let local_secret = StaticSecret::from(secret.0);
    let remote = PublicKey::from(remote_public.0);
    local_secret.diffie_hellman(&remote).to_bytes()
}
