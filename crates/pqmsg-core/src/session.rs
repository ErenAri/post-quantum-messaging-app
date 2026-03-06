use crate::aead::{decrypt, encrypt_with_rng, CiphertextEnvelope};
use crate::dh::{generate_keypair, DhKeyPair, DhPublicKey};
use crate::kdf::hkdf_sha256_32;
use crate::kem::KemProvider;
use crate::ratchet::pq::{self, PqRatchetState};
use crate::ratchet::{dh_root_step, ChainState, SkippedKeyId, SkippedMessageKeys};
use crate::tlv::{critical_type, encode, TlvRecord};
use crate::wire::{WireMessage, DEFAULT_SUITE_ID, WIRE_VERSION};
use crate::CoreError;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const INFO_INITIATOR_SEND: &[u8] = b"pqmsg-session-initiator-send";
const INFO_INITIATOR_RECV: &[u8] = b"pqmsg-session-initiator-recv";
const AD_TAG_PROTOCOL_VERSION: u16 = critical_type(0x1101);
const AD_TAG_SUITE_ID: u16 = critical_type(0x1102);
const AD_TAG_EXTERNAL_AD: u16 = critical_type(0x1103);
const AD_TAG_SENDER_DH_PUB: u16 = critical_type(0x1104);
const AD_TAG_MSG_NUM: u16 = critical_type(0x1105);
const AD_TAG_PREV_CHAIN_LEN: u16 = critical_type(0x1106);
const AD_TAG_PQ_STEP_CT: u16 = critical_type(0x1107);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqRatchetSnapshot {
    pub interval: u32,
    pub local_public_key: Vec<u8>,
    pub local_secret_key: Vec<u8>,
    pub remote_public_key: Vec<u8>,
}

impl Drop for PqRatchetSnapshot {
    fn drop(&mut self) {
        self.local_secret_key.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SkippedMessageKeySnapshot {
    pub dh_pub: [u8; 32],
    pub msg_num: u32,
    pub message_key: [u8; 32],
}

impl Drop for SkippedMessageKeySnapshot {
    fn drop(&mut self) {
        self.message_key.zeroize();
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub version: u16,
    pub suite_id: u16,
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub sending_next_msg_num: u32,
    pub receiving_chain_key: [u8; 32],
    pub receiving_next_msg_num: u32,
    pub local_dh_public: [u8; 32],
    pub local_dh_secret: [u8; 32],
    pub remote_dh_pub: [u8; 32],
    pub prev_chain_len: u32,
    pub max_skipped: usize,
    pub skipped: Vec<SkippedMessageKeySnapshot>,
    #[serde(default)]
    pub pq_ratchet: Option<PqRatchetSnapshot>,
}

impl Drop for SessionSnapshot {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.sending_chain_key.zeroize();
        self.receiving_chain_key.zeroize();
        self.local_dh_secret.zeroize();
    }
}

pub struct SessionState {
    version: u16,
    suite_id: u16,
    root_key: [u8; 32],
    sending_chain: ChainState,
    receiving_chain: ChainState,
    local_dh: DhKeyPair,
    remote_dh_pub: DhPublicKey,
    prev_chain_len: u32,
    skipped: SkippedMessageKeys,
    pq_state: Option<PqRatchetState>,
    pq_kem: Option<Box<dyn KemProvider>>,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

impl SessionState {
    pub fn from_handshake(
        role: SessionRole,
        handshake_root_key: [u8; 32],
        local_dh: DhKeyPair,
        remote_dh_pub: DhPublicKey,
        max_skipped: usize,
    ) -> Result<Self, CoreError> {
        Self::from_handshake_with_suite(
            role,
            handshake_root_key,
            local_dh,
            remote_dh_pub,
            DEFAULT_SUITE_ID,
            max_skipped,
        )
    }

    pub fn from_handshake_with_suite(
        role: SessionRole,
        handshake_root_key: [u8; 32],
        local_dh: DhKeyPair,
        remote_dh_pub: DhPublicKey,
        suite_id: u16,
        max_skipped: usize,
    ) -> Result<Self, CoreError> {
        let (send_info, recv_info) = match role {
            SessionRole::Initiator => (INFO_INITIATOR_SEND, INFO_INITIATOR_RECV),
            SessionRole::Responder => (INFO_INITIATOR_RECV, INFO_INITIATOR_SEND),
        };
        let sending_chain_key = hkdf_sha256_32(&handshake_root_key, None, send_info)?;
        let receiving_chain_key = hkdf_sha256_32(&handshake_root_key, None, recv_info)?;

        Ok(Self {
            version: WIRE_VERSION,
            suite_id,
            root_key: handshake_root_key,
            sending_chain: ChainState::new(sending_chain_key),
            receiving_chain: ChainState::new(receiving_chain_key),
            local_dh,
            remote_dh_pub,
            prev_chain_len: 0,
            skipped: SkippedMessageKeys::new(max_skipped),
            pq_state: None,
            pq_kem: None,
        })
    }

    pub fn enable_pq_ratchet(&mut self, state: PqRatchetState, kem: Box<dyn KemProvider>) {
        self.pq_state = Some(state);
        self.pq_kem = Some(kem);
    }

    pub fn pq_ratchet_enabled(&self) -> bool {
        self.pq_state.is_some() && self.pq_kem.is_some()
    }

    pub fn pq_ratchet_interval(&self) -> Option<u32> {
        self.pq_state.as_ref().map(|s| s.interval)
    }

    pub fn root_key(&self) -> [u8; 32] {
        self.root_key
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        let skipped = self
            .skipped
            .entries()
            .into_iter()
            .map(|(key_id, message_key)| SkippedMessageKeySnapshot {
                dh_pub: key_id.dh_pub,
                msg_num: key_id.msg_num,
                message_key,
            })
            .collect();

        let pq_ratchet = self.pq_state.as_ref().map(|s| PqRatchetSnapshot {
            interval: s.interval,
            local_public_key: s.local_public_key.clone(),
            local_secret_key: s.local_secret_key.as_slice().to_vec(),
            remote_public_key: s.remote_public_key.clone(),
        });

        SessionSnapshot {
            version: self.version,
            suite_id: self.suite_id,
            root_key: self.root_key,
            sending_chain_key: self.sending_chain.chain_key(),
            sending_next_msg_num: self.sending_chain.next_msg_num(),
            receiving_chain_key: self.receiving_chain.chain_key(),
            receiving_next_msg_num: self.receiving_chain.next_msg_num(),
            local_dh_public: self.local_dh.public.0,
            local_dh_secret: self.local_dh.secret.0,
            remote_dh_pub: self.remote_dh_pub.0,
            prev_chain_len: self.prev_chain_len,
            max_skipped: self.skipped.max_entries(),
            skipped,
            pq_ratchet,
        }
    }

    pub fn from_snapshot(snapshot: SessionSnapshot) -> Self {
        Self::from_snapshot_with_kem(snapshot, None)
    }

    pub fn from_snapshot_with_kem(
        mut snapshot: SessionSnapshot,
        kem: Option<Box<dyn KemProvider>>,
    ) -> Self {
        let skipped_items = std::mem::take(&mut snapshot.skipped);
        let skipped = skipped_items
            .into_iter()
            .map(|item| {
                (
                    SkippedKeyId {
                        dh_pub: item.dh_pub,
                        msg_num: item.msg_num,
                    },
                    item.message_key,
                )
            })
            .collect();

        let root_key = std::mem::take(&mut snapshot.root_key);
        let sending_chain_key = std::mem::take(&mut snapshot.sending_chain_key);
        let receiving_chain_key = std::mem::take(&mut snapshot.receiving_chain_key);
        let local_dh_secret = std::mem::take(&mut snapshot.local_dh_secret);

        let pq_state = snapshot.pq_ratchet.take().map(|mut s| {
            let secret = std::mem::take(&mut s.local_secret_key);
            PqRatchetState {
                interval: s.interval,
                local_public_key: s.local_public_key.clone(),
                local_secret_key: crate::keys::SecretBytes::from(secret),
                remote_public_key: s.remote_public_key.clone(),
            }
        });

        Self {
            version: snapshot.version,
            suite_id: snapshot.suite_id,
            root_key,
            sending_chain: ChainState::from_parts(sending_chain_key, snapshot.sending_next_msg_num),
            receiving_chain: ChainState::from_parts(
                receiving_chain_key,
                snapshot.receiving_next_msg_num,
            ),
            local_dh: DhKeyPair {
                public: DhPublicKey(snapshot.local_dh_public),
                secret: crate::dh::DhSecretKey(local_dh_secret),
            },
            remote_dh_pub: DhPublicKey(snapshot.remote_dh_pub),
            prev_chain_len: snapshot.prev_chain_len,
            skipped: SkippedMessageKeys::from_entries(snapshot.max_skipped, skipped),
            pq_state,
            pq_kem: kem,
        }
    }

    pub fn encrypt(&mut self, message: &[u8], ad: &[u8]) -> Result<Vec<u8>, CoreError> {
        let (msg_num, mut message_key) = self.sending_chain.next_message_key()?;
        let mut pq_step_ct = None;

        if let (Some(state), Some(kem)) = (&self.pq_state, &self.pq_kem) {
            if let Some(mut step) = pq::sender_step(state, kem.as_ref(), &self.root_key, msg_num)? {
                self.root_key = std::mem::take(&mut step.root_key);
                pq_step_ct = Some(std::mem::take(&mut step.ciphertext));
            }
        }

        let sender_dh_pub = self.local_dh.public.0;
        let prev_chain_len = self.prev_chain_len;
        let associated_data = session_associated_data(
            self.version,
            self.suite_id,
            &sender_dh_pub,
            msg_num,
            prev_chain_len,
            pq_step_ct.as_deref(),
            ad,
        )?;
        let mut rng = OsRng;
        let envelope = encrypt_with_rng(&message_key, message, &associated_data, &mut rng)?;

        let wire = WireMessage {
            version: self.version,
            suite_id: self.suite_id,
            sender_dh_pub,
            msg_num,
            prev_chain_len,
            pq_step_ct,
            aead_nonce: envelope.nonce,
            ciphertext: envelope.ciphertext,
        };
        message_key.zeroize();
        wire.encode()
    }

    pub fn decrypt(&mut self, wire_bytes: &[u8], ad: &[u8]) -> Result<Vec<u8>, CoreError> {
        let wire = WireMessage::decode(wire_bytes)?;
        if wire.version != self.version {
            return Err(CoreError::UnsupportedAlgorithm("wire.version"));
        }
        if wire.suite_id != self.suite_id {
            return Err(CoreError::UnsupportedAlgorithm("wire.suite_id"));
        }

        let sender_dh_pub = DhPublicKey(wire.sender_dh_pub);
        if sender_dh_pub != self.remote_dh_pub {
            self.skip_until(self.remote_dh_pub.0, wire.prev_chain_len)?;
            self.apply_dh_ratchet(sender_dh_pub)?;
        }

        let key_id = SkippedKeyId {
            dh_pub: wire.sender_dh_pub,
            msg_num: wire.msg_num,
        };

        let mut message_key = if wire.msg_num < self.receiving_chain.next_msg_num() {
            self.skipped
                .take(key_id)
                .ok_or(CoreError::MessageKeyUnavailable)?
        } else {
            self.skip_until(wire.sender_dh_pub, wire.msg_num)?;
            let (_, key) = self.receiving_chain.next_message_key()?;
            key
        };

        let envelope = CiphertextEnvelope {
            nonce: wire.aead_nonce,
            ciphertext: wire.ciphertext,
            aad: session_associated_data(
                wire.version,
                wire.suite_id,
                &wire.sender_dh_pub,
                wire.msg_num,
                wire.prev_chain_len,
                wire.pq_step_ct.as_deref(),
                ad,
            )?,
        };
        let plaintext = decrypt(&message_key, &envelope)?;
        message_key.zeroize();

        if let Some(ct) = wire.pq_step_ct.as_deref() {
            let state = self.pq_state.as_ref().ok_or(CoreError::PqRatchetDisabled)?;
            let kem = self.pq_kem.as_ref().ok_or(CoreError::PqRatchetDisabled)?;
            self.root_key = pq::receiver_step(state, kem.as_ref(), &self.root_key, ct)?;
        }

        Ok(plaintext)
    }

    fn skip_until(&mut self, dh_pub: [u8; 32], until_msg_num: u32) -> Result<(), CoreError> {
        while self.receiving_chain.next_msg_num() < until_msg_num {
            let (msg_num, key) = self.receiving_chain.next_message_key()?;
            self.skipped.insert(SkippedKeyId { dh_pub, msg_num }, key);
        }
        Ok(())
    }

    fn apply_dh_ratchet(&mut self, new_remote_dh_pub: DhPublicKey) -> Result<(), CoreError> {
        let mut recv_step =
            dh_root_step(&self.root_key, &self.local_dh.secret, &new_remote_dh_pub)?;
        self.root_key = std::mem::take(&mut recv_step.root_key);
        self.receiving_chain
            .reset(std::mem::take(&mut recv_step.chain_key));

        self.prev_chain_len = self.sending_chain.next_msg_num();
        self.remote_dh_pub = new_remote_dh_pub;

        let mut rng = OsRng;
        self.local_dh = generate_keypair(&mut rng);

        let mut send_step =
            dh_root_step(&self.root_key, &self.local_dh.secret, &self.remote_dh_pub)?;
        self.root_key = std::mem::take(&mut send_step.root_key);
        self.sending_chain
            .reset(std::mem::take(&mut send_step.chain_key));
        Ok(())
    }
}

fn session_associated_data(
    version: u16,
    suite_id: u16,
    sender_dh_pub: &[u8; 32],
    msg_num: u32,
    prev_chain_len: u32,
    pq_step_ct: Option<&[u8]>,
    external_ad: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let mut records = vec![
        TlvRecord {
            ty: AD_TAG_PROTOCOL_VERSION,
            value: version.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_SUITE_ID,
            value: suite_id.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_SENDER_DH_PUB,
            value: sender_dh_pub.to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_MSG_NUM,
            value: msg_num.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_PREV_CHAIN_LEN,
            value: prev_chain_len.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_EXTERNAL_AD,
            value: external_ad.to_vec(),
        },
    ];
    if let Some(pq_step_ct) = pq_step_ct {
        records.push(TlvRecord {
            ty: AD_TAG_PQ_STEP_CT,
            value: pq_step_ct.to_vec(),
        });
    }
    encode(&records)
}

#[cfg(test)]
mod tests {
    use super::{SessionRole, SessionState};
    use crate::dh::generate_keypair;
    use crate::handshake::{
        alice_initiate, bob_receive, pq_signed_prekey_signature_message,
        signed_prekey_signature_message, SignatureVerifier,
    };
    use crate::kem::{KemEncapsulation, KemProvider};
    use crate::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
    use crate::ratchet::pq::PqRatchetState;
    use crate::wire::WireMessage;
    use crate::CoreError;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    struct TestSignatureVerifier;
    struct MockKem;

    impl SignatureVerifier for TestSignatureVerifier {
        fn verify(
            &self,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), CoreError> {
            let expected = test_signature(public_key, message);
            if signature == expected {
                Ok(())
            } else {
                Err(CoreError::SignatureVerificationFailed)
            }
        }
    }

    impl KemProvider for MockKem {
        fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError> {
            if recipient_public_key.len() != 32 {
                return Err(CoreError::InvalidLength {
                    field: "mock_kem.public_key",
                    expected: 32,
                    actual: recipient_public_key.len(),
                });
            }
            let ciphertext = digest3(b"ct", recipient_public_key, b"");
            let shared_secret = digest3(b"ss", recipient_public_key, &ciphertext);
            Ok(KemEncapsulation {
                ciphertext,
                shared_secret: Zeroizing::new(shared_secret),
            })
        }

        fn decapsulate(
            &self,
            recipient_secret_key: &[u8],
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>, CoreError> {
            if recipient_secret_key.len() != 32 {
                return Err(CoreError::InvalidLength {
                    field: "mock_kem.secret_key",
                    expected: 32,
                    actual: recipient_secret_key.len(),
                });
            }
            Ok(Zeroizing::new(digest3(
                b"ss",
                recipient_secret_key,
                ciphertext,
            )))
        }
    }

    fn digest3(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.update(c);
        hasher.finalize().to_vec()
    }

    fn test_signature(public_key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn setup_handshake_root() -> [u8; 32] {
        let kem = MockKem;
        let verifier = TestSignatureVerifier;
        let mut rng = OsRng;
        let alice_identity = IdentityKeyPair::generate("alice-ik", &mut rng);
        let bob_identity = IdentityKeyPair::generate("bob-ik", &mut rng);
        let bob_spk = OneTimePreKey::generate("bob-spk", &mut rng);

        let mut pq_prekey = [0u8; 32];
        rng.fill_bytes(&mut pq_prekey);
        let bob_pq_spk = KEMPreKey {
            key_id: "bob-pqspk".to_string(),
            public_key: pq_prekey.to_vec(),
            secret_key: SecretBytes::from(pq_prekey.to_vec()),
        };

        let signature_public_key = b"test-signature-pubkey".to_vec();
        let spk_msg = signed_prekey_signature_message(1, &bob_spk.public_key).expect("spk msg");
        let pq_msg =
            pq_signed_prekey_signature_message(1, &bob_pq_spk.public_key).expect("pqspk msg");
        let bundle = PreKeyBundle::new(
            "bob",
            bob_identity.public_key,
            bob_spk.public_key,
            bob_pq_spk.public_key.clone(),
            test_signature(&signature_public_key, &spk_msg),
            test_signature(&signature_public_key, &pq_msg),
            signature_public_key,
        );

        let initiator = alice_initiate(
            &mut rng,
            &verifier,
            &kem,
            "alice",
            "bob",
            &alice_identity,
            &bundle,
            b"seed",
        )
        .expect("alice initiate");
        let responder = bob_receive(
            &kem,
            &bob_identity,
            &bob_spk,
            &bob_pq_spk,
            &initiator.initial_message,
        )
        .expect("bob receive");
        assert_eq!(initiator.session_key, responder.session_key);
        *initiator.session_key.as_bytes()
    }

    fn setup_sessions(max_skipped: usize) -> (SessionState, SessionState) {
        let root = setup_handshake_root();
        let mut rng = OsRng;
        let alice_dh = generate_keypair(&mut rng);
        let bob_dh = generate_keypair(&mut rng);

        let alice = SessionState::from_handshake(
            SessionRole::Initiator,
            root,
            alice_dh.clone(),
            bob_dh.public,
            max_skipped,
        )
        .expect("alice session");
        let bob = SessionState::from_handshake(
            SessionRole::Responder,
            root,
            bob_dh,
            alice_dh.public,
            max_skipped,
        )
        .expect("bob session");
        (alice, bob)
    }

    #[test]
    fn session_initialized_from_handshake_root() {
        let root = setup_handshake_root();
        let mut rng = OsRng;
        let alice_dh = generate_keypair(&mut rng);
        let bob_dh = generate_keypair(&mut rng);
        let alice = SessionState::from_handshake(
            SessionRole::Initiator,
            root,
            alice_dh.clone(),
            bob_dh.public,
            16,
        )
        .expect("alice");
        let bob =
            SessionState::from_handshake(SessionRole::Responder, root, bob_dh, alice_dh.public, 16)
                .expect("bob");
        assert_eq!(alice.root_key(), root);
        assert_eq!(bob.root_key(), root);
    }

    #[test]
    fn multi_message_exchange_roundtrips() {
        let (mut alice, mut bob) = setup_sessions(16);
        let ad = b"session-ad";

        let wire1 = alice.encrypt(b"hello-1", ad).expect("encrypt1");
        let plain1 = bob.decrypt(&wire1, ad).expect("decrypt1");
        assert_eq!(plain1, b"hello-1");

        let wire2 = bob.encrypt(b"world-1", ad).expect("encrypt2");
        let plain2 = alice.decrypt(&wire2, ad).expect("decrypt2");
        assert_eq!(plain2, b"world-1");

        let wire3 = alice.encrypt(b"hello-2", ad).expect("encrypt3");
        let plain3 = bob.decrypt(&wire3, ad).expect("decrypt3");
        assert_eq!(plain3, b"hello-2");
    }

    #[test]
    fn out_of_order_delivery_uses_skipped_cache() {
        let (mut alice, mut bob) = setup_sessions(16);
        let ad = b"session-ad";

        let wire1 = alice.encrypt(b"m1", ad).expect("encrypt1");
        let wire2 = alice.encrypt(b"m2", ad).expect("encrypt2");
        let wire3 = alice.encrypt(b"m3", ad).expect("encrypt3");

        let plain1 = bob.decrypt(&wire1, ad).expect("decrypt1");
        assert_eq!(plain1, b"m1");

        let plain3 = bob.decrypt(&wire3, ad).expect("decrypt3");
        assert_eq!(plain3, b"m3");

        let plain2 = bob.decrypt(&wire2, ad).expect("decrypt2");
        assert_eq!(plain2, b"m2");
    }

    #[test]
    fn mismatched_suite_id_is_rejected() {
        let (mut alice, mut bob) = setup_sessions(16);
        let ad = b"session-ad";

        let wire = alice.encrypt(b"hello", ad).expect("encrypt");
        let mut parsed = WireMessage::decode(&wire).expect("decode wire");
        parsed.suite_id ^= 0x0001;
        let tampered = parsed.encode().expect("encode wire");

        let result = bob.decrypt(&tampered, ad);
        assert!(matches!(
            result,
            Err(CoreError::UnsupportedAlgorithm("wire.suite_id"))
        ));
    }

    #[test]
    fn pq_step_evolves_root_and_keeps_decryption_working() {
        let (mut alice, mut bob) = setup_sessions(32);
        let ad = b"session-ad";
        let mut rng = OsRng;
        let mut alice_pq = [0u8; 32];
        let mut bob_pq = [0u8; 32];
        rng.fill_bytes(&mut alice_pq);
        rng.fill_bytes(&mut bob_pq);

        alice.enable_pq_ratchet(
            PqRatchetState {
                interval: 2,
                local_public_key: alice_pq.to_vec(),
                local_secret_key: SecretBytes::from(alice_pq.to_vec()),
                remote_public_key: bob_pq.to_vec(),
            },
            Box::new(MockKem),
        );
        bob.enable_pq_ratchet(
            PqRatchetState {
                interval: 2,
                local_public_key: bob_pq.to_vec(),
                local_secret_key: SecretBytes::from(bob_pq.to_vec()),
                remote_public_key: alice_pq.to_vec(),
            },
            Box::new(MockKem),
        );

        let root_before_alice = alice.root_key();
        let root_before_bob = bob.root_key();

        let wire1 = alice.encrypt(b"a1", ad).expect("encrypt a1");
        let plain1 = bob.decrypt(&wire1, ad).expect("decrypt a1");
        assert_eq!(plain1, b"a1");

        let wire2 = alice.encrypt(b"a2", ad).expect("encrypt a2");
        let parsed = WireMessage::decode(&wire2).expect("decode wire2");
        assert!(parsed.pq_step_ct.is_some());
        let plain2 = bob.decrypt(&wire2, ad).expect("decrypt a2");
        assert_eq!(plain2, b"a2");

        assert_ne!(alice.root_key(), root_before_alice);
        assert_ne!(bob.root_key(), root_before_bob);
        assert_eq!(alice.root_key(), bob.root_key());

        let wire3 = bob.encrypt(b"b1", ad).expect("encrypt b1");
        let plain3 = alice.decrypt(&wire3, ad).expect("decrypt b1");
        assert_eq!(plain3, b"b1");
    }

    #[test]
    fn tampered_pq_step_ciphertext_is_rejected() {
        let (mut alice, mut bob) = setup_sessions(32);
        let ad = b"session-ad";
        let mut rng = OsRng;
        let mut alice_pq = [0u8; 32];
        let mut bob_pq = [0u8; 32];
        rng.fill_bytes(&mut alice_pq);
        rng.fill_bytes(&mut bob_pq);

        alice.enable_pq_ratchet(
            PqRatchetState {
                interval: 1,
                local_public_key: alice_pq.to_vec(),
                local_secret_key: SecretBytes::from(alice_pq.to_vec()),
                remote_public_key: bob_pq.to_vec(),
            },
            Box::new(MockKem),
        );
        bob.enable_pq_ratchet(
            PqRatchetState {
                interval: 1,
                local_public_key: bob_pq.to_vec(),
                local_secret_key: SecretBytes::from(bob_pq.to_vec()),
                remote_public_key: alice_pq.to_vec(),
            },
            Box::new(MockKem),
        );

        let wire = alice.encrypt(b"payload", ad).expect("encrypt");
        let mut parsed = WireMessage::decode(&wire).expect("decode");
        let mut pq_step_ct = parsed.pq_step_ct.take().expect("pq step present");
        pq_step_ct[0] ^= 0x01;
        parsed.pq_step_ct = Some(pq_step_ct);
        let tampered = parsed.encode().expect("encode");

        let result = bob.decrypt(&tampered, ad);
        assert!(matches!(result, Err(CoreError::AeadOperation)));
    }

    #[test]
    fn pq_snapshot_restore_with_kem_preserves_future_steps() {
        let (mut alice, mut bob) = setup_sessions(32);
        let ad = b"session-ad";
        let mut rng = OsRng;
        let mut alice_pq = [0u8; 32];
        let mut bob_pq = [0u8; 32];
        rng.fill_bytes(&mut alice_pq);
        rng.fill_bytes(&mut bob_pq);

        alice.enable_pq_ratchet(
            PqRatchetState {
                interval: 1,
                local_public_key: alice_pq.to_vec(),
                local_secret_key: SecretBytes::from(alice_pq.to_vec()),
                remote_public_key: bob_pq.to_vec(),
            },
            Box::new(MockKem),
        );
        bob.enable_pq_ratchet(
            PqRatchetState {
                interval: 1,
                local_public_key: bob_pq.to_vec(),
                local_secret_key: SecretBytes::from(bob_pq.to_vec()),
                remote_public_key: alice_pq.to_vec(),
            },
            Box::new(MockKem),
        );

        let alice_snapshot = alice.snapshot();
        let bob_snapshot = bob.snapshot();

        let mut alice =
            SessionState::from_snapshot_with_kem(alice_snapshot, Some(Box::new(MockKem)));
        let mut bob = SessionState::from_snapshot_with_kem(bob_snapshot, Some(Box::new(MockKem)));

        let wire = alice
            .encrypt(b"restored", ad)
            .expect("encrypt after restore");
        let parsed = WireMessage::decode(&wire).expect("decode restored wire");
        assert!(parsed.pq_step_ct.is_some());
        let plain = bob.decrypt(&wire, ad).expect("decrypt after restore");
        assert_eq!(plain, b"restored");
    }
}
