use crate::aead::{decrypt, encrypt_with_rng, CiphertextEnvelope};
use crate::alg::{AlgorithmSuite, PROTOCOL_VERSION_V1};
use crate::dh::{diffie_hellman, generate_keypair, DhPublicKey};
use crate::kdf::hkdf_sha256_32;
use crate::kem::KemProvider;
use crate::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle};
use crate::tlv::{critical_type, decode_strict, encode, require, TlvRecord};
use crate::CoreError;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const INFO_SK: &[u8] = b"pqmsg-pqxdh-v1";

const AD_TAG_PROTOCOL_VERSION: u16 = critical_type(0x0001);
const AD_TAG_SUITE_ID: u16 = critical_type(0x0002);
const AD_TAG_INITIATOR_IDENTITY_KEY: u16 = critical_type(0x0003);
const AD_TAG_RESPONDER_IDENTITY_KEY: u16 = critical_type(0x0004);

const MSG_TAG_PROTOCOL_VERSION: u16 = critical_type(0x0101);
const MSG_TAG_SUITE_ID: u16 = critical_type(0x0109);
const MSG_TAG_SENDER_ID: u16 = critical_type(0x0102);
const MSG_TAG_RECIPIENT_ID: u16 = critical_type(0x0103);
const MSG_TAG_IK_A_PUB: u16 = critical_type(0x0104);
const MSG_TAG_EK_A_PUB: u16 = critical_type(0x0105);
const MSG_TAG_PQ_CT: u16 = critical_type(0x0106);
const MSG_TAG_NONCE: u16 = critical_type(0x0107);
const MSG_TAG_CIPHERTEXT: u16 = critical_type(0x0108);

const SIG_TAG_PROTOCOL_VERSION: u16 = critical_type(0x0201);
const SIG_TAG_LABEL: u16 = critical_type(0x0202);
const SIG_TAG_KEY_MATERIAL: u16 = critical_type(0x0203);

#[derive(Clone, Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionKey").field(&"[REDACTED]").finish()
    }
}

pub trait SignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialMessage {
    pub protocol_version: u16,
    pub suite_id: u16,
    pub sender_id: String,
    pub recipient_id: String,
    pub ik_a_pub: DhPublicKey,
    pub ek_a_pub: DhPublicKey,
    pub pq_ct: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl InitialMessage {
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let records = vec![
            TlvRecord {
                ty: MSG_TAG_PROTOCOL_VERSION,
                value: self.protocol_version.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: MSG_TAG_SUITE_ID,
                value: self.suite_id.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: MSG_TAG_SENDER_ID,
                value: self.sender_id.as_bytes().to_vec(),
            },
            TlvRecord {
                ty: MSG_TAG_RECIPIENT_ID,
                value: self.recipient_id.as_bytes().to_vec(),
            },
            TlvRecord {
                ty: MSG_TAG_IK_A_PUB,
                value: self.ik_a_pub.0.to_vec(),
            },
            TlvRecord {
                ty: MSG_TAG_EK_A_PUB,
                value: self.ek_a_pub.0.to_vec(),
            },
            TlvRecord {
                ty: MSG_TAG_PQ_CT,
                value: self.pq_ct.clone(),
            },
            TlvRecord {
                ty: MSG_TAG_NONCE,
                value: self.nonce.to_vec(),
            },
            TlvRecord {
                ty: MSG_TAG_CIPHERTEXT,
                value: self.ciphertext.clone(),
            },
        ];
        encode(&records)
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        let known_types = [
            MSG_TAG_PROTOCOL_VERSION,
            MSG_TAG_SUITE_ID,
            MSG_TAG_SENDER_ID,
            MSG_TAG_RECIPIENT_ID,
            MSG_TAG_IK_A_PUB,
            MSG_TAG_EK_A_PUB,
            MSG_TAG_PQ_CT,
            MSG_TAG_NONCE,
            MSG_TAG_CIPHERTEXT,
        ];
        let records = decode_strict(input, &known_types)?;

        let version = parse_u16_be(
            require(&records, MSG_TAG_PROTOCOL_VERSION, "protocol_version")?,
            "protocol_version",
        )?;
        let suite_id = parse_u16_be(require(&records, MSG_TAG_SUITE_ID, "suite_id")?, "suite_id")?;
        let sender_id = parse_utf8(
            require(&records, MSG_TAG_SENDER_ID, "sender_id")?,
            "sender_id",
        )?;
        let recipient_id = parse_utf8(
            require(&records, MSG_TAG_RECIPIENT_ID, "recipient_id")?,
            "recipient_id",
        )?;
        let ik_a_pub = parse_32(require(&records, MSG_TAG_IK_A_PUB, "ik_a_pub")?, "ik_a_pub")?;
        let ek_a_pub = parse_32(require(&records, MSG_TAG_EK_A_PUB, "ek_a_pub")?, "ek_a_pub")?;
        let pq_ct = require(&records, MSG_TAG_PQ_CT, "pq_ct")?.to_vec();
        let nonce = parse_12(require(&records, MSG_TAG_NONCE, "nonce")?, "nonce")?;
        let ciphertext = require(&records, MSG_TAG_CIPHERTEXT, "ciphertext")?.to_vec();

        Ok(Self {
            protocol_version: version,
            suite_id,
            sender_id,
            recipient_id,
            ik_a_pub: DhPublicKey(ik_a_pub),
            ek_a_pub: DhPublicKey(ek_a_pub),
            pq_ct,
            nonce,
            ciphertext,
        })
    }
}

#[derive(Clone, Debug)]
pub struct InitiatorOutput {
    pub initial_message: InitialMessage,
    pub session_key: SessionKey,
}

#[derive(Clone, Debug)]
pub struct ResponderOutput {
    pub plaintext: Vec<u8>,
    pub session_key: SessionKey,
}

pub fn signed_prekey_signature_message(
    protocol_version: u16,
    signed_prekey: &DhPublicKey,
) -> Result<Vec<u8>, CoreError> {
    signature_message(protocol_version, b"SPK", &signed_prekey.0)
}

pub fn pq_signed_prekey_signature_message(
    protocol_version: u16,
    pq_signed_prekey: &[u8],
) -> Result<Vec<u8>, CoreError> {
    signature_message(protocol_version, b"PQSPK", pq_signed_prekey)
}

pub fn validate_prekey_bundle_signatures<V: SignatureVerifier>(
    bundle: &PreKeyBundle,
    verifier: &V,
) -> Result<(), CoreError> {
    let spk_message =
        signed_prekey_signature_message(bundle.protocol_version, &bundle.signed_prekey)?;
    verifier.verify(
        &bundle.signature_public_key,
        &spk_message,
        &bundle.spk_signature,
    )?;

    let pqspk_message =
        pq_signed_prekey_signature_message(bundle.protocol_version, &bundle.pq_signed_prekey)?;
    verifier.verify(
        &bundle.signature_public_key,
        &pqspk_message,
        &bundle.pqspk_signature,
    )?;
    Ok(())
}

pub fn associated_data(
    protocol_version: u16,
    suite_id: u16,
    initiator_identity_key: &DhPublicKey,
    responder_identity_key: &DhPublicKey,
) -> Result<Vec<u8>, CoreError> {
    encode(&[
        TlvRecord {
            ty: AD_TAG_PROTOCOL_VERSION,
            value: protocol_version.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_SUITE_ID,
            value: suite_id.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_INITIATOR_IDENTITY_KEY,
            value: initiator_identity_key.0.to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_RESPONDER_IDENTITY_KEY,
            value: responder_identity_key.0.to_vec(),
        },
    ])
}

pub fn alice_initiate<R: RngCore + CryptoRng, V: SignatureVerifier, K: KemProvider>(
    rng: &mut R,
    verifier: &V,
    kem: &K,
    alice_id: &str,
    bob_id: &str,
    alice_identity: &IdentityKeyPair,
    bob_bundle: &PreKeyBundle,
    payload: &[u8],
) -> Result<InitiatorOutput, CoreError> {
    if bob_bundle.protocol_version != PROTOCOL_VERSION_V1 {
        return Err(CoreError::UnsupportedAlgorithm("protocol.version"));
    }
    let suite_id = bob_bundle.suite.suite_id()?;
    validate_prekey_bundle_signatures(bob_bundle, verifier)?;

    let alice_ik_secret = alice_identity.require_secret_key()?;
    let alice_ek = generate_keypair(rng);

    let kem_encapsulation = kem.encapsulate(&bob_bundle.pq_signed_prekey)?;
    let mut dh1 = diffie_hellman(&alice_ik_secret, &bob_bundle.signed_prekey);
    let mut dh2 = diffie_hellman(&alice_ek.secret, &bob_bundle.identity_key);
    let mut dh3 = diffie_hellman(&alice_ek.secret, &bob_bundle.signed_prekey);

    let mut ikm = Zeroizing::new(Vec::with_capacity(
        dh1.len() + dh2.len() + dh3.len() + kem_encapsulation.shared_secret.len(),
    ));
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    ikm.extend_from_slice(&kem_encapsulation.shared_secret);

    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();

    let session_key = SessionKey::new(hkdf_sha256_32(&ikm, None, INFO_SK)?);
    let ad = associated_data(
        bob_bundle.protocol_version,
        suite_id,
        &alice_identity.public_key,
        &bob_bundle.identity_key,
    )?;
    let envelope = encrypt_with_rng(session_key.as_bytes(), payload, &ad, rng)?;

    let initial_message = InitialMessage {
        protocol_version: bob_bundle.protocol_version,
        suite_id,
        sender_id: alice_id.to_string(),
        recipient_id: bob_id.to_string(),
        ik_a_pub: alice_identity.public_key,
        ek_a_pub: alice_ek.public,
        pq_ct: kem_encapsulation.ciphertext,
        nonce: envelope.nonce,
        ciphertext: envelope.ciphertext,
    };

    Ok(InitiatorOutput {
        initial_message,
        session_key,
    })
}

pub fn bob_receive<K: KemProvider>(
    kem: &K,
    bob_identity: &IdentityKeyPair,
    bob_signed_prekey: &OneTimePreKey,
    bob_pq_signed_prekey: &KEMPreKey,
    initial_message: &InitialMessage,
) -> Result<ResponderOutput, CoreError> {
    if initial_message.protocol_version != PROTOCOL_VERSION_V1 {
        return Err(CoreError::UnsupportedAlgorithm("protocol.version"));
    }
    let _ = AlgorithmSuite::from_suite_id(initial_message.suite_id)?;

    let bob_identity_secret = bob_identity.require_secret_key()?;
    let bob_spk_secret = bob_signed_prekey.require_secret_key()?;

    let ss_pq = kem.decapsulate(
        bob_pq_signed_prekey.secret_key.as_slice(),
        &initial_message.pq_ct,
    )?;
    let mut dh1 = diffie_hellman(&bob_spk_secret, &initial_message.ik_a_pub);
    let mut dh2 = diffie_hellman(&bob_identity_secret, &initial_message.ek_a_pub);
    let mut dh3 = diffie_hellman(&bob_spk_secret, &initial_message.ek_a_pub);

    let mut ikm = Zeroizing::new(Vec::with_capacity(
        dh1.len() + dh2.len() + dh3.len() + ss_pq.len(),
    ));
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);
    ikm.extend_from_slice(&ss_pq);

    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();

    let session_key = SessionKey::new(hkdf_sha256_32(&ikm, None, INFO_SK)?);
    let ad = associated_data(
        initial_message.protocol_version,
        initial_message.suite_id,
        &initial_message.ik_a_pub,
        &bob_identity.public_key,
    )?;
    let envelope = CiphertextEnvelope {
        nonce: initial_message.nonce,
        ciphertext: initial_message.ciphertext.clone(),
        aad: ad,
    };
    let plaintext = decrypt(session_key.as_bytes(), &envelope)?;

    Ok(ResponderOutput {
        plaintext,
        session_key,
    })
}

fn signature_message(
    protocol_version: u16,
    label: &[u8],
    key_material: &[u8],
) -> Result<Vec<u8>, CoreError> {
    encode(&[
        TlvRecord {
            ty: SIG_TAG_PROTOCOL_VERSION,
            value: protocol_version.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: SIG_TAG_LABEL,
            value: label.to_vec(),
        },
        TlvRecord {
            ty: SIG_TAG_KEY_MATERIAL,
            value: key_material.to_vec(),
        },
    ])
}

fn parse_u16_be(input: &[u8], field: &'static str) -> Result<u16, CoreError> {
    if input.len() != 2 {
        return Err(CoreError::InvalidLength {
            field,
            expected: 2,
            actual: input.len(),
        });
    }
    Ok(u16::from_be_bytes([input[0], input[1]]))
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

fn parse_utf8(input: &[u8], field: &'static str) -> Result<String, CoreError> {
    let value = std::str::from_utf8(input).map_err(|_| CoreError::InvalidUtf8(field))?;
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        alice_initiate, bob_receive, pq_signed_prekey_signature_message,
        signed_prekey_signature_message, InitialMessage, SignatureVerifier,
    };
    use crate::kem::{KemEncapsulation, KemProvider};
    use crate::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
    use crate::CoreError;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
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
            let shared_secret = digest3(b"ss", recipient_secret_key, ciphertext);
            Ok(Zeroizing::new(shared_secret))
        }
    }

    fn test_signature(public_key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn digest3(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(a);
        hasher.update(b);
        hasher.update(c);
        hasher.finalize().to_vec()
    }

    fn hex_encode(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len() * 2);
        for byte in input {
            use std::fmt::Write;
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }

    fn setup_bundle() -> (
        IdentityKeyPair,
        OneTimePreKey,
        KEMPreKey,
        PreKeyBundle,
        Vec<u8>,
    ) {
        let mut rng = OsRng;
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
            signature_public_key.clone(),
        );

        (
            bob_identity,
            bob_spk,
            bob_pq_spk,
            bundle,
            signature_public_key,
        )
    }

    #[test]
    fn handshake_happy_path_same_session_key() {
        let kem = MockKem;
        let verifier = TestSignatureVerifier;
        let mut rng = OsRng;
        let alice_identity = IdentityKeyPair::generate("alice-ik", &mut rng);
        let (bob_identity, bob_spk, bob_pq_spk, bundle, _) = setup_bundle();

        let initiator = alice_initiate(
            &mut rng,
            &verifier,
            &kem,
            "alice",
            "bob",
            &alice_identity,
            &bundle,
            b"hello pqmsg",
        )
        .expect("alice initiate");

        let encoded = initiator.initial_message.encode().expect("encode");
        let decoded = InitialMessage::decode(&encoded).expect("decode");
        let responder =
            bob_receive(&kem, &bob_identity, &bob_spk, &bob_pq_spk, &decoded).expect("bob receive");

        assert_eq!(initiator.session_key, responder.session_key);
        assert_eq!(responder.plaintext, b"hello pqmsg".to_vec());
    }

    #[test]
    fn decrypt_fails_on_tampered_pq_ct() {
        let kem = MockKem;
        let verifier = TestSignatureVerifier;
        let mut rng = OsRng;
        let alice_identity = IdentityKeyPair::generate("alice-ik", &mut rng);
        let (bob_identity, bob_spk, bob_pq_spk, bundle, _) = setup_bundle();

        let initiator = alice_initiate(
            &mut rng,
            &verifier,
            &kem,
            "alice",
            "bob",
            &alice_identity,
            &bundle,
            b"payload",
        )
        .expect("alice initiate");

        let mut tampered = initiator.initial_message.clone();
        if tampered.pq_ct.is_empty() {
            tampered.pq_ct.push(0x01);
        } else {
            tampered.pq_ct[0] ^= 0x01;
        }

        let result = bob_receive(&kem, &bob_identity, &bob_spk, &bob_pq_spk, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_fails_on_tampered_ciphertext() {
        let kem = MockKem;
        let verifier = TestSignatureVerifier;
        let mut rng = OsRng;
        let alice_identity = IdentityKeyPair::generate("alice-ik", &mut rng);
        let (bob_identity, bob_spk, bob_pq_spk, bundle, _) = setup_bundle();

        let initiator = alice_initiate(
            &mut rng,
            &verifier,
            &kem,
            "alice",
            "bob",
            &alice_identity,
            &bundle,
            b"payload",
        )
        .expect("alice initiate");

        let mut tampered = initiator.initial_message.clone();
        if tampered.ciphertext.is_empty() {
            tampered.ciphertext.push(0x01);
        } else {
            tampered.ciphertext[0] ^= 0x01;
        }

        let result = bob_receive(&kem, &bob_identity, &bob_spk, &bob_pq_spk, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn handshake_kat_seeded_rng_transcript() {
        let kem = MockKem;
        let verifier = TestSignatureVerifier;
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
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

        let signature_public_key = b"deterministic-signature-key".to_vec();
        let spk_msg = signed_prekey_signature_message(1, &bob_spk.public_key).expect("spk msg");
        let pq_msg = pq_signed_prekey_signature_message(1, &bob_pq_spk.public_key).expect("pq msg");
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
            b"kat-payload",
        )
        .expect("alice initiate");
        let encoded = initiator.initial_message.encode().expect("encode");
        let responder = bob_receive(
            &kem,
            &bob_identity,
            &bob_spk,
            &bob_pq_spk,
            &initiator.initial_message,
        )
        .expect("bob receive");

        assert_eq!(responder.plaintext, b"kat-payload");
        assert_eq!(initiator.session_key, responder.session_key);

        let expected_transcript_hex = "81010002000181090002000181020005616c69636581030003626f628104002018b7279e7599928f72e167111e89af25fbdff045bd6faa83425ab2d1468c8b6781050020e0ce49028ee32078ac70bf8910b2ebbab37d6e1baf5afc0b393be2ff634b78298106002074e6fa5c389000b2bf9774c6625d6368d03aa43fb398eb1736b8ae93ac5769768107000cc82fb56107fe74a0d3679f848108001b2f1799c2714d83a71a98cc1a34d299696579b15278aca29e7e981e";
        let expected_session_key_hex =
            "7d40f0a2f7cbb531ffeb2d944bf7b57dfeb5a98e8090965ff1f9576f64793270";
        assert_eq!(hex_encode(&encoded), expected_transcript_hex);
        assert_eq!(
            hex_encode(initiator.session_key.as_bytes()),
            expected_session_key_hex
        );
    }
}
