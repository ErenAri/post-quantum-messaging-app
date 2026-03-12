use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pqmsg_core::aead;
use pqmsg_core::dh;
use pqmsg_core::handshake::{
    alice_initiate, bob_receive, pq_signed_prekey_signature_message,
    signed_prekey_signature_message, InitialMessage, SignatureVerifier,
};
use pqmsg_core::kdf;
use pqmsg_core::kem::{KemEncapsulation, KemProvider, MlKem768};
use pqmsg_core::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
use pqmsg_core::ratchet::{dh_root_step, kdf_root_step, ChainState};
use pqmsg_core::sealed::{derive_pairwise_sealed_sender_key, open_message, seal_message};
use pqmsg_core::session::{SessionRole, SessionState};
use pqmsg_core::storage::{unwrap_bytes, wrap_bytes_with_params, Argon2idParams};
use pqmsg_core::tlv::{self, critical_type, TlvRecord};
use pqmsg_core::wire::WireMessage;
use pqmsg_core::CoreError;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Test helpers (mirror the pattern from handshake.rs tests)
// ---------------------------------------------------------------------------

struct BenchSignatureVerifier;
struct BenchMockKem;

impl SignatureVerifier for BenchSignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        let expected = bench_signature(public_key, message);
        if signature == expected {
            Ok(())
        } else {
            Err(CoreError::SignatureVerificationFailed)
        }
    }
}

impl KemProvider for BenchMockKem {
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

fn bench_signature(public_key: &[u8], message: &[u8]) -> Vec<u8> {
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

fn setup_bundle(
    rng: &mut ChaCha20Rng,
) -> (IdentityKeyPair, OneTimePreKey, KEMPreKey, PreKeyBundle) {
    use rand::RngCore;
    let bob_identity = IdentityKeyPair::generate("bob-ik", rng);
    let bob_spk = OneTimePreKey::generate("bob-spk", rng);
    let mut pq_bytes = [0u8; 32];
    rng.fill_bytes(&mut pq_bytes);
    let bob_pq_spk = KEMPreKey {
        key_id: "bob-pqspk".to_string(),
        public_key: pq_bytes.to_vec(),
        secret_key: SecretBytes::from(pq_bytes.to_vec()),
    };
    let sig_pub = b"bench-signature-pubkey".to_vec();
    let spk_msg = signed_prekey_signature_message(1, &bob_spk.public_key).unwrap();
    let pq_msg = pq_signed_prekey_signature_message(1, &bob_pq_spk.public_key).unwrap();
    let bundle = PreKeyBundle::new(
        "bob",
        bob_identity.public_key,
        bob_spk.public_key,
        bob_pq_spk.public_key.clone(),
        bench_signature(&sig_pub, &spk_msg),
        bench_signature(&sig_pub, &pq_msg),
        sig_pub,
    );
    (bob_identity, bob_spk, bob_pq_spk, bundle)
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_dh(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let kp_a = dh::generate_keypair(&mut rng);
    let kp_b = dh::generate_keypair(&mut rng);

    c.bench_function("dh/x25519_keygen", |b| {
        b.iter(|| dh::generate_keypair(black_box(&mut rng)))
    });

    c.bench_function("dh/x25519_shared_secret", |b| {
        b.iter(|| dh::diffie_hellman(black_box(&kp_a.secret), black_box(&kp_b.public)))
    });
}

fn bench_kem(c: &mut Criterion) {
    let kem = MlKem768::new_preferred().expect("kem init");
    let kp = kem.keypair().expect("kem keypair");

    c.bench_function("kem/ml_kem_768_keygen", |b| {
        b.iter(|| kem.keypair().unwrap())
    });

    c.bench_function("kem/ml_kem_768_encapsulate", |b| {
        b.iter(|| kem.encapsulate(black_box(&kp.public_key)).unwrap())
    });

    let enc = kem.encapsulate(&kp.public_key).unwrap();
    c.bench_function("kem/ml_kem_768_decapsulate", |b| {
        b.iter(|| {
            kem.decapsulate(
                black_box(kp.secret_key.as_slice()),
                black_box(&enc.ciphertext),
            )
            .unwrap()
        })
    });
}

fn bench_aead(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0u8; 12];

    let mut group = c.benchmark_group("aead/chacha20poly1305");
    for size in [64, 256, 1024, 16384] {
        let plaintext = vec![0xABu8; size];
        let envelope = aead::encrypt(&key, &plaintext, b"ad", nonce).unwrap();

        group.bench_with_input(BenchmarkId::new("encrypt", size), &plaintext, |b, pt| {
            b.iter(|| aead::encrypt(black_box(&key), black_box(pt), b"ad", nonce).unwrap())
        });

        group.bench_with_input(BenchmarkId::new("decrypt", size), &envelope, |b, env| {
            b.iter(|| aead::decrypt(black_box(&key), black_box(env)).unwrap())
        });
    }
    group.finish();
}

fn bench_kdf(c: &mut Criterion) {
    let ikm = [0x01u8; 32];
    let salt = [0x02u8; 32];

    c.bench_function("kdf/hkdf_sha256_32", |b| {
        b.iter(|| {
            kdf::hkdf_sha256_32(black_box(&ikm), Some(black_box(&salt)), black_box(b"info"))
                .unwrap()
        })
    });
}

fn bench_tlv(c: &mut Criterion) {
    let records = vec![
        TlvRecord {
            ty: critical_type(0x0001),
            value: vec![0u8; 32],
        },
        TlvRecord {
            ty: critical_type(0x0002),
            value: vec![0u8; 64],
        },
        TlvRecord {
            ty: 0x0004,
            value: vec![0u8; 128],
        },
    ];
    let encoded = tlv::encode(&records).unwrap();
    let known = [critical_type(0x0001), critical_type(0x0002), 0x0004];

    c.bench_function("tlv/encode_3_records", |b| {
        b.iter(|| tlv::encode(black_box(&records)).unwrap())
    });

    c.bench_function("tlv/decode_strict_3_records", |b| {
        b.iter(|| tlv::decode_strict(black_box(&encoded), black_box(&known)).unwrap())
    });
}

fn bench_wire(c: &mut Criterion) {
    let msg = WireMessage {
        version: 1,
        suite_id: 0x0001,
        sender_dh_pub: [0xAA; 32],
        msg_num: 42,
        prev_chain_len: 10,
        pq_step_ct: Some(vec![0xBB; 1088]),
        pq_target_pub_hash: None,
        pq_next_public_key: None,
        aead_nonce: [0xCC; 12],
        ciphertext: vec![0xDD; 256],
    };
    let encoded = msg.encode().unwrap();

    c.bench_function("wire/encode", |b| {
        b.iter(|| black_box(&msg).encode().unwrap())
    });

    c.bench_function("wire/decode", |b| {
        b.iter(|| WireMessage::decode(black_box(&encoded)).unwrap())
    });
}

fn bench_ratchet(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let root_key = [0x11u8; 32];
    let dh_output = [0x22u8; 32];
    let kp = dh::generate_keypair(&mut rng);
    let remote = dh::generate_keypair(&mut rng);

    c.bench_function("ratchet/kdf_root_step", |b| {
        b.iter(|| kdf_root_step(black_box(&root_key), black_box(&dh_output)).unwrap())
    });

    c.bench_function("ratchet/dh_root_step", |b| {
        b.iter(|| {
            dh_root_step(
                black_box(&root_key),
                black_box(&kp.secret),
                black_box(&remote.public),
            )
            .unwrap()
        })
    });

    c.bench_function("ratchet/chain_next_message_key", |b| {
        b.iter_batched(
            || ChainState::new([0x33u8; 32]),
            |mut chain| chain.next_message_key().unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_handshake(c: &mut Criterion) {
    let kem = BenchMockKem;
    let verifier = BenchSignatureVerifier;

    c.bench_function("handshake/alice_initiate", |b| {
        b.iter_batched(
            || {
                let mut rng = ChaCha20Rng::seed_from_u64(100);
                let alice = IdentityKeyPair::generate("alice-ik", &mut rng);
                let (_, _, _, bundle) = setup_bundle(&mut rng);
                (rng, alice, bundle)
            },
            |(mut rng, alice, bundle)| {
                alice_initiate(
                    &mut rng,
                    &verifier,
                    &kem,
                    "alice",
                    "bob",
                    &alice,
                    &alice.public_key.0,
                    &bundle,
                    b"bench-payload",
                )
                .unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("handshake/bob_receive", |b| {
        b.iter_batched(
            || {
                let mut rng = ChaCha20Rng::seed_from_u64(200);
                let alice = IdentityKeyPair::generate("alice-ik", &mut rng);
                let (bob_id, bob_spk, bob_pq_spk, bundle) = setup_bundle(&mut rng);
                let out = alice_initiate(
                    &mut rng,
                    &verifier,
                    &kem,
                    "alice",
                    "bob",
                    &alice,
                    &alice.public_key.0,
                    &bundle,
                    b"bench-payload",
                )
                .unwrap();
                let encoded = out.initial_message.encode().unwrap();
                let decoded = InitialMessage::decode(&encoded).unwrap();
                (bob_id, bob_spk, bob_pq_spk, decoded)
            },
            |(bob_id, bob_spk, bob_pq_spk, msg)| {
                bob_receive(&kem, &bob_id, &bob_spk, &bob_pq_spk, None, &msg).unwrap()
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_sealed_sender(c: &mut Criterion) {
    let key = [0x55u8; 32];
    let payload = vec![0xABu8; 256];

    let sealed = seal_message(&key, 0x0001, "bob", "alice", "dev1", &payload).unwrap();

    c.bench_function("sealed/seal_message_256b", |b| {
        b.iter(|| {
            seal_message(
                black_box(&key),
                0x0001,
                "bob",
                "alice",
                "dev1",
                black_box(&payload),
            )
            .unwrap()
        })
    });

    c.bench_function("sealed/open_message_256b", |b| {
        b.iter(|| open_message(black_box(&key), black_box(&sealed), 0x0001, "bob").unwrap())
    });

    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let local_kp = dh::generate_keypair(&mut rng);
    let remote_kp = dh::generate_keypair(&mut rng);

    c.bench_function("sealed/derive_pairwise_key", |b| {
        b.iter(|| {
            derive_pairwise_sealed_sender_key(
                black_box(&local_kp.secret),
                black_box(&remote_kp.public),
                0x0001,
            )
            .unwrap()
        })
    });
}

fn bench_session(c: &mut Criterion) {
    let root_key = [0x44u8; 32];
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let alice_dh = dh::generate_keypair(&mut rng);
    let bob_dh = dh::generate_keypair(&mut rng);
    let alice_pub = alice_dh.public;
    let bob_pub = bob_dh.public;

    // Both sides share the same handshake root key. Alice sees Bob's pub, Bob sees Alice's pub.
    let mut alice =
        SessionState::from_handshake(SessionRole::Initiator, root_key, alice_dh, bob_pub, 2000)
            .unwrap();
    let mut bob =
        SessionState::from_handshake(SessionRole::Responder, root_key, bob_dh, alice_pub, 2000)
            .unwrap();

    // Alice sends, Bob receives — this validates the session pair is valid.
    let ct0 = alice.encrypt(b"warmup", b"ad").unwrap();
    bob.decrypt(&ct0, b"ad")
        .expect("session warmup decrypt must succeed");

    c.bench_function("session/encrypt_256b", |b| {
        let msg = vec![0xABu8; 256];
        b.iter(|| alice.encrypt(black_box(&msg), b"ad").unwrap())
    });

    // For decrypt we need fresh ciphertexts each iteration.
    // alice.encrypt advances Alice's sending chain; bob.decrypt
    // consumes each corresponding message key in order.
    c.bench_function("session/decrypt_256b", |b| {
        b.iter_batched(
            || alice.encrypt(&[0xABu8; 256], b"ad").unwrap(),
            |ct| bob.decrypt(black_box(&ct), b"ad").unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_argon2id(c: &mut Criterion) {
    // Use fast params so benchmarks complete quickly; this still exercises
    // the full wrap/unwrap flow including AEAD + base64 + JSON serialization.
    let fast_params = Argon2idParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };
    let passphrase = SecretString::new("bench-passphrase".to_string().into());
    let plaintext = b"secret key material 32 bytes!!!";

    let wrapped = wrap_bytes_with_params(&passphrase, plaintext, fast_params).unwrap();

    c.bench_function("storage/argon2id_wrap_fast", |b| {
        b.iter(|| {
            wrap_bytes_with_params(black_box(&passphrase), black_box(plaintext), fast_params)
                .unwrap()
        })
    });

    c.bench_function("storage/argon2id_unwrap_fast", |b| {
        b.iter(|| unwrap_bytes(black_box(&passphrase), black_box(&wrapped)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_dh,
    bench_kem,
    bench_aead,
    bench_kdf,
    bench_tlv,
    bench_wire,
    bench_ratchet,
    bench_handshake,
    bench_sealed_sender,
    bench_session,
    bench_argon2id,
);
criterion_main!(benches);
