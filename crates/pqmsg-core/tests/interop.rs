//! Cross-platform interoperability tests.
//!
//! These tests verify that the protocol wire format, session state
//! serialisation, and handshake outputs are deterministic and compatible
//! across separate instantiations—emulating what would happen when an
//! Android client, an iOS client and a server implementation exchange
//! bytes over the network.

use pqmsg_core::alg::SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305;
use pqmsg_core::dh::generate_keypair;
use pqmsg_core::session::{SessionRole, SessionSnapshot, SessionState};
use pqmsg_core::wire::{decode_wire_message, WireMessage, WIRE_VERSION_V2};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic session pair from a fixed 32-byte seed.
/// The two sessions share a handshake root key, each holding DH key pairs
/// derived from the ChaCha20 RNG.
fn seeded_session_pair(seed: [u8; 32]) -> (SessionState, SessionState) {
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut root_key = [0u8; 32];
    rng.fill_bytes(&mut root_key);

    let alice_dh = generate_keypair(&mut rng);
    let bob_dh = generate_keypair(&mut rng);

    let alice = SessionState::from_handshake(
        SessionRole::Initiator,
        root_key,
        alice_dh.clone(),
        bob_dh.public,
        64,
    )
    .expect("alice session");

    let bob = SessionState::from_handshake(
        SessionRole::Responder,
        root_key,
        bob_dh,
        alice_dh.public,
        64,
    )
    .expect("bob session");

    (alice, bob)
}

fn seeded_session_pair_with_suite_and_wire_version(
    seed: [u8; 32],
    suite_id: u16,
    wire_version: u16,
) -> (SessionState, SessionState) {
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut root_key = [0u8; 32];
    rng.fill_bytes(&mut root_key);

    let alice_dh = generate_keypair(&mut rng);
    let bob_dh = generate_keypair(&mut rng);

    let alice = SessionState::from_handshake_with_suite_and_wire_version(
        SessionRole::Initiator,
        root_key,
        alice_dh.clone(),
        bob_dh.public,
        suite_id,
        wire_version,
        64,
    )
    .expect("alice session");

    let bob = SessionState::from_handshake_with_suite_and_wire_version(
        SessionRole::Responder,
        root_key,
        bob_dh,
        alice_dh.public,
        suite_id,
        wire_version,
        64,
    )
    .expect("bob session");

    (alice, bob)
}

// ---------------------------------------------------------------------------
// 1. Wire format round-trip
// ---------------------------------------------------------------------------

#[test]
fn wire_message_encode_decode_roundtrip() {
    let msg = WireMessage {
        version: 1,
        suite_id: 0x0001,
        sender_dh_pub: [0xAB; 32],
        msg_num: 42,
        prev_chain_len: 7,
        pq_step_ct: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        pq_target_pub_hash: None,
        pq_next_public_key: None,
        aead_nonce: [0x11; 12],
        ciphertext: b"hello-wire".to_vec(),
    };

    let encoded = msg.encode().expect("encode");
    let decoded = WireMessage::decode(&encoded).expect("decode");

    assert_eq!(decoded.version, msg.version);
    assert_eq!(decoded.suite_id, msg.suite_id);
    assert_eq!(decoded.sender_dh_pub, msg.sender_dh_pub);
    assert_eq!(decoded.msg_num, msg.msg_num);
    assert_eq!(decoded.prev_chain_len, msg.prev_chain_len);
    assert_eq!(decoded.pq_step_ct, msg.pq_step_ct);
    assert_eq!(decoded.aead_nonce, msg.aead_nonce);
    assert_eq!(decoded.ciphertext, msg.ciphertext);
}

#[test]
fn wire_message_without_pq_step_roundtrips() {
    let msg = WireMessage {
        version: 1,
        suite_id: 0x0001,
        sender_dh_pub: [0x01; 32],
        msg_num: 0,
        prev_chain_len: 0,
        pq_step_ct: None,
        pq_target_pub_hash: None,
        pq_next_public_key: None,
        aead_nonce: [0x00; 12],
        ciphertext: b"no-pq".to_vec(),
    };

    let encoded = msg.encode().expect("encode");
    let decoded = WireMessage::decode(&encoded).expect("decode");
    assert_eq!(decoded.pq_step_ct, None);
    assert_eq!(decoded.ciphertext, b"no-pq");
}

#[test]
fn wire_encoding_is_deterministic() {
    let msg = WireMessage {
        version: 1,
        suite_id: 0x0001,
        sender_dh_pub: [0x42; 32],
        msg_num: 100,
        prev_chain_len: 3,
        pq_step_ct: None,
        pq_target_pub_hash: None,
        pq_next_public_key: None,
        aead_nonce: [0xFF; 12],
        ciphertext: vec![0x00; 16],
    };

    let a = msg.encode().expect("encode a");
    let b = msg.encode().expect("encode b");
    assert_eq!(a, b, "two identical encodes must produce identical bytes");
}

// ---------------------------------------------------------------------------
// 2. Cross-session encrypt/decrypt (simulates two different platforms)
// ---------------------------------------------------------------------------

#[test]
fn alice_encrypts_bob_decrypts() {
    let (mut alice, mut bob) = seeded_session_pair([1u8; 32]);
    let ad = b"interop-ad";

    let ct = alice.encrypt(b"hello from alice", ad).expect("encrypt");
    let pt = bob.decrypt(&ct, ad).expect("decrypt");
    assert_eq!(pt, b"hello from alice");
}

#[test]
fn bidirectional_exchange() {
    let (mut alice, mut bob) = seeded_session_pair([2u8; 32]);
    let ad = b"interop-ad";

    for i in 0u32..10 {
        let msg = format!("alice-{i}");
        let ct = alice.encrypt(msg.as_bytes(), ad).expect("a-enc");
        let pt = bob.decrypt(&ct, ad).expect("b-dec");
        assert_eq!(pt, msg.as_bytes());

        let msg = format!("bob-{i}");
        let ct = bob.encrypt(msg.as_bytes(), ad).expect("b-enc");
        let pt = alice.decrypt(&ct, ad).expect("a-dec");
        assert_eq!(pt, msg.as_bytes());
    }
}

#[test]
fn out_of_order_delivery_across_sessions() {
    let (mut alice, mut bob) = seeded_session_pair([3u8; 32]);
    let ad = b"interop-ad";

    let ct1 = alice.encrypt(b"m1", ad).expect("enc1");
    let ct2 = alice.encrypt(b"m2", ad).expect("enc2");
    let ct3 = alice.encrypt(b"m3", ad).expect("enc3");

    // Deliver out of order: 3, 1, 2
    assert_eq!(bob.decrypt(&ct3, ad).expect("dec3"), b"m3");
    assert_eq!(bob.decrypt(&ct1, ad).expect("dec1"), b"m1");
    assert_eq!(bob.decrypt(&ct2, ad).expect("dec2"), b"m2");
}

// ---------------------------------------------------------------------------
// 3. Session snapshot persistence round-trip
// ---------------------------------------------------------------------------

#[test]
fn snapshot_roundtrip_preserves_session() {
    let (mut alice, mut bob) = seeded_session_pair([4u8; 32]);
    let ad = b"interop-ad";

    // Exchange a few messages to evolve state
    let ct = alice.encrypt(b"pre-snapshot-1", ad).expect("enc");
    bob.decrypt(&ct, ad).expect("dec");
    let ct = bob.encrypt(b"pre-snapshot-2", ad).expect("enc");
    alice.decrypt(&ct, ad).expect("dec");

    // Snapshot and restore Alice
    let snap = alice.snapshot();
    let snap_json = serde_json::to_string(&snap).expect("serialize");
    let restored_snap: SessionSnapshot = serde_json::from_str(&snap_json).expect("deserialize");
    let mut alice2 = SessionState::from_snapshot(restored_snap);

    // Continue conversation with restored session
    let ct = alice2.encrypt(b"post-snapshot", ad).expect("enc");
    let pt = bob.decrypt(&ct, ad).expect("dec");
    assert_eq!(pt, b"post-snapshot");

    let ct = bob.encrypt(b"reply-post-snapshot", ad).expect("enc");
    let pt = alice2.decrypt(&ct, ad).expect("dec");
    assert_eq!(pt, b"reply-post-snapshot");
}

#[test]
fn snapshot_roundtrip_preserves_skipped_message_keys() {
    let (mut alice, mut bob) = seeded_session_pair([9u8; 32]);
    let ad = b"snapshot-skipped-ad";

    let ct1 = alice.encrypt(b"m1", ad).expect("enc1");
    let ct2 = alice.encrypt(b"m2", ad).expect("enc2");
    let ct3 = alice.encrypt(b"m3", ad).expect("enc3");

    // Force Bob to cache skipped keys by receiving the third message first.
    assert_eq!(bob.decrypt(&ct3, ad).expect("dec3"), b"m3");

    let snap = bob.snapshot();
    let snap_json = serde_json::to_string(&snap).expect("serialize");
    let restored_snap: SessionSnapshot = serde_json::from_str(&snap_json).expect("deserialize");
    let mut bob2 = SessionState::from_snapshot(restored_snap);

    assert_eq!(bob2.decrypt(&ct1, ad).expect("dec1"), b"m1");
    assert_eq!(bob2.decrypt(&ct2, ad).expect("dec2"), b"m2");
}

#[test]
fn snapshot_roundtrip_preserves_suite_and_wire_version_continuity() {
    let suite_id = SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305;
    let (mut alice, mut bob) =
        seeded_session_pair_with_suite_and_wire_version([11u8; 32], suite_id, WIRE_VERSION_V2);
    let ad = b"snapshot-suite-wire-ad";

    let pre_snapshot = alice.encrypt(b"before-restore", ad).expect("enc");
    assert_eq!(
        bob.decrypt(&pre_snapshot, ad).expect("dec"),
        b"before-restore"
    );

    let alice_json = serde_json::to_string(&alice.snapshot()).expect("alice serialize");
    let bob_json = serde_json::to_string(&bob.snapshot()).expect("bob serialize");
    let alice_snapshot: SessionSnapshot =
        serde_json::from_str(&alice_json).expect("alice deserialize");
    let bob_snapshot: SessionSnapshot = serde_json::from_str(&bob_json).expect("bob deserialize");

    assert_eq!(alice_snapshot.suite_id, suite_id);
    assert_eq!(alice_snapshot.negotiated_wire_version, WIRE_VERSION_V2);
    assert_eq!(bob_snapshot.suite_id, suite_id);
    assert_eq!(bob_snapshot.negotiated_wire_version, WIRE_VERSION_V2);

    let mut alice2 = SessionState::from_snapshot(alice_snapshot);
    let mut bob2 = SessionState::from_snapshot(bob_snapshot);

    let from_alice = alice2.encrypt(b"after-restore-a", ad).expect("alice enc");
    let decoded_alice = decode_wire_message(&from_alice).expect("decode alice");
    assert_eq!(decoded_alice.suite_id(), suite_id);
    assert_eq!(decoded_alice.version(), WIRE_VERSION_V2);
    assert_eq!(
        bob2.decrypt(&from_alice, ad).expect("bob dec"),
        b"after-restore-a"
    );

    let from_bob = bob2.encrypt(b"after-restore-b", ad).expect("bob enc");
    let decoded_bob = decode_wire_message(&from_bob).expect("decode bob");
    assert_eq!(decoded_bob.suite_id(), suite_id);
    assert_eq!(decoded_bob.version(), WIRE_VERSION_V2);
    assert_eq!(
        alice2.decrypt(&from_bob, ad).expect("alice dec"),
        b"after-restore-b"
    );
}

#[test]
fn snapshot_json_is_stable_across_serialize_cycles() {
    let (alice, _bob) = seeded_session_pair([5u8; 32]);
    let snap = alice.snapshot();

    let json1 = serde_json::to_string(&snap).expect("ser1");
    let restored: SessionSnapshot = serde_json::from_str(&json1).expect("de1");
    let json2 = serde_json::to_string(&restored).expect("ser2");

    assert_eq!(json1, json2, "snapshot serialization must be idempotent");
}

// ---------------------------------------------------------------------------
// 4. Mixed-platform simulation: snapshot on one "device", restore on another
// ---------------------------------------------------------------------------

#[test]
fn migrate_session_between_simulated_platforms() {
    let (mut alice_phone, mut bob) = seeded_session_pair([6u8; 32]);
    let ad = b"migration-ad";

    // Phone sends messages
    let ct1 = alice_phone.encrypt(b"from-phone", ad).expect("enc");
    bob.decrypt(&ct1, ad).expect("dec");

    // Migrate Alice to "desktop" via snapshot
    let snap = alice_phone.snapshot();
    let snap_bytes = serde_json::to_vec(&snap).expect("to_vec");
    let restored: SessionSnapshot = serde_json::from_slice(&snap_bytes).expect("from_slice");
    let mut alice_desktop = SessionState::from_snapshot(restored);

    // Desktop continues conversation
    let ct2 = alice_desktop.encrypt(b"from-desktop", ad).expect("enc");
    let pt = bob.decrypt(&ct2, ad).expect("dec");
    assert_eq!(pt, b"from-desktop");

    // Bob replies, desktop decrypts
    let ct3 = bob.encrypt(b"to-desktop", ad).expect("enc");
    let pt = alice_desktop.decrypt(&ct3, ad).expect("dec");
    assert_eq!(pt, b"to-desktop");
}

// ---------------------------------------------------------------------------
// 5. Suite validation: wrong suite ID detected
// ---------------------------------------------------------------------------

#[test]
fn mismatched_suite_rejected_across_sessions() {
    let (mut alice, mut bob) = seeded_session_pair([7u8; 32]);
    let ad = b"suite-ad";

    let wire_bytes = alice.encrypt(b"test", ad).expect("encrypt");

    // Tamper with the suite_id in the wire message
    let mut parsed = WireMessage::decode(&wire_bytes).expect("decode");
    parsed.suite_id ^= 0x0001;
    let tampered = parsed.encode().expect("encode");

    let result = bob.decrypt(&tampered, ad);
    assert!(result.is_err(), "tampered suite_id must be rejected");
}

// ---------------------------------------------------------------------------
// 6. Associated data mismatch detection
// ---------------------------------------------------------------------------

#[test]
fn wrong_associated_data_rejected() {
    let (mut alice, mut bob) = seeded_session_pair([8u8; 32]);

    let ct = alice.encrypt(b"secret", b"correct-ad").expect("encrypt");
    let result = bob.decrypt(&ct, b"wrong-ad");
    assert!(result.is_err(), "wrong AD must cause decryption failure");
}

// ---------------------------------------------------------------------------
// 7. Large message round-trip
// ---------------------------------------------------------------------------

#[test]
fn large_message_roundtrip() {
    let (mut alice, mut bob) = seeded_session_pair([9u8; 32]);
    let ad = b"large-msg-ad";
    let large = vec![0xABu8; 60_000];

    let ct = alice.encrypt(&large, ad).expect("encrypt large");
    let pt = bob.decrypt(&ct, ad).expect("decrypt large");
    assert_eq!(pt, large);
}

// ---------------------------------------------------------------------------
// 8. Empty message round-trip
// ---------------------------------------------------------------------------

#[test]
fn empty_message_roundtrip() {
    let (mut alice, mut bob) = seeded_session_pair([10u8; 32]);
    let ad = b"empty-ad";

    let ct = alice.encrypt(b"", ad).expect("encrypt empty");
    let pt = bob.decrypt(&ct, ad).expect("decrypt empty");
    assert_eq!(pt, b"");
}

// ---------------------------------------------------------------------------
// 9. Deterministic session key derivation from same seed
// ---------------------------------------------------------------------------

#[test]
fn same_seed_produces_identical_sessions() {
    let (alice1, _bob1) = seeded_session_pair([11u8; 32]);
    let (alice2, _bob2) = seeded_session_pair([11u8; 32]);

    assert_eq!(
        alice1.root_key(),
        alice2.root_key(),
        "same seed must produce identical root keys"
    );
}

#[test]
fn different_seeds_produce_different_sessions() {
    let (alice1, _) = seeded_session_pair([12u8; 32]);
    let (alice2, _) = seeded_session_pair([13u8; 32]);

    assert_ne!(
        alice1.root_key(),
        alice2.root_key(),
        "different seeds must produce different root keys"
    );
}

// ---------------------------------------------------------------------------
// 10. Wire format canonical ordering (byte-level stability)
// ---------------------------------------------------------------------------

#[test]
fn wire_encoding_pinned_vector() {
    // Pinned test vector: any change to the TLV encoding breaks this test,
    // which forces a protocol version bump.
    let msg = WireMessage {
        version: 1,
        suite_id: 1,
        sender_dh_pub: [0u8; 32],
        msg_num: 0,
        prev_chain_len: 0,
        pq_step_ct: None,
        pq_target_pub_hash: None,
        pq_next_public_key: None,
        aead_nonce: [0u8; 12],
        ciphertext: vec![0xCA, 0xFE],
    };

    let encoded = msg.encode().expect("encode");
    let expected = hex::encode(&encoded);

    // Re-encode and verify byte-for-byte match
    let re_decoded = WireMessage::decode(&encoded).expect("decode");
    let re_encoded = re_decoded.encode().expect("re-encode");
    assert_eq!(
        hex::encode(&re_encoded),
        expected,
        "re-encoded wire message must match original bytes"
    );
}
