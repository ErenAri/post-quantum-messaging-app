#![forbid(unsafe_code)]

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pqmsg_core::alg::{AlgorithmSuite, KemAlgorithm};
use pqmsg_core::dh::{DhKeyPair, DhPublicKey};
use pqmsg_core::handshake::{
    alice_initiate, bob_receive, pq_signed_prekey_signature_message,
    signed_prekey_signature_message, InitialMessage, SignatureVerifier,
};
use pqmsg_core::kem::{KemEncapsulation, KemProvider};
use pqmsg_core::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
use pqmsg_core::session::{SessionRole, SessionSnapshot, SessionState};
use pqmsg_core::CoreError;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const MAX_ONE_TIME_PREKEYS: u32 = 256;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, uniffi::Enum)]
pub enum Suite {
    MlKem768,
    Kyber768,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OneTimeKeyRecord {
    key_id: String,
    public_b64: String,
    secret_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserKeysFile {
    version: u16,
    user_id: String,
    device_id: String,
    suite: Suite,
    identity_x25519_pub_b64: String,
    identity_x25519_secret_b64: String,
    identity_sig_pub_b64: String,
    identity_sig_secret_b64: String,
    signed_prekey_x25519_pub_b64: String,
    signed_prekey_x25519_secret_b64: String,
    pq_signed_prekey_pub_b64: String,
    pq_signed_prekey_secret_b64: String,
    one_time_prekeys_x25519: Vec<OneTimeKeyRecord>,
    one_time_prekeys_mlkem768: Vec<OneTimeKeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionFile {
    version: u16,
    user_id: String,
    peer_user_id: String,
    suite: Suite,
    snapshot: SessionSnapshot,
}

#[derive(Debug, Clone, Deserialize)]
struct BundleResponse {
    user_id: String,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    signed_prekey_x25519_pub: String,
    sig_over_spk: String,
    pq_signed_prekey_pub_mlkem768: String,
    sig_over_pqspk: String,
    one_time_prekey_x25519: Option<String>,
    one_time_prekey_mlkem768: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct UserProfile {
    pub user_id: String,
    pub device_id: String,
    pub suite: Suite,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RegisterPayload {
    pub user_id: String,
    pub identity_x25519_pub: String,
    pub identity_sig_pub: String,
    pub device_id: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct PublishPrekeysPayload {
    pub signed_prekey_x25519_pub: String,
    pub sig_over_spk: String,
    pub pq_signed_prekey_pub_mlkem768: String,
    pub sig_over_pqspk: String,
    pub one_time_prekeys_x25519: Vec<String>,
    pub one_time_prekeys_mlkem768: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Record)]
pub struct ServerBundle {
    pub user_id: String,
    pub identity_x25519_pub: String,
    pub identity_sig_pub: String,
    pub signed_prekey_x25519_pub: String,
    pub sig_over_spk: String,
    pub pq_signed_prekey_pub_mlkem768: String,
    pub sig_over_pqspk: String,
    pub one_time_prekey_x25519: Option<String>,
    pub one_time_prekey_mlkem768: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SendResult {
    pub message_bytes_base64: String,
    pub session_json: String,
    pub used_handshake: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DecryptResult {
    pub plaintext_utf8: String,
    pub plaintext_base64: String,
    pub session_json: String,
    pub used_handshake: bool,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PqmsgAndroidError {
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },
    #[error("operation failed: {reason}")]
    OperationFailed { reason: String },
}

struct DemoSignatureVerifier;
struct DemoKem;

impl SignatureVerifier for DemoSignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        let expected = demo_signature(public_key, message);
        if expected == signature {
            Ok(())
        } else {
            Err(CoreError::SignatureVerificationFailed)
        }
    }
}

impl KemProvider for DemoKem {
    fn encapsulate(&self, recipient_public_key: &[u8]) -> Result<KemEncapsulation, CoreError> {
        if recipient_public_key.len() != 32 {
            return Err(CoreError::InvalidLength {
                field: "demo_kem.public_key",
                expected: 32,
                actual: recipient_public_key.len(),
            });
        }
        let ciphertext = hash3(b"ct", recipient_public_key, b"");
        let shared_secret = hash3(b"ss", recipient_public_key, &ciphertext);
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
                field: "demo_kem.secret_key",
                expected: 32,
                actual: recipient_secret_key.len(),
            });
        }
        Ok(Zeroizing::new(hash3(
            b"ss",
            recipient_secret_key,
            ciphertext,
        )))
    }
}

#[uniffi::export]
pub fn generate_identity_keys(
    user_id: String,
    device_id: String,
    suite: Suite,
    one_time_count: u32,
) -> Result<String, PqmsgAndroidError> {
    if user_id.trim().is_empty() {
        return Err(invalid_input("user_id must not be empty"));
    }
    if device_id.trim().is_empty() {
        return Err(invalid_input("device_id must not be empty"));
    }
    if one_time_count == 0 || one_time_count > MAX_ONE_TIME_PREKEYS {
        return Err(invalid_input(format!(
            "one_time_count must be in 1..={MAX_ONE_TIME_PREKEYS}"
        )));
    }

    let mut rng = OsRng;
    let identity = IdentityKeyPair::generate(format!("{user_id}-ik"), &mut rng);
    let signed_prekey = OneTimePreKey::generate(format!("{user_id}-spk"), &mut rng);

    let mut identity_sig = [0u8; 32];
    rng.fill_bytes(&mut identity_sig);

    let mut pq_signed_prekey = [0u8; 32];
    rng.fill_bytes(&mut pq_signed_prekey);

    let mut one_time_x25519 = Vec::with_capacity(one_time_count as usize);
    let mut one_time_mlkem = Vec::with_capacity(one_time_count as usize);

    for idx in 0..one_time_count {
        let key = OneTimePreKey::generate(format!("{user_id}-otk-x-{idx}"), &mut rng);
        one_time_x25519.push(OneTimeKeyRecord {
            key_id: key.key_id,
            public_b64: B64.encode(key.public_key.0),
            secret_b64: B64.encode(key.secret_key.as_slice()),
        });

        let mut pq_key = [0u8; 32];
        rng.fill_bytes(&mut pq_key);
        one_time_mlkem.push(OneTimeKeyRecord {
            key_id: format!("{user_id}-otk-pq-{idx}"),
            public_b64: B64.encode(pq_key),
            secret_b64: B64.encode(pq_key),
        });
    }

    let keys = UserKeysFile {
        version: 1,
        user_id,
        device_id,
        suite,
        identity_x25519_pub_b64: B64.encode(identity.public_key.0),
        identity_x25519_secret_b64: B64.encode(identity.secret_key.as_slice()),
        identity_sig_pub_b64: B64.encode(identity_sig),
        identity_sig_secret_b64: B64.encode(identity_sig),
        signed_prekey_x25519_pub_b64: B64.encode(signed_prekey.public_key.0),
        signed_prekey_x25519_secret_b64: B64.encode(signed_prekey.secret_key.as_slice()),
        pq_signed_prekey_pub_b64: B64.encode(pq_signed_prekey),
        pq_signed_prekey_secret_b64: B64.encode(pq_signed_prekey),
        one_time_prekeys_x25519: one_time_x25519,
        one_time_prekeys_mlkem768: one_time_mlkem,
    };

    serde_json::to_string_pretty(&keys).map_err(Into::into)
}

#[uniffi::export]
pub fn load_user_profile(keys_json: String) -> Result<UserProfile, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    Ok(UserProfile {
        user_id: keys.user_id,
        device_id: keys.device_id,
        suite: keys.suite,
    })
}

#[uniffi::export]
pub fn build_register_payload(keys_json: String) -> Result<RegisterPayload, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    Ok(RegisterPayload {
        user_id: keys.user_id,
        identity_x25519_pub: keys.identity_x25519_pub_b64,
        identity_sig_pub: keys.identity_sig_pub_b64,
        device_id: keys.device_id,
    })
}

#[uniffi::export]
pub fn build_publish_prekeys_payload(
    keys_json: String,
) -> Result<PublishPrekeysPayload, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    let spk_pub = decode_b64_32(
        "signed_prekey_x25519_pub_b64",
        &keys.signed_prekey_x25519_pub_b64,
    )?;
    let pq_spk_pub = decode_b64("pq_signed_prekey_pub_b64", &keys.pq_signed_prekey_pub_b64)?;
    let sig_pub = decode_b64("identity_sig_pub_b64", &keys.identity_sig_pub_b64)?;

    let spk_msg = signed_prekey_signature_message(1, &DhPublicKey(spk_pub))?;
    let pq_msg = pq_signed_prekey_signature_message(1, &pq_spk_pub)?;

    Ok(PublishPrekeysPayload {
        signed_prekey_x25519_pub: keys.signed_prekey_x25519_pub_b64,
        sig_over_spk: B64.encode(demo_signature(&sig_pub, &spk_msg)),
        pq_signed_prekey_pub_mlkem768: keys.pq_signed_prekey_pub_b64,
        sig_over_pqspk: B64.encode(demo_signature(&sig_pub, &pq_msg)),
        one_time_prekeys_x25519: keys
            .one_time_prekeys_x25519
            .into_iter()
            .map(|item| item.public_b64)
            .collect(),
        one_time_prekeys_mlkem768: keys
            .one_time_prekeys_mlkem768
            .into_iter()
            .map(|item| item.public_b64)
            .collect(),
    })
}

#[uniffi::export]
pub fn parse_bundle_json(bundle_json: String) -> Result<ServerBundle, PqmsgAndroidError> {
    let bundle: BundleResponse = serde_json::from_str(&bundle_json)?;
    Ok(ServerBundle {
        user_id: bundle.user_id,
        identity_x25519_pub: bundle.identity_x25519_pub,
        identity_sig_pub: bundle.identity_sig_pub,
        signed_prekey_x25519_pub: bundle.signed_prekey_x25519_pub,
        sig_over_spk: bundle.sig_over_spk,
        pq_signed_prekey_pub_mlkem768: bundle.pq_signed_prekey_pub_mlkem768,
        sig_over_pqspk: bundle.sig_over_pqspk,
        one_time_prekey_x25519: bundle.one_time_prekey_x25519,
        one_time_prekey_mlkem768: bundle.one_time_prekey_mlkem768,
    })
}

#[uniffi::export]
pub fn initiate_session_and_encrypt(
    keys_json: String,
    from_user_id: String,
    peer_user_id: String,
    peer_bundle: ServerBundle,
    plaintext_utf8: String,
    suite_override: Option<Suite>,
) -> Result<SendResult, PqmsgAndroidError> {
    let mut keys = read_keys_file(&keys_json)?;
    if keys.user_id != from_user_id {
        return Err(invalid_input(format!(
            "from_user_id '{}' does not match keys user '{}'",
            from_user_id, keys.user_id
        )));
    }
    if let Some(suite) = suite_override {
        keys.suite = suite;
    }

    let prekey_bundle = bundle_to_core(&peer_bundle, keys.suite)?;
    let identity = to_identity_keypair(&keys)?;
    let kem = DemoKem;
    let verifier = DemoSignatureVerifier;
    let initiator = alice_initiate(
        &mut OsRng,
        &verifier,
        &kem,
        &from_user_id,
        &peer_user_id,
        &identity,
        &prekey_bundle,
        plaintext_utf8.as_bytes(),
    )?;

    let initial_encoded = initiator.initial_message.encode()?;
    let local_dh = DhKeyPair {
        public: identity.public_key,
        secret: identity.require_secret_key()?,
    };
    let session = SessionState::from_handshake_with_suite(
        SessionRole::Initiator,
        *initiator.session_key.as_bytes(),
        local_dh,
        prekey_bundle.signed_prekey,
        prekey_bundle.suite.suite_id()?,
        512,
    )?;
    let session_file = SessionFile {
        version: 1,
        user_id: from_user_id,
        peer_user_id,
        suite: keys.suite,
        snapshot: session.snapshot(),
    };

    Ok(SendResult {
        message_bytes_base64: B64.encode(initial_encoded),
        session_json: serde_json::to_string_pretty(&session_file)?,
        used_handshake: true,
    })
}

#[uniffi::export]
pub fn normalize_session_json(session_json: String) -> Result<String, PqmsgAndroidError> {
    let session = read_session_file(&session_json)?;
    serde_json::to_string_pretty(&session).map_err(Into::into)
}

#[uniffi::export]
pub fn encrypt_with_session(
    session_json: String,
    sender_user_id: String,
    peer_user_id: String,
    plaintext_utf8: String,
) -> Result<SendResult, PqmsgAndroidError> {
    let mut session_file = read_session_file(&session_json)?;
    if session_file.user_id != sender_user_id {
        return Err(invalid_input(format!(
            "sender_user_id '{}' does not match session user '{}'",
            sender_user_id, session_file.user_id
        )));
    }
    if session_file.peer_user_id != peer_user_id {
        return Err(invalid_input(format!(
            "peer_user_id '{}' does not match session peer '{}'",
            peer_user_id, session_file.peer_user_id
        )));
    }

    let mut session = SessionState::from_snapshot(session_file.snapshot.clone());
    let ad = make_ad(&sender_user_id, &peer_user_id);
    let wire = session.encrypt(plaintext_utf8.as_bytes(), &ad)?;
    session_file.snapshot = session.snapshot();

    Ok(SendResult {
        message_bytes_base64: B64.encode(wire),
        session_json: serde_json::to_string_pretty(&session_file)?,
        used_handshake: false,
    })
}

#[uniffi::export]
pub fn decrypt_message(
    keys_json: String,
    recipient_user_id: String,
    sender_user_id: String,
    message_bytes_base64: String,
    existing_session_json: Option<String>,
) -> Result<DecryptResult, PqmsgAndroidError> {
    let keys = read_keys_file(&keys_json)?;
    if keys.user_id != recipient_user_id {
        return Err(invalid_input(format!(
            "recipient_user_id '{}' does not match keys user '{}'",
            recipient_user_id, keys.user_id
        )));
    }

    let message_bytes = decode_b64("message_bytes_base64", &message_bytes_base64)?;
    if let Ok(initial) = InitialMessage::decode(&message_bytes) {
        if initial.sender_id != sender_user_id {
            return Err(invalid_input(format!(
                "sender_user_id '{}' does not match handshake sender '{}'",
                sender_user_id, initial.sender_id
            )));
        }
        if initial.recipient_id != recipient_user_id {
            return Err(invalid_input(format!(
                "recipient_user_id '{}' does not match handshake recipient '{}'",
                recipient_user_id, initial.recipient_id
            )));
        }

        let kem = DemoKem;
        let identity = to_identity_keypair(&keys)?;
        let signed_prekey = to_signed_prekey(&keys)?;
        let pq_signed_prekey = to_pq_signed_prekey(&keys)?;
        let responder = bob_receive(&kem, &identity, &signed_prekey, &pq_signed_prekey, &initial)?;
        let local_dh = DhKeyPair {
            public: signed_prekey.public_key,
            secret: signed_prekey.require_secret_key()?,
        };
        let session = SessionState::from_handshake_with_suite(
            SessionRole::Responder,
            *responder.session_key.as_bytes(),
            local_dh,
            initial.ik_a_pub,
            initial.suite_id,
            512,
        )?;
        let session_file = SessionFile {
            version: 1,
            user_id: recipient_user_id,
            peer_user_id: sender_user_id,
            suite: keys.suite,
            snapshot: session.snapshot(),
        };
        let plaintext_base64 = B64.encode(&responder.plaintext);
        let plaintext_utf8 = String::from_utf8_lossy(&responder.plaintext).to_string();

        return Ok(DecryptResult {
            plaintext_utf8,
            plaintext_base64,
            session_json: serde_json::to_string_pretty(&session_file)?,
            used_handshake: true,
        });
    }

    let Some(session_json) = existing_session_json else {
        return Err(invalid_input(
            "existing_session_json is required for non-handshake messages",
        ));
    };
    let mut session_file = read_session_file(&session_json)?;
    if session_file.user_id != recipient_user_id {
        return Err(invalid_input(format!(
            "recipient_user_id '{}' does not match session user '{}'",
            recipient_user_id, session_file.user_id
        )));
    }
    if session_file.peer_user_id != sender_user_id {
        return Err(invalid_input(format!(
            "sender_user_id '{}' does not match session peer '{}'",
            sender_user_id, session_file.peer_user_id
        )));
    }

    let mut session = SessionState::from_snapshot(session_file.snapshot.clone());
    let ad = make_ad(&sender_user_id, &recipient_user_id);
    let plaintext = session.decrypt(&message_bytes, &ad)?;
    session_file.snapshot = session.snapshot();
    let plaintext_base64 = B64.encode(&plaintext);
    let plaintext_utf8 = String::from_utf8_lossy(&plaintext).to_string();

    Ok(DecryptResult {
        plaintext_utf8,
        plaintext_base64,
        session_json: serde_json::to_string_pretty(&session_file)?,
        used_handshake: false,
    })
}

fn read_keys_file(keys_json: &str) -> Result<UserKeysFile, PqmsgAndroidError> {
    serde_json::from_str(keys_json).map_err(Into::into)
}

fn read_session_file(session_json: &str) -> Result<SessionFile, PqmsgAndroidError> {
    serde_json::from_str(session_json).map_err(Into::into)
}

fn to_identity_keypair(keys: &UserKeysFile) -> Result<IdentityKeyPair, PqmsgAndroidError> {
    Ok(IdentityKeyPair {
        key_id: format!("{}-ik", keys.user_id),
        public_key: DhPublicKey(decode_b64_32(
            "identity_x25519_pub_b64",
            &keys.identity_x25519_pub_b64,
        )?),
        secret_key: SecretBytes::from(decode_b64(
            "identity_x25519_secret_b64",
            &keys.identity_x25519_secret_b64,
        )?),
    })
}

fn to_signed_prekey(keys: &UserKeysFile) -> Result<OneTimePreKey, PqmsgAndroidError> {
    Ok(OneTimePreKey {
        key_id: format!("{}-spk", keys.user_id),
        public_key: DhPublicKey(decode_b64_32(
            "signed_prekey_x25519_pub_b64",
            &keys.signed_prekey_x25519_pub_b64,
        )?),
        secret_key: SecretBytes::from(decode_b64(
            "signed_prekey_x25519_secret_b64",
            &keys.signed_prekey_x25519_secret_b64,
        )?),
    })
}

fn to_pq_signed_prekey(keys: &UserKeysFile) -> Result<KEMPreKey, PqmsgAndroidError> {
    Ok(KEMPreKey {
        key_id: format!("{}-pqspk", keys.user_id),
        public_key: decode_b64("pq_signed_prekey_pub_b64", &keys.pq_signed_prekey_pub_b64)?,
        secret_key: SecretBytes::from(decode_b64(
            "pq_signed_prekey_secret_b64",
            &keys.pq_signed_prekey_secret_b64,
        )?),
    })
}

fn bundle_to_core(bundle: &ServerBundle, suite: Suite) -> Result<PreKeyBundle, PqmsgAndroidError> {
    let mut core_suite = AlgorithmSuite::default();
    core_suite.kem = match suite {
        Suite::MlKem768 => KemAlgorithm::MlKem768,
        Suite::Kyber768 => KemAlgorithm::Kyber768Alias,
    };

    let mut out = PreKeyBundle::new(
        bundle.user_id.clone(),
        DhPublicKey(decode_b64_32(
            "identity_x25519_pub",
            &bundle.identity_x25519_pub,
        )?),
        DhPublicKey(decode_b64_32(
            "signed_prekey_x25519_pub",
            &bundle.signed_prekey_x25519_pub,
        )?),
        decode_b64(
            "pq_signed_prekey_pub_mlkem768",
            &bundle.pq_signed_prekey_pub_mlkem768,
        )?,
        decode_b64("sig_over_spk", &bundle.sig_over_spk)?,
        decode_b64("sig_over_pqspk", &bundle.sig_over_pqspk)?,
        decode_b64("identity_sig_pub", &bundle.identity_sig_pub)?,
    );
    out.suite = core_suite;
    out.one_time_prekey = bundle
        .one_time_prekey_x25519
        .as_ref()
        .map(|value| decode_b64_32("one_time_prekey_x25519", value))
        .transpose()?
        .map(DhPublicKey);
    out.one_time_pq_prekey = bundle
        .one_time_prekey_mlkem768
        .as_ref()
        .map(|value| decode_b64("one_time_prekey_mlkem768", value))
        .transpose()?;
    Ok(out)
}

fn make_ad(sender: &str, recipient: &str) -> Vec<u8> {
    format!("pqmsg-android-ad:v1:{sender}:{recipient}").into_bytes()
}

fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>, PqmsgAndroidError> {
    B64.decode(value.as_bytes())
        .map_err(|_| invalid_input(format!("invalid base64 for field '{field}'")))
}

fn decode_b64_32(field: &'static str, value: &str) -> Result<[u8; 32], PqmsgAndroidError> {
    let bytes = decode_b64(field, value)?;
    if bytes.len() != 32 {
        return Err(invalid_input(format!(
            "field '{field}' must decode to 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn invalid_input(message: impl Into<String>) -> PqmsgAndroidError {
    PqmsgAndroidError::InvalidInput {
        reason: message.into(),
    }
}

fn operation_failed(message: impl Into<String>) -> PqmsgAndroidError {
    PqmsgAndroidError::OperationFailed {
        reason: message.into(),
    }
}

fn demo_signature(pub_or_secret: &[u8], message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(pub_or_secret);
    hasher.update(message);
    hasher.finalize().to_vec()
}

fn hash3(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.update(c);
    hasher.finalize().to_vec()
}

impl From<CoreError> for PqmsgAndroidError {
    fn from(value: CoreError) -> Self {
        operation_failed(value.to_string())
    }
}

impl From<serde_json::Error> for PqmsgAndroidError {
    fn from(value: serde_json::Error) -> Self {
        invalid_input(value.to_string())
    }
}

impl From<base64::DecodeError> for PqmsgAndroidError {
    fn from(value: base64::DecodeError) -> Self {
        invalid_input(value.to_string())
    }
}

uniffi::setup_scaffolding!();
