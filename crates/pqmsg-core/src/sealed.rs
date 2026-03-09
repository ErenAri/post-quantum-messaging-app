use crate::aead::{decrypt, encrypt_with_rng, CiphertextEnvelope};
use crate::dh::{diffie_hellman, DhPublicKey, DhSecretKey};
use crate::kdf::hkdf_sha256_32;
use crate::tlv::{
    build_record_map, critical_type, decode_strict, encode, require_from_map, TlvRecord,
};
use crate::CoreError;
use rand_core::OsRng;
use zeroize::Zeroize;

const SEALED_VERSION: u16 = 1;
const INFO_SEALED_KEY: &[u8] = b"pqmsg-sealed-sender-key-v1";
const AD_TAG_VERSION: u16 = critical_type(0xA101);
const AD_TAG_SUITE_ID: u16 = critical_type(0xA102);
const AD_TAG_RECIPIENT_USER_ID: u16 = critical_type(0xA103);
const OUTER_TAG_VERSION: u16 = critical_type(0xA201);
const OUTER_TAG_SUITE_ID: u16 = critical_type(0xA202);
const OUTER_TAG_RECIPIENT_USER_ID: u16 = critical_type(0xA203);
const OUTER_TAG_AEAD_NONCE: u16 = critical_type(0xA204);
const OUTER_TAG_CIPHERTEXT: u16 = critical_type(0xA205);
const INNER_TAG_SENDER_USER_ID: u16 = critical_type(0xA301);
const INNER_TAG_SENDER_DEVICE_ID: u16 = critical_type(0xA302);
const INNER_TAG_PAYLOAD: u16 = critical_type(0xA303);
const MAX_ID_LEN: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedEnvelope {
    pub version: u16,
    pub suite_id: u16,
    pub recipient_user_id: String,
    pub aead_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedSealedMessage {
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub payload: Vec<u8>,
}

impl SealedEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        encode(&[
            TlvRecord {
                ty: OUTER_TAG_VERSION,
                value: self.version.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: OUTER_TAG_SUITE_ID,
                value: self.suite_id.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: OUTER_TAG_RECIPIENT_USER_ID,
                value: self.recipient_user_id.as_bytes().to_vec(),
            },
            TlvRecord {
                ty: OUTER_TAG_AEAD_NONCE,
                value: self.aead_nonce.to_vec(),
            },
            TlvRecord {
                ty: OUTER_TAG_CIPHERTEXT,
                value: self.ciphertext.clone(),
            },
        ])
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        let known_types = [
            OUTER_TAG_VERSION,
            OUTER_TAG_SUITE_ID,
            OUTER_TAG_RECIPIENT_USER_ID,
            OUTER_TAG_AEAD_NONCE,
            OUTER_TAG_CIPHERTEXT,
        ];
        let records = decode_strict(input, &known_types)?;
        let map = build_record_map(&records);
        let version = decode_u16(require_from_map(&map, OUTER_TAG_VERSION, "sealed.version")?)?;
        let suite_id = decode_u16(require_from_map(
            &map,
            OUTER_TAG_SUITE_ID,
            "sealed.suite_id",
        )?)?;
        let recipient_user_id = decode_id(
            require_from_map(
                &map,
                OUTER_TAG_RECIPIENT_USER_ID,
                "sealed.recipient_user_id",
            )?,
            "sealed.recipient_user_id",
        )?;
        let nonce_bytes = require_from_map(&map, OUTER_TAG_AEAD_NONCE, "sealed.aead_nonce")?;
        let aead_nonce: [u8; 12] =
            nonce_bytes
                .try_into()
                .map_err(|_| CoreError::InvalidLength {
                    field: "sealed.aead_nonce",
                    expected: 12,
                    actual: nonce_bytes.len(),
                })?;
        let ciphertext =
            require_from_map(&map, OUTER_TAG_CIPHERTEXT, "sealed.ciphertext")?.to_vec();
        if ciphertext.is_empty() {
            return Err(CoreError::InvalidLength {
                field: "sealed.ciphertext",
                expected: 1,
                actual: 0,
            });
        }
        Ok(Self {
            version,
            suite_id,
            recipient_user_id,
            aead_nonce,
            ciphertext,
        })
    }
}

pub fn derive_sealed_sender_key(
    shared_secret: &[u8; 32],
    suite_id: u16,
) -> Result<[u8; 32], CoreError> {
    let mut info = Vec::with_capacity(INFO_SEALED_KEY.len() + 2);
    info.extend_from_slice(INFO_SEALED_KEY);
    info.extend_from_slice(&suite_id.to_be_bytes());
    hkdf_sha256_32(shared_secret, None, &info)
}

pub fn derive_pairwise_sealed_sender_key(
    local_secret: &DhSecretKey,
    remote_public: &DhPublicKey,
    suite_id: u16,
) -> Result<[u8; 32], CoreError> {
    let mut shared_secret = diffie_hellman(local_secret, remote_public);
    let key = derive_sealed_sender_key(&shared_secret, suite_id);
    shared_secret.zeroize();
    key
}

pub fn seal_message(
    key: &[u8; 32],
    suite_id: u16,
    recipient_user_id: &str,
    sender_user_id: &str,
    sender_device_id: &str,
    payload: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if payload.is_empty() {
        return Err(CoreError::InvalidLength {
            field: "sealed.payload",
            expected: 1,
            actual: 0,
        });
    }
    validate_id("sealed.recipient_user_id", recipient_user_id)?;
    validate_id("sealed.sender_user_id", sender_user_id)?;
    validate_id("sealed.sender_device_id", sender_device_id)?;

    let ad = sealed_associated_data(SEALED_VERSION, suite_id, recipient_user_id)?;
    let inner = encode(&[
        TlvRecord {
            ty: INNER_TAG_SENDER_USER_ID,
            value: sender_user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: INNER_TAG_SENDER_DEVICE_ID,
            value: sender_device_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: INNER_TAG_PAYLOAD,
            value: payload.to_vec(),
        },
    ])?;
    let mut rng = OsRng;
    let envelope = encrypt_with_rng(key, &inner, &ad, &mut rng)?;
    SealedEnvelope {
        version: SEALED_VERSION,
        suite_id,
        recipient_user_id: recipient_user_id.to_string(),
        aead_nonce: envelope.nonce,
        ciphertext: envelope.ciphertext,
    }
    .encode()
}

pub fn open_message(
    key: &[u8; 32],
    envelope_bytes: &[u8],
    expected_suite_id: u16,
    expected_recipient_user_id: &str,
) -> Result<OpenedSealedMessage, CoreError> {
    validate_id(
        "sealed.expected_recipient_user_id",
        expected_recipient_user_id,
    )?;
    let envelope = SealedEnvelope::decode(envelope_bytes)?;
    if envelope.version != SEALED_VERSION {
        return Err(CoreError::UnsupportedAlgorithm("sealed.version"));
    }
    if envelope.suite_id != expected_suite_id {
        return Err(CoreError::UnsupportedAlgorithm("sealed.suite_id"));
    }
    if envelope.recipient_user_id != expected_recipient_user_id {
        return Err(CoreError::PolicyViolation("sealed.recipient_mismatch"));
    }

    let ad = sealed_associated_data(
        envelope.version,
        envelope.suite_id,
        &envelope.recipient_user_id,
    )?;
    let inner = decrypt(
        key,
        &CiphertextEnvelope {
            nonce: envelope.aead_nonce,
            ciphertext: envelope.ciphertext,
            aad: ad,
        },
    )?;
    let known_types = [
        INNER_TAG_SENDER_USER_ID,
        INNER_TAG_SENDER_DEVICE_ID,
        INNER_TAG_PAYLOAD,
    ];
    let records = decode_strict(&inner, &known_types)?;
    let map = build_record_map(&records);
    let sender_user_id = decode_id(
        require_from_map(&map, INNER_TAG_SENDER_USER_ID, "sealed.sender_user_id")?,
        "sealed.sender_user_id",
    )?;
    let sender_device_id = decode_id(
        require_from_map(&map, INNER_TAG_SENDER_DEVICE_ID, "sealed.sender_device_id")?,
        "sealed.sender_device_id",
    )?;
    let payload = require_from_map(&map, INNER_TAG_PAYLOAD, "sealed.payload")?.to_vec();
    if payload.is_empty() {
        return Err(CoreError::InvalidLength {
            field: "sealed.payload",
            expected: 1,
            actual: 0,
        });
    }
    Ok(OpenedSealedMessage {
        sender_user_id,
        sender_device_id,
        payload,
    })
}

fn sealed_associated_data(
    version: u16,
    suite_id: u16,
    recipient_user_id: &str,
) -> Result<Vec<u8>, CoreError> {
    encode(&[
        TlvRecord {
            ty: AD_TAG_VERSION,
            value: version.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_SUITE_ID,
            value: suite_id.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AD_TAG_RECIPIENT_USER_ID,
            value: recipient_user_id.as_bytes().to_vec(),
        },
    ])
}

fn decode_u16(value: &[u8]) -> Result<u16, CoreError> {
    let bytes: [u8; 2] = value.try_into().map_err(|_| CoreError::InvalidLength {
        field: "sealed.u16",
        expected: 2,
        actual: value.len(),
    })?;
    Ok(u16::from_be_bytes(bytes))
}

fn decode_id(value: &[u8], field: &'static str) -> Result<String, CoreError> {
    let text = std::str::from_utf8(value).map_err(|_| CoreError::InvalidUtf8(field))?;
    validate_id(field, text)?;
    Ok(text.to_string())
}

fn validate_id(field: &'static str, value: &str) -> Result<(), CoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ID_LEN {
        return Err(CoreError::InvalidLength {
            field,
            expected: MAX_ID_LEN,
            actual: trimmed.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{derive_pairwise_sealed_sender_key, open_message, seal_message};
    use crate::dh::generate_keypair;
    use rand::rngs::OsRng;

    #[test]
    fn sealed_message_roundtrip() {
        let mut rng = OsRng;
        let alice = generate_keypair(&mut rng);
        let bob = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let alice_key = derive_pairwise_sealed_sender_key(&alice.secret, &bob.public, suite_id)
            .expect("alice key");
        let bob_key = derive_pairwise_sealed_sender_key(&bob.secret, &alice.public, suite_id)
            .expect("bob key");
        assert_eq!(alice_key, bob_key);

        let encoded = seal_message(
            &alice_key,
            suite_id,
            "bob",
            "alice",
            "alice-dev-1",
            b"ciphertext-placeholder",
        )
        .expect("seal");
        let opened = open_message(&bob_key, &encoded, suite_id, "bob").expect("open");
        assert_eq!(opened.sender_user_id, "alice");
        assert_eq!(opened.sender_device_id, "alice-dev-1");
        assert_eq!(opened.payload, b"ciphertext-placeholder");
    }

    #[test]
    fn sealed_message_rejects_tamper() {
        let mut rng = OsRng;
        let alice = generate_keypair(&mut rng);
        let bob = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let key =
            derive_pairwise_sealed_sender_key(&alice.secret, &bob.public, suite_id).expect("key");
        let mut encoded =
            seal_message(&key, suite_id, "bob", "alice", "alice-dev-1", b"payload").expect("seal");
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        let result = open_message(&key, &encoded, suite_id, "bob");
        assert!(result.is_err());
    }

    #[test]
    fn sealed_message_rejects_wrong_recipient() {
        let mut rng = OsRng;
        let alice = generate_keypair(&mut rng);
        let bob = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let key =
            derive_pairwise_sealed_sender_key(&alice.secret, &bob.public, suite_id).expect("key");
        let encoded =
            seal_message(&key, suite_id, "bob", "alice", "alice-dev-1", b"payload").expect("seal");
        let result = open_message(&key, &encoded, suite_id, "carol");
        assert!(result.is_err());
    }
}
