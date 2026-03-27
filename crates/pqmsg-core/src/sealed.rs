use crate::aead::{decrypt, encrypt_with_rng, CiphertextEnvelope};
use crate::dh::{diffie_hellman, generate_keypair, DhPublicKey, DhSecretKey};
use crate::kdf::hkdf_sha256_32;
use crate::tlv::{
    build_record_map, critical_type, decode_strict, encode, require_from_map, TlvRecord,
};
use crate::CoreError;
use rand_core::OsRng;
use zeroize::Zeroize;

const SEALED_VERSION: u16 = 1;
const SEALED_CERTIFIED_VERSION: u16 = 2;
const INFO_SEALED_KEY: &[u8] = b"pqmsg-sealed-sender-key-v1";
const INFO_SEALED_SENDER_HINT_KEY: &[u8] = b"pqmsg-sealed-sender-hint-key-v1";
const AD_TAG_VERSION: u16 = critical_type(0xA101);
const AD_TAG_SUITE_ID: u16 = critical_type(0xA102);
const AD_TAG_RECIPIENT_USER_ID: u16 = critical_type(0xA103);
const AD_TAG_SENDER_HINT_EPHEMERAL_PUB: u16 = critical_type(0xA104);
const OUTER_TAG_VERSION: u16 = critical_type(0xA201);
const OUTER_TAG_SUITE_ID: u16 = critical_type(0xA202);
const OUTER_TAG_RECIPIENT_USER_ID: u16 = critical_type(0xA203);
const OUTER_TAG_AEAD_NONCE: u16 = critical_type(0xA204);
const OUTER_TAG_CIPHERTEXT: u16 = critical_type(0xA205);
const OUTER_TAG_SENDER_HINT_EPHEMERAL_PUB: u16 = critical_type(0xA206);
const OUTER_TAG_SENDER_HINT_NONCE: u16 = critical_type(0xA207);
const OUTER_TAG_SENDER_HINT_CIPHERTEXT: u16 = critical_type(0xA208);
const INNER_TAG_SENDER_USER_ID: u16 = critical_type(0xA301);
const INNER_TAG_SENDER_DEVICE_ID: u16 = critical_type(0xA302);
const INNER_TAG_PAYLOAD: u16 = critical_type(0xA303);
const INNER_TAG_SENDER_CERT: u16 = critical_type(0xA304);
const MAX_ID_LEN: usize = 128;

/// Sender certificate validity duration: 24 hours in seconds.
pub const SENDER_CERT_VALIDITY_SECS: u64 = 24 * 60 * 60;
/// Clock skew tolerance for certificate expiration checks: 5 minutes.
pub const SENDER_CERT_CLOCK_SKEW_SECS: u64 = 5 * 60;

// Sender certificate TLV tags
const CERT_TAG_SENDER_USER_ID: u16 = critical_type(0xA401);
const CERT_TAG_SENDER_DEVICE_ID: u16 = critical_type(0xA402);
const CERT_TAG_SENDER_IDENTITY_PUB: u16 = critical_type(0xA403);
const CERT_TAG_EXPIRES_AT: u16 = critical_type(0xA404);
const CERT_TAG_SERVER_SIGNATURE: u16 = critical_type(0xA405);

/// A short-lived sender certificate issued by the server. The certificate
/// binds a sender's identity public key to their user ID and device ID.
/// Recipients verify the server's signature and expiration before accepting
/// sealed-sender messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderCertificate {
    pub sender_user_id: String,
    pub sender_device_id: String,
    /// Sender's X25519 identity public key (32 bytes).
    pub sender_identity_pub: [u8; 32],
    /// Certificate expiration as Unix timestamp (seconds since epoch).
    pub expires_at: u64,
    /// Ed25519 signature over the certificate body, created by the server.
    pub server_signature: Vec<u8>,
}

impl SenderCertificate {
    /// Encode the certificate to TLV bytes.
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        encode(&[
            TlvRecord {
                ty: CERT_TAG_SENDER_USER_ID,
                value: self.sender_user_id.as_bytes().to_vec(),
            },
            TlvRecord {
                ty: CERT_TAG_SENDER_DEVICE_ID,
                value: self.sender_device_id.as_bytes().to_vec(),
            },
            TlvRecord {
                ty: CERT_TAG_SENDER_IDENTITY_PUB,
                value: self.sender_identity_pub.to_vec(),
            },
            TlvRecord {
                ty: CERT_TAG_EXPIRES_AT,
                value: self.expires_at.to_be_bytes().to_vec(),
            },
            TlvRecord {
                ty: CERT_TAG_SERVER_SIGNATURE,
                value: self.server_signature.clone(),
            },
        ])
    }

    /// Decode a certificate from TLV bytes.
    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        let known_types = [
            CERT_TAG_SENDER_USER_ID,
            CERT_TAG_SENDER_DEVICE_ID,
            CERT_TAG_SENDER_IDENTITY_PUB,
            CERT_TAG_EXPIRES_AT,
            CERT_TAG_SERVER_SIGNATURE,
        ];
        let records = decode_strict(input, &known_types)?;
        let map = build_record_map(&records);
        let sender_user_id = decode_id(
            require_from_map(&map, CERT_TAG_SENDER_USER_ID, "cert.sender_user_id")?,
            "cert.sender_user_id",
        )?;
        let sender_device_id = decode_id(
            require_from_map(&map, CERT_TAG_SENDER_DEVICE_ID, "cert.sender_device_id")?,
            "cert.sender_device_id",
        )?;
        let sender_identity_pub = parse_32(
            require_from_map(
                &map,
                CERT_TAG_SENDER_IDENTITY_PUB,
                "cert.sender_identity_pub",
            )?,
            "cert.sender_identity_pub",
        )?;
        let expires_at = decode_u64(require_from_map(
            &map,
            CERT_TAG_EXPIRES_AT,
            "cert.expires_at",
        )?)?;
        let server_signature =
            require_from_map(&map, CERT_TAG_SERVER_SIGNATURE, "cert.server_signature")?.to_vec();
        Ok(Self {
            sender_user_id,
            sender_device_id,
            sender_identity_pub,
            expires_at,
            server_signature,
        })
    }

    /// The body bytes that the server signs. This is the TLV encoding of
    /// user_id, device_id, identity_pub, and expires_at (without the signature).
    pub fn signing_body(&self) -> Result<Vec<u8>, CoreError> {
        encode(&[
            TlvRecord {
                ty: CERT_TAG_SENDER_USER_ID,
                value: self.sender_user_id.as_bytes().to_vec(),
            },
            TlvRecord {
                ty: CERT_TAG_SENDER_DEVICE_ID,
                value: self.sender_device_id.as_bytes().to_vec(),
            },
            TlvRecord {
                ty: CERT_TAG_SENDER_IDENTITY_PUB,
                value: self.sender_identity_pub.to_vec(),
            },
            TlvRecord {
                ty: CERT_TAG_EXPIRES_AT,
                value: self.expires_at.to_be_bytes().to_vec(),
            },
        ])
    }
}

/// Validate a sender certificate against the server's public key and current time.
pub fn validate_sender_certificate(
    cert: &SenderCertificate,
    server_pub_key: &ed25519_dalek::VerifyingKey,
    now_unix_secs: u64,
) -> Result<(), CoreError> {
    // Check expiration with clock skew tolerance
    if now_unix_secs > cert.expires_at + SENDER_CERT_CLOCK_SKEW_SECS {
        return Err(CoreError::PolicyViolation("sender_cert.expired"));
    }
    // Verify server signature
    let body = cert.signing_body()?;
    let signature = ed25519_dalek::Signature::from_slice(&cert.server_signature)
        .map_err(|_| CoreError::SignatureVerificationFailed)?;
    use ed25519_dalek::Verifier;
    server_pub_key
        .verify(&body, &signature)
        .map_err(|_| CoreError::SignatureVerificationFailed)?;
    Ok(())
}

fn parse_32(value: &[u8], field: &'static str) -> Result<[u8; 32], CoreError> {
    value.try_into().map_err(|_| CoreError::InvalidLength {
        field,
        expected: 32,
        actual: value.len(),
    })
}

fn decode_u64(value: &[u8]) -> Result<u64, CoreError> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| CoreError::InvalidLength {
        field: "sealed.u64",
        expected: 8,
        actual: value.len(),
    })?;
    Ok(u64::from_be_bytes(bytes))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedEnvelope {
    pub version: u16,
    pub suite_id: u16,
    pub recipient_user_id: String,
    pub aead_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub sender_hint_ephemeral_pub: Option<[u8; 32]>,
    pub sender_hint_nonce: Option<[u8; 12]>,
    pub sender_hint_ciphertext: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedSealedMessage {
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub payload: Vec<u8>,
}

impl SealedEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, CoreError> {
        let mut records = vec![
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
        ];
        if let Some(ephemeral_pub) = self.sender_hint_ephemeral_pub {
            records.push(TlvRecord {
                ty: OUTER_TAG_SENDER_HINT_EPHEMERAL_PUB,
                value: ephemeral_pub.to_vec(),
            });
        }
        if let Some(nonce) = self.sender_hint_nonce {
            records.push(TlvRecord {
                ty: OUTER_TAG_SENDER_HINT_NONCE,
                value: nonce.to_vec(),
            });
        }
        if let Some(ciphertext) = &self.sender_hint_ciphertext {
            records.push(TlvRecord {
                ty: OUTER_TAG_SENDER_HINT_CIPHERTEXT,
                value: ciphertext.clone(),
            });
        }
        encode(&records)
    }

    pub fn decode(input: &[u8]) -> Result<Self, CoreError> {
        let known_types = [
            OUTER_TAG_VERSION,
            OUTER_TAG_SUITE_ID,
            OUTER_TAG_RECIPIENT_USER_ID,
            OUTER_TAG_AEAD_NONCE,
            OUTER_TAG_CIPHERTEXT,
            OUTER_TAG_SENDER_HINT_EPHEMERAL_PUB,
            OUTER_TAG_SENDER_HINT_NONCE,
            OUTER_TAG_SENDER_HINT_CIPHERTEXT,
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
        let sender_hint_ephemeral_pub = map
            .get(&OUTER_TAG_SENDER_HINT_EPHEMERAL_PUB)
            .map(|value| parse_32(value, "sealed.sender_hint_ephemeral_pub"))
            .transpose()?;
        let sender_hint_nonce = map
            .get(&OUTER_TAG_SENDER_HINT_NONCE)
            .map(|value| {
                (*value).try_into().map_err(|_| CoreError::InvalidLength {
                    field: "sealed.sender_hint_nonce",
                    expected: 12,
                    actual: value.len(),
                })
            })
            .transpose()?;
        let sender_hint_ciphertext = map
            .get(&OUTER_TAG_SENDER_HINT_CIPHERTEXT)
            .map(|value| value.to_vec());
        Ok(Self {
            version,
            suite_id,
            recipient_user_id,
            aead_nonce,
            ciphertext,
            sender_hint_ephemeral_pub,
            sender_hint_nonce,
            sender_hint_ciphertext,
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

fn derive_sealed_sender_hint_key(
    shared_secret: &[u8; 32],
    suite_id: u16,
) -> Result<[u8; 32], CoreError> {
    let mut info = Vec::with_capacity(INFO_SEALED_SENDER_HINT_KEY.len() + 2);
    info.extend_from_slice(INFO_SEALED_SENDER_HINT_KEY);
    info.extend_from_slice(&suite_id.to_be_bytes());
    hkdf_sha256_32(shared_secret, None, &info)
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
        sender_hint_ephemeral_pub: None,
        sender_hint_nonce: None,
        sender_hint_ciphertext: None,
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

#[cfg(test)]
fn seal_message_with_cert_v1(
    pairwise_key: &[u8; 32],
    suite_id: u16,
    recipient_user_id: &str,
    sender_user_id: &str,
    sender_device_id: &str,
    payload: &[u8],
    sender_cert: &SenderCertificate,
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

    let cert_bytes = sender_cert.encode()?;

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
        TlvRecord {
            ty: INNER_TAG_SENDER_CERT,
            value: cert_bytes,
        },
    ])?;
    let mut rng = OsRng;
    let envelope = encrypt_with_rng(pairwise_key, &inner, &ad, &mut rng)?;
    SealedEnvelope {
        version: SEALED_VERSION,
        suite_id,
        recipient_user_id: recipient_user_id.to_string(),
        aead_nonce: envelope.nonce,
        ciphertext: envelope.ciphertext,
        sender_hint_ephemeral_pub: None,
        sender_hint_nonce: None,
        sender_hint_ciphertext: None,
    }
    .encode()
}

/// Seal a message with an attached sender certificate. The certificate is
/// included as an additional TLV record inside the encrypted inner payload.
/// Certified envelopes also carry an encrypted sender-identity hint so the
/// recipient can open the transport without server-supplied sender metadata.
#[allow(clippy::too_many_arguments)]
pub fn seal_message_with_cert(
    sender_local_secret: &DhSecretKey,
    recipient_identity_pub: &DhPublicKey,
    suite_id: u16,
    recipient_user_id: &str,
    sender_user_id: &str,
    sender_device_id: &str,
    payload: &[u8],
    sender_cert: &SenderCertificate,
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

    let cert_bytes = sender_cert.encode()?;
    let pairwise_key =
        derive_pairwise_sealed_sender_key(sender_local_secret, recipient_identity_pub, suite_id)?;
    let ad = sealed_associated_data(SEALED_CERTIFIED_VERSION, suite_id, recipient_user_id)?;
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
        TlvRecord {
            ty: INNER_TAG_SENDER_CERT,
            value: cert_bytes,
        },
    ])?;
    let mut rng = OsRng;
    let envelope = encrypt_with_rng(&pairwise_key, &inner, &ad, &mut rng)?;
    let sender_hint_keypair = generate_keypair(&mut rng);
    let mut sender_hint_shared_secret =
        diffie_hellman(&sender_hint_keypair.secret, recipient_identity_pub);
    let sender_hint_key = derive_sealed_sender_hint_key(&sender_hint_shared_secret, suite_id)?;
    sender_hint_shared_secret.zeroize();
    let sender_hint_ad = sender_hint_associated_data(
        SEALED_CERTIFIED_VERSION,
        suite_id,
        recipient_user_id,
        &sender_hint_keypair.public.0,
    )?;
    let sender_hint_envelope = encrypt_with_rng(
        &sender_hint_key,
        &sender_cert.sender_identity_pub,
        &sender_hint_ad,
        &mut rng,
    )?;
    SealedEnvelope {
        version: SEALED_CERTIFIED_VERSION,
        suite_id,
        recipient_user_id: recipient_user_id.to_string(),
        aead_nonce: envelope.nonce,
        ciphertext: envelope.ciphertext,
        sender_hint_ephemeral_pub: Some(sender_hint_keypair.public.0),
        sender_hint_nonce: Some(sender_hint_envelope.nonce),
        sender_hint_ciphertext: Some(sender_hint_envelope.ciphertext),
    }
    .encode()
}

/// Opened sealed message that includes an optional sender certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedCertifiedSealedMessage {
    pub sender_user_id: String,
    pub sender_device_id: String,
    pub payload: Vec<u8>,
    pub sender_cert: Option<SenderCertificate>,
}

fn open_message_with_cert_inner(
    pairwise_key: &[u8; 32],
    envelope: &SealedEnvelope,
    server_pub_key: Option<&ed25519_dalek::VerifyingKey>,
    now_unix_secs: u64,
    expected_sender_identity_pub: Option<&[u8; 32]>,
) -> Result<OpenedCertifiedSealedMessage, CoreError> {
    let ad = sealed_associated_data(
        envelope.version,
        envelope.suite_id,
        &envelope.recipient_user_id,
    )?;
    let inner = decrypt(
        pairwise_key,
        &CiphertextEnvelope {
            nonce: envelope.aead_nonce,
            ciphertext: envelope.ciphertext.clone(),
            aad: ad,
        },
    )?;
    let known_types = [
        INNER_TAG_SENDER_USER_ID,
        INNER_TAG_SENDER_DEVICE_ID,
        INNER_TAG_PAYLOAD,
        INNER_TAG_SENDER_CERT,
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

    let sender_cert = if let Some(cert_bytes) = map.get(&INNER_TAG_SENDER_CERT) {
        let cert = SenderCertificate::decode(cert_bytes)?;
        if let Some(server_key) = server_pub_key {
            validate_sender_certificate(&cert, server_key, now_unix_secs)?;
        }
        if cert.sender_user_id != sender_user_id {
            return Err(CoreError::PolicyViolation("sender_cert.user_id_mismatch"));
        }
        if cert.sender_device_id != sender_device_id {
            return Err(CoreError::PolicyViolation("sender_cert.device_id_mismatch"));
        }
        if let Some(expected_sender_identity_pub) = expected_sender_identity_pub {
            if cert.sender_identity_pub != *expected_sender_identity_pub {
                return Err(CoreError::PolicyViolation(
                    "sender_cert.identity_pub_mismatch",
                ));
            }
        }
        Some(cert)
    } else {
        None
    };

    Ok(OpenedCertifiedSealedMessage {
        sender_user_id,
        sender_device_id,
        payload,
        sender_cert,
    })
}

/// Open a sealed message and validate the sender certificate if present.
///
/// If a certificate is found inside the payload and `server_pub_key` is
/// provided, the certificate is validated. If the certificate is expired or
/// the signature is invalid, an error is returned.
pub fn open_message_with_cert(
    recipient_local_secret: &DhSecretKey,
    envelope_bytes: &[u8],
    expected_suite_id: u16,
    expected_recipient_user_id: &str,
    server_pub_key: Option<&ed25519_dalek::VerifyingKey>,
    now_unix_secs: u64,
    legacy_sender_identity_pub: Option<&DhPublicKey>,
) -> Result<OpenedCertifiedSealedMessage, CoreError> {
    validate_id(
        "sealed.expected_recipient_user_id",
        expected_recipient_user_id,
    )?;
    let envelope = SealedEnvelope::decode(envelope_bytes)?;
    if envelope.version != SEALED_VERSION && envelope.version != SEALED_CERTIFIED_VERSION {
        return Err(CoreError::UnsupportedAlgorithm("sealed.version"));
    }
    if envelope.suite_id != expected_suite_id {
        return Err(CoreError::UnsupportedAlgorithm("sealed.suite_id"));
    }
    if envelope.recipient_user_id != expected_recipient_user_id {
        return Err(CoreError::PolicyViolation("sealed.recipient_mismatch"));
    }
    match envelope.version {
        SEALED_VERSION => {
            let sender_identity_pub = legacy_sender_identity_pub.ok_or(
                CoreError::PolicyViolation("sealed.legacy_sender_identity_missing"),
            )?;
            let pairwise_key = derive_pairwise_sealed_sender_key(
                recipient_local_secret,
                sender_identity_pub,
                envelope.suite_id,
            )?;
            open_message_with_cert_inner(
                &pairwise_key,
                &envelope,
                server_pub_key,
                now_unix_secs,
                Some(&sender_identity_pub.0),
            )
        }
        SEALED_CERTIFIED_VERSION => {
            let sender_hint_ephemeral_pub = DhPublicKey(envelope.sender_hint_ephemeral_pub.ok_or(
                CoreError::PolicyViolation("sealed.sender_hint_ephemeral_missing"),
            )?);
            let sender_hint_nonce =
                envelope
                    .sender_hint_nonce
                    .ok_or(CoreError::PolicyViolation(
                        "sealed.sender_hint_nonce_missing",
                    ))?;
            let sender_hint_ciphertext =
                envelope
                    .sender_hint_ciphertext
                    .clone()
                    .ok_or(CoreError::PolicyViolation(
                        "sealed.sender_hint_ciphertext_missing",
                    ))?;
            let mut sender_hint_shared_secret =
                diffie_hellman(recipient_local_secret, &sender_hint_ephemeral_pub);
            let sender_hint_key =
                derive_sealed_sender_hint_key(&sender_hint_shared_secret, envelope.suite_id)?;
            sender_hint_shared_secret.zeroize();
            let sender_hint_ad = sender_hint_associated_data(
                envelope.version,
                envelope.suite_id,
                &envelope.recipient_user_id,
                &sender_hint_ephemeral_pub.0,
            )?;
            let sender_identity_bytes = decrypt(
                &sender_hint_key,
                &CiphertextEnvelope {
                    nonce: sender_hint_nonce,
                    ciphertext: sender_hint_ciphertext,
                    aad: sender_hint_ad,
                },
            )?;
            let sender_identity_pub_bytes =
                parse_32(&sender_identity_bytes, "sealed.sender_identity_pub")?;
            let sender_identity_pub = DhPublicKey(sender_identity_pub_bytes);
            let pairwise_key = derive_pairwise_sealed_sender_key(
                recipient_local_secret,
                &sender_identity_pub,
                envelope.suite_id,
            )?;
            open_message_with_cert_inner(
                &pairwise_key,
                &envelope,
                server_pub_key,
                now_unix_secs,
                Some(&sender_identity_pub.0),
            )
        }
        _ => Err(CoreError::UnsupportedAlgorithm("sealed.version")),
    }
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

fn sender_hint_associated_data(
    version: u16,
    suite_id: u16,
    recipient_user_id: &str,
    ephemeral_pub: &[u8; 32],
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
        TlvRecord {
            ty: AD_TAG_SENDER_HINT_EPHEMERAL_PUB,
            value: ephemeral_pub.to_vec(),
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
    use super::*;
    use crate::dh::generate_keypair;
    use ed25519_dalek::{Signer, SigningKey};
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

    fn make_test_cert(
        server_signing_key: &SigningKey,
        sender_identity_pub: [u8; 32],
        expires_at: u64,
    ) -> SenderCertificate {
        let mut cert = SenderCertificate {
            sender_user_id: "alice".to_string(),
            sender_device_id: "alice-dev-1".to_string(),
            sender_identity_pub,
            expires_at,
            server_signature: vec![],
        };
        let body = cert.signing_body().expect("signing body");
        cert.server_signature = server_signing_key.sign(&body).to_bytes().to_vec();
        cert
    }

    #[test]
    fn sender_certificate_encode_decode_roundtrip() {
        let mut rng = OsRng;
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, [0xAA; 32], 1700000000);
        let encoded = cert.encode().expect("encode cert");
        let decoded = SenderCertificate::decode(&encoded).expect("decode cert");
        assert_eq!(cert, decoded);
    }

    #[test]
    fn sender_certificate_validates_with_correct_key() {
        let mut rng = OsRng;
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, [0xAA; 32], 1700000000);
        let now = 1700000000 - 3600; // 1 hour before expiry
        validate_sender_certificate(&cert, &server_key.verifying_key(), now)
            .expect("should validate");
    }

    #[test]
    fn sender_certificate_rejects_expired() {
        let mut rng = OsRng;
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, [0xAA; 32], 1700000000);
        // Well past expiration + clock skew
        let now = 1700000000 + SENDER_CERT_CLOCK_SKEW_SECS + 1;
        let result = validate_sender_certificate(&cert, &server_key.verifying_key(), now);
        assert!(result.is_err());
    }

    #[test]
    fn sender_certificate_allows_clock_skew() {
        let mut rng = OsRng;
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, [0xAA; 32], 1700000000);
        // Just within clock skew tolerance
        let now = 1700000000 + SENDER_CERT_CLOCK_SKEW_SECS;
        validate_sender_certificate(&cert, &server_key.verifying_key(), now)
            .expect("within clock skew tolerance");
    }

    #[test]
    fn sender_certificate_rejects_wrong_server_key() {
        let mut rng = OsRng;
        let server_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, [0xAA; 32], 1700000000);
        let result = validate_sender_certificate(&cert, &wrong_key.verifying_key(), 1700000000);
        assert!(result.is_err());
    }

    #[test]
    fn sealed_message_with_cert_roundtrip() {
        let mut rng = OsRng;
        let alice_dh = generate_keypair(&mut rng);
        let bob_dh = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, alice_dh.public.0, 1700000000);

        let encoded = seal_message_with_cert(
            &alice_dh.secret,
            &bob_dh.public,
            suite_id,
            "bob",
            "alice",
            "alice-dev-1",
            b"certified-payload",
            &cert,
        )
        .expect("seal with cert");

        let opened = open_message_with_cert(
            &bob_dh.secret,
            &encoded,
            suite_id,
            "bob",
            Some(&server_key.verifying_key()),
            1700000000 - 3600,
            None,
        )
        .expect("open with cert");

        assert_eq!(opened.sender_user_id, "alice");
        assert_eq!(opened.sender_device_id, "alice-dev-1");
        assert_eq!(opened.payload, b"certified-payload");
        assert!(opened.sender_cert.is_some());
        let returned_cert = opened.sender_cert.unwrap();
        assert_eq!(returned_cert.sender_identity_pub, alice_dh.public.0);
    }

    #[test]
    fn sealed_message_with_cert_rejects_expired_cert() {
        let mut rng = OsRng;
        let alice_dh = generate_keypair(&mut rng);
        let bob_dh = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, alice_dh.public.0, 1700000000);

        let encoded = seal_message_with_cert(
            &alice_dh.secret,
            &bob_dh.public,
            suite_id,
            "bob",
            "alice",
            "alice-dev-1",
            b"payload",
            &cert,
        )
        .expect("seal");

        // Open well past expiration
        let result = open_message_with_cert(
            &bob_dh.secret,
            &encoded,
            suite_id,
            "bob",
            Some(&server_key.verifying_key()),
            1700000000 + SENDER_CERT_CLOCK_SKEW_SECS + 1,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn open_without_cert_still_works() {
        let mut rng = OsRng;
        let alice_dh = generate_keypair(&mut rng);
        let bob_dh = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let key = derive_pairwise_sealed_sender_key(&alice_dh.secret, &bob_dh.public, suite_id)
            .expect("key");

        // Seal without cert
        let encoded = seal_message(
            &key,
            suite_id,
            "bob",
            "alice",
            "alice-dev-1",
            b"no-cert-payload",
        )
        .expect("seal");

        // Open with cert-aware function — should work, cert will be None
        let server_key = SigningKey::generate(&mut rng);
        let opened = open_message_with_cert_inner(
            &key,
            &SealedEnvelope::decode(&encoded).expect("decode"),
            Some(&server_key.verifying_key()),
            1700000000,
            None,
        )
        .expect("open");
        assert_eq!(opened.payload, b"no-cert-payload");
        assert!(opened.sender_cert.is_none());
    }

    #[test]
    fn certified_sealed_message_legacy_v1_roundtrip_with_sender_identity_hint() {
        let mut rng = OsRng;
        let alice_dh = generate_keypair(&mut rng);
        let bob_dh = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let key = derive_pairwise_sealed_sender_key(&alice_dh.secret, &bob_dh.public, suite_id)
            .expect("key");
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, alice_dh.public.0, 1700000000);
        let encoded = seal_message_with_cert_v1(
            &key,
            suite_id,
            "bob",
            "alice",
            "alice-dev-1",
            b"legacy-certified",
            &cert,
        )
        .expect("seal");
        let opened = open_message_with_cert(
            &bob_dh.secret,
            &encoded,
            suite_id,
            "bob",
            Some(&server_key.verifying_key()),
            1700000000,
            Some(&alice_dh.public),
        )
        .expect("open");
        assert_eq!(opened.payload, b"legacy-certified");
        assert_eq!(opened.sender_user_id, "alice");
    }

    #[test]
    fn certified_sealed_message_legacy_v1_requires_sender_identity_hint() {
        let mut rng = OsRng;
        let alice_dh = generate_keypair(&mut rng);
        let bob_dh = generate_keypair(&mut rng);
        let suite_id = 1u16;
        let key = derive_pairwise_sealed_sender_key(&alice_dh.secret, &bob_dh.public, suite_id)
            .expect("key");
        let server_key = SigningKey::generate(&mut rng);
        let cert = make_test_cert(&server_key, alice_dh.public.0, 1700000000);
        let encoded = seal_message_with_cert_v1(
            &key,
            suite_id,
            "bob",
            "alice",
            "alice-dev-1",
            b"legacy-certified",
            &cert,
        )
        .expect("seal");
        let result = open_message_with_cert(
            &bob_dh.secret,
            &encoded,
            suite_id,
            "bob",
            Some(&server_key.verifying_key()),
            1700000000,
            None,
        );
        assert!(result.is_err());
    }
}
