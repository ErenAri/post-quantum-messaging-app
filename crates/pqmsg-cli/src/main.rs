use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqmsg_core::ad::conversation_associated_data;
use pqmsg_core::alg::{
    enforce_runtime_security_profile, AlgorithmSuite, KemAlgorithm, SecurityProfile,
    SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use pqmsg_core::dh::{DhKeyPair, DhPublicKey};
use pqmsg_core::handshake::{
    alice_initiate, bob_receive, pq_signed_prekey_signature_message,
    signed_prekey_signature_message, InitialMessage, SignatureVerifier,
};
use pqmsg_core::kem::MlKem768;
use pqmsg_core::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
use pqmsg_core::session::{SessionRole, SessionSnapshot, SessionState};
use pqmsg_core::storage::{
    unwrap_bytes as unwrap_wrapped_bytes, wrap_bytes as wrap_wrapped_bytes, WrappedSecret,
};
use pqmsg_core::tlv::{critical_type, encode, TlvRecord};
use pqmsg_core::CoreError;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use reqwest::Client;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_STATE_DIR: &str = "./state";
const DEFAULT_KEYS_DIR: &str = "./devkeys";
const DEFAULT_ONE_TIME_PREKEYS: usize = 16;
const MAX_ONE_TIME_PREKEYS: usize = 256;
const AUTH_HEADER_USER: &str = "x-pqmsg-auth-user";
const AUTH_HEADER_DEVICE: &str = "x-pqmsg-auth-device";
const AUTH_HEADER_TIMESTAMP: &str = "x-pqmsg-auth-timestamp";
const AUTH_HEADER_NONCE: &str = "x-pqmsg-auth-nonce";
const AUTH_HEADER_SIGNATURE: &str = "x-pqmsg-auth-signature";
const AUTH_TAG_ENDPOINT: u16 = critical_type(0x3201);
const AUTH_TAG_USER_ID: u16 = critical_type(0x3202);
const AUTH_TAG_DEVICE_ID: u16 = critical_type(0x3203);
const AUTH_TAG_TIMESTAMP: u16 = critical_type(0x3204);
const AUTH_TAG_NONCE: u16 = critical_type(0x3205);
const AUTH_TAG_RECIPIENT_ID: u16 = critical_type(0x3206);
const AUTH_TAG_SINCE: u16 = critical_type(0x3207);
const AUTH_TAG_MESSAGE_BLOB: u16 = critical_type(0x3208);
const AUTH_TAG_PREKEY_SPK_HASH: u16 = critical_type(0x3209);
const AUTH_TAG_PREKEY_PQSPK_HASH: u16 = critical_type(0x320A);
#[allow(dead_code)]
const AUTH_TAG_ROTATE_NEW_X25519_HASH: u16 = critical_type(0x320B);
#[allow(dead_code)]
const AUTH_TAG_ROTATE_NEW_SIG_HASH: u16 = critical_type(0x320C);
#[allow(dead_code)]
const AUTH_TAG_ROTATE_CHALLENGE_ID: u16 = critical_type(0x320D);
#[allow(dead_code)]
const AUTH_TAG_ROTATE_SIG_CURRENT_HASH: u16 = critical_type(0x320E);
#[allow(dead_code)]
const AUTH_TAG_ROTATE_SIG_NEW_HASH: u16 = critical_type(0x320F);
const LEGACY_STORAGE_SEALED_KIND: &str = "pqmsg-cli-sealed";
const LEGACY_STORAGE_SEALED_VERSION: u16 = 1;
const LEGACY_STORAGE_SALT_BYTES: usize = 16;
const LEGACY_STORAGE_NONCE_BYTES: usize = 12;
const LEGACY_STORAGE_AAD: &[u8] = b"pqmsg-cli-storage-v1";
const ENV_STATE_PASSPHRASE: &str = "PQMSG_STATE_PASSPHRASE";
const REPLAY_GUARD_VERSION: u16 = 1;
const REPLAY_HASH_TTL_SECONDS: i64 = 86_400;
const REPLAY_HASH_MAX_ENTRIES_PER_PEER: usize = 512;
const PREKEY_REPLENISH_TARGET: usize = DEFAULT_ONE_TIME_PREKEYS;

static STORAGE_POLICY: OnceLock<StoragePolicy> = OnceLock::new();

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
enum SuiteFlag {
    #[value(name = "ml-kem-768")]
    MlKem768,
    #[value(name = "kyber768")]
    Kyber768,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum SecurityProfileFlag {
    #[value(name = "research")]
    Research,
    #[value(name = "high-assurance")]
    HighAssurance,
    #[value(name = "nss-aligned")]
    NssAligned,
}

#[derive(Debug, Parser)]
#[command(name = "pqmsg-cli")]
struct Cli {
    #[arg(long, global = true, default_value = "http://localhost:3000")]
    server: String,
    #[arg(long, global = true, default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
    #[arg(long, global = true, value_enum, default_value = "high-assurance")]
    security_profile: SecurityProfileFlag,
    #[arg(long, global = true)]
    state_passphrase: Option<String>,
    #[arg(long, global = true, default_value_t = false)]
    allow_plaintext_state: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Keygen {
        #[arg(long)]
        user: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, value_enum, default_value = "ml-kem-768")]
        suite: SuiteFlag,
        #[arg(long, default_value_t = DEFAULT_ONE_TIME_PREKEYS)]
        one_time_count: usize,
        #[arg(long)]
        device_id: Option<String>,
    },
    Register {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
    },
    PublishPrekeys {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long, value_enum)]
        suite: Option<SuiteFlag>,
    },
    BackupKeys {
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        backup_passphrase: String,
    },
    RestoreKeys {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        backup_passphrase: String,
    },
    Send {
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        text: String,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long, value_enum)]
        suite: Option<SuiteFlag>,
        #[arg(long, default_value_t = false)]
        accept_key_change: bool,
    },
    Poll {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
    },
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
    suite: SuiteFlag,
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
    suite: SuiteFlag,
    snapshot: SessionSnapshot,
    passphrase_kdf_hint: Option<String>,
}

#[derive(Debug, Clone)]
struct StoragePolicy {
    passphrase: Option<String>,
    allow_plaintext: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacySealedFile {
    kind: String,
    version: u16,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InboxCursor {
    since_message_id: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SeenMessageHash {
    hash_hex: String,
    expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PeerReplayGuard {
    last_message_id: i64,
    seen_hashes: Vec<SeenMessageHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReplayGuardFile {
    version: u16,
    user_id: String,
    peers: HashMap<String, PeerReplayGuard>,
}

#[derive(Debug, Deserialize)]
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
    remaining_one_time_prekeys_x25519: Option<usize>,
    remaining_one_time_prekeys_mlkem768: Option<usize>,
    low_one_time_prekeys: Option<bool>,
    minimum_recommended_one_time_prekeys: Option<usize>,
    last_resort_prekey_only: Option<bool>,
    identity_key_version: Option<u32>,
    identity_fingerprint_sha256: Option<String>,
    bundle_generated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrekeysStatusResponse {
    user_id: String,
    device_id: String,
    remaining_one_time_prekeys_x25519: usize,
    remaining_one_time_prekeys_mlkem768: usize,
    low_one_time_prekeys: bool,
    minimum_recommended_one_time_prekeys: usize,
    checked_at: String,
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    user_id: String,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    device_id: String,
}

#[derive(Debug, Serialize)]
struct PublishPrekeysRequest {
    signed_prekey_x25519_pub: String,
    sig_over_spk: String,
    pq_signed_prekey_pub_mlkem768: String,
    sig_over_pqspk: String,
    one_time_prekeys_x25519: Vec<String>,
    one_time_prekeys_mlkem768: Vec<String>,
}

#[derive(Debug, Serialize)]
struct RelayRequest {
    sender_user_id: String,
    device_id: String,
    message_bytes_base64: String,
}

#[derive(Debug, Deserialize)]
struct RelayResponse {
    message_id: i64,
    received_at: String,
}

#[derive(Debug, Deserialize)]
struct InboxResponse {
    messages: Vec<InboxMessage>,
}

#[derive(Debug, Deserialize)]
struct InboxMessage {
    message_id: i64,
    sender_user_id: String,
    message_bytes_base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityPinEntry {
    identity_fingerprint_sha256: String,
    identity_key_version: u32,
    identity_sig_pub: String,
    observed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityPinsFile {
    version: u16,
    user_id: String,
    peers: HashMap<String, IdentityPinEntry>,
}

#[derive(Clone, Copy)]
struct SendOptions {
    security_profile: SecurityProfile,
    accept_key_change: bool,
}

struct Ed25519SignatureVerifier;

impl SignatureVerifier for Ed25519SignatureVerifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CoreError> {
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| CoreError::InvalidLength {
                field: "signature.public_key",
                expected: 32,
                actual: public_key.len(),
            })?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| CoreError::InvalidLength {
            field: "signature.signature",
            expected: 64,
            actual: signature.len(),
        })?;
        let verifier = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CoreError::SignatureVerificationFailed)?;
        let signature = Signature::from_bytes(&signature);
        verifier
            .verify(message, &signature)
            .map_err(|_| CoreError::SignatureVerificationFailed)
    }
}

fn suite_to_kem_algorithm(suite: SuiteFlag) -> KemAlgorithm {
    match suite {
        SuiteFlag::MlKem768 => KemAlgorithm::MlKem768,
        SuiteFlag::Kyber768 => KemAlgorithm::Kyber768Alias,
    }
}

fn suite_to_suite_id(suite: SuiteFlag) -> u16 {
    match suite {
        SuiteFlag::MlKem768 => SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
        SuiteFlag::Kyber768 => SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    }
}

fn security_profile_from_flag(flag: SecurityProfileFlag) -> SecurityProfile {
    match flag {
        SecurityProfileFlag::Research => SecurityProfile::Research,
        SecurityProfileFlag::HighAssurance => SecurityProfile::HighAssurance,
        SecurityProfileFlag::NssAligned => SecurityProfile::NssAligned,
    }
}

fn suite_from_suite_id(suite_id: u16) -> Result<SuiteFlag> {
    match suite_id {
        SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok(SuiteFlag::MlKem768),
        SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305 => Ok(SuiteFlag::Kyber768),
        _ => Err(anyhow!("unsupported suite_id '{}'", suite_id)),
    }
}

fn build_kem_for_suite(suite: SuiteFlag) -> Result<MlKem768> {
    MlKem768::new(suite_to_kem_algorithm(suite))
        .map_err(|err| anyhow!("failed to initialize KEM for suite '{suite:?}': {err}"))
}

fn decode_signing_key_b64(field: &'static str, value: &str) -> Result<SigningKey> {
    let bytes = decode_b64(field, value)?;
    let actual_len = bytes.len();
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow!(
            "field '{}' must decode to 32 bytes (got {})",
            field,
            actual_len
        )
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> SigningKey {
    SigningKey::generate(rng)
}

fn build_signature_payload(signing_key: &SigningKey, message: &[u8]) -> String {
    B64.encode(signing_key.sign(message).to_bytes())
}

fn auth_signing_key_for_user(keys: &UserKeysFile) -> Result<SigningKey> {
    let signing_key =
        decode_signing_key_b64("identity_sig_secret_b64", &keys.identity_sig_secret_b64)?;
    Ok(signing_key)
}

fn print_runtime_crypto_profile(
    security_profile: SecurityProfile,
    suite_id: Option<u16>,
) -> Result<()> {
    let profile = enforce_runtime_security_profile(security_profile, suite_id)?;
    println!(
        "active_profile: {} protocol_v{} suite_id={} kem={:?} dh={:?} kdf={:?} aead={:?} pq_oqs={}",
        security_profile.as_str(),
        profile.protocol_version,
        profile.suite_id,
        profile.kem,
        profile.dh,
        profile.kdf,
        profile.aead,
        profile.pq_oqs_enabled
    );
    Ok(())
}

fn validate_server_url_for_profile(security_profile: SecurityProfile, server: &str) -> Result<()> {
    let url = reqwest::Url::parse(server)
        .with_context(|| format!("invalid --server URL '{}'", server))?;
    if security_profile.requires_tls() && url.scheme() != "https" {
        return Err(anyhow!(
            "security profile '{}' requires HTTPS server URL, got '{}'",
            security_profile.as_str(),
            server
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let security_profile = security_profile_from_flag(cli.security_profile);
    let state_passphrase = cli
        .state_passphrase
        .clone()
        .or_else(|| env::var(ENV_STATE_PASSPHRASE).ok())
        .filter(|value| !value.trim().is_empty());
    let allow_plaintext_state =
        cli.allow_plaintext_state || matches!(security_profile, SecurityProfile::Research);
    let _ = STORAGE_POLICY.set(StoragePolicy {
        passphrase: state_passphrase,
        allow_plaintext: allow_plaintext_state,
    });
    let client = Client::new();
    print_runtime_crypto_profile(security_profile, None)?;

    match cli.command {
        Commands::Keygen {
            user,
            out,
            suite,
            one_time_count,
            device_id,
        } => {
            security_profile.enforce_suite_id(suite_to_suite_id(suite))?;
            let keys = generate_user_keys(
                &user,
                device_id.unwrap_or_else(|| format!("{user}-device-1")),
                suite,
                one_time_count,
            )?;
            write_json_file(&out, &keys)?;
            println!("wrote keys: {}", out.display());
        }
        Commands::Register { user, keys } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            security_profile.enforce_suite_id(suite_to_suite_id(keys_file.suite))?;
            validate_server_url_for_profile(security_profile, &cli.server)?;
            register_user(&client, &cli.server, &keys_file).await?;
        }
        Commands::PublishPrekeys { user, keys, suite } => {
            let mut keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            if let Some(override_suite) = suite {
                keys_file.suite = override_suite;
            }
            security_profile.enforce_suite_id(suite_to_suite_id(keys_file.suite))?;
            validate_server_url_for_profile(security_profile, &cli.server)?;
            publish_prekeys(&client, &cli.server, &keys_file).await?;
        }
        Commands::BackupKeys {
            keys,
            out,
            backup_passphrase,
        } => {
            backup_keys_file(&keys, &out, &backup_passphrase)?;
            println!("wrote encrypted key backup: {}", out.display());
        }
        Commands::RestoreKeys {
            input,
            out,
            backup_passphrase,
        } => {
            let keys = restore_keys_file(&input, &backup_passphrase)?;
            write_json_file(&out, &keys)?;
            println!("restored keys for '{}': {}", keys.user_id, out.display());
        }
        Commands::Send {
            from,
            to,
            text,
            keys,
            suite,
            accept_key_change,
        } => {
            let keys_path = keys.unwrap_or_else(|| default_keys_path(&from));
            let mut keys_file = read_keys_file(&keys_path)?;
            if keys_file.user_id != from {
                return Err(anyhow!(
                    "from mismatch: command from '{}' vs keys file user '{}'",
                    from,
                    keys_file.user_id
                ));
            }
            if let Some(override_suite) = suite {
                keys_file.suite = override_suite;
            }
            security_profile.enforce_suite_id(suite_to_suite_id(keys_file.suite))?;
            validate_server_url_for_profile(security_profile, &cli.server)?;
            ensure_prekeys_replenished(&client, &cli.server, &keys_path, &mut keys_file).await?;
            send_message_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                SendOptions {
                    security_profile,
                    accept_key_change,
                },
                &keys_file,
                &to,
                text.as_bytes(),
            )
            .await?;
        }
        Commands::Poll { user, keys } => {
            let mut keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            security_profile.enforce_suite_id(suite_to_suite_id(keys_file.suite))?;
            validate_server_url_for_profile(security_profile, &cli.server)?;
            ensure_prekeys_replenished(&client, &cli.server, &keys, &mut keys_file).await?;
            poll_inbox_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                security_profile,
                &keys_file,
            )
            .await?;
        }
    }

    Ok(())
}

fn generate_user_keys(
    user: &str,
    device_id: String,
    suite: SuiteFlag,
    one_time_count: usize,
) -> Result<UserKeysFile> {
    let mut rng = OsRng;
    let identity = IdentityKeyPair::generate(format!("{user}-ik"), &mut rng);
    let signed_prekey = OneTimePreKey::generate(format!("{user}-spk"), &mut rng);
    let identity_sig = generate_signing_key(&mut rng);
    let kem = build_kem_for_suite(suite)?;
    let pq_signed_prekey = kem.keypair()?;

    let mut one_time_x25519 = Vec::with_capacity(one_time_count);
    let mut one_time_mlkem = Vec::with_capacity(one_time_count);

    for idx in 0..one_time_count {
        let key = OneTimePreKey::generate(format!("{user}-otk-x-{idx}"), &mut rng);
        one_time_x25519.push(OneTimeKeyRecord {
            key_id: key.key_id,
            public_b64: B64.encode(key.public_key.0),
            secret_b64: B64.encode(key.secret_key.as_slice()),
        });

        let pq_key = kem.keypair()?;
        one_time_mlkem.push(OneTimeKeyRecord {
            key_id: format!("{user}-otk-pq-{idx}"),
            public_b64: B64.encode(pq_key.public_key),
            secret_b64: B64.encode(pq_key.secret_key.as_slice()),
        });
    }

    Ok(UserKeysFile {
        version: 1,
        user_id: user.to_string(),
        device_id,
        suite,
        identity_x25519_pub_b64: B64.encode(identity.public_key.0),
        identity_x25519_secret_b64: B64.encode(identity.secret_key.as_slice()),
        identity_sig_pub_b64: B64.encode(identity_sig.verifying_key().to_bytes()),
        identity_sig_secret_b64: B64.encode(identity_sig.to_bytes()),
        signed_prekey_x25519_pub_b64: B64.encode(signed_prekey.public_key.0),
        signed_prekey_x25519_secret_b64: B64.encode(signed_prekey.secret_key.as_slice()),
        pq_signed_prekey_pub_b64: B64.encode(pq_signed_prekey.public_key),
        pq_signed_prekey_secret_b64: B64.encode(pq_signed_prekey.secret_key.as_slice()),
        one_time_prekeys_x25519: one_time_x25519,
        one_time_prekeys_mlkem768: one_time_mlkem,
    })
}

fn refresh_one_time_prekeys(keys: &mut UserKeysFile, one_time_count: usize) -> Result<()> {
    if one_time_count == 0 || one_time_count > MAX_ONE_TIME_PREKEYS {
        return Err(anyhow!(
            "one_time_count must be in 1..={MAX_ONE_TIME_PREKEYS}"
        ));
    }
    let mut rng = OsRng;
    let kem = build_kem_for_suite(keys.suite)?;
    let timestamp = auth_timestamp().unwrap_or(0);
    let mut one_time_x25519 = Vec::with_capacity(one_time_count);
    let mut one_time_mlkem = Vec::with_capacity(one_time_count);

    for idx in 0..one_time_count {
        let key = OneTimePreKey::generate(
            format!("{}-otk-x-{}-{idx}", keys.user_id, timestamp),
            &mut rng,
        );
        one_time_x25519.push(OneTimeKeyRecord {
            key_id: key.key_id,
            public_b64: B64.encode(key.public_key.0),
            secret_b64: B64.encode(key.secret_key.as_slice()),
        });

        let pq_key = kem.keypair()?;
        one_time_mlkem.push(OneTimeKeyRecord {
            key_id: format!("{}-otk-pq-{}-{idx}", keys.user_id, timestamp),
            public_b64: B64.encode(pq_key.public_key),
            secret_b64: B64.encode(pq_key.secret_key.as_slice()),
        });
    }

    keys.one_time_prekeys_x25519 = one_time_x25519;
    keys.one_time_prekeys_mlkem768 = one_time_mlkem;
    Ok(())
}

async fn register_user(client: &Client, server: &str, keys: &UserKeysFile) -> Result<()> {
    let req = RegisterRequest {
        user_id: keys.user_id.clone(),
        identity_x25519_pub: keys.identity_x25519_pub_b64.clone(),
        identity_sig_pub: keys.identity_sig_pub_b64.clone(),
        device_id: keys.device_id.clone(),
    };
    let value = post_json(client, format!("{server}/v1/users/register"), &req).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn publish_prekeys(client: &Client, server: &str, keys: &UserKeysFile) -> Result<()> {
    let spk_pub = decode_b64_32(
        "signed_prekey_x25519_pub_b64",
        &keys.signed_prekey_x25519_pub_b64,
    )?;
    let pq_spk_pub = decode_b64("pq_signed_prekey_pub_b64", &keys.pq_signed_prekey_pub_b64)?;
    let signing_key =
        decode_signing_key_b64("identity_sig_secret_b64", &keys.identity_sig_secret_b64)?;
    let expected_pub = B64.encode(signing_key.verifying_key().to_bytes());
    if expected_pub != keys.identity_sig_pub_b64 {
        return Err(anyhow!(
            "identity_sig_pub_b64 does not match identity_sig_secret_b64"
        ));
    }

    let spk_msg = signed_prekey_signature_message(1, &DhPublicKey(spk_pub))?;
    let pq_msg = pq_signed_prekey_signature_message(1, &pq_spk_pub)?;

    let req = PublishPrekeysRequest {
        signed_prekey_x25519_pub: keys.signed_prekey_x25519_pub_b64.clone(),
        sig_over_spk: build_signature_payload(&signing_key, &spk_msg),
        pq_signed_prekey_pub_mlkem768: keys.pq_signed_prekey_pub_b64.clone(),
        sig_over_pqspk: build_signature_payload(&signing_key, &pq_msg),
        one_time_prekeys_x25519: keys
            .one_time_prekeys_x25519
            .iter()
            .map(|item| item.public_b64.clone())
            .collect(),
        one_time_prekeys_mlkem768: keys
            .one_time_prekeys_mlkem768
            .iter()
            .map(|item| item.public_b64.clone())
            .collect(),
    };

    let auth_signing_key = auth_signing_key_for_user(keys)?;
    let auth_headers =
        prekeys_auth_headers(&auth_signing_key, &keys.user_id, &keys.device_id, &req)?;
    let mut request = client
        .post(format!("{server}/v1/users/{}/prekeys", keys.user_id))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("publish prekeys request failed")?;
    let value: Value = handle_json_response(response).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn fetch_prekeys_status(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<PrekeysStatusResponse> {
    let auth_headers = prekeys_status_auth_headers(auth_signing_key, user, device_id)?;
    let mut request = client.get(format!("{server}/v1/users/{user}/prekeys/status"));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("fetch prekeys status request failed")?;
    handle_json_response(response).await
}

async fn ensure_prekeys_replenished(
    client: &Client,
    server: &str,
    keys_path: &Path,
    keys: &mut UserKeysFile,
) -> Result<()> {
    let auth_signing_key = auth_signing_key_for_user(keys)?;
    let status = fetch_prekeys_status(
        client,
        server,
        &keys.user_id,
        &keys.device_id,
        &auth_signing_key,
    )
    .await?;
    if status.user_id != keys.user_id || status.device_id != keys.device_id {
        return Err(anyhow!(
            "prekeys status identity mismatch: expected {}/{} got {}/{}",
            keys.user_id,
            keys.device_id,
            status.user_id,
            status.device_id
        ));
    }
    if !status.low_one_time_prekeys {
        return Ok(());
    }

    let target = status
        .minimum_recommended_one_time_prekeys
        .max(PREKEY_REPLENISH_TARGET);
    refresh_one_time_prekeys(keys, target)?;
    publish_prekeys(client, server, keys).await?;
    write_json_file(keys_path, keys)?;
    println!(
        "auto-replenished one-time prekeys for {} (x25519={}, mlkem768={}, checked_at={})",
        keys.user_id,
        status.remaining_one_time_prekeys_x25519,
        status.remaining_one_time_prekeys_mlkem768,
        status.checked_at
    );
    Ok(())
}

async fn send_message_flow(
    client: &Client,
    server: &str,
    state_dir: &Path,
    options: SendOptions,
    sender_keys: &UserKeysFile,
    to: &str,
    plaintext: &[u8],
) -> Result<()> {
    let from = sender_keys.user_id.as_str();
    let session_path = session_file_path(state_dir, from, to);
    let ad = make_ad(from, to)?;
    let auth_signing_key = auth_signing_key_for_user(sender_keys)?;

    if session_path.exists() {
        let mut session = load_session(&session_path)?;
        let wire = session.encrypt(plaintext, &ad)?;
        let response = relay_message(
            client,
            server,
            from,
            &sender_keys.device_id,
            &wire,
            to,
            &auth_signing_key,
        )
        .await?;
        save_session(
            &session_path,
            SessionFile {
                version: 1,
                user_id: from.to_string(),
                peer_user_id: to.to_string(),
                suite: sender_keys.suite,
                snapshot: session.snapshot(),
                passphrase_kdf_hint: None,
            },
        )?;
        println!(
            "sent session message {} at {}",
            response.message_id, response.received_at
        );
        return Ok(());
    }

    let bundle = fetch_bundle(client, server, to).await?;
    if bundle.low_one_time_prekeys.unwrap_or(false) {
        println!(
            "bundle for '{}' reports low prekey inventory (remaining_x25519={:?}, remaining_mlkem768={:?}, recommended={:?})",
            to,
            bundle.remaining_one_time_prekeys_x25519,
            bundle.remaining_one_time_prekeys_mlkem768,
            bundle.minimum_recommended_one_time_prekeys
        );
    }
    if bundle.last_resort_prekey_only.unwrap_or(false) {
        println!(
            "bundle for '{}' is in last-resort mode (remaining_x25519={:?}, remaining_mlkem768={:?})",
            to,
            bundle.remaining_one_time_prekeys_x25519,
            bundle.remaining_one_time_prekeys_mlkem768
        );
    }
    enforce_identity_pin(state_dir, from, &bundle, options.accept_key_change)?;
    let prekey_bundle = bundle_to_core(&bundle, sender_keys.suite)?;
    options
        .security_profile
        .enforce_suite_id(prekey_bundle.suite.suite_id()?)?;
    let identity = to_identity_keypair(sender_keys)?;
    let kem = build_kem_for_suite(sender_keys.suite)?;
    let verifier = Ed25519SignatureVerifier;

    let initiator = alice_initiate(
        &mut OsRng,
        &verifier,
        &kem,
        from,
        to,
        &identity,
        &prekey_bundle,
        plaintext,
    )?;
    let initial_encoded = initiator.initial_message.encode()?;
    let response = relay_message(
        client,
        server,
        from,
        &sender_keys.device_id,
        &initial_encoded,
        to,
        &auth_signing_key,
    )
    .await?;

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
    save_session(
        &session_path,
        SessionFile {
            version: 1,
            user_id: from.to_string(),
            peer_user_id: to.to_string(),
            suite: sender_keys.suite,
            snapshot: session.snapshot(),
            passphrase_kdf_hint: None,
        },
    )?;

    println!(
        "sent initial handshake message {} at {}",
        response.message_id, response.received_at
    );
    Ok(())
}

async fn poll_inbox_flow(
    client: &Client,
    server: &str,
    state_dir: &Path,
    security_profile: SecurityProfile,
    keys: &UserKeysFile,
) -> Result<()> {
    let cursor_path = inbox_cursor_path(state_dir, &keys.user_id);
    let replay_guard_path = replay_guard_file_path(state_dir, &keys.user_id);
    let mut cursor = load_cursor(&cursor_path)?;
    let mut replay_guard = load_replay_guard(&replay_guard_path, &keys.user_id)?;
    let now_unix = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow!("system time before UNIX epoch"))?
            .as_secs(),
    )
    .map_err(|_| anyhow!("system time overflow"))?;
    let auth_signing_key = auth_signing_key_for_user(keys)?;
    let inbox = fetch_inbox(
        client,
        server,
        &keys.user_id,
        &keys.device_id,
        cursor.since_message_id,
        &auth_signing_key,
    )
    .await?;

    for item in inbox.messages {
        let bytes = decode_b64("message_bytes_base64", &item.message_bytes_base64)?;
        let sender = item.sender_user_id.clone();
        let message_hash = message_hash_hex(&bytes);
        {
            let peer_guard = replay_guard.peers.entry(sender.clone()).or_default();
            peer_guard
                .seen_hashes
                .retain(|entry| entry.expires_at_unix > now_unix);
            if item.message_id <= peer_guard.last_message_id {
                eprintln!(
                    "[{}] rejected replayed transport message id {} (last seen {})",
                    sender, item.message_id, peer_guard.last_message_id
                );
                cursor.since_message_id = cursor.since_message_id.max(item.message_id);
                continue;
            }
            if peer_guard
                .seen_hashes
                .iter()
                .any(|entry| entry.hash_hex == message_hash)
            {
                eprintln!(
                    "[{}] rejected duplicate ciphertext blob for message id {}",
                    sender, item.message_id
                );
                peer_guard.last_message_id = peer_guard.last_message_id.max(item.message_id);
                cursor.since_message_id = cursor.since_message_id.max(item.message_id);
                continue;
            }
        }
        let ad = make_ad(&sender, &keys.user_id)?;
        let session_path = session_file_path(state_dir, &keys.user_id, &sender);

        let mut handled = false;
        if let Ok(initial) = InitialMessage::decode(&bytes) {
            security_profile.enforce_suite_id(initial.suite_id)?;
            let suite = suite_from_suite_id(initial.suite_id)?;
            let kem = build_kem_for_suite(suite)?;
            let identity = to_identity_keypair(keys)?;
            let spk = to_signed_prekey(keys)?;
            let pqspk = to_pq_signed_prekey(keys)?;
            let responder = bob_receive(&kem, &identity, &spk, &pqspk, &initial)?;
            let text = String::from_utf8(responder.plaintext.clone())
                .unwrap_or_else(|_| format!("<{} bytes binary>", responder.plaintext.len()));
            println!("[{}] {}", sender, text);

            let local_dh = DhKeyPair {
                public: spk.public_key,
                secret: spk.require_secret_key()?,
            };
            let session = SessionState::from_handshake_with_suite(
                SessionRole::Responder,
                *responder.session_key.as_bytes(),
                local_dh,
                initial.ik_a_pub,
                initial.suite_id,
                512,
            )?;
            save_session(
                &session_path,
                SessionFile {
                    version: 1,
                    user_id: keys.user_id.clone(),
                    peer_user_id: sender.clone(),
                    suite,
                    snapshot: session.snapshot(),
                    passphrase_kdf_hint: None,
                },
            )?;
            handled = true;
        }

        if !handled && session_path.exists() {
            let mut session = load_session(&session_path)?;
            match session.decrypt(&bytes, &ad) {
                Ok(plaintext) => {
                    let text = String::from_utf8(plaintext.clone())
                        .unwrap_or_else(|_| format!("<{} bytes binary>", plaintext.len()));
                    println!("[{}] {}", sender, text);
                    save_session(
                        &session_path,
                        SessionFile {
                            version: 1,
                            user_id: keys.user_id.clone(),
                            peer_user_id: sender.clone(),
                            suite: keys.suite,
                            snapshot: session.snapshot(),
                            passphrase_kdf_hint: None,
                        },
                    )?;
                }
                Err(err) => {
                    eprintln!(
                        "[{}] failed to decrypt message {}: {}",
                        sender, item.message_id, err
                    );
                }
            }
            handled = true;
        }

        if !handled {
            eprintln!(
                "[{}] no session and message is not a valid handshake initial (msg id {})",
                sender, item.message_id
            );
        }

        let peer_guard = replay_guard.peers.entry(sender).or_default();
        peer_guard.last_message_id = peer_guard.last_message_id.max(item.message_id);
        peer_guard.seen_hashes.push(SeenMessageHash {
            hash_hex: message_hash,
            expires_at_unix: now_unix + REPLAY_HASH_TTL_SECONDS,
        });
        if peer_guard.seen_hashes.len() > REPLAY_HASH_MAX_ENTRIES_PER_PEER {
            let overflow = peer_guard.seen_hashes.len() - REPLAY_HASH_MAX_ENTRIES_PER_PEER;
            peer_guard.seen_hashes.drain(0..overflow);
        }
        cursor.since_message_id = cursor.since_message_id.max(item.message_id);
    }

    save_cursor(&cursor_path, &cursor)?;
    save_replay_guard(&replay_guard_path, &replay_guard)?;
    Ok(())
}

fn bundle_to_core(bundle: &BundleResponse, suite: SuiteFlag) -> Result<PreKeyBundle> {
    let core_suite = AlgorithmSuite {
        kem: suite_to_kem_algorithm(suite),
        ..AlgorithmSuite::default()
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

async fn fetch_bundle(client: &Client, server: &str, user: &str) -> Result<BundleResponse> {
    let response = client
        .get(format!("{server}/v1/users/{user}/bundle"))
        .send()
        .await
        .context("fetch bundle request failed")?;
    handle_json_response(response).await
}

async fn relay_message(
    client: &Client,
    server: &str,
    sender_user_id: &str,
    device_id: &str,
    message_bytes: &[u8],
    recipient: &str,
    auth_signing_key: &SigningKey,
) -> Result<RelayResponse> {
    let req = RelayRequest {
        sender_user_id: sender_user_id.to_string(),
        device_id: device_id.to_string(),
        message_bytes_base64: B64.encode(message_bytes),
    };
    let auth_headers = relay_auth_headers(
        auth_signing_key,
        sender_user_id,
        device_id,
        recipient,
        message_bytes,
    )?;
    let mut request = client
        .post(format!("{server}/v1/relay/{recipient}"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request.send().await.context("relay request failed")?;
    handle_json_response(response).await
}

async fn fetch_inbox(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    since: i64,
    auth_signing_key: &SigningKey,
) -> Result<InboxResponse> {
    let auth_headers = inbox_auth_headers(auth_signing_key, user, device_id, since)?;
    let mut request = client.get(format!("{server}/v1/inbox/{user}?since={since}"));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request.send().await.context("fetch inbox request failed")?;
    handle_json_response(response).await
}

async fn post_json<T: Serialize>(client: &Client, url: String, body: &T) -> Result<Value> {
    let response = client.post(url).json(body).send().await?;
    handle_json_response(response).await
}

async fn handle_json_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T> {
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        let text = String::from_utf8_lossy(&bytes).to_string();
        return Err(anyhow!("server returned {status}: {text}"));
    }
    let parsed = serde_json::from_slice(&bytes).context("failed to parse server JSON response")?;
    Ok(parsed)
}

fn to_identity_keypair(keys: &UserKeysFile) -> Result<IdentityKeyPair> {
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

fn to_signed_prekey(keys: &UserKeysFile) -> Result<OneTimePreKey> {
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

fn to_pq_signed_prekey(keys: &UserKeysFile) -> Result<KEMPreKey> {
    Ok(KEMPreKey {
        key_id: format!("{}-pqspk", keys.user_id),
        public_key: decode_b64("pq_signed_prekey_pub_b64", &keys.pq_signed_prekey_pub_b64)?,
        secret_key: SecretBytes::from(decode_b64(
            "pq_signed_prekey_secret_b64",
            &keys.pq_signed_prekey_secret_b64,
        )?),
    })
}

fn default_keys_path(user: &str) -> PathBuf {
    Path::new(DEFAULT_KEYS_DIR).join(format!("{user}.json"))
}

fn identity_pins_file_path(state_dir: &Path, user: &str) -> PathBuf {
    state_dir.join(user).join("_identity_pins.json")
}

fn replay_guard_file_path(state_dir: &Path, user: &str) -> PathBuf {
    state_dir.join(user).join("_replay_guard.json")
}

fn session_file_path(state_dir: &Path, user: &str, peer: &str) -> PathBuf {
    state_dir.join(user).join(format!("{peer}.json"))
}

fn inbox_cursor_path(state_dir: &Path, user: &str) -> PathBuf {
    state_dir.join(user).join("_inbox_cursor.json")
}

fn message_hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn make_ad(sender: &str, recipient: &str) -> Result<Vec<u8>> {
    conversation_associated_data(sender, recipient)
        .map_err(|err| anyhow!("failed to build associated data: {err}"))
}

fn auth_timestamp() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system time is before UNIX epoch"))?;
    i64::try_from(duration.as_secs()).map_err(|_| anyhow!("system time overflow"))
}

fn auth_nonce() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

fn auth_common_records(
    endpoint: &'static str,
    user_id: &str,
    device_id: &str,
    timestamp: i64,
    nonce: &str,
) -> Vec<TlvRecord> {
    vec![
        TlvRecord {
            ty: AUTH_TAG_ENDPOINT,
            value: endpoint.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_USER_ID,
            value: user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_DEVICE_ID,
            value: device_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_TIMESTAMP,
            value: timestamp.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: AUTH_TAG_NONCE,
            value: nonce.as_bytes().to_vec(),
        },
    ]
}

fn relay_auth_headers(
    signing_key: &SigningKey,
    sender_user_id: &str,
    sender_device_id: &str,
    recipient_user_id: &str,
    message_blob: &[u8],
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("relay", sender_user_id, sender_device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: recipient_user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_MESSAGE_BLOB,
        value: message_blob.to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode relay auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, sender_user_id.to_string()),
        (AUTH_HEADER_DEVICE, sender_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn inbox_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("inbox", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode inbox auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn prekeys_status_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("prekeys-status", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode prekeys-status auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn prekeys_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    request: &PublishPrekeysRequest,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("prekeys", user_id, device_id, timestamp, &nonce);
    let mut hasher = Sha256::new();
    hasher.update(request.signed_prekey_x25519_pub.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_SPK_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    hasher.update(request.pq_signed_prekey_pub_mlkem768.as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_PREKEY_PQSPK_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode prekeys auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn bundle_identity_fingerprint(bundle: &BundleResponse) -> Result<String> {
    if let Some(fingerprint) = &bundle.identity_fingerprint_sha256 {
        let normalized = fingerprint.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            return Ok(normalized);
        }
    }
    let identity_key = decode_b64("identity_x25519_pub", &bundle.identity_x25519_pub)?;
    let mut hasher = Sha256::new();
    hasher.update(identity_key);
    Ok(hex::encode(hasher.finalize()))
}

fn bundle_identity_version(bundle: &BundleResponse) -> u32 {
    bundle.identity_key_version.unwrap_or(1)
}

fn bundle_observed_at(bundle: &BundleResponse) -> String {
    bundle
        .bundle_generated_at
        .clone()
        .unwrap_or_else(|| "unknown".to_string())
}

fn load_identity_pins(path: &Path, user_id: &str) -> Result<IdentityPinsFile> {
    if !path.exists() {
        return Ok(IdentityPinsFile {
            version: 1,
            user_id: user_id.to_string(),
            peers: HashMap::new(),
        });
    }
    read_json_file(path)
}

fn save_identity_pins(path: &Path, pins: &IdentityPinsFile) -> Result<()> {
    write_json_file(path, pins)
}

fn enforce_identity_pin(
    state_dir: &Path,
    user_id: &str,
    bundle: &BundleResponse,
    accept_key_change: bool,
) -> Result<()> {
    let pins_path = identity_pins_file_path(state_dir, user_id);
    let mut pins = load_identity_pins(&pins_path, user_id)?;
    let peer = bundle.user_id.clone();
    let observed = IdentityPinEntry {
        identity_fingerprint_sha256: bundle_identity_fingerprint(bundle)?,
        identity_key_version: bundle_identity_version(bundle),
        identity_sig_pub: bundle.identity_sig_pub.clone(),
        observed_at: bundle_observed_at(bundle),
    };

    match pins.peers.get(&peer) {
        None => {
            pins.peers.insert(peer.clone(), observed);
            save_identity_pins(&pins_path, &pins)?;
            println!("pinned identity for peer '{}'", peer);
        }
        Some(existing)
            if existing.identity_fingerprint_sha256 == observed.identity_fingerprint_sha256 =>
        {
            if existing.identity_key_version != observed.identity_key_version
                || existing.identity_sig_pub != observed.identity_sig_pub
            {
                pins.peers.insert(peer.clone(), observed);
                save_identity_pins(&pins_path, &pins)?;
            }
        }
        Some(existing) => {
            if !accept_key_change {
                return Err(anyhow!(
                    "peer identity key changed for '{}': {} (v{}) -> {} (v{}). rerun send with --accept-key-change to trust new identity",
                    peer,
                    existing.identity_fingerprint_sha256,
                    existing.identity_key_version,
                    observed.identity_fingerprint_sha256,
                    observed.identity_key_version
                ));
            }
            pins.peers.insert(peer.clone(), observed);
            save_identity_pins(&pins_path, &pins)?;
            println!("accepted updated identity for peer '{}'", peer);
        }
    }

    Ok(())
}

fn load_session(path: &Path) -> Result<SessionState> {
    let file: SessionFile = read_json_file(path)?;
    Ok(SessionState::from_snapshot(file.snapshot))
}

fn save_session(path: &Path, file: SessionFile) -> Result<()> {
    write_json_file(path, &file)
}

fn load_cursor(path: &Path) -> Result<InboxCursor> {
    if !path.exists() {
        return Ok(InboxCursor::default());
    }
    read_json_file(path)
}

fn save_cursor(path: &Path, cursor: &InboxCursor) -> Result<()> {
    write_json_file(path, cursor)
}

fn load_replay_guard(path: &Path, user_id: &str) -> Result<ReplayGuardFile> {
    if !path.exists() {
        return Ok(ReplayGuardFile {
            version: REPLAY_GUARD_VERSION,
            user_id: user_id.to_string(),
            peers: HashMap::new(),
        });
    }
    let guard: ReplayGuardFile = read_json_file(path)?;
    if guard.version != REPLAY_GUARD_VERSION {
        return Err(anyhow!(
            "unsupported replay guard version '{}' in {}",
            guard.version,
            path.display()
        ));
    }
    if guard.user_id != user_id {
        return Err(anyhow!(
            "replay guard user mismatch in {}: expected '{}' got '{}'",
            path.display(),
            user_id,
            guard.user_id
        ));
    }
    Ok(guard)
}

fn save_replay_guard(path: &Path, guard: &ReplayGuardFile) -> Result<()> {
    write_json_file(path, guard)
}

fn read_keys_file(path: &Path) -> Result<UserKeysFile> {
    read_json_file(path)
}

fn backup_keys_file(keys_path: &Path, out_path: &Path, passphrase: &str) -> Result<()> {
    if passphrase.trim().is_empty() {
        return Err(anyhow!("backup_passphrase cannot be empty"));
    }
    let keys = read_keys_file(keys_path)?;
    let plaintext = serde_json::to_vec_pretty(&keys)
        .with_context(|| format!("failed to encode keys from {}", keys_path.display()))?;
    let sealed = seal_plaintext(&plaintext, passphrase)?;
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    fs::write(out_path, sealed)
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    Ok(())
}

fn restore_keys_file(backup_path: &Path, passphrase: &str) -> Result<UserKeysFile> {
    if passphrase.trim().is_empty() {
        return Err(anyhow!("backup_passphrase cannot be empty"));
    }
    let data = fs::read(backup_path)
        .with_context(|| format!("failed to read {}", backup_path.display()))?;
    if let Ok(wrapped) = serde_json::from_slice::<WrappedSecret>(&data) {
        if is_wrapped_secret(&wrapped) {
            let plaintext = unseal_plaintext(&wrapped, passphrase)
                .with_context(|| format!("failed to decrypt {}", backup_path.display()))?;
            return serde_json::from_slice(&plaintext)
                .with_context(|| format!("failed to parse {}", backup_path.display()));
        }
    }
    if let Ok(legacy) = serde_json::from_slice::<LegacySealedFile>(&data) {
        let plaintext = unseal_legacy_plaintext(&legacy, passphrase)
            .with_context(|| format!("failed to decrypt {}", backup_path.display()))?;
        return serde_json::from_slice(&plaintext)
            .with_context(|| format!("failed to parse {}", backup_path.display()));
    }
    Err(anyhow!(
        "backup file '{}' is not a supported encrypted key backup format",
        backup_path.display()
    ))
}

fn storage_policy() -> StoragePolicy {
    STORAGE_POLICY.get().cloned().unwrap_or(StoragePolicy {
        passphrase: None,
        allow_plaintext: true,
    })
}

fn is_wrapped_secret(value: &WrappedSecret) -> bool {
    value.kind == "pqmsg-sealed"
        && value.version == 1
        && value.kdf == "argon2id"
        && value.aead == "aes-256-gcm"
}

fn seal_plaintext(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let wrapped = wrap_wrapped_bytes(&SecretString::new(passphrase.to_string().into()), plaintext)
        .map_err(|e| anyhow!("failed to encrypt local state: {e}"))?;
    serde_json::to_vec_pretty(&wrapped).context("failed to encode sealed local state")
}

fn unseal_plaintext(sealed: &WrappedSecret, passphrase: &str) -> Result<Vec<u8>> {
    unwrap_wrapped_bytes(&SecretString::new(passphrase.to_string().into()), sealed)
        .map_err(|e| anyhow!("failed to decrypt local state; check passphrase: {e}"))
}

fn legacy_derive_storage_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), passphrase.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(LEGACY_STORAGE_AAD, &mut key)
        .map_err(|_| anyhow!("failed to derive legacy storage key"))?;
    Ok(key)
}

fn unseal_legacy_plaintext(sealed: &LegacySealedFile, passphrase: &str) -> Result<Vec<u8>> {
    if sealed.kind != LEGACY_STORAGE_SEALED_KIND || sealed.version != LEGACY_STORAGE_SEALED_VERSION
    {
        return Err(anyhow!("unsupported legacy sealed local state format"));
    }
    let salt = decode_b64("sealed.salt_b64", &sealed.salt_b64)?;
    let nonce = decode_b64("sealed.nonce_b64", &sealed.nonce_b64)?;
    let ciphertext = decode_b64("sealed.ciphertext_b64", &sealed.ciphertext_b64)?;
    if salt.len() != LEGACY_STORAGE_SALT_BYTES {
        return Err(anyhow!(
            "legacy sealed salt must be {LEGACY_STORAGE_SALT_BYTES} bytes, got {}",
            salt.len()
        ));
    }
    if nonce.len() != LEGACY_STORAGE_NONCE_BYTES {
        return Err(anyhow!(
            "legacy sealed nonce must be {LEGACY_STORAGE_NONCE_BYTES} bytes, got {}",
            nonce.len()
        ));
    }
    let key = legacy_derive_storage_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| anyhow!("failed to initialize legacy storage cipher"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: LEGACY_STORAGE_AAD,
            },
        )
        .map_err(|_| anyhow!("failed to decrypt legacy local state; check passphrase"))?;
    Ok(plaintext)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if let Ok(sealed) = serde_json::from_slice::<WrappedSecret>(&data) {
        if is_wrapped_secret(&sealed) {
            let policy = storage_policy();
            let passphrase = policy.passphrase.ok_or_else(|| {
                anyhow!(
                    "state file '{}' is encrypted; set --state-passphrase or {}",
                    path.display(),
                    ENV_STATE_PASSPHRASE
                )
            })?;
            let plaintext = unseal_plaintext(&sealed, &passphrase)
                .with_context(|| format!("failed to decrypt {}", path.display()))?;
            return serde_json::from_slice(&plaintext)
                .with_context(|| format!("failed to parse {}", path.display()));
        }
    }
    if let Ok(sealed) = serde_json::from_slice::<LegacySealedFile>(&data) {
        let policy = storage_policy();
        let passphrase = policy.passphrase.ok_or_else(|| {
            anyhow!(
                "state file '{}' is encrypted; set --state-passphrase or {}",
                path.display(),
                ENV_STATE_PASSPHRASE
            )
        })?;
        let plaintext = unseal_legacy_plaintext(&sealed, &passphrase)
            .with_context(|| format!("failed to decrypt {}", path.display()))?;
        return serde_json::from_slice(&plaintext)
            .with_context(|| format!("failed to parse {}", path.display()));
    }

    let policy = storage_policy();
    if !policy.allow_plaintext {
        return Err(anyhow!(
            "plaintext local state is disabled for '{}'; provide --state-passphrase or use --allow-plaintext-state",
            path.display()
        ));
    }
    serde_json::from_slice(&data).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let plaintext = serde_json::to_vec_pretty(value)?;
    let policy = storage_policy();
    let data = match policy.passphrase {
        Some(passphrase) => seal_plaintext(&plaintext, &passphrase)
            .with_context(|| format!("failed to encrypt {}", path.display()))?,
        None => {
            if !policy.allow_plaintext {
                return Err(anyhow!(
                    "plaintext local state is disabled for '{}'; provide --state-passphrase or use --allow-plaintext-state",
                    path.display()
                ));
            }
            plaintext
        }
    };
    fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn decode_b64(field: &'static str, value: &str) -> Result<Vec<u8>> {
    B64.decode(value.as_bytes())
        .with_context(|| format!("invalid base64 for field '{field}'"))
}

fn decode_b64_32(field: &'static str, value: &str) -> Result<[u8; 32]> {
    let bytes = decode_b64(field, value)?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "field '{}' must decode to 32 bytes (got {})",
            field,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_keygen_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "keygen",
            "--user",
            "alice",
            "--out",
            "./devkeys/alice.json",
        ])
        .expect("parse");
        match cli.command {
            Commands::Keygen { user, .. } => assert_eq!(user, "alice"),
            _ => panic!("expected keygen command"),
        }
    }

    #[test]
    fn parse_register_with_global_server_after_subcommand() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "register",
            "--server",
            "http://localhost:3000",
            "--user",
            "alice",
            "--keys",
            "./devkeys/alice.json",
        ])
        .expect("parse");
        assert_eq!(cli.server, "http://localhost:3000");
        match cli.command {
            Commands::Register { user, keys } => {
                assert_eq!(user, "alice");
                assert_eq!(keys, PathBuf::from("./devkeys/alice.json"));
            }
            _ => panic!("expected register command"),
        }
    }

    #[test]
    fn parse_backup_keys_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "backup-keys",
            "--keys",
            "./devkeys/alice.json",
            "--out",
            "./backups/alice.backup.json",
            "--backup-passphrase",
            "secret",
        ])
        .expect("parse");
        match cli.command {
            Commands::BackupKeys { .. } => {}
            _ => panic!("expected backup-keys command"),
        }
    }

    #[test]
    fn parse_security_profile_flag() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "--security-profile",
            "nss-aligned",
            "keygen",
            "--user",
            "alice",
            "--out",
            "./devkeys/alice.json",
        ])
        .expect("parse");
        assert_eq!(cli.security_profile, SecurityProfileFlag::NssAligned);
    }

    #[test]
    fn high_assurance_requires_https_server_url() {
        let result = validate_server_url_for_profile(
            SecurityProfile::HighAssurance,
            "http://localhost:3000",
        );
        assert!(result.is_err());
        validate_server_url_for_profile(SecurityProfile::HighAssurance, "https://example.test")
            .expect("https allowed");
    }

    #[test]
    fn identity_pin_requires_explicit_acceptance_on_key_change() {
        let dir = tempdir().expect("tempdir");
        let bundle_v1 = BundleResponse {
            user_id: "bob".to_string(),
            identity_x25519_pub: B64.encode([1u8; 32]),
            identity_sig_pub: B64.encode([2u8; 32]),
            signed_prekey_x25519_pub: B64.encode([3u8; 32]),
            sig_over_spk: B64.encode([4u8; 64]),
            pq_signed_prekey_pub_mlkem768: B64.encode([5u8; 64]),
            sig_over_pqspk: B64.encode([6u8; 64]),
            one_time_prekey_x25519: None,
            one_time_prekey_mlkem768: None,
            remaining_one_time_prekeys_x25519: Some(0),
            remaining_one_time_prekeys_mlkem768: Some(0),
            low_one_time_prekeys: Some(true),
            minimum_recommended_one_time_prekeys: Some(PREKEY_REPLENISH_TARGET),
            last_resort_prekey_only: Some(true),
            identity_key_version: Some(1),
            identity_fingerprint_sha256: Some("aaa".to_string()),
            bundle_generated_at: Some("2026-03-04T00:00:00Z".to_string()),
        };
        enforce_identity_pin(dir.path(), "alice", &bundle_v1, false).expect("first pin");

        let mut bundle_v2 = bundle_v1;
        bundle_v2.identity_key_version = Some(2);
        bundle_v2.identity_fingerprint_sha256 = Some("bbb".to_string());
        let blocked = enforce_identity_pin(dir.path(), "alice", &bundle_v2, false);
        assert!(blocked.is_err());
        enforce_identity_pin(dir.path(), "alice", &bundle_v2, true).expect("accepted key change");
    }

    #[test]
    fn mocked_flow_handshake_then_session_roundtrip() {
        if let Ok(profile) = pqmsg_core::alg::runtime_crypto_profile() {
            if !profile.pq_oqs_enabled {
                return;
            }
        }

        let alice_keys = generate_user_keys(
            "alice",
            "alice-device-1".to_string(),
            SuiteFlag::MlKem768,
            4,
        )
        .expect("alice keys");
        let bob_keys =
            generate_user_keys("bob", "bob-device-1".to_string(), SuiteFlag::MlKem768, 4)
                .expect("bob keys");

        let bundle = {
            let spk_pub = decode_b64_32(
                "signed_prekey_x25519_pub_b64",
                &bob_keys.signed_prekey_x25519_pub_b64,
            )
            .expect("spk pub");
            let pq_pub = decode_b64(
                "pq_signed_prekey_pub_b64",
                &bob_keys.pq_signed_prekey_pub_b64,
            )
            .expect("pq pub");
            let sig_pub = decode_b64("identity_sig_pub_b64", &bob_keys.identity_sig_pub_b64)
                .expect("sig pub");
            let sig_sk = decode_signing_key_b64(
                "identity_sig_secret_b64",
                &bob_keys.identity_sig_secret_b64,
            )
            .expect("sig sk");
            let spk_msg =
                signed_prekey_signature_message(1, &DhPublicKey(spk_pub)).expect("spk msg");
            let pq_msg = pq_signed_prekey_signature_message(1, &pq_pub).expect("pq msg");

            let mut out = PreKeyBundle::new(
                "bob",
                DhPublicKey(
                    decode_b64_32("identity_x25519_pub_b64", &bob_keys.identity_x25519_pub_b64)
                        .expect("ik pub"),
                ),
                DhPublicKey(spk_pub),
                pq_pub,
                sig_sk.sign(&spk_msg).to_bytes().to_vec(),
                sig_sk.sign(&pq_msg).to_bytes().to_vec(),
                sig_pub,
            );
            out.suite.kem = KemAlgorithm::MlKem768;
            out
        };

        let alice_identity = to_identity_keypair(&alice_keys).expect("alice identity");
        let kem = build_kem_for_suite(SuiteFlag::MlKem768).expect("kem");
        let verifier = Ed25519SignatureVerifier;
        let initial = alice_initiate(
            &mut OsRng,
            &verifier,
            &kem,
            "alice",
            "bob",
            &alice_identity,
            &bundle,
            b"hello",
        )
        .expect("alice initiate");
        let encoded = initial.initial_message.encode().expect("encode");
        let decoded = InitialMessage::decode(&encoded).expect("decode");

        let bob_identity = to_identity_keypair(&bob_keys).expect("bob identity");
        let bob_spk = to_signed_prekey(&bob_keys).expect("bob spk");
        let bob_pq = to_pq_signed_prekey(&bob_keys).expect("bob pq");
        let first_plain =
            bob_receive(&kem, &bob_identity, &bob_spk, &bob_pq, &decoded).expect("bob receive");
        assert_eq!(first_plain.plaintext, b"hello");

        let mut alice_session = SessionState::from_handshake(
            SessionRole::Initiator,
            *initial.session_key.as_bytes(),
            DhKeyPair {
                public: alice_identity.public_key,
                secret: alice_identity.require_secret_key().expect("alice sk"),
            },
            bundle.signed_prekey,
            64,
        )
        .expect("alice session");
        let mut bob_session = SessionState::from_handshake(
            SessionRole::Responder,
            *first_plain.session_key.as_bytes(),
            DhKeyPair {
                public: bob_spk.public_key,
                secret: bob_spk.require_secret_key().expect("bob sk"),
            },
            decoded.ik_a_pub,
            64,
        )
        .expect("bob session");

        let dir = tempdir().expect("tempdir");
        let session_path = dir.path().join("alice").join("bob.json");
        save_session(
            &session_path,
            SessionFile {
                version: 1,
                user_id: "alice".to_string(),
                peer_user_id: "bob".to_string(),
                suite: SuiteFlag::MlKem768,
                snapshot: alice_session.snapshot(),
                passphrase_kdf_hint: None,
            },
        )
        .expect("save");

        alice_session = load_session(&session_path).expect("load");
        let ad = make_ad("alice", "bob").expect("ad");
        let wire = alice_session.encrypt(b"next", &ad).expect("encrypt");
        let plain = bob_session.decrypt(&wire, &ad).expect("decrypt");
        assert_eq!(plain, b"next");
    }

    #[test]
    fn backup_and_restore_keys_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let keys_path = dir.path().join("alice.json");
        let backup_path = dir.path().join("alice.backup.json");
        let keys = UserKeysFile {
            version: 1,
            user_id: "alice".to_string(),
            device_id: "alice-device-1".to_string(),
            suite: SuiteFlag::MlKem768,
            identity_x25519_pub_b64: B64.encode([1u8; 32]),
            identity_x25519_secret_b64: B64.encode([2u8; 32]),
            identity_sig_pub_b64: B64.encode([3u8; 32]),
            identity_sig_secret_b64: B64.encode([4u8; 32]),
            signed_prekey_x25519_pub_b64: B64.encode([5u8; 32]),
            signed_prekey_x25519_secret_b64: B64.encode([6u8; 32]),
            pq_signed_prekey_pub_b64: B64.encode([7u8; 64]),
            pq_signed_prekey_secret_b64: B64.encode([8u8; 64]),
            one_time_prekeys_x25519: vec![
                OneTimeKeyRecord {
                    key_id: "otk-x-1".to_string(),
                    public_b64: B64.encode([9u8; 32]),
                    secret_b64: B64.encode([10u8; 32]),
                },
                OneTimeKeyRecord {
                    key_id: "otk-x-2".to_string(),
                    public_b64: B64.encode([11u8; 32]),
                    secret_b64: B64.encode([12u8; 32]),
                },
            ],
            one_time_prekeys_mlkem768: vec![
                OneTimeKeyRecord {
                    key_id: "otk-pq-1".to_string(),
                    public_b64: B64.encode([13u8; 64]),
                    secret_b64: B64.encode([14u8; 64]),
                },
                OneTimeKeyRecord {
                    key_id: "otk-pq-2".to_string(),
                    public_b64: B64.encode([15u8; 64]),
                    secret_b64: B64.encode([16u8; 64]),
                },
            ],
        };
        let keys_json = serde_json::to_vec_pretty(&keys).expect("serialize");
        fs::write(&keys_path, keys_json).expect("write keys");

        backup_keys_file(&keys_path, &backup_path, "backup-passphrase").expect("backup");
        let restored = restore_keys_file(&backup_path, "backup-passphrase").expect("restore");

        assert_eq!(restored.user_id, keys.user_id);
        assert_eq!(restored.device_id, keys.device_id);
        assert_eq!(
            restored.identity_x25519_secret_b64,
            keys.identity_x25519_secret_b64
        );
        assert_eq!(
            restored.identity_sig_secret_b64,
            keys.identity_sig_secret_b64
        );
        assert_eq!(restored.one_time_prekeys_x25519.len(), 2);
        assert_eq!(restored.one_time_prekeys_mlkem768.len(), 2);
    }

    #[test]
    fn replay_guard_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let path = replay_guard_file_path(dir.path(), "alice");
        let guard = ReplayGuardFile {
            version: REPLAY_GUARD_VERSION,
            user_id: "alice".to_string(),
            peers: HashMap::from([(
                "bob".to_string(),
                PeerReplayGuard {
                    last_message_id: 12,
                    seen_hashes: vec![SeenMessageHash {
                        hash_hex: "abcd".to_string(),
                        expires_at_unix: 999_999,
                    }],
                },
            )]),
        };
        save_replay_guard(&path, &guard).expect("save guard");
        let loaded = load_replay_guard(&path, "alice").expect("load guard");
        assert_eq!(loaded.user_id, "alice");
        assert_eq!(
            loaded.peers.get("bob").expect("bob entry").last_message_id,
            12
        );
    }

    #[test]
    fn refresh_one_time_prekeys_updates_inventory() {
        if let Ok(profile) = pqmsg_core::alg::runtime_crypto_profile() {
            if !profile.pq_oqs_enabled {
                return;
            }
        }
        let mut keys = generate_user_keys(
            "alice",
            "alice-device-1".to_string(),
            SuiteFlag::MlKem768,
            2,
        )
        .expect("keys");
        refresh_one_time_prekeys(&mut keys, 5).expect("refresh");
        assert_eq!(keys.one_time_prekeys_x25519.len(), 5);
        assert_eq!(keys.one_time_prekeys_mlkem768.len(), 5);
    }

    #[test]
    fn sealed_state_roundtrip() {
        let plaintext = br#"{"v":1,"sample":"state"}"#;
        let sealed = seal_plaintext(plaintext, "passphrase").expect("seal");
        let parsed: WrappedSecret = serde_json::from_slice(&sealed).expect("parse sealed");
        let unsealed = unseal_plaintext(&parsed, "passphrase").expect("unseal");
        assert_eq!(unsealed, plaintext);
    }

    #[test]
    fn sealed_state_rejects_wrong_passphrase() {
        let plaintext = br#"{"v":1,"sample":"state"}"#;
        let sealed = seal_plaintext(plaintext, "passphrase").expect("seal");
        let parsed: WrappedSecret = serde_json::from_slice(&sealed).expect("parse sealed");
        assert!(unseal_plaintext(&parsed, "wrong-passphrase").is_err());
    }
}
