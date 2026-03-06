use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use pqmsg_core::ad::conversation_associated_data;
use pqmsg_core::alg::{
    enforce_runtime_security_profile, runtime_crypto_profile, AlgorithmSuite, KemAlgorithm,
    RuntimeCryptoProfile, SecurityProfile, SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
    SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
};
use pqmsg_core::dh::{DhKeyPair, DhPublicKey};
use pqmsg_core::handshake::{
    alice_initiate, bob_receive, pq_signed_prekey_signature_message,
    signed_prekey_signature_message, InitialMessage, SignatureVerifier,
};
use pqmsg_core::kem::MlKem768;
use pqmsg_core::keys::{IdentityKeyPair, KEMPreKey, OneTimePreKey, PreKeyBundle, SecretBytes};
use pqmsg_core::sealed::{
    derive_pairwise_sealed_sender_key, open_message as open_sealed_message,
    seal_message as seal_sealed_message, SealedEnvelope,
};
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
const AUTH_TAG_LINK_DEVICE_ID: u16 = critical_type(0x3212);
const AUTH_TAG_REVOKE_DEVICE_ID: u16 = critical_type(0x3213);
const AUTH_TAG_DELETE_IDS_HASH: u16 = critical_type(0x3214);
const AUTH_TAG_DELETE_BEFORE_ID: u16 = critical_type(0x3215);
const AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH: u16 = critical_type(0x3216);
const AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH: u16 = critical_type(0x3217);
const AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH: u16 = critical_type(0x3218);
const AUTH_TAG_CONTACT_USER_ID: u16 = critical_type(0x3219);
const AUTH_TAG_CONTACT_ALIAS_HASH: u16 = critical_type(0x321A);
const AUTH_TAG_CONTACT_VERIFIED_FLAG: u16 = critical_type(0x321B);
const AUTH_TAG_CONTACT_FINGERPRINT: u16 = critical_type(0x321C);
const AUTH_TAG_GROUP_ID: u16 = critical_type(0x321D);
const AUTH_TAG_GROUP_MEMBER_USER_ID: u16 = critical_type(0x321E);
const AUTH_TAG_GROUP_MEMBERS_HASH: u16 = critical_type(0x321F);
const AUTH_TAG_GROUP_SENDER_USER_ID: u16 = critical_type(0x3220);
const AUTH_TAG_GROUP_MESSAGE_BLOB_HASH: u16 = critical_type(0x3221);
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
const DEFAULT_MESSAGE_RETENTION_DAYS: u32 = 30;
const MESSAGE_STORE_VERSION: u16 = 1;
const MAX_LOCAL_MESSAGE_HISTORY: usize = 10_000;
const MAX_REMOTE_DELETE_BATCH: usize = 512;
const MAX_DISCOVERY_HASHES: usize = 4096;
const SHA256_HEX_LEN: usize = 64;
const MAX_CONTACT_ALIAS_LEN: usize = 128;
const MAX_GROUP_MEMBERS: usize = 512;
const MAX_GROUP_MESSAGE_BYTES: usize = 1_000_000;
const QR_PAYLOAD_VERSION: u16 = 1;
const MAX_REGISTRATION_POW_BITS: u8 = 26;

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
    #[arg(
        long,
        global = true,
        default_value_t = DEFAULT_MESSAGE_RETENTION_DAYS,
        value_parser = clap::value_parser!(u32).range(1..=3650)
    )]
    message_retention_days: u32,
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
    DevicesList {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
    },
    DevicesLink {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        new_device_id: String,
    },
    DevicesRevoke {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        target_device_id: String,
    },
    DiscoveryUpload {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long = "phone-hash")]
        phone_hashes_sha256: Vec<String>,
        #[arg(long = "email-hash")]
        email_hashes_sha256: Vec<String>,
    },
    DiscoveryMatch {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long = "hash")]
        hashes_sha256: Vec<String>,
    },
    ContactsAdd {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        peer: String,
        #[arg(long)]
        alias: Option<String>,
        #[arg(long)]
        qr_payload: Option<String>,
    },
    ContactsList {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
    },
    ContactsRemove {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        peer: String,
    },
    GroupsCreate {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        group: String,
        #[arg(long = "member")]
        members: Vec<String>,
    },
    GroupsMembers {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        group: String,
    },
    GroupsAddMember {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        group: String,
        #[arg(long)]
        member: String,
    },
    GroupsRemoveMember {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        group: String,
        #[arg(long)]
        member: String,
    },
    GroupsSend {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        group: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        payload_b64: Option<String>,
    },
    QrExport {
        #[arg(long)]
        keys: PathBuf,
    },
    QrVerify {
        #[arg(long)]
        payload: String,
        #[arg(long)]
        expected_user: Option<String>,
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
    SendSealed {
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
    PollSealed {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
    },
    DeleteMessages {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: PathBuf,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long)]
        before_message_id: Option<i64>,
        #[arg(long, default_value_t = false)]
        remote: bool,
    },
    ResetLocalState {
        #[arg(long)]
        user: String,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        wipe_keys: bool,
        #[arg(long, default_value_t = false)]
        remote_retire: bool,
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
struct DiscoveryHandlesUploadRequest {
    phone_hashes_sha256: Vec<String>,
    email_hashes_sha256: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryHandlesUploadResponse {
    user_id: String,
    device_id: String,
    uploaded_phone_hashes: usize,
    uploaded_email_hashes: usize,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct DiscoveryMatchRequest {
    hashes_sha256: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryMatchItem {
    hash_sha256: String,
    matched_user_id: String,
    handle_kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscoveryMatchResponse {
    user_id: String,
    matches: Vec<DiscoveryMatchItem>,
    checked_at: String,
}

#[derive(Debug, Serialize)]
struct UpsertContactRequest {
    contact_user_id: String,
    alias: Option<String>,
    verified_by_qr: Option<bool>,
    verified_fingerprint_sha256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpsertContactResponse {
    user_id: String,
    contact_user_id: String,
    alias: Option<String>,
    verified_by_qr: bool,
    verified_fingerprint_sha256: Option<String>,
    updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContactListItem {
    contact_user_id: String,
    alias: Option<String>,
    verified_by_qr: bool,
    verified_fingerprint_sha256: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContactListResponse {
    user_id: String,
    contacts: Vec<ContactListItem>,
}

#[derive(Debug, Serialize)]
struct RemoveContactRequest {
    contact_user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RemoveContactResponse {
    user_id: String,
    removed_contact_user_id: String,
    removed: bool,
    removed_at: String,
}

#[derive(Debug, Serialize)]
struct CreateGroupRequest {
    group_id: String,
    member_user_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateGroupResponse {
    group_id: String,
    owner_user_id: String,
    member_count: usize,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupMemberRecord {
    user_id: String,
    joined_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupMembersResponse {
    group_id: String,
    members: Vec<GroupMemberRecord>,
}

#[derive(Debug, Serialize)]
struct GroupMemberMutationRequest {
    member_user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupMemberMutationResponse {
    group_id: String,
    member_user_id: String,
    owner_user_id: String,
    changed: bool,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct GroupRelayRequest {
    sender_user_id: String,
    device_id: String,
    message_bytes_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupRelayResponse {
    group_id: String,
    delivered_message_count: usize,
    delivered_user_count: usize,
    first_message_id: Option<i64>,
    received_at: String,
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    user_id: String,
    identity_x25519_pub: String,
    identity_sig_pub: String,
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pow_nonce: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ServerCapabilitiesResponse {
    capability_schema_version: u16,
    security_profile: String,
    deployment_mode: String,
    tls_required: bool,
    tls_enabled: bool,
    supported_suite_ids: Vec<u16>,
    runtime_crypto_profile: RuntimeCryptoProfile,
    production_baseline_met: bool,
    registration_pow_bits: u8,
    prekey_bundle_reserve_count: i64,
    pq_ratchet_interval: u32,
    web_client_policy: String,
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

#[derive(Debug, Serialize)]
struct SealedRelayRequest {
    message_bytes_base64: String,
}

#[derive(Debug, Deserialize)]
struct SealedRelayResponse {
    delivered_device_count: usize,
    first_message_id: Option<i64>,
    received_at: String,
}

#[derive(Debug, Deserialize)]
struct RelayResponse {
    message_id: i64,
    delivered_device_count: Option<usize>,
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
    received_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SealedInboxResponse {
    messages: Vec<SealedInboxMessage>,
}

#[derive(Debug, Deserialize)]
struct SealedInboxMessage {
    message_id: i64,
    message_bytes_base64: String,
    received_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeleteInboxRequest {
    message_ids: Vec<i64>,
    delete_before_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DeleteInboxResponse {
    user_id: String,
    device_id: String,
    deleted_count: u64,
    deleted_at: String,
}

#[derive(Debug, Deserialize)]
struct RetireCurrentDeviceResponse {
    user_id: String,
    retired_device_id: String,
    retired_at: String,
    remaining_active_devices: usize,
}

#[derive(Debug, Serialize)]
struct LinkDeviceRequest {
    new_device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LinkDeviceResponse {
    user_id: String,
    linked_device_id: String,
    linked_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RevokeDeviceResponse {
    user_id: String,
    revoked_device_id: String,
    revoked_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceRecord {
    device_id: String,
    active: bool,
    linked_at: String,
    revoked_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceListResponse {
    user_id: String,
    devices: Vec<DeviceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QrIdentityPayload {
    version: u16,
    user_id: String,
    device_id: String,
    suite: SuiteFlag,
    identity_x25519_pub_b64: String,
    identity_sig_pub_b64: String,
    identity_fingerprint_sha256: String,
    generated_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessageRecord {
    message_id: i64,
    peer_user_id: String,
    direction: String,
    text: String,
    server_timestamp: Option<String>,
    stored_at_unix: i64,
    expires_at_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageStoreFile {
    version: u16,
    user_id: String,
    retention_seconds: i64,
    messages: Vec<StoredMessageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityPinEntry {
    identity_fingerprint_sha256: String,
    identity_key_version: u32,
    identity_sig_pub: String,
    #[serde(default)]
    identity_x25519_pub: Option<String>,
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
    message_retention_seconds: i64,
}

struct DeleteMessagesOptions<'a> {
    peer: Option<&'a str>,
    before_message_id: Option<i64>,
    remote: bool,
    message_retention_seconds: i64,
}

struct LocalStateWipeSummary {
    state_removed: bool,
    keys_removed: bool,
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

fn server_profile_satisfies_client(
    client_profile: SecurityProfile,
    server_profile: SecurityProfile,
) -> bool {
    match client_profile {
        SecurityProfile::Research => true,
        SecurityProfile::HighAssurance => matches!(
            server_profile,
            SecurityProfile::HighAssurance | SecurityProfile::NssAligned
        ),
        SecurityProfile::NssAligned => matches!(server_profile, SecurityProfile::NssAligned),
    }
}

fn validate_server_capabilities_for_cli(
    security_profile: SecurityProfile,
    suite_id: Option<u16>,
    capabilities: &ServerCapabilitiesResponse,
    server: &str,
) -> Result<()> {
    if capabilities.capability_schema_version != 1 {
        return Err(anyhow!(
            "server capability schema version {} is unsupported by this cli",
            capabilities.capability_schema_version
        ));
    }
    let server_profile = SecurityProfile::parse(&capabilities.security_profile).map_err(|_| {
        anyhow!(
            "server reported unknown security profile '{}'",
            capabilities.security_profile
        )
    })?;
    if !server_profile_satisfies_client(security_profile, server_profile) {
        return Err(anyhow!(
            "server profile '{}' is weaker than requested cli security profile '{}'",
            capabilities.security_profile,
            security_profile.as_str()
        ));
    }
    if security_profile.requires_tls() && (!capabilities.tls_required || !capabilities.tls_enabled)
    {
        return Err(anyhow!(
            "server capabilities for '{}' do not satisfy required TLS transport for profile '{}'",
            server,
            security_profile.as_str()
        ));
    }
    if security_profile.requires_pq_backend() && !capabilities.runtime_crypto_profile.pq_oqs_enabled
    {
        return Err(anyhow!(
            "server '{}' is not running a PQ-enabled crypto backend required by profile '{}'",
            server,
            security_profile.as_str()
        ));
    }
    if capabilities.deployment_mode != "development" && !capabilities.production_baseline_met {
        return Err(anyhow!(
            "server '{}' advertises deployment_mode='{}' but production_baseline_met=false",
            server,
            capabilities.deployment_mode
        ));
    }
    if let Some(suite_id) = suite_id {
        if !capabilities.supported_suite_ids.contains(&suite_id) {
            return Err(anyhow!(
                "server '{}' does not support requested suite_id={} for profile '{}'",
                server,
                suite_id,
                security_profile.as_str()
            ));
        }
    }
    Ok(())
}

async fn fetch_server_capabilities(
    client: &Client,
    server: &str,
) -> Result<ServerCapabilitiesResponse> {
    let response = client
        .get(format!("{server}/v1/capabilities"))
        .send()
        .await
        .context("capabilities request failed")?;
    handle_json_response(response).await
}

async fn preflight_server_command(
    client: &Client,
    server: &str,
    security_profile: SecurityProfile,
    suite_id: Option<u16>,
) -> Result<ServerCapabilitiesResponse> {
    validate_server_url_for_profile(security_profile, server)?;
    let capabilities = fetch_server_capabilities(client, server).await?;
    validate_server_capabilities_for_cli(security_profile, suite_id, &capabilities, server)?;
    Ok(capabilities)
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
    let message_retention_seconds = message_retention_days_to_seconds(cli.message_retention_days)?;
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
            let suite_id = suite_to_suite_id(keys_file.suite);
            security_profile.enforce_suite_id(suite_id)?;
            let capabilities =
                preflight_server_command(&client, &cli.server, security_profile, Some(suite_id))
                    .await?;
            register_user(
                &client,
                &cli.server,
                &keys_file,
                capabilities.registration_pow_bits,
            )
            .await?;
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
            let suite_id = suite_to_suite_id(keys_file.suite);
            security_profile.enforce_suite_id(suite_id)?;
            preflight_server_command(&client, &cli.server, security_profile, Some(suite_id))
                .await?;
            publish_prekeys(&client, &cli.server, &keys_file).await?;
        }
        Commands::DevicesList { user, keys } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = list_devices_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::DevicesLink {
            user,
            keys,
            new_device_id,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            validate_id("new_device_id", &new_device_id)?;
            if new_device_id == keys_file.device_id {
                return Err(anyhow!(
                    "new_device_id must differ from the authenticated device_id '{}'",
                    keys_file.device_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = link_device_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &new_device_id,
                &auth_signing_key,
            )
            .await?;
            validate_link_device_response(&response, &keys_file.user_id, &new_device_id)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::DevicesRevoke {
            user,
            keys,
            target_device_id,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            validate_id("target_device_id", &target_device_id)?;
            if target_device_id == keys_file.device_id {
                return Err(anyhow!(
                    "target_device_id matches the authenticated device; use reset-local-state --remote-retire for self-retirement"
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = revoke_device_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &target_device_id,
                &auth_signing_key,
            )
            .await?;
            validate_revoke_device_response(&response, &keys_file.user_id, &target_device_id)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::DiscoveryUpload {
            user,
            keys,
            phone_hashes_sha256,
            email_hashes_sha256,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            let phone_hashes =
                normalize_sha256_hashes("phone_hashes_sha256", &phone_hashes_sha256)?;
            let email_hashes =
                normalize_sha256_hashes("email_hashes_sha256", &email_hashes_sha256)?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = upload_discovery_handles_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &phone_hashes,
                &email_hashes,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::DiscoveryMatch {
            user,
            keys,
            hashes_sha256,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            let hashes = normalize_sha256_hashes("hashes_sha256", &hashes_sha256)?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = discovery_match_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &hashes,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::ContactsAdd {
            user,
            keys,
            peer,
            alias,
            qr_payload,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            validate_id("peer", &peer)?;
            let alias = validate_optional_alias(alias.as_deref())?;
            let qr_verified = if let Some(payload) = qr_payload {
                let qr = decode_qr_payload(&payload)?;
                verify_qr_payload(&qr, Some(&peer))?;
                Some(qr.identity_fingerprint_sha256)
            } else {
                None
            };
            let req = UpsertContactRequest {
                contact_user_id: peer.clone(),
                alias: alias.clone(),
                verified_by_qr: Some(qr_verified.is_some()),
                verified_fingerprint_sha256: qr_verified.clone(),
            };
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = upsert_contact_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &req,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::ContactsList { user, keys } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = list_contacts_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::ContactsRemove { user, keys, peer } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            validate_id("peer", &peer)?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = remove_contact_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &peer,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::GroupsCreate {
            user,
            keys,
            group,
            members,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            validate_id("group", &group)?;
            let members = normalize_group_member_ids(&members)?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = create_group_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &group,
                &members,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::GroupsMembers { user, keys, group } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            validate_id("group", &group)?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = list_group_members_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &group,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::GroupsAddMember {
            user,
            keys,
            group,
            member,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            validate_id("group", &group)?;
            validate_id("member", &member)?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = add_group_member_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &group,
                &member,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::GroupsRemoveMember {
            user,
            keys,
            group,
            member,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            validate_id("group", &group)?;
            validate_id("member", &member)?;
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = remove_group_member_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &group,
                &member,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::GroupsSend {
            user,
            keys,
            group,
            text,
            payload_b64,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            preflight_server_command(&client, &cli.server, security_profile, None).await?;
            validate_id("group", &group)?;
            let message_blob = match (text, payload_b64) {
                (Some(value), None) => value.into_bytes(),
                (None, Some(value)) => decode_group_payload_b64(&value)?,
                (Some(_), Some(_)) => {
                    return Err(anyhow!(
                        "provide only one of --text or --payload-b64 for groups-send"
                    ))
                }
                (None, None) => {
                    return Err(anyhow!(
                        "provide either --text or --payload-b64 for groups-send"
                    ))
                }
            };
            if message_blob.is_empty() || message_blob.len() > MAX_GROUP_MESSAGE_BYTES {
                return Err(anyhow!(
                    "group message bytes must be 1..={MAX_GROUP_MESSAGE_BYTES}"
                ));
            }
            let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
            let response = relay_group_message_remote(
                &client,
                &cli.server,
                &keys_file.user_id,
                &keys_file.device_id,
                &group,
                &message_blob,
                &auth_signing_key,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::QrExport { keys } => {
            let keys_file = read_keys_file(&keys)?;
            let payload = build_qr_payload(&keys_file)?;
            let encoded = encode_qr_payload(&payload)?;
            println!("{}", serde_json::to_string_pretty(&payload)?);
            println!("{encoded}");
        }
        Commands::QrVerify {
            payload,
            expected_user,
        } => {
            let decoded = decode_qr_payload(&payload)?;
            verify_qr_payload(&decoded, expected_user.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&decoded)?);
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
            let suite_id = suite_to_suite_id(keys_file.suite);
            security_profile.enforce_suite_id(suite_id)?;
            preflight_server_command(&client, &cli.server, security_profile, Some(suite_id))
                .await?;
            ensure_prekeys_replenished(&client, &cli.server, &keys_path, &mut keys_file).await?;
            send_message_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                SendOptions {
                    security_profile,
                    accept_key_change,
                    message_retention_seconds,
                },
                &keys_file,
                &to,
                text.as_bytes(),
            )
            .await?;
        }
        Commands::SendSealed {
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
            let suite_id = suite_to_suite_id(keys_file.suite);
            security_profile.enforce_suite_id(suite_id)?;
            preflight_server_command(&client, &cli.server, security_profile, Some(suite_id))
                .await?;
            ensure_prekeys_replenished(&client, &cli.server, &keys_path, &mut keys_file).await?;
            send_sealed_message_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                SendOptions {
                    security_profile,
                    accept_key_change,
                    message_retention_seconds,
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
            let suite_id = suite_to_suite_id(keys_file.suite);
            security_profile.enforce_suite_id(suite_id)?;
            preflight_server_command(&client, &cli.server, security_profile, Some(suite_id))
                .await?;
            ensure_prekeys_replenished(&client, &cli.server, &keys, &mut keys_file).await?;
            poll_inbox_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                message_retention_seconds,
                security_profile,
                &keys_file,
            )
            .await?;
        }
        Commands::PollSealed { user, keys } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            let suite_id = suite_to_suite_id(keys_file.suite);
            security_profile.enforce_suite_id(suite_id)?;
            preflight_server_command(&client, &cli.server, security_profile, Some(suite_id))
                .await?;
            poll_sealed_inbox_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                message_retention_seconds,
                security_profile,
                &keys_file,
            )
            .await?;
        }
        Commands::DeleteMessages {
            user,
            keys,
            peer,
            before_message_id,
            remote,
        } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            if remote {
                preflight_server_command(&client, &cli.server, security_profile, None).await?;
            }
            delete_messages_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                &keys_file,
                DeleteMessagesOptions {
                    peer: peer.as_deref(),
                    before_message_id,
                    remote,
                    message_retention_seconds,
                },
            )
            .await?;
        }
        Commands::ResetLocalState {
            user,
            keys,
            wipe_keys,
            remote_retire,
        } => {
            validate_id("user", &user)?;
            let mut remote_retire_remaining = None;
            if remote_retire {
                let keys_path = keys.clone().unwrap_or_else(|| default_keys_path(&user));
                let keys_file = read_keys_file(&keys_path)?;
                if keys_file.user_id != user {
                    return Err(anyhow!(
                        "user mismatch: command user '{}' vs keys file user '{}'",
                        user,
                        keys_file.user_id
                    ));
                }
                preflight_server_command(&client, &cli.server, security_profile, None).await?;
                let auth_signing_key = auth_signing_key_for_user(&keys_file)?;
                let response = retire_current_device_remote(
                    &client,
                    &cli.server,
                    &keys_file.user_id,
                    &keys_file.device_id,
                    &auth_signing_key,
                )
                .await?;
                validate_retire_current_device_response(&response, &keys_file)?;
                remote_retire_remaining = Some(response.remaining_active_devices);
            }
            let summary = wipe_local_state(&cli.state_dir, &user, keys.as_deref(), wipe_keys)?;
            if let Some(remaining_active_devices) = remote_retire_remaining {
                println!(
                    "retired current device for '{}' on server (remaining_active_devices={})",
                    user, remaining_active_devices
                );
            }
            println!(
                "cleared local state for '{}' (state_removed={}, keys_removed={})",
                user, summary.state_removed, summary.keys_removed
            );
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

async fn register_user(
    client: &Client,
    server: &str,
    keys: &UserKeysFile,
    registration_pow_bits: u8,
) -> Result<()> {
    let mut req = RegisterRequest {
        user_id: keys.user_id.clone(),
        identity_x25519_pub: keys.identity_x25519_pub_b64.clone(),
        identity_sig_pub: keys.identity_sig_pub_b64.clone(),
        device_id: keys.device_id.clone(),
        pow_nonce: None,
    };
    if registration_pow_bits > 0 {
        req.pow_nonce = Some(solve_registration_pow(&req, registration_pow_bits)?);
    }
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

async fn list_devices_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<DeviceListResponse> {
    let auth_headers = devices_list_auth_headers(auth_signing_key, user, device_id)?;
    let mut request = client.get(format!("{server}/v1/users/{user}/devices"));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("list devices request failed")?;
    handle_json_response(response).await
}

async fn link_device_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    new_device_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<LinkDeviceResponse> {
    let req = LinkDeviceRequest {
        new_device_id: new_device_id.to_string(),
    };
    let auth_headers = devices_link_auth_headers(auth_signing_key, user, device_id, new_device_id)?;
    let mut request = client
        .post(format!("{server}/v1/users/{user}/devices/link"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request.send().await.context("link device request failed")?;
    handle_json_response(response).await
}

async fn revoke_device_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    target_device_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<RevokeDeviceResponse> {
    let auth_headers =
        devices_revoke_auth_headers(auth_signing_key, user, device_id, target_device_id)?;
    let mut request = client.post(format!(
        "{server}/v1/users/{user}/devices/{target_device_id}/revoke"
    ));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("revoke device request failed")?;
    handle_json_response(response).await
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

async fn upload_discovery_handles_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    phone_hashes_sha256: &[String],
    email_hashes_sha256: &[String],
    auth_signing_key: &SigningKey,
) -> Result<DiscoveryHandlesUploadResponse> {
    let req = DiscoveryHandlesUploadRequest {
        phone_hashes_sha256: phone_hashes_sha256.to_vec(),
        email_hashes_sha256: email_hashes_sha256.to_vec(),
    };
    let auth_headers = discovery_handles_auth_headers(
        auth_signing_key,
        user,
        device_id,
        &req.phone_hashes_sha256,
        &req.email_hashes_sha256,
    )?;
    let mut request = client
        .post(format!("{server}/v1/users/{user}/discovery/handles"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("upload discovery handles request failed")?;
    handle_json_response(response).await
}

async fn discovery_match_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    hashes_sha256: &[String],
    auth_signing_key: &SigningKey,
) -> Result<DiscoveryMatchResponse> {
    let req = DiscoveryMatchRequest {
        hashes_sha256: hashes_sha256.to_vec(),
    };
    let auth_headers =
        discovery_match_auth_headers(auth_signing_key, user, device_id, &req.hashes_sha256)?;
    let mut request = client
        .post(format!("{server}/v1/users/{user}/discovery/match"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("discovery match request failed")?;
    handle_json_response(response).await
}

async fn upsert_contact_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    req: &UpsertContactRequest,
    auth_signing_key: &SigningKey,
) -> Result<UpsertContactResponse> {
    let auth_headers = contacts_upsert_auth_headers(
        auth_signing_key,
        user,
        device_id,
        &req.contact_user_id,
        req.alias.as_deref(),
        req.verified_by_qr.unwrap_or(false),
        req.verified_fingerprint_sha256.as_deref(),
    )?;
    let mut request = client
        .post(format!("{server}/v1/users/{user}/contacts"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("upsert contact request failed")?;
    handle_json_response(response).await
}

async fn list_contacts_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<ContactListResponse> {
    let auth_headers = contacts_list_auth_headers(auth_signing_key, user, device_id)?;
    let mut request = client.get(format!("{server}/v1/users/{user}/contacts"));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("list contacts request failed")?;
    handle_json_response(response).await
}

async fn remove_contact_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    peer_user_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<RemoveContactResponse> {
    let req = RemoveContactRequest {
        contact_user_id: peer_user_id.to_string(),
    };
    let auth_headers =
        contacts_remove_auth_headers(auth_signing_key, user, device_id, &req.contact_user_id)?;
    let mut request = client
        .post(format!("{server}/v1/users/{user}/contacts/remove"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("remove contact request failed")?;
    handle_json_response(response).await
}

async fn create_group_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    group_id: &str,
    member_user_ids: &[String],
    auth_signing_key: &SigningKey,
) -> Result<CreateGroupResponse> {
    let req = CreateGroupRequest {
        group_id: group_id.to_string(),
        member_user_ids: member_user_ids.to_vec(),
    };
    let auth_headers = groups_create_auth_headers(
        auth_signing_key,
        user,
        device_id,
        &req.group_id,
        &req.member_user_ids,
    )?;
    let mut request = client.post(format!("{server}/v1/groups")).json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("create group request failed")?;
    handle_json_response(response).await
}

async fn list_group_members_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    group_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<GroupMembersResponse> {
    let auth_headers =
        groups_members_list_auth_headers(auth_signing_key, user, device_id, group_id)?;
    let mut request = client.get(format!("{server}/v1/groups/{group_id}/members"));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("list group members request failed")?;
    handle_json_response(response).await
}

async fn add_group_member_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    group_id: &str,
    member_user_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<GroupMemberMutationResponse> {
    let req = GroupMemberMutationRequest {
        member_user_id: member_user_id.to_string(),
    };
    let auth_headers = groups_members_add_auth_headers(
        auth_signing_key,
        user,
        device_id,
        group_id,
        &req.member_user_id,
    )?;
    let mut request = client
        .post(format!("{server}/v1/groups/{group_id}/members/add"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("add group member request failed")?;
    handle_json_response(response).await
}

async fn remove_group_member_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    group_id: &str,
    member_user_id: &str,
    auth_signing_key: &SigningKey,
) -> Result<GroupMemberMutationResponse> {
    let req = GroupMemberMutationRequest {
        member_user_id: member_user_id.to_string(),
    };
    let auth_headers = groups_members_remove_auth_headers(
        auth_signing_key,
        user,
        device_id,
        group_id,
        &req.member_user_id,
    )?;
    let mut request = client
        .post(format!("{server}/v1/groups/{group_id}/members/remove"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("remove group member request failed")?;
    handle_json_response(response).await
}

async fn relay_group_message_remote(
    client: &Client,
    server: &str,
    sender_user_id: &str,
    sender_device_id: &str,
    group_id: &str,
    message_blob: &[u8],
    auth_signing_key: &SigningKey,
) -> Result<GroupRelayResponse> {
    let req = GroupRelayRequest {
        sender_user_id: sender_user_id.to_string(),
        device_id: sender_device_id.to_string(),
        message_bytes_base64: B64.encode(message_blob),
    };
    let auth_headers = groups_relay_auth_headers(
        auth_signing_key,
        sender_user_id,
        sender_device_id,
        group_id,
        &req.sender_user_id,
        message_blob,
    )?;
    let mut request = client
        .post(format!("{server}/v1/groups/{group_id}/relay"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("relay group message request failed")?;
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
        let text = String::from_utf8_lossy(plaintext).to_string();
        append_message_record(
            state_dir,
            from,
            options.message_retention_seconds,
            StoredMessageRecord {
                message_id: response.message_id,
                peer_user_id: to.to_string(),
                direction: "outgoing".to_string(),
                text,
                server_timestamp: Some(response.received_at.clone()),
                stored_at_unix: unix_time_now()?,
                expires_at_unix: 0,
            },
        )?;
        println!(
            "sent session message {} at {} (fanout_devices={})",
            response.message_id,
            response.received_at,
            response.delivered_device_count.unwrap_or(1)
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
    let text = String::from_utf8_lossy(plaintext).to_string();
    append_message_record(
        state_dir,
        from,
        options.message_retention_seconds,
        StoredMessageRecord {
            message_id: response.message_id,
            peer_user_id: to.to_string(),
            direction: "outgoing".to_string(),
            text,
            server_timestamp: Some(response.received_at.clone()),
            stored_at_unix: unix_time_now()?,
            expires_at_unix: 0,
        },
    )?;

    println!(
        "sent initial handshake message {} at {} (fanout_devices={})",
        response.message_id,
        response.received_at,
        response.delivered_device_count.unwrap_or(1)
    );
    Ok(())
}

async fn send_sealed_message_flow(
    client: &Client,
    server: &str,
    state_dir: &Path,
    options: SendOptions,
    sender_keys: &UserKeysFile,
    to: &str,
    plaintext: &[u8],
) -> Result<()> {
    let from = sender_keys.user_id.as_str();
    let suite_id = suite_to_suite_id(sender_keys.suite);
    options.security_profile.enforce_suite_id(suite_id)?;

    let bundle = fetch_bundle(client, server, to).await?;
    enforce_identity_pin(state_dir, from, &bundle, options.accept_key_change)?;

    let identity = to_identity_keypair(sender_keys)?;
    let local_secret = identity.require_secret_key()?;
    let remote_pub = DhPublicKey(decode_b64_32(
        "identity_x25519_pub",
        &bundle.identity_x25519_pub,
    )?);
    let sealed_key = derive_pairwise_sealed_sender_key(&local_secret, &remote_pub, suite_id)?;
    let sealed_payload = seal_sealed_message(
        &sealed_key,
        suite_id,
        to,
        from,
        &sender_keys.device_id,
        plaintext,
    )?;
    let response = relay_sealed_message(client, server, to, &sealed_payload).await?;

    let text = String::from_utf8_lossy(plaintext).to_string();
    append_message_record(
        state_dir,
        from,
        options.message_retention_seconds,
        StoredMessageRecord {
            message_id: response.first_message_id.unwrap_or(0),
            peer_user_id: to.to_string(),
            direction: "outgoing-sealed".to_string(),
            text,
            server_timestamp: Some(response.received_at.clone()),
            stored_at_unix: unix_time_now()?,
            expires_at_unix: 0,
        },
    )?;
    println!(
        "sent sealed message at {} (fanout_devices={})",
        response.received_at, response.delivered_device_count
    );
    Ok(())
}

async fn poll_inbox_flow(
    client: &Client,
    server: &str,
    state_dir: &Path,
    message_retention_seconds: i64,
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
            append_message_record(
                state_dir,
                &keys.user_id,
                message_retention_seconds,
                StoredMessageRecord {
                    message_id: item.message_id,
                    peer_user_id: sender.clone(),
                    direction: "incoming".to_string(),
                    text,
                    server_timestamp: item.received_at.clone(),
                    stored_at_unix: unix_time_now()?,
                    expires_at_unix: 0,
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
                    append_message_record(
                        state_dir,
                        &keys.user_id,
                        message_retention_seconds,
                        StoredMessageRecord {
                            message_id: item.message_id,
                            peer_user_id: sender.clone(),
                            direction: "incoming".to_string(),
                            text,
                            server_timestamp: item.received_at.clone(),
                            stored_at_unix: unix_time_now()?,
                            expires_at_unix: 0,
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

async fn poll_sealed_inbox_flow(
    client: &Client,
    server: &str,
    state_dir: &Path,
    message_retention_seconds: i64,
    security_profile: SecurityProfile,
    keys: &UserKeysFile,
) -> Result<()> {
    let cursor_path = sealed_inbox_cursor_path(state_dir, &keys.user_id);
    let mut cursor = load_cursor(&cursor_path)?;
    let auth_signing_key = auth_signing_key_for_user(keys)?;
    let inbox = fetch_sealed_inbox(
        client,
        server,
        &keys.user_id,
        &keys.device_id,
        cursor.since_message_id,
        &auth_signing_key,
    )
    .await?;

    let pins_path = identity_pins_file_path(state_dir, &keys.user_id);
    let pins = load_identity_pins(&pins_path, &keys.user_id)?;
    let identity = to_identity_keypair(keys)?;
    let local_secret = identity.require_secret_key()?;

    for item in inbox.messages {
        let bytes = decode_b64("message_bytes_base64", &item.message_bytes_base64)?;
        let envelope = match SealedEnvelope::decode(&bytes) {
            Ok(value) => value,
            Err(_) => {
                cursor.since_message_id = cursor.since_message_id.max(item.message_id);
                continue;
            }
        };
        security_profile.enforce_suite_id(envelope.suite_id)?;

        let mut opened_message = None;
        for pin in pins.peers.values() {
            let Some(identity_x25519_pub) = pin.identity_x25519_pub.as_deref() else {
                continue;
            };
            let Ok(peer_pub_bytes) = decode_b64_32("pin.identity_x25519_pub", identity_x25519_pub)
            else {
                continue;
            };
            let peer_pub = DhPublicKey(peer_pub_bytes);
            let Ok(sealed_key) =
                derive_pairwise_sealed_sender_key(&local_secret, &peer_pub, envelope.suite_id)
            else {
                continue;
            };
            if let Ok(opened) =
                open_sealed_message(&sealed_key, &bytes, envelope.suite_id, &keys.user_id)
            {
                opened_message = Some(opened);
                break;
            }
        }

        if let Some(opened) = opened_message {
            let text = String::from_utf8(opened.payload.clone())
                .unwrap_or_else(|_| format!("<{} bytes binary>", opened.payload.len()));
            println!("[sealed:{}] {}", opened.sender_user_id, text);
            append_message_record(
                state_dir,
                &keys.user_id,
                message_retention_seconds,
                StoredMessageRecord {
                    message_id: item.message_id,
                    peer_user_id: opened.sender_user_id,
                    direction: "incoming-sealed".to_string(),
                    text,
                    server_timestamp: item.received_at.clone(),
                    stored_at_unix: unix_time_now()?,
                    expires_at_unix: 0,
                },
            )?;
        } else {
            eprintln!(
                "unable to decrypt sealed message id {} for user '{}'",
                item.message_id, keys.user_id
            );
        }
        cursor.since_message_id = cursor.since_message_id.max(item.message_id);
    }

    save_cursor(&cursor_path, &cursor)?;
    Ok(())
}

async fn delete_messages_flow(
    client: &Client,
    server: &str,
    state_dir: &Path,
    keys: &UserKeysFile,
    options: DeleteMessagesOptions<'_>,
) -> Result<()> {
    if options.before_message_id.is_some_and(|value| value <= 0) {
        return Err(anyhow!("before_message_id must be a positive integer"));
    }
    if let Some(peer_user) = options.peer {
        validate_id("peer", peer_user)?;
    }

    let message_store_path = message_store_file_path(state_dir, &keys.user_id);
    let mut message_store = load_message_store(
        &message_store_path,
        &keys.user_id,
        options.message_retention_seconds,
    )?;
    let deleted_local_ids =
        delete_message_records(&mut message_store, options.peer, options.before_message_id);
    let deleted_local_count = deleted_local_ids.len();
    save_message_store(&message_store_path, &message_store)?;
    println!(
        "deleted {} local archived messages for user '{}'",
        deleted_local_count, keys.user_id
    );

    if !options.remote {
        return Ok(());
    }

    let auth_signing_key = auth_signing_key_for_user(keys)?;
    let mut remote_deleted_total: u64 = 0;
    if options.peer.is_none() && options.before_message_id.is_some() {
        let response = delete_inbox_remote(
            client,
            server,
            &keys.user_id,
            &keys.device_id,
            &[],
            options.before_message_id,
            &auth_signing_key,
        )
        .await?;
        validate_delete_inbox_response(&response, keys)?;
        remote_deleted_total = remote_deleted_total.saturating_add(response.deleted_count);
    } else {
        let normalized_ids = normalize_message_ids(&deleted_local_ids);
        for chunk in normalized_ids.chunks(MAX_REMOTE_DELETE_BATCH) {
            let response = delete_inbox_remote(
                client,
                server,
                &keys.user_id,
                &keys.device_id,
                chunk,
                None,
                &auth_signing_key,
            )
            .await?;
            validate_delete_inbox_response(&response, keys)?;
            remote_deleted_total = remote_deleted_total.saturating_add(response.deleted_count);
        }
    }

    println!(
        "requested remote inbox deletion for user '{}' device '{}' (deleted_count={})",
        keys.user_id, keys.device_id, remote_deleted_total
    );
    Ok(())
}

fn validate_delete_inbox_response(
    response: &DeleteInboxResponse,
    keys: &UserKeysFile,
) -> Result<()> {
    if response.user_id != keys.user_id || response.device_id != keys.device_id {
        return Err(anyhow!(
            "delete inbox response identity mismatch: expected {}/{} got {}/{}",
            keys.user_id,
            keys.device_id,
            response.user_id,
            response.device_id
        ));
    }
    if response.deleted_at.trim().is_empty() {
        return Err(anyhow!("delete inbox response missing deleted_at"));
    }
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

async fn relay_sealed_message(
    client: &Client,
    server: &str,
    recipient: &str,
    message_bytes: &[u8],
) -> Result<SealedRelayResponse> {
    let req = SealedRelayRequest {
        message_bytes_base64: B64.encode(message_bytes),
    };
    let response = client
        .post(format!("{server}/v1/sealed-relay/{recipient}"))
        .json(&req)
        .send()
        .await
        .context("sealed relay request failed")?;
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

async fn fetch_sealed_inbox(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    since: i64,
    auth_signing_key: &SigningKey,
) -> Result<SealedInboxResponse> {
    let auth_headers = sealed_inbox_auth_headers(auth_signing_key, user, device_id, since)?;
    let mut request = client.get(format!("{server}/v1/sealed-inbox/{user}?since={since}"));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("fetch sealed inbox request failed")?;
    handle_json_response(response).await
}

async fn delete_inbox_remote(
    client: &Client,
    server: &str,
    user: &str,
    device_id: &str,
    message_ids: &[i64],
    delete_before_id: Option<i64>,
    auth_signing_key: &SigningKey,
) -> Result<DeleteInboxResponse> {
    let req = DeleteInboxRequest {
        message_ids: message_ids.to_vec(),
        delete_before_id,
    };
    let auth_headers = inbox_delete_auth_headers(
        auth_signing_key,
        user,
        device_id,
        &req.message_ids,
        req.delete_before_id,
    )?;
    let mut request = client
        .post(format!("{server}/v1/inbox/{user}/delete"))
        .json(&req);
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("delete inbox request failed")?;
    handle_json_response(response).await
}

async fn post_json<T: Serialize>(client: &Client, url: String, body: &T) -> Result<Value> {
    let response = client.post(url).json(body).send().await?;
    handle_json_response(response).await
}

async fn retire_current_device_remote(
    client: &Client,
    server: &str,
    user_id: &str,
    device_id: &str,
    signing_key: &SigningKey,
) -> Result<RetireCurrentDeviceResponse> {
    let auth_headers = retire_current_device_auth_headers(signing_key, user_id, device_id)?;
    let mut request = client.post(format!(
        "{server}/v1/users/{user_id}/devices/current/retire"
    ));
    for (name, value) in auth_headers {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .await
        .context("retire current device request failed")?;
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

fn solve_registration_pow(request: &RegisterRequest, bits: u8) -> Result<String> {
    if bits == 0 {
        return Ok("0".to_string());
    }
    if bits > MAX_REGISTRATION_POW_BITS {
        return Err(anyhow!(
            "server requested registration pow bits={bits}; max supported by cli is {MAX_REGISTRATION_POW_BITS}"
        ));
    }
    let mut counter: u64 = 0;
    loop {
        let nonce = format!("{counter:x}");
        let digest = Sha256::digest(registration_pow_message(request, &nonce));
        if has_leading_zero_bits(&digest, bits) {
            return Ok(nonce);
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow!("registration pow nonce space exhausted"))?;
    }
}

fn registration_pow_message(request: &RegisterRequest, nonce: &str) -> Vec<u8> {
    [
        b"register".as_slice(),
        request.user_id.as_bytes(),
        request.device_id.as_bytes(),
        request.identity_x25519_pub.as_bytes(),
        request.identity_sig_pub.as_bytes(),
        nonce.as_bytes(),
    ]
    .join(&[0u8][..])
}

fn has_leading_zero_bits(bytes: &[u8], bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let full_bytes = usize::from(bits / 8);
    let remaining_bits = bits % 8;
    if bytes.len() < full_bytes {
        return false;
    }
    if bytes.iter().take(full_bytes).any(|byte| *byte != 0) {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    if bytes.len() <= full_bytes {
        return false;
    }
    let mask = 0xFFu8 << (8 - remaining_bits);
    bytes[full_bytes] & mask == 0
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

fn sealed_inbox_cursor_path(state_dir: &Path, user: &str) -> PathBuf {
    state_dir.join(user).join("_sealed_inbox_cursor.json")
}

fn message_store_file_path(state_dir: &Path, user: &str) -> PathBuf {
    state_dir.join(user).join("_messages.json")
}

fn wipe_local_state(
    state_dir: &Path,
    user: &str,
    keys_path: Option<&Path>,
    wipe_keys: bool,
) -> Result<LocalStateWipeSummary> {
    let state_removed = remove_path_if_exists(&state_dir.join(user))?;
    let keys_removed = if wipe_keys {
        let path = keys_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| default_keys_path(user));
        remove_path_if_exists(&path)?
    } else {
        false
    };
    Ok(LocalStateWipeSummary {
        state_removed,
        keys_removed,
    })
}

fn remove_path_if_exists(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
            .with_context(|| format!("failed to remove directory {}", path.display()))?;
    } else {
        fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    Ok(true)
}

fn message_hash_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn normalize_message_ids(message_ids: &[i64]) -> Vec<i64> {
    let mut ids = message_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn hash_string_list_sha256(values: &[String]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update(value.as_bytes());
    }
    hasher.finalize().to_vec()
}

fn unix_time_now() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system time before UNIX epoch"))?;
    i64::try_from(duration.as_secs()).map_err(|_| anyhow!("system time overflow"))
}

fn message_retention_days_to_seconds(days: u32) -> Result<i64> {
    let seconds = i64::from(days)
        .checked_mul(86_400)
        .ok_or_else(|| anyhow!("message retention days overflow"))?;
    Ok(seconds)
}

fn validate_id(field: &'static str, value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 128 {
        return Err(anyhow!("{field} must be 1..128 non-whitespace characters"));
    }
    Ok(())
}

fn validate_optional_alias(value: Option<&str>) -> Result<Option<String>> {
    let Some(alias) = value else {
        return Ok(None);
    };
    let trimmed = alias.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > MAX_CONTACT_ALIAS_LEN {
        return Err(anyhow!(
            "alias must be <= {MAX_CONTACT_ALIAS_LEN} characters"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn normalize_group_member_ids(values: &[String]) -> Result<Vec<String>> {
    if values.len() > MAX_GROUP_MEMBERS {
        return Err(anyhow!("members cannot exceed {MAX_GROUP_MEMBERS} entries"));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        validate_id("member", value)?;
        normalized.push(value.trim().to_string());
    }
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

fn decode_group_payload_b64(value: &str) -> Result<Vec<u8>> {
    let payload = decode_b64("payload_b64", value)?;
    if payload.is_empty() || payload.len() > MAX_GROUP_MESSAGE_BYTES {
        return Err(anyhow!(
            "decoded payload_b64 must be 1..={MAX_GROUP_MESSAGE_BYTES} bytes"
        ));
    }
    Ok(payload)
}

fn validate_sha256_hex(field: &'static str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != SHA256_HEX_LEN {
        return Err(anyhow!(
            "{field} must be {SHA256_HEX_LEN} lowercase hex characters"
        ));
    }
    if !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(anyhow!("{field} must be lowercase hex"));
    }
    Ok(normalized)
}

fn normalize_sha256_hashes(field: &'static str, values: &[String]) -> Result<Vec<String>> {
    if values.len() > MAX_DISCOVERY_HASHES {
        return Err(anyhow!(
            "{field} cannot exceed {MAX_DISCOVERY_HASHES} entries"
        ));
    }
    let mut hashes = values
        .iter()
        .map(|value| validate_sha256_hex(field, value))
        .collect::<Result<Vec<_>>>()?;
    hashes.sort_unstable();
    hashes.dedup();
    Ok(hashes)
}

fn identity_fingerprint_from_pub_b64(identity_pub_b64: &str) -> Result<String> {
    let bytes = decode_b64("identity_x25519_pub_b64", identity_pub_b64)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn build_qr_payload(keys: &UserKeysFile) -> Result<QrIdentityPayload> {
    Ok(QrIdentityPayload {
        version: QR_PAYLOAD_VERSION,
        user_id: keys.user_id.clone(),
        device_id: keys.device_id.clone(),
        suite: keys.suite,
        identity_x25519_pub_b64: keys.identity_x25519_pub_b64.clone(),
        identity_sig_pub_b64: keys.identity_sig_pub_b64.clone(),
        identity_fingerprint_sha256: identity_fingerprint_from_pub_b64(
            &keys.identity_x25519_pub_b64,
        )?,
        generated_at_unix: unix_time_now()?,
    })
}

fn encode_qr_payload(payload: &QrIdentityPayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload).context("failed to encode QR payload")?;
    Ok(B64URL.encode(bytes))
}

fn decode_qr_payload(payload: &str) -> Result<QrIdentityPayload> {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("qr payload cannot be empty"));
    }
    let decoded = B64URL.decode(trimmed.as_bytes()).ok();
    let parsed = if let Some(raw) = decoded {
        serde_json::from_slice::<QrIdentityPayload>(&raw)
            .context("failed to parse base64 QR payload JSON")?
    } else {
        serde_json::from_str::<QrIdentityPayload>(trimmed)
            .context("failed to parse QR payload JSON")?
    };
    Ok(parsed)
}

fn verify_qr_payload(payload: &QrIdentityPayload, expected_user: Option<&str>) -> Result<()> {
    if payload.version != QR_PAYLOAD_VERSION {
        return Err(anyhow!(
            "unsupported qr payload version '{}'",
            payload.version
        ));
    }
    if let Some(expected) = expected_user {
        if payload.user_id != expected {
            return Err(anyhow!(
                "qr payload user mismatch: expected '{}' got '{}'",
                expected,
                payload.user_id
            ));
        }
    }
    validate_id("qr.user_id", &payload.user_id)?;
    validate_id("qr.device_id", &payload.device_id)?;
    let fingerprint = identity_fingerprint_from_pub_b64(&payload.identity_x25519_pub_b64)?;
    let normalized = validate_sha256_hex(
        "qr.identity_fingerprint_sha256",
        &payload.identity_fingerprint_sha256,
    )?;
    if fingerprint != normalized {
        return Err(anyhow!(
            "qr payload fingerprint does not match identity_x25519_pub_b64"
        ));
    }
    decode_b64("qr.identity_sig_pub_b64", &payload.identity_sig_pub_b64)?;
    Ok(())
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

fn sealed_inbox_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    since: i64,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("sealed-inbox", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_SINCE,
        value: since.to_be_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode sealed-inbox auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn inbox_delete_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    message_ids: &[i64],
    delete_before_id: Option<i64>,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("inbox-delete", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let normalized_ids = normalize_message_ids(message_ids);
    let mut hasher = Sha256::new();
    for message_id in &normalized_ids {
        hasher.update(message_id.to_be_bytes());
    }
    records.push(TlvRecord {
        ty: AUTH_TAG_DELETE_IDS_HASH,
        value: hasher.finalize_reset().to_vec(),
    });
    if let Some(delete_before) = delete_before_id {
        records.push(TlvRecord {
            ty: AUTH_TAG_DELETE_BEFORE_ID,
            value: delete_before.to_be_bytes().to_vec(),
        });
    }
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode inbox-delete auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn devices_list_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("devices-list", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode devices-list auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn devices_link_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    auth_device_id: &str,
    new_device_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("devices-link", user_id, auth_device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_LINK_DEVICE_ID,
        value: new_device_id.as_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode devices-link auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, auth_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn devices_revoke_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    auth_device_id: &str,
    target_device_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("devices-revoke", user_id, auth_device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_REVOKE_DEVICE_ID,
        value: target_device_id.as_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode devices-revoke auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, auth_device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn retire_current_device_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("devices-retire", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_REVOKE_DEVICE_ID,
        value: device_id.as_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode devices-retire auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn validate_link_device_response(
    response: &LinkDeviceResponse,
    user_id: &str,
    new_device_id: &str,
) -> Result<()> {
    if response.user_id != user_id || response.linked_device_id != new_device_id {
        return Err(anyhow!(
            "link device response identity mismatch: expected {}/{} got {}/{}",
            user_id,
            new_device_id,
            response.user_id,
            response.linked_device_id
        ));
    }
    if response.linked_at.trim().is_empty() {
        return Err(anyhow!("link device response missing linked_at"));
    }
    Ok(())
}

fn validate_revoke_device_response(
    response: &RevokeDeviceResponse,
    user_id: &str,
    target_device_id: &str,
) -> Result<()> {
    if response.user_id != user_id || response.revoked_device_id != target_device_id {
        return Err(anyhow!(
            "revoke device response identity mismatch: expected {}/{} got {}/{}",
            user_id,
            target_device_id,
            response.user_id,
            response.revoked_device_id
        ));
    }
    if response.revoked_at.trim().is_empty() {
        return Err(anyhow!("revoke device response missing revoked_at"));
    }
    Ok(())
}

fn validate_retire_current_device_response(
    response: &RetireCurrentDeviceResponse,
    keys: &UserKeysFile,
) -> Result<()> {
    if response.user_id != keys.user_id || response.retired_device_id != keys.device_id {
        return Err(anyhow!(
            "retire device response identity mismatch: expected {}/{} got {}/{}",
            keys.user_id,
            keys.device_id,
            response.user_id,
            response.retired_device_id
        ));
    }
    if response.retired_at.trim().is_empty() {
        return Err(anyhow!("retire device response missing retired_at"));
    }
    Ok(())
}

fn discovery_handles_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    phone_hashes_sha256: &[String],
    email_hashes_sha256: &[String],
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("discovery-handles", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH,
        value: hash_string_list_sha256(&normalize_sha256_hashes(
            "phone_hashes_sha256",
            phone_hashes_sha256,
        )?),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH,
        value: hash_string_list_sha256(&normalize_sha256_hashes(
            "email_hashes_sha256",
            email_hashes_sha256,
        )?),
    });
    let transcript = encode(&records)
        .map_err(|_| anyhow!("failed to encode discovery-handles auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn discovery_match_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    hashes_sha256: &[String],
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("discovery-match", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH,
        value: hash_string_list_sha256(&normalize_sha256_hashes("hashes_sha256", hashes_sha256)?),
    });
    let transcript = encode(&records)
        .map_err(|_| anyhow!("failed to encode discovery-match auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn contacts_list_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("contacts-list", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode contacts-list auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn contacts_upsert_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    contact_user_id: &str,
    alias: Option<&str>,
    verified_by_qr: bool,
    verified_fingerprint_sha256: Option<&str>,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("contacts-upsert", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    let mut alias_hasher = Sha256::new();
    alias_hasher.update(alias.unwrap_or_default().as_bytes());
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_ALIAS_HASH,
        value: alias_hasher.finalize().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_VERIFIED_FLAG,
        value: vec![if verified_by_qr { 1 } else { 0 }],
    });
    if let Some(fingerprint) = verified_fingerprint_sha256 {
        records.push(TlvRecord {
            ty: AUTH_TAG_CONTACT_FINGERPRINT,
            value: fingerprint.as_bytes().to_vec(),
        });
    }
    let transcript = encode(&records)
        .map_err(|_| anyhow!("failed to encode contacts-upsert auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn contacts_remove_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    contact_user_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("contacts-remove", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_RECIPIENT_ID,
        value: user_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_CONTACT_USER_ID,
        value: contact_user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| anyhow!("failed to encode contacts-remove auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn groups_create_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    member_user_ids: &[String],
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("groups-create", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBERS_HASH,
        value: hash_string_list_sha256(&normalize_group_member_ids(member_user_ids)?),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode groups-create auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn groups_members_list_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("groups-members-list", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| anyhow!("failed to encode groups-members-list auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn groups_members_add_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    member_user_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records =
        auth_common_records("groups-members-add", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| anyhow!("failed to encode groups-members-add auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn groups_members_remove_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    member_user_id: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records(
        "groups-members-remove",
        user_id,
        device_id,
        timestamp,
        &nonce,
    );
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MEMBER_USER_ID,
        value: member_user_id.as_bytes().to_vec(),
    });
    let transcript = encode(&records)
        .map_err(|_| anyhow!("failed to encode groups-members-remove auth transcript"))?;
    let signature = signing_key.sign(&transcript).to_bytes();
    Ok(vec![
        (AUTH_HEADER_USER, user_id.to_string()),
        (AUTH_HEADER_DEVICE, device_id.to_string()),
        (AUTH_HEADER_TIMESTAMP, timestamp.to_string()),
        (AUTH_HEADER_NONCE, nonce),
        (AUTH_HEADER_SIGNATURE, B64.encode(signature)),
    ])
}

fn groups_relay_auth_headers(
    signing_key: &SigningKey,
    user_id: &str,
    device_id: &str,
    group_id: &str,
    sender_user_id: &str,
    message_blob: &[u8],
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = auth_timestamp()?;
    let nonce = auth_nonce();
    let mut records = auth_common_records("groups-relay", user_id, device_id, timestamp, &nonce);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_ID,
        value: group_id.as_bytes().to_vec(),
    });
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_SENDER_USER_ID,
        value: sender_user_id.as_bytes().to_vec(),
    });
    let mut hasher = Sha256::new();
    hasher.update(message_blob);
    records.push(TlvRecord {
        ty: AUTH_TAG_GROUP_MESSAGE_BLOB_HASH,
        value: hasher.finalize().to_vec(),
    });
    let transcript =
        encode(&records).map_err(|_| anyhow!("failed to encode groups-relay auth transcript"))?;
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
        identity_x25519_pub: Some(bundle.identity_x25519_pub.clone()),
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
    let kem = build_kem_for_suite(file.suite)?;
    Ok(SessionState::from_snapshot_with_kem(
        file.snapshot,
        Some(Box::new(kem)),
    ))
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

fn default_message_store(user_id: &str, retention_seconds: i64) -> MessageStoreFile {
    MessageStoreFile {
        version: MESSAGE_STORE_VERSION,
        user_id: user_id.to_string(),
        retention_seconds,
        messages: Vec::new(),
    }
}

fn load_message_store(
    path: &Path,
    user_id: &str,
    retention_seconds: i64,
) -> Result<MessageStoreFile> {
    if !path.exists() {
        return Ok(default_message_store(user_id, retention_seconds));
    }
    let mut store: MessageStoreFile = read_json_file(path)?;
    if store.version != MESSAGE_STORE_VERSION {
        return Err(anyhow!(
            "unsupported message store version '{}' in {}",
            store.version,
            path.display()
        ));
    }
    if store.user_id != user_id {
        return Err(anyhow!(
            "message store user mismatch in {}: expected '{}' got '{}'",
            path.display(),
            user_id,
            store.user_id
        ));
    }
    store.retention_seconds = retention_seconds;
    prune_message_store(&mut store, unix_time_now()?);
    Ok(store)
}

fn save_message_store(path: &Path, store: &MessageStoreFile) -> Result<()> {
    write_json_file(path, store)
}

fn prune_message_store(store: &mut MessageStoreFile, now_unix: i64) {
    store
        .messages
        .retain(|item| item.expires_at_unix > 0 && item.expires_at_unix > now_unix);
    if store.messages.len() > MAX_LOCAL_MESSAGE_HISTORY {
        let overflow = store.messages.len() - MAX_LOCAL_MESSAGE_HISTORY;
        store.messages.drain(0..overflow);
    }
}

fn append_message_record(
    state_dir: &Path,
    user_id: &str,
    retention_seconds: i64,
    mut record: StoredMessageRecord,
) -> Result<()> {
    let store_path = message_store_file_path(state_dir, user_id);
    let mut store = load_message_store(&store_path, user_id, retention_seconds)?;
    if record.stored_at_unix <= 0 {
        record.stored_at_unix = unix_time_now()?;
    }
    record.expires_at_unix = record.stored_at_unix.saturating_add(retention_seconds);
    store.messages.push(record);
    prune_message_store(&mut store, unix_time_now()?);
    save_message_store(&store_path, &store)
}

fn delete_message_records(
    store: &mut MessageStoreFile,
    peer: Option<&str>,
    before_message_id: Option<i64>,
) -> Vec<i64> {
    let mut deleted_ids = Vec::new();
    store.messages.retain(|item| {
        let peer_match = peer.map_or(true, |target| item.peer_user_id == target);
        let before_match = before_message_id.map_or(true, |threshold| item.message_id <= threshold);
        let should_delete = peer_match && before_match;
        if should_delete && item.message_id > 0 {
            deleted_ids.push(item.message_id);
        }
        !should_delete
    });
    normalize_message_ids(&deleted_ids)
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
    fn parse_delete_messages_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "delete-messages",
            "--user",
            "alice",
            "--keys",
            "./devkeys/alice.json",
            "--peer",
            "bob",
            "--before-message-id",
            "42",
            "--remote",
        ])
        .expect("parse");
        match cli.command {
            Commands::DeleteMessages {
                user,
                keys,
                peer,
                before_message_id,
                remote,
            } => {
                assert_eq!(user, "alice");
                assert_eq!(keys, PathBuf::from("./devkeys/alice.json"));
                assert_eq!(peer.as_deref(), Some("bob"));
                assert_eq!(before_message_id, Some(42));
                assert!(remote);
            }
            _ => panic!("expected delete-messages command"),
        }
    }

    #[test]
    fn parse_reset_local_state_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "reset-local-state",
            "--user",
            "alice",
            "--wipe-keys",
        ])
        .expect("parse");
        match cli.command {
            Commands::ResetLocalState {
                user,
                keys,
                wipe_keys,
                remote_retire,
            } => {
                assert_eq!(user, "alice");
                assert!(keys.is_none());
                assert!(wipe_keys);
                assert!(!remote_retire);
            }
            _ => panic!("expected reset-local-state command"),
        }
    }

    #[test]
    fn parse_devices_list_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "devices-list",
            "--user",
            "alice",
            "--keys",
            "./devkeys/alice.json",
        ])
        .expect("parse");
        match cli.command {
            Commands::DevicesList { user, keys } => {
                assert_eq!(user, "alice");
                assert_eq!(keys, PathBuf::from("./devkeys/alice.json"));
            }
            _ => panic!("expected devices-list command"),
        }
    }

    #[test]
    fn parse_devices_link_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "devices-link",
            "--user",
            "alice",
            "--keys",
            "./devkeys/alice.json",
            "--new-device-id",
            "alice-device-2",
        ])
        .expect("parse");
        match cli.command {
            Commands::DevicesLink {
                user,
                keys,
                new_device_id,
            } => {
                assert_eq!(user, "alice");
                assert_eq!(keys, PathBuf::from("./devkeys/alice.json"));
                assert_eq!(new_device_id, "alice-device-2");
            }
            _ => panic!("expected devices-link command"),
        }
    }

    #[test]
    fn parse_devices_revoke_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "devices-revoke",
            "--user",
            "alice",
            "--keys",
            "./devkeys/alice.json",
            "--target-device-id",
            "alice-device-2",
        ])
        .expect("parse");
        match cli.command {
            Commands::DevicesRevoke {
                user,
                keys,
                target_device_id,
            } => {
                assert_eq!(user, "alice");
                assert_eq!(keys, PathBuf::from("./devkeys/alice.json"));
                assert_eq!(target_device_id, "alice-device-2");
            }
            _ => panic!("expected devices-revoke command"),
        }
    }

    #[test]
    fn parse_groups_create_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "groups-create",
            "--user",
            "alice",
            "--keys",
            "./devkeys/alice.json",
            "--group",
            "alpha",
            "--member",
            "bob",
            "--member",
            "carol",
        ])
        .expect("parse");
        match cli.command {
            Commands::GroupsCreate {
                user,
                keys,
                group,
                members,
            } => {
                assert_eq!(user, "alice");
                assert_eq!(keys, PathBuf::from("./devkeys/alice.json"));
                assert_eq!(group, "alpha");
                assert_eq!(members, vec!["bob".to_string(), "carol".to_string()]);
            }
            _ => panic!("expected groups-create command"),
        }
    }

    #[test]
    fn parse_send_sealed_args() {
        let cli = Cli::try_parse_from([
            "pqmsg-cli",
            "send-sealed",
            "--from",
            "alice",
            "--to",
            "bob",
            "--text",
            "hello",
        ])
        .expect("parse");
        match cli.command {
            Commands::SendSealed { from, to, text, .. } => {
                assert_eq!(from, "alice");
                assert_eq!(to, "bob");
                assert_eq!(text, "hello");
            }
            _ => panic!("expected send-sealed command"),
        }
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

    fn sample_capabilities() -> ServerCapabilitiesResponse {
        ServerCapabilitiesResponse {
            capability_schema_version: 1,
            security_profile: "high_assurance".to_string(),
            deployment_mode: "development".to_string(),
            tls_required: true,
            tls_enabled: true,
            supported_suite_ids: vec![
                SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305,
                SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305,
            ],
            runtime_crypto_profile: runtime_crypto_profile().expect("runtime profile"),
            production_baseline_met: false,
            registration_pow_bits: 0,
            prekey_bundle_reserve_count: 2,
            pq_ratchet_interval: 4,
            web_client_policy: "demo_only".to_string(),
        }
    }

    #[test]
    fn nss_client_rejects_weaker_server_profile() {
        let mut capabilities = sample_capabilities();
        capabilities.security_profile = "high_assurance".to_string();
        let result = validate_server_capabilities_for_cli(
            SecurityProfile::NssAligned,
            Some(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305),
            &capabilities,
            "https://example.test",
        );
        assert!(result.is_err());
    }

    #[test]
    fn production_mode_requires_server_baseline() {
        let mut capabilities = sample_capabilities();
        capabilities.deployment_mode = "production".to_string();
        capabilities.production_baseline_met = false;
        let result = validate_server_capabilities_for_cli(
            SecurityProfile::HighAssurance,
            Some(SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305),
            &capabilities,
            "https://example.test",
        );
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_unsupported_suite_from_server_capabilities() {
        let mut capabilities = sample_capabilities();
        capabilities.supported_suite_ids =
            vec![SUITE_ID_MLKEM768_X25519_HKDF_SHA256_CHACHA20POLY1305];
        let result = validate_server_capabilities_for_cli(
            SecurityProfile::HighAssurance,
            Some(SUITE_ID_KYBER768_X25519_HKDF_SHA256_CHACHA20POLY1305),
            &capabilities,
            "https://example.test",
        );
        assert!(result.is_err());
    }

    #[test]
    fn message_store_prunes_expired_entries() {
        let dir = tempdir().expect("tempdir");
        let path = message_store_file_path(dir.path(), "alice");
        let now = unix_time_now().expect("unix now");
        let mut store = default_message_store("alice", 60);
        store.messages.push(StoredMessageRecord {
            message_id: 1,
            peer_user_id: "bob".to_string(),
            direction: "incoming".to_string(),
            text: "expired".to_string(),
            server_timestamp: None,
            stored_at_unix: now - 120,
            expires_at_unix: now - 1,
        });
        store.messages.push(StoredMessageRecord {
            message_id: 2,
            peer_user_id: "bob".to_string(),
            direction: "incoming".to_string(),
            text: "fresh".to_string(),
            server_timestamp: None,
            stored_at_unix: now,
            expires_at_unix: now + 60,
        });
        save_message_store(&path, &store).expect("save");
        let loaded = load_message_store(&path, "alice", 60).expect("load");
        assert_eq!(loaded.messages.len(), 1);
        assert_eq!(loaded.messages[0].message_id, 2);
    }

    #[test]
    fn delete_message_records_filters_by_peer_and_message_id() {
        let mut store = default_message_store("alice", 60);
        store.messages = vec![
            StoredMessageRecord {
                message_id: 1,
                peer_user_id: "bob".to_string(),
                direction: "incoming".to_string(),
                text: "a".to_string(),
                server_timestamp: None,
                stored_at_unix: 1,
                expires_at_unix: 100,
            },
            StoredMessageRecord {
                message_id: 2,
                peer_user_id: "bob".to_string(),
                direction: "outgoing".to_string(),
                text: "b".to_string(),
                server_timestamp: None,
                stored_at_unix: 2,
                expires_at_unix: 100,
            },
            StoredMessageRecord {
                message_id: 3,
                peer_user_id: "carol".to_string(),
                direction: "incoming".to_string(),
                text: "c".to_string(),
                server_timestamp: None,
                stored_at_unix: 3,
                expires_at_unix: 100,
            },
        ];
        let deleted = delete_message_records(&mut store, Some("bob"), Some(2));
        assert_eq!(deleted, vec![1, 2]);
        assert_eq!(store.messages.len(), 1);
        assert_eq!(store.messages[0].peer_user_id, "carol");
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
    fn wipe_local_state_removes_only_requested_user() {
        let dir = tempdir().expect("tempdir");
        let alice_state = dir.path().join("state").join("alice");
        let bob_state = dir.path().join("state").join("bob");
        fs::create_dir_all(&alice_state).expect("alice state dir");
        fs::create_dir_all(&bob_state).expect("bob state dir");
        fs::write(alice_state.join("_messages.json"), b"{}").expect("alice messages");
        fs::write(bob_state.join("_messages.json"), b"{}").expect("bob messages");

        let alice_keys = dir.path().join("alice.json");
        let bob_keys = dir.path().join("bob.json");
        fs::write(&alice_keys, b"{}").expect("alice keys");
        fs::write(&bob_keys, b"{}").expect("bob keys");

        let summary = wipe_local_state(
            dir.path().join("state").as_path(),
            "alice",
            Some(&alice_keys),
            true,
        )
        .expect("wipe");
        assert!(summary.state_removed);
        assert!(summary.keys_removed);
        assert!(!alice_state.exists());
        assert!(!alice_keys.exists());
        assert!(bob_state.exists());
        assert!(bob_keys.exists());
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
