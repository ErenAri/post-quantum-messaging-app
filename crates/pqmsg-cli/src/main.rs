use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
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
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DEFAULT_STATE_DIR: &str = "./state";
const DEFAULT_KEYS_DIR: &str = "./devkeys";
const DEFAULT_ONE_TIME_PREKEYS: usize = 16;

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum, Serialize, Deserialize)]
enum SuiteFlag {
    #[value(name = "ml-kem-768")]
    MlKem768,
    #[value(name = "kyber768")]
    Kyber768,
}

#[derive(Debug, Parser)]
#[command(name = "pqmsg-cli")]
struct Cli {
    #[arg(long, global = true, default_value = "http://localhost:3000")]
    server: String,
    #[arg(long, global = true, default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InboxCursor {
    since_message_id: i64,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = Client::new();

    match cli.command {
        Commands::Keygen {
            user,
            out,
            suite,
            one_time_count,
            device_id,
        } => {
            let keys = generate_user_keys(
                &user,
                device_id.unwrap_or_else(|| format!("{user}-device-1")),
                suite,
                one_time_count,
            );
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
            publish_prekeys(&client, &cli.server, &keys_file).await?;
        }
        Commands::Send {
            from,
            to,
            text,
            keys,
            suite,
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
            send_message_flow(
                &client,
                &cli.server,
                &cli.state_dir,
                &keys_file,
                &from,
                &to,
                text.as_bytes(),
            )
            .await?;
        }
        Commands::Poll { user, keys } => {
            let keys_file = read_keys_file(&keys)?;
            if keys_file.user_id != user {
                return Err(anyhow!(
                    "user mismatch: command user '{}' vs keys file user '{}'",
                    user,
                    keys_file.user_id
                ));
            }
            poll_inbox_flow(&client, &cli.server, &cli.state_dir, &keys_file).await?;
        }
    }

    Ok(())
}

fn generate_user_keys(
    user: &str,
    device_id: String,
    suite: SuiteFlag,
    one_time_count: usize,
) -> UserKeysFile {
    let mut rng = OsRng;
    let identity = IdentityKeyPair::generate(format!("{user}-ik"), &mut rng);
    let signed_prekey = OneTimePreKey::generate(format!("{user}-spk"), &mut rng);

    let mut identity_sig = [0u8; 32];
    rng.fill_bytes(&mut identity_sig);

    let mut pq_signed_prekey = [0u8; 32];
    rng.fill_bytes(&mut pq_signed_prekey);

    let mut one_time_x25519 = Vec::with_capacity(one_time_count);
    let mut one_time_mlkem = Vec::with_capacity(one_time_count);

    for idx in 0..one_time_count {
        let key = OneTimePreKey::generate(format!("{user}-otk-x-{idx}"), &mut rng);
        one_time_x25519.push(OneTimeKeyRecord {
            key_id: key.key_id,
            public_b64: B64.encode(key.public_key.0),
            secret_b64: B64.encode(key.secret_key.as_slice()),
        });

        let mut pq_key = [0u8; 32];
        rng.fill_bytes(&mut pq_key);
        one_time_mlkem.push(OneTimeKeyRecord {
            key_id: format!("{user}-otk-pq-{idx}"),
            public_b64: B64.encode(pq_key),
            secret_b64: B64.encode(pq_key),
        });
    }

    UserKeysFile {
        version: 1,
        user_id: user.to_string(),
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
    }
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
    let sig_pub = decode_b64("identity_sig_pub_b64", &keys.identity_sig_pub_b64)?;

    let spk_msg = signed_prekey_signature_message(1, &DhPublicKey(spk_pub))?;
    let pq_msg = pq_signed_prekey_signature_message(1, &pq_spk_pub)?;

    let req = PublishPrekeysRequest {
        signed_prekey_x25519_pub: keys.signed_prekey_x25519_pub_b64.clone(),
        sig_over_spk: B64.encode(demo_signature(&sig_pub, &spk_msg)),
        pq_signed_prekey_pub_mlkem768: keys.pq_signed_prekey_pub_b64.clone(),
        sig_over_pqspk: B64.encode(demo_signature(&sig_pub, &pq_msg)),
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

    let value = post_json(
        client,
        format!("{server}/v1/users/{}/prekeys", keys.user_id),
        &req,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn send_message_flow(
    client: &Client,
    server: &str,
    state_dir: &Path,
    sender_keys: &UserKeysFile,
    from: &str,
    to: &str,
    plaintext: &[u8],
) -> Result<()> {
    let session_path = session_file_path(state_dir, from, to);
    let ad = make_ad(from, to);

    if session_path.exists() {
        let mut session = load_session(&session_path)?;
        let wire = session.encrypt(plaintext, &ad)?;
        let response =
            relay_message(client, server, from, &sender_keys.device_id, &wire, to).await?;
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
    let prekey_bundle = bundle_to_core(&bundle, sender_keys.suite)?;
    let identity = to_identity_keypair(sender_keys)?;
    let kem = DemoKem;
    let verifier = DemoSignatureVerifier;

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
    keys: &UserKeysFile,
) -> Result<()> {
    let cursor_path = inbox_cursor_path(state_dir, &keys.user_id);
    let mut cursor = load_cursor(&cursor_path)?;
    let inbox = fetch_inbox(client, server, &keys.user_id, cursor.since_message_id).await?;

    for item in inbox.messages {
        let bytes = decode_b64("message_bytes_base64", &item.message_bytes_base64)?;
        let sender = item.sender_user_id.clone();
        let ad = make_ad(&sender, &keys.user_id);
        let session_path = session_file_path(state_dir, &keys.user_id, &sender);

        let mut handled = false;
        if let Ok(initial) = InitialMessage::decode(&bytes) {
            let kem = DemoKem;
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
                    suite: keys.suite,
                    snapshot: session.snapshot(),
                    passphrase_kdf_hint: None,
                },
            )?;
            handled = true;
        }

        if !handled {
            if session_path.exists() {
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
        }

        if !handled {
            eprintln!(
                "[{}] no session and message is not a valid handshake initial (msg id {})",
                sender, item.message_id
            );
        }

        cursor.since_message_id = cursor.since_message_id.max(item.message_id);
    }

    save_cursor(&cursor_path, &cursor)?;
    Ok(())
}

fn bundle_to_core(bundle: &BundleResponse, suite: SuiteFlag) -> Result<PreKeyBundle> {
    let mut core_suite = AlgorithmSuite::default();
    core_suite.kem = match suite {
        SuiteFlag::MlKem768 => KemAlgorithm::MlKem768,
        SuiteFlag::Kyber768 => KemAlgorithm::Kyber768Alias,
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
) -> Result<RelayResponse> {
    let req = RelayRequest {
        sender_user_id: sender_user_id.to_string(),
        device_id: device_id.to_string(),
        message_bytes_base64: B64.encode(message_bytes),
    };
    let response = client
        .post(format!("{server}/v1/relay/{recipient}"))
        .json(&req)
        .send()
        .await
        .context("relay request failed")?;
    handle_json_response(response).await
}

async fn fetch_inbox(
    client: &Client,
    server: &str,
    user: &str,
    since: i64,
) -> Result<InboxResponse> {
    let response = client
        .get(format!("{server}/v1/inbox/{user}?since={since}"))
        .send()
        .await
        .context("fetch inbox request failed")?;
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

fn session_file_path(state_dir: &Path, user: &str, peer: &str) -> PathBuf {
    state_dir.join(user).join(format!("{peer}.json"))
}

fn inbox_cursor_path(state_dir: &Path, user: &str) -> PathBuf {
    state_dir.join(user).join("_inbox_cursor.json")
}

fn make_ad(sender: &str, recipient: &str) -> Vec<u8> {
    format!("pqmsg-cli-ad:v1:{sender}:{recipient}").into_bytes()
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

fn read_keys_file(path: &Path) -> Result<UserKeysFile> {
    read_json_file(path)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&data).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(value)?;
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
    fn mocked_flow_handshake_then_session_roundtrip() {
        let alice_keys = generate_user_keys(
            "alice",
            "alice-device-1".to_string(),
            SuiteFlag::MlKem768,
            4,
        );
        let bob_keys =
            generate_user_keys("bob", "bob-device-1".to_string(), SuiteFlag::MlKem768, 4);

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
                demo_signature(&sig_pub, &spk_msg),
                demo_signature(&sig_pub, &pq_msg),
                sig_pub,
            );
            out.suite.kem = KemAlgorithm::MlKem768;
            out
        };

        let alice_identity = to_identity_keypair(&alice_keys).expect("alice identity");
        let kem = DemoKem;
        let verifier = DemoSignatureVerifier;
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
        let ad = make_ad("alice", "bob");
        let wire = alice_session.encrypt(b"next", &ad).expect("encrypt");
        let plain = bob_session.decrypt(&wire, &ad).expect("decrypt");
        assert_eq!(plain, b"next");
    }
}
