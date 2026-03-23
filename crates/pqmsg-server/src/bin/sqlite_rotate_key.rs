use anyhow::Context;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pqmsg_server::{
    parse_db_backend, rotate_sqlite_encrypted_database_key, DbBackend, SqliteEncryptionConfig,
    SqliteEncryptionRotation,
};
use std::env;

fn usage() -> &'static str {
    "Usage: cargo run -p pqmsg-server --bin sqlite_rotate_key -- \
  --database-url <sqlite-url> \
  --from-key-b64 <base64-current-32-byte-key> \
  --to-key-b64 <base64-target-32-byte-key> \
  [--cipher-compatibility <1..4>] \
  [--cipher-page-size <512..65536-power-of-two>]

Environment fallbacks:
  PQMSG_DATABASE_URL
  PQMSG_SQLITE_ROTATE_FROM_KEY_B64
  PQMSG_SQLITE_ENCRYPTION_KEY_B64
  PQMSG_SQLITE_CIPHER_COMPATIBILITY
  PQMSG_SQLITE_CIPHER_PAGE_SIZE"
}

#[derive(Default)]
struct RawArgs {
    database_url: Option<String>,
    from_key_b64: Option<String>,
    to_key_b64: Option<String>,
    cipher_compatibility: Option<u8>,
    cipher_page_size: Option<u32>,
    help: bool,
}

fn parse_args() -> anyhow::Result<RawArgs> {
    let mut raw = RawArgs::default();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => raw.help = true,
            "--database-url" => raw.database_url = Some(expect_value(&mut args, "--database-url")?),
            "--from-key-b64" => raw.from_key_b64 = Some(expect_value(&mut args, "--from-key-b64")?),
            "--to-key-b64" => raw.to_key_b64 = Some(expect_value(&mut args, "--to-key-b64")?),
            "--cipher-compatibility" => {
                let value = expect_value(&mut args, "--cipher-compatibility")?;
                raw.cipher_compatibility = Some(value.parse::<u8>().with_context(|| {
                    format!("invalid --cipher-compatibility '{value}': expected integer 1..4")
                })?);
            }
            "--cipher-page-size" => {
                let value = expect_value(&mut args, "--cipher-page-size")?;
                raw.cipher_page_size = Some(value.parse::<u32>().with_context(|| {
                    format!("invalid --cipher-page-size '{value}': expected integer")
                })?);
            }
            other => anyhow::bail!("unknown argument '{other}'\n\n{}", usage()),
        }
    }
    Ok(raw)
}

fn expect_value(args: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing value for {flag}\n\n{}", usage()))
}

fn env_or(raw: Option<String>, env_name: &str) -> Option<String> {
    raw.or_else(|| env::var(env_name).ok()).and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn env_or_parsed_u8(raw: Option<u8>, env_name: &str) -> anyhow::Result<Option<u8>> {
    match raw {
        Some(value) => Ok(Some(value)),
        None => match env::var(env_name) {
            Ok(value) if !value.trim().is_empty() => value
                .parse::<u8>()
                .with_context(|| format!("invalid {env_name}='{value}': expected integer 1..4"))
                .map(Some),
            Ok(_) | Err(_) => Ok(None),
        },
    }
}

fn env_or_parsed_u32(raw: Option<u32>, env_name: &str) -> anyhow::Result<Option<u32>> {
    match raw {
        Some(value) => Ok(Some(value)),
        None => match env::var(env_name) {
            Ok(value) if !value.trim().is_empty() => value
                .parse::<u32>()
                .with_context(|| format!("invalid {env_name}='{value}': expected integer"))
                .map(Some),
            Ok(_) | Err(_) => Ok(None),
        },
    }
}

fn decode_key(name: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    B64.decode(value.trim())
        .with_context(|| format!("invalid {name}: expected base64-encoded 32-byte raw key"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw = parse_args()?;
    if raw.help {
        println!("{}", usage());
        return Ok(());
    }

    let database_url = env_or(raw.database_url, "PQMSG_DATABASE_URL").ok_or_else(|| {
        anyhow::anyhow!(
            "missing --database-url and PQMSG_DATABASE_URL\n\n{}",
            usage()
        )
    })?;
    if parse_db_backend(&database_url).map_err(|message| anyhow::anyhow!("{message}"))?
        != DbBackend::Sqlite
    {
        anyhow::bail!("sqlite_rotate_key only supports sqlite:// database URLs");
    }

    let from_key_b64 =
        env_or(raw.from_key_b64, "PQMSG_SQLITE_ROTATE_FROM_KEY_B64").ok_or_else(|| {
            anyhow::anyhow!(
                "missing --from-key-b64 and PQMSG_SQLITE_ROTATE_FROM_KEY_B64\n\n{}",
                usage()
            )
        })?;
    let to_key_b64 =
        env_or(raw.to_key_b64, "PQMSG_SQLITE_ENCRYPTION_KEY_B64").ok_or_else(|| {
            anyhow::anyhow!(
                "missing --to-key-b64 and PQMSG_SQLITE_ENCRYPTION_KEY_B64\n\n{}",
                usage()
            )
        })?;
    let cipher_compatibility = env_or_parsed_u8(
        raw.cipher_compatibility,
        "PQMSG_SQLITE_CIPHER_COMPATIBILITY",
    )?;
    let cipher_page_size =
        env_or_parsed_u32(raw.cipher_page_size, "PQMSG_SQLITE_CIPHER_PAGE_SIZE")?;

    let mut target =
        SqliteEncryptionConfig::from_raw_key(&decode_key("--to-key-b64", &to_key_b64)?)
            .map_err(anyhow::Error::msg)?;
    if let Some(value) = cipher_compatibility {
        target = target
            .with_cipher_compatibility(value)
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(value) = cipher_page_size {
        target = target
            .with_cipher_page_size(value)
            .map_err(anyhow::Error::msg)?;
    }
    let current =
        SqliteEncryptionConfig::from_raw_key(&decode_key("--from-key-b64", &from_key_b64)?)
            .map_err(anyhow::Error::msg)?
            .copy_cipher_settings_from(&target)
            .map_err(anyhow::Error::msg)?;

    match rotate_sqlite_encrypted_database_key(&database_url, &current, &target).await? {
        SqliteEncryptionRotation::NoExistingFile => {
            println!("No SQLite database file exists at the configured path; nothing rotated.");
        }
        SqliteEncryptionRotation::AlreadyUsingTargetKey => {
            println!("SQLite database already uses the configured target key.");
        }
        SqliteEncryptionRotation::Rotated => {
            println!("SQLite SQLCipher key rotation completed successfully.");
        }
    }

    Ok(())
}
