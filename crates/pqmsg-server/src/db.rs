use crate::error::AppError;
use anyhow::{anyhow, Context};
use sqlx::any::AnyPoolOptions;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{AnyPool, ConnectOptions, Connection, Executor, Row};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration as StdDuration;

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbBackend {
    Sqlite,
    Postgres,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteEncryptionConfig {
    key_hex: String,
    cipher_compatibility: Option<u8>,
    cipher_page_size: Option<u32>,
}

impl SqliteEncryptionConfig {
    pub fn from_raw_key(key_bytes: &[u8]) -> Result<Self, &'static str> {
        if key_bytes.len() != 32 {
            return Err("SQLite encryption key must be exactly 32 bytes");
        }
        Ok(Self {
            key_hex: hex::encode(key_bytes),
            cipher_compatibility: None,
            cipher_page_size: None,
        })
    }

    pub fn with_cipher_compatibility(mut self, version: u8) -> Result<Self, &'static str> {
        if !(1..=4).contains(&version) {
            return Err("SQLite cipher compatibility must be between 1 and 4");
        }
        self.cipher_compatibility = Some(version);
        Ok(self)
    }

    pub fn with_cipher_page_size(mut self, page_size: u32) -> Result<Self, &'static str> {
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(
                "SQLite cipher page size must be a power of two between 512 and 65536 bytes",
            );
        }
        self.cipher_page_size = Some(page_size);
        Ok(self)
    }

    fn key_pragma_value(&self) -> String {
        format!("\"x'{}'\"", self.key_hex)
    }

    fn key_pragma_sql(&self) -> String {
        format!("PRAGMA key = {};", self.key_pragma_value())
    }

    fn connect_pragmas(&self) -> Vec<String> {
        let mut statements = Vec::with_capacity(4);
        statements.push(self.key_pragma_sql());
        if let Some(version) = self.cipher_compatibility {
            statements.push(format!("PRAGMA cipher_compatibility = {version};"));
        }
        if let Some(page_size) = self.cipher_page_size {
            statements.push(format!("PRAGMA cipher_page_size = {page_size};"));
        }
        statements
    }

    fn apply_to_options(&self, options: SqliteConnectOptions) -> SqliteConnectOptions {
        let mut options = options.pragma("key", self.key_pragma_value());
        if let Some(version) = self.cipher_compatibility {
            options = options.pragma("cipher_compatibility", version.to_string());
        }
        if let Some(page_size) = self.cipher_page_size {
            options = options.pragma("cipher_page_size", page_size.to_string());
        }
        options
    }

    fn attached_database_pragmas(&self, schema: &str) -> Vec<String> {
        let mut statements = Vec::with_capacity(2);
        if let Some(version) = self.cipher_compatibility {
            statements.push(format!("PRAGMA {schema}.cipher_compatibility = {version};"));
        }
        if let Some(page_size) = self.cipher_page_size {
            statements.push(format!("PRAGMA {schema}.cipher_page_size = {page_size};"));
        }
        statements
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteEncryptionPreparation {
    NoExistingFile,
    AlreadyEncrypted,
    MigratedPlaintext,
}

impl DbBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

pub fn parse_db_backend(database_url: &str) -> Result<DbBackend, &'static str> {
    let normalized = database_url.trim().to_ascii_lowercase();
    if normalized.starts_with("sqlite:") {
        return Ok(DbBackend::Sqlite);
    }
    if normalized.starts_with("postgres:")
        || normalized.starts_with("postgresql:")
        || normalized.starts_with("pgsql:")
    {
        return Ok(DbBackend::Postgres);
    }
    Err("unsupported PQMSG_DATABASE_URL scheme; expected sqlite:// or postgres://")
}

pub async fn init_db(
    pool: &AnyPool,
    db_backend: DbBackend,
) -> Result<(), sqlx::migrate::MigrateError> {
    match db_backend {
        DbBackend::Sqlite => SQLITE_MIGRATOR.run(pool).await,
        DbBackend::Postgres => POSTGRES_MIGRATOR.run(pool).await,
    }
}

pub async fn prepare_sqlite_encrypted_database(
    database_url: &str,
    encryption: &SqliteEncryptionConfig,
    allow_plaintext_migration: bool,
) -> anyhow::Result<SqliteEncryptionPreparation> {
    if sqlite_database_is_memory(database_url) {
        return Ok(SqliteEncryptionPreparation::NoExistingFile);
    }

    let base_options = sqlite_connect_options(database_url, false)?;
    let database_path = base_options.get_filename().to_path_buf();
    if !database_path.exists() {
        return Ok(SqliteEncryptionPreparation::NoExistingFile);
    }

    if try_open_sqlite(database_url, Some(encryption))
        .await
        .is_ok()
    {
        return Ok(SqliteEncryptionPreparation::AlreadyEncrypted);
    }

    let mut plaintext = try_open_sqlite(database_url, None).await.with_context(|| {
        format!(
            "failed to open '{}' as plaintext SQLite after encrypted open failed",
            database_path.display()
        )
    })?;
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master")
        .fetch_one(&mut plaintext)
        .await
        .with_context(|| {
            format!(
                "database '{}' is neither readable as SQLCipher with the supplied key nor as plaintext SQLite",
                database_path.display()
            )
        })?;

    if !allow_plaintext_migration {
        plaintext.close().await.ok();
        return Err(anyhow!(
            "SQLite encryption key provided for plaintext database '{}'. Set PQMSG_SQLITE_MIGRATE_PLAINTEXT=true to migrate it to SQLCipher, or move the plaintext file aside first.",
            database_path.display()
        ));
    }

    let migrating_path = sqlite_sibling_path(&database_path, ".sqlcipher-migrating");
    let backup_path = sqlite_sibling_path(&database_path, ".plaintext-backup");
    ensure_absent(&migrating_path, "stale SQLCipher migration file")?;
    ensure_absent(&backup_path, "stale plaintext backup file")?;

    let user_version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut plaintext)
        .await
        .context("read SQLite user_version before migration")?;
    let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut plaintext)
        .await
        .context("read SQLite application_id before migration")?;

    let attach_path = sql_quote_literal(&migrating_path.to_string_lossy());
    let attach = format!(
        "ATTACH DATABASE '{}' AS encrypted KEY {};",
        attach_path,
        encryption.key_pragma_value()
    );
    plaintext
        .execute(attach.as_str())
        .await
        .context("attach encrypted SQLite migration target")?;
    for statement in encryption.attached_database_pragmas("encrypted") {
        plaintext
            .execute(statement.as_str())
            .await
            .with_context(|| format!("apply attached SQLCipher pragma '{statement}'"))?;
    }
    let _: i64 = sqlx::query_scalar("SELECT sqlcipher_export('encrypted')")
        .fetch_one(&mut plaintext)
        .await
        .context("export plaintext SQLite into encrypted SQLCipher database")?;
    plaintext
        .execute(format!("PRAGMA encrypted.user_version = {user_version};").as_str())
        .await
        .context("preserve user_version during SQLCipher migration")?;
    plaintext
        .execute(format!("PRAGMA encrypted.application_id = {application_id};").as_str())
        .await
        .context("preserve application_id during SQLCipher migration")?;
    plaintext
        .execute("DETACH DATABASE encrypted;")
        .await
        .context("detach encrypted SQLite migration target")?;
    plaintext.close().await.ok();

    validate_sqlite_encrypted_file(&migrating_path, encryption)
        .await
        .context("validate encrypted SQLite migration output")?;
    replace_plaintext_sqlite_file(&database_path, &migrating_path, &backup_path)
        .context("replace plaintext SQLite database with SQLCipher output")?;
    validate_sqlite_encrypted_file(&database_path, encryption)
        .await
        .context("validate SQLCipher database after plaintext replacement")?;

    let _ = fs::remove_file(&backup_path);
    Ok(SqliteEncryptionPreparation::MigratedPlaintext)
}

pub async fn connect_db_pool(
    database_url: &str,
    db_backend: DbBackend,
    max_connections: u32,
    min_connections: u32,
    acquire_timeout: StdDuration,
    idle_timeout: StdDuration,
    sqlite_encryption: Option<SqliteEncryptionConfig>,
) -> Result<AnyPool, sqlx::Error> {
    let mut pool_options = AnyPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(acquire_timeout)
        .idle_timeout(Some(idle_timeout));

    if db_backend == DbBackend::Sqlite {
        if let Some(encryption) = sqlite_encryption {
            let statements = encryption.connect_pragmas();
            pool_options = pool_options.after_connect(move |conn, _meta| {
                let statements = statements.clone();
                Box::pin(async move {
                    for statement in &statements {
                        conn.execute(statement.as_str()).await?;
                    }
                    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master")
                        .fetch_one(conn)
                        .await?;
                    Ok(())
                })
            });
        }
    }

    pool_options.connect(database_url).await
}

fn sqlite_database_is_memory(database_url: &str) -> bool {
    let normalized = database_url.trim().to_ascii_lowercase();
    normalized == "sqlite::memory:" || normalized.contains("?mode=memory")
}

fn sqlite_connect_options(
    database_url: &str,
    create_if_missing: bool,
) -> Result<SqliteConnectOptions, sqlx::Error> {
    SqliteConnectOptions::from_str(database_url)
        .map(|opts| opts.create_if_missing(create_if_missing))
}

async fn try_open_sqlite(
    database_url: &str,
    encryption: Option<&SqliteEncryptionConfig>,
) -> Result<sqlx::SqliteConnection, sqlx::Error> {
    let options = sqlite_connect_options(database_url, false)?;
    let options = if let Some(encryption) = encryption {
        encryption.apply_to_options(options)
    } else {
        options
    };
    options.connect().await
}

async fn validate_sqlite_encrypted_file(
    database_path: &Path,
    encryption: &SqliteEncryptionConfig,
) -> anyhow::Result<()> {
    let database_url = format!(
        "sqlite://{}",
        database_path.to_string_lossy().replace('\\', "/")
    );
    let mut conn = try_open_sqlite(&database_url, Some(encryption))
        .await
        .with_context(|| format!("open encrypted SQLite file '{}'", database_path.display()))?;
    let _: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master")
        .fetch_one(&mut conn)
        .await
        .with_context(|| {
            format!(
                "read encrypted SQLite schema from '{}'",
                database_path.display()
            )
        })?;
    conn.close().await.ok();
    Ok(())
}

fn replace_plaintext_sqlite_file(
    database_path: &Path,
    migrating_path: &Path,
    backup_path: &Path,
) -> anyhow::Result<()> {
    fs::rename(database_path, backup_path).with_context(|| {
        format!(
            "rename plaintext SQLite database '{}' to backup '{}'",
            database_path.display(),
            backup_path.display()
        )
    })?;
    for sidecar in sqlite_plaintext_sidecars(database_path) {
        let _ = fs::remove_file(sidecar);
    }
    if let Err(error) = fs::rename(migrating_path, database_path) {
        let _ = fs::rename(backup_path, database_path);
        return Err(error).with_context(|| {
            format!(
                "promote migrated SQLCipher database '{}' into '{}'",
                migrating_path.display(),
                database_path.display()
            )
        });
    }
    Ok(())
}

fn sqlite_plaintext_sidecars(database_path: &Path) -> Vec<PathBuf> {
    ["-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| sqlite_sibling_path(database_path, suffix))
        .collect()
}

fn sqlite_sibling_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut file_name = database_path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("pqmsg-server.db"));
    file_name.push(suffix);
    database_path.with_file_name(file_name)
}

fn ensure_absent(path: &Path, label: &str) -> anyhow::Result<()> {
    if path.exists() {
        return Err(anyhow!("{label} already exists at '{}'", path.display()));
    }
    Ok(())
}

fn sql_quote_literal(input: &str) -> String {
    input.replace('\'', "''")
}

pub(crate) async fn ensure_user_exists(pool: &AnyPool, user_id: &str) -> Result<(), AppError> {
    let exists = sqlx::query("SELECT 1 FROM users WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    if exists.is_none() {
        return Err(AppError::not_found(format!("user '{user_id}' not found")));
    }
    Ok(())
}

pub(crate) async fn load_active_device_ids(
    pool: &AnyPool,
    user_id: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query(
        "SELECT device_id
         FROM user_devices
         WHERE user_id = $1 AND active = 1
         ORDER BY linked_at ASC, device_id ASC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let mut device_ids = Vec::with_capacity(rows.len());
    for row in rows {
        device_ids.push(row.try_get("device_id")?);
    }
    Ok(device_ids)
}

pub(crate) async fn load_group_owner_user_id(
    pool: &AnyPool,
    group_id: &str,
) -> Result<String, AppError> {
    let owner_user_id = sqlx::query_scalar::<_, String>(
        "SELECT owner_user_id
         FROM groups
         WHERE group_id = $1",
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await?;
    owner_user_id.ok_or_else(|| AppError::not_found("group not found"))
}

pub(crate) async fn is_active_group_member(
    pool: &AnyPool,
    group_id: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let member = sqlx::query(
        "SELECT 1
         FROM group_members
         WHERE group_id = $1 AND user_id = $2 AND removed_at IS NULL",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    Ok(member.is_some())
}

pub(crate) async fn count_active_group_members(
    pool: &AnyPool,
    group_id: &str,
) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) AS count
         FROM group_members
         WHERE group_id = $1 AND removed_at IS NULL",
    )
    .bind(group_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Batch-load all active devices for every active member of a group in a single
/// JOIN query instead of the N+1 pattern of fetching member user IDs then
/// calling `load_active_device_ids` per member.
pub(crate) async fn load_active_group_member_devices(
    pool: &AnyPool,
    group_id: &str,
) -> Result<Vec<(String, String)>, AppError> {
    let rows = sqlx::query(
        "SELECT gm.user_id, ud.device_id
         FROM group_members gm
         JOIN user_devices ud ON ud.user_id = gm.user_id AND ud.active = 1
         WHERE gm.group_id = $1 AND gm.removed_at IS NULL
         ORDER BY gm.user_id, ud.device_id",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        result.push((row.try_get("user_id")?, row.try_get("device_id")?));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{
        connect_db_pool, prepare_sqlite_encrypted_database, DbBackend, SqliteEncryptionConfig,
        SqliteEncryptionPreparation,
    };
    use sqlx::Row;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration as StdDuration;
    use uuid::Uuid;

    fn temp_db_path(label: &str) -> (PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("pqmsg-sqlcipher-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join(format!("{label}.sqlite3"));
        let url = format!(
            "sqlite://{}?mode=rwc",
            path.to_string_lossy().replace('\\', "/")
        );
        (path, url)
    }

    #[tokio::test]
    async fn sqlite_encryption_requires_correct_key() {
        sqlx::any::install_default_drivers();

        let (db_path, database_url) = temp_db_path("encrypted");
        let encryption = SqliteEncryptionConfig::from_raw_key(&[0x41; 32])
            .expect("key")
            .with_cipher_page_size(4096)
            .expect("page size");

        let pool = connect_db_pool(
            &database_url,
            DbBackend::Sqlite,
            1,
            1,
            StdDuration::from_secs(5),
            StdDuration::from_secs(30),
            Some(encryption.clone()),
        )
        .await
        .expect("connect encrypted sqlite");

        sqlx::query("CREATE TABLE demo_secure (value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .expect("create table");
        sqlx::query("INSERT INTO demo_secure(value) VALUES ($1)")
            .bind("secret")
            .execute(&pool)
            .await
            .expect("insert row");
        pool.close().await;

        let pool_without_key = connect_db_pool(
            &database_url,
            DbBackend::Sqlite,
            1,
            1,
            StdDuration::from_secs(5),
            StdDuration::from_secs(30),
            None,
        )
        .await
        .expect("connect without key");
        let read_without_key = sqlx::query("SELECT value FROM demo_secure")
            .fetch_one(&pool_without_key)
            .await;
        assert!(read_without_key.is_err(), "plaintext read should fail");
        pool_without_key.close().await;

        let wrong_key = SqliteEncryptionConfig::from_raw_key(&[0x55; 32]).expect("wrong key");
        let pool_wrong_key = connect_db_pool(
            &database_url,
            DbBackend::Sqlite,
            1,
            1,
            StdDuration::from_secs(5),
            StdDuration::from_secs(30),
            Some(wrong_key),
        )
        .await;
        assert!(pool_wrong_key.is_err(), "wrong key should fail at connect");

        let pool_with_key = connect_db_pool(
            &database_url,
            DbBackend::Sqlite,
            1,
            1,
            StdDuration::from_secs(5),
            StdDuration::from_secs(30),
            Some(encryption),
        )
        .await
        .expect("reconnect with correct key");
        let row = sqlx::query("SELECT value FROM demo_secure")
            .fetch_one(&pool_with_key)
            .await
            .expect("read with correct key");
        let value: String = row.try_get("value").expect("extract value");
        assert_eq!(value, "secret");
        pool_with_key.close().await;

        let _ = fs::remove_file(&db_path);
        if let Some(parent) = db_path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    #[tokio::test]
    async fn sqlite_plaintext_database_can_be_migrated_to_sqlcipher() {
        sqlx::any::install_default_drivers();

        let (db_path, database_url) = temp_db_path("plaintext");
        let mut plaintext = super::try_open_sqlite(&database_url, None)
            .await
            .expect("open plaintext sqlite");
        sqlx::query("CREATE TABLE demo_plain (value TEXT NOT NULL)")
            .execute(&mut plaintext)
            .await
            .expect("create plaintext table");
        sqlx::query("INSERT INTO demo_plain(value) VALUES ($1)")
            .bind("hello")
            .execute(&mut plaintext)
            .await
            .expect("insert plaintext row");
        plaintext.close().await.ok();

        let encryption = SqliteEncryptionConfig::from_raw_key(&[0x33; 32])
            .expect("key")
            .with_cipher_page_size(4096)
            .expect("page size");
        let result = prepare_sqlite_encrypted_database(&database_url, &encryption, true)
            .await
            .expect("migrate plaintext sqlite");
        assert_eq!(result, SqliteEncryptionPreparation::MigratedPlaintext);

        let mut encrypted = super::try_open_sqlite(&database_url, Some(&encryption))
            .await
            .expect("open encrypted sqlite");
        let row = sqlx::query("SELECT value FROM demo_plain")
            .fetch_one(&mut encrypted)
            .await
            .expect("read encrypted row");
        let value: String = row.try_get("value").expect("extract value");
        assert_eq!(value, "hello");
        encrypted.close().await.ok();

        let mut without_key = super::try_open_sqlite(&database_url, None)
            .await
            .expect("open encrypted file without key");
        let read_without_key = sqlx::query("SELECT value FROM demo_plain")
            .fetch_one(&mut without_key)
            .await;
        assert!(
            read_without_key.is_err(),
            "plaintext reads must fail after migration"
        );
        without_key.close().await.ok();

        let _ = fs::remove_file(&db_path);
        if let Some(parent) = db_path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
}
