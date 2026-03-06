use crate::error::AppError;
use sqlx::{AnyPool, Row};

static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbBackend {
    Sqlite,
    Postgres,
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

pub(crate) async fn load_active_group_member_user_ids(
    pool: &AnyPool,
    group_id: &str,
) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query(
        "SELECT user_id
         FROM group_members
         WHERE group_id = $1 AND removed_at IS NULL
         ORDER BY joined_at ASC, user_id ASC",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    let mut user_ids = Vec::with_capacity(rows.len());
    for row in rows {
        user_ids.push(row.try_get("user_id")?);
    }
    Ok(user_ids)
}
