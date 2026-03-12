use anyhow::{anyhow, Context};
use pqmsg_server::{init_db, parse_db_backend, DbBackend};
use sqlx::any::AnyPoolOptions;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Row;
use std::env;

#[derive(Debug)]
struct Config {
    sqlite_url: String,
    postgres_url: String,
}

fn parse_args() -> anyhow::Result<Config> {
    let mut sqlite_url = env::var("PQMSG_SQLITE_URL").ok();
    let mut postgres_url = env::var("PQMSG_POSTGRES_URL").ok();

    let mut args = env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--sqlite-url" => {
                sqlite_url = args.next();
            }
            "--postgres-url" => {
                postgres_url = args.next();
            }
            _ => {
                return Err(anyhow!(
                    "unknown argument '{flag}'; expected --sqlite-url and --postgres-url"
                ));
            }
        }
    }

    let sqlite_url = sqlite_url
        .ok_or_else(|| anyhow!("missing sqlite URL; set --sqlite-url or PQMSG_SQLITE_URL"))?;
    let postgres_url = postgres_url
        .ok_or_else(|| anyhow!("missing postgres URL; set --postgres-url or PQMSG_POSTGRES_URL"))?;
    let backend = parse_db_backend(&postgres_url).map_err(anyhow::Error::msg)?;
    if backend != DbBackend::Postgres {
        return Err(anyhow!(
            "--postgres-url must use postgres:// or postgresql:// scheme"
        ));
    }
    Ok(Config {
        sqlite_url,
        postgres_url,
    })
}

async fn sqlite_table_exists(pool: &sqlx::SqlitePool, table: &str) -> anyhow::Result<bool> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1
         FROM sqlite_master
         WHERE type = 'table' AND name = $1
         LIMIT 1",
    )
    .bind(table)
    .fetch_optional(pool)
    .await?
    .is_some();
    Ok(exists)
}

async fn sqlite_table_has_column(
    pool: &sqlx::SqlitePool,
    table: &str,
    column: &str,
) -> anyhow::Result<bool> {
    let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().any(|row| {
        row.try_get::<String, _>("name")
            .map(|name| name == column)
            .unwrap_or(false)
    }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sqlx::any::install_default_drivers();
    let config = parse_args()?;

    let sqlite = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&config.sqlite_url)
        .await
        .with_context(|| format!("failed to connect sqlite '{}'", config.sqlite_url))?;

    let postgres = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.postgres_url)
        .await
        .with_context(|| format!("failed to connect postgres '{}'", config.postgres_url))?;

    let any_postgres = AnyPoolOptions::new()
        .max_connections(5)
        .connect(&config.postgres_url)
        .await
        .with_context(|| {
            format!(
                "failed to connect postgres via any pool '{}'",
                config.postgres_url
            )
        })?;
    init_db(&any_postgres, DbBackend::Postgres)
        .await
        .context("failed to run postgres migrations")?;

    let users = if sqlite_table_has_column(&sqlite, "users", "sealed_delivery_token").await? {
        sqlx::query(
            "SELECT user_id, identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id, sealed_delivery_token, created_at, updated_at
             FROM users
             ORDER BY user_id ASC",
        )
        .fetch_all(&sqlite)
        .await?
    } else {
        sqlx::query(
            "SELECT user_id, identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id, NULL AS sealed_delivery_token, created_at, updated_at
             FROM users
             ORDER BY user_id ASC",
        )
        .fetch_all(&sqlite)
        .await?
    };

    let prekeys = sqlx::query(
        "SELECT user_id, signed_prekey_x25519_pub, sig_over_spk, pq_signed_prekey_pub_mlkem768, sig_over_pqspk, pq_sig_over_spk, pq_sig_over_pqspk, updated_at
         FROM prekeys
         ORDER BY user_id ASC",
    )
    .fetch_all(&sqlite)
    .await?;

    let one_time_x = sqlx::query(
        "SELECT id, user_id, prekey, consumed, created_at
         FROM one_time_prekeys_x25519
         ORDER BY id ASC",
    )
    .fetch_all(&sqlite)
    .await?;

    let one_time_pq = sqlx::query(
        "SELECT id, user_id, prekey, consumed, created_at
         FROM one_time_prekeys_mlkem768
         ORDER BY id ASC",
    )
    .fetch_all(&sqlite)
    .await?;

    let relay_messages = sqlx::query(
        "SELECT message_id, recipient_user_id, sender_user_id, device_id, message_blob, received_at
         FROM relay_messages
         ORDER BY message_id ASC",
    )
    .fetch_all(&sqlite)
    .await?;

    let identity_events = if sqlite_table_exists(&sqlite, "identity_events").await? {
        sqlx::query(
            "SELECT id, user_id, version, identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id, event_type, changed_at
             FROM identity_events
             ORDER BY id ASC",
        )
        .fetch_all(&sqlite)
        .await?
    } else {
        Vec::new()
    };

    let rotation_challenges = if sqlite_table_exists(&sqlite, "identity_rotation_challenges")
        .await?
    {
        sqlx::query(
            "SELECT challenge_id, user_id, nonce, new_identity_x25519_pub, new_identity_sig_pub, new_identity_pq_sig_pub, new_device_id, created_at, expires_at, consumed
             FROM identity_rotation_challenges
             ORDER BY created_at ASC",
        )
        .fetch_all(&sqlite)
        .await?
    } else {
        Vec::new()
    };

    let push_tokens = if sqlite_table_exists(&sqlite, "push_tokens").await? {
        sqlx::query(
            "SELECT user_id, device_id, provider, token, updated_at
             FROM push_tokens
             ORDER BY user_id ASC, device_id ASC, provider ASC",
        )
        .fetch_all(&sqlite)
        .await?
    } else {
        Vec::new()
    };

    let relay_dedup = if sqlite_table_exists(&sqlite, "relay_dedup").await? {
        sqlx::query(
            "SELECT dedup_key, expires_at_unix, updated_at
             FROM relay_dedup
             ORDER BY dedup_key ASC",
        )
        .fetch_all(&sqlite)
        .await?
    } else {
        Vec::new()
    };

    let inbox_cursors = if sqlite_table_exists(&sqlite, "inbox_cursors").await? {
        sqlx::query(
            "SELECT user_id, device_id, last_message_id, updated_at
             FROM inbox_cursors
             ORDER BY user_id ASC, device_id ASC",
        )
        .fetch_all(&sqlite)
        .await?
    } else {
        Vec::new()
    };

    let mut tx = postgres.begin().await?;

    for row in &users {
        sqlx::query(
            "INSERT INTO users (user_id, identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id, sealed_delivery_token, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (user_id) DO UPDATE SET
               identity_x25519_pub = EXCLUDED.identity_x25519_pub,
               identity_sig_pub = EXCLUDED.identity_sig_pub,
               identity_pq_sig_pub = EXCLUDED.identity_pq_sig_pub,
               device_id = EXCLUDED.device_id,
               sealed_delivery_token = EXCLUDED.sealed_delivery_token,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<Vec<u8>, _>("identity_x25519_pub")?)
        .bind(row.try_get::<Vec<u8>, _>("identity_sig_pub")?)
        .bind(row.try_get::<Option<Vec<u8>>, _>("identity_pq_sig_pub")?)
        .bind(row.try_get::<String, _>("device_id")?)
        .bind(row.try_get::<Option<Vec<u8>>, _>("sealed_delivery_token")?)
        .bind(row.try_get::<String, _>("created_at")?)
        .bind(row.try_get::<String, _>("updated_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &prekeys {
        sqlx::query(
            "INSERT INTO prekeys (
                user_id,
                signed_prekey_x25519_pub,
                sig_over_spk,
                pq_signed_prekey_pub_mlkem768,
                sig_over_pqspk,
                pq_sig_over_spk,
                pq_sig_over_pqspk,
                updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (user_id) DO UPDATE SET
               signed_prekey_x25519_pub = EXCLUDED.signed_prekey_x25519_pub,
               sig_over_spk = EXCLUDED.sig_over_spk,
               pq_signed_prekey_pub_mlkem768 = EXCLUDED.pq_signed_prekey_pub_mlkem768,
               sig_over_pqspk = EXCLUDED.sig_over_pqspk,
               pq_sig_over_spk = EXCLUDED.pq_sig_over_spk,
               pq_sig_over_pqspk = EXCLUDED.pq_sig_over_pqspk,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<Vec<u8>, _>("signed_prekey_x25519_pub")?)
        .bind(row.try_get::<Vec<u8>, _>("sig_over_spk")?)
        .bind(row.try_get::<Vec<u8>, _>("pq_signed_prekey_pub_mlkem768")?)
        .bind(row.try_get::<Vec<u8>, _>("sig_over_pqspk")?)
        .bind(row.try_get::<Option<Vec<u8>>, _>("pq_sig_over_spk")?)
        .bind(row.try_get::<Option<Vec<u8>>, _>("pq_sig_over_pqspk")?)
        .bind(row.try_get::<String, _>("updated_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &one_time_x {
        sqlx::query(
            "INSERT INTO one_time_prekeys_x25519 (id, user_id, prekey, consumed, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (id) DO UPDATE SET
               user_id = EXCLUDED.user_id,
               prekey = EXCLUDED.prekey,
               consumed = EXCLUDED.consumed,
               created_at = EXCLUDED.created_at",
        )
        .bind(row.try_get::<i64, _>("id")?)
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<Vec<u8>, _>("prekey")?)
        .bind(row.try_get::<i64, _>("consumed")?)
        .bind(row.try_get::<String, _>("created_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &one_time_pq {
        sqlx::query(
            "INSERT INTO one_time_prekeys_mlkem768 (id, user_id, prekey, consumed, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (id) DO UPDATE SET
               user_id = EXCLUDED.user_id,
               prekey = EXCLUDED.prekey,
               consumed = EXCLUDED.consumed,
               created_at = EXCLUDED.created_at",
        )
        .bind(row.try_get::<i64, _>("id")?)
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<Vec<u8>, _>("prekey")?)
        .bind(row.try_get::<i64, _>("consumed")?)
        .bind(row.try_get::<String, _>("created_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &relay_messages {
        sqlx::query(
            "INSERT INTO relay_messages (
                message_id,
                recipient_user_id,
                sender_user_id,
                device_id,
                message_blob,
                received_at
             ) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (message_id) DO UPDATE SET
               recipient_user_id = EXCLUDED.recipient_user_id,
               sender_user_id = EXCLUDED.sender_user_id,
               device_id = EXCLUDED.device_id,
               message_blob = EXCLUDED.message_blob,
               received_at = EXCLUDED.received_at",
        )
        .bind(row.try_get::<i64, _>("message_id")?)
        .bind(row.try_get::<String, _>("recipient_user_id")?)
        .bind(row.try_get::<String, _>("sender_user_id")?)
        .bind(row.try_get::<String, _>("device_id")?)
        .bind(row.try_get::<Vec<u8>, _>("message_blob")?)
        .bind(row.try_get::<String, _>("received_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &identity_events {
        sqlx::query(
            "INSERT INTO identity_events (
                id,
                user_id,
                version,
                identity_x25519_pub,
                identity_sig_pub,
                identity_pq_sig_pub,
                device_id,
                event_type,
                changed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO UPDATE SET
               user_id = EXCLUDED.user_id,
               version = EXCLUDED.version,
               identity_x25519_pub = EXCLUDED.identity_x25519_pub,
               identity_sig_pub = EXCLUDED.identity_sig_pub,
               identity_pq_sig_pub = EXCLUDED.identity_pq_sig_pub,
               device_id = EXCLUDED.device_id,
               event_type = EXCLUDED.event_type,
               changed_at = EXCLUDED.changed_at",
        )
        .bind(row.try_get::<i64, _>("id")?)
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<i64, _>("version")?)
        .bind(row.try_get::<Vec<u8>, _>("identity_x25519_pub")?)
        .bind(row.try_get::<Vec<u8>, _>("identity_sig_pub")?)
        .bind(row.try_get::<Option<Vec<u8>>, _>("identity_pq_sig_pub")?)
        .bind(row.try_get::<String, _>("device_id")?)
        .bind(row.try_get::<String, _>("event_type")?)
        .bind(row.try_get::<String, _>("changed_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &rotation_challenges {
        sqlx::query(
            "INSERT INTO identity_rotation_challenges (
                challenge_id,
                user_id,
                nonce,
                new_identity_x25519_pub,
                new_identity_sig_pub,
                new_identity_pq_sig_pub,
                new_device_id,
                created_at,
                expires_at,
                consumed
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (challenge_id) DO UPDATE SET
               user_id = EXCLUDED.user_id,
               nonce = EXCLUDED.nonce,
               new_identity_x25519_pub = EXCLUDED.new_identity_x25519_pub,
               new_identity_sig_pub = EXCLUDED.new_identity_sig_pub,
               new_identity_pq_sig_pub = EXCLUDED.new_identity_pq_sig_pub,
               new_device_id = EXCLUDED.new_device_id,
               created_at = EXCLUDED.created_at,
               expires_at = EXCLUDED.expires_at,
               consumed = EXCLUDED.consumed",
        )
        .bind(row.try_get::<String, _>("challenge_id")?)
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<Vec<u8>, _>("nonce")?)
        .bind(row.try_get::<Vec<u8>, _>("new_identity_x25519_pub")?)
        .bind(row.try_get::<Vec<u8>, _>("new_identity_sig_pub")?)
        .bind(row.try_get::<Option<Vec<u8>>, _>("new_identity_pq_sig_pub")?)
        .bind(row.try_get::<String, _>("new_device_id")?)
        .bind(row.try_get::<String, _>("created_at")?)
        .bind(row.try_get::<String, _>("expires_at")?)
        .bind(row.try_get::<i64, _>("consumed")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &push_tokens {
        sqlx::query(
            "INSERT INTO push_tokens (
                user_id,
                device_id,
                provider,
                token,
                updated_at
             ) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (user_id, device_id, provider) DO UPDATE SET
               token = EXCLUDED.token,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<String, _>("device_id")?)
        .bind(row.try_get::<String, _>("provider")?)
        .bind(row.try_get::<String, _>("token")?)
        .bind(row.try_get::<String, _>("updated_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &relay_dedup {
        sqlx::query(
            "INSERT INTO relay_dedup (
                dedup_key,
                expires_at_unix,
                updated_at
             ) VALUES ($1, $2, $3)
             ON CONFLICT (dedup_key) DO UPDATE SET
               expires_at_unix = EXCLUDED.expires_at_unix,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(row.try_get::<String, _>("dedup_key")?)
        .bind(row.try_get::<i64, _>("expires_at_unix")?)
        .bind(row.try_get::<String, _>("updated_at")?)
        .execute(&mut *tx)
        .await?;
    }

    for row in &inbox_cursors {
        sqlx::query(
            "INSERT INTO inbox_cursors (
                user_id,
                device_id,
                last_message_id,
                updated_at
             ) VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, device_id) DO UPDATE SET
               last_message_id = EXCLUDED.last_message_id,
               updated_at = EXCLUDED.updated_at",
        )
        .bind(row.try_get::<String, _>("user_id")?)
        .bind(row.try_get::<String, _>("device_id")?)
        .bind(row.try_get::<i64, _>("last_message_id")?)
        .bind(row.try_get::<String, _>("updated_at")?)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        "SELECT setval(
            pg_get_serial_sequence('one_time_prekeys_x25519', 'id'),
            COALESCE((SELECT MAX(id) FROM one_time_prekeys_x25519), 0) + 1,
            false
         )",
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "SELECT setval(
            pg_get_serial_sequence('one_time_prekeys_mlkem768', 'id'),
            COALESCE((SELECT MAX(id) FROM one_time_prekeys_mlkem768), 0) + 1,
            false
         )",
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "SELECT setval(
            pg_get_serial_sequence('relay_messages', 'message_id'),
            COALESCE((SELECT MAX(message_id) FROM relay_messages), 0) + 1,
            false
         )",
    )
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "SELECT setval(
            pg_get_serial_sequence('identity_events', 'id'),
            COALESCE((SELECT MAX(id) FROM identity_events), 0) + 1,
            false
         )",
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    println!(
        "migrated rows: users={} prekeys={} one_time_x25519={} one_time_mlkem768={} relay_messages={} identity_events={} identity_rotation_challenges={} push_tokens={} relay_dedup={} inbox_cursors={}",
        users.len(),
        prekeys.len(),
        one_time_x.len(),
        one_time_pq.len(),
        relay_messages.len(),
        identity_events.len(),
        rotation_challenges.len(),
        push_tokens.len(),
        relay_dedup.len(),
        inbox_cursors.len()
    );

    Ok(())
}
