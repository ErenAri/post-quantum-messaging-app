use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::types::TypingIndicator;

#[derive(Clone)]
pub struct EphemeralStateStore {
    redis: Option<RedisEphemeralState>,
}

#[derive(Clone)]
struct RedisEphemeralState {
    client: redis::Client,
    key_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PresenceRecord {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) status: String,
    pub(crate) updated_at: String,
    pub(crate) expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WsInboxTicketRecord {
    pub(crate) user_id: String,
    pub(crate) device_id: String,
    pub(crate) since: i64,
    pub(crate) expires_at: String,
}

impl EphemeralStateStore {
    pub fn disabled() -> Self {
        Self { redis: None }
    }

    pub fn with_redis(
        redis_url: &str,
        key_prefix: impl Into<String>,
    ) -> Result<Self, redis::RedisError> {
        Ok(Self {
            redis: Some(RedisEphemeralState {
                client: redis::Client::open(redis_url)?,
                key_prefix: key_prefix.into(),
            }),
        })
    }

    pub fn is_distributed(&self) -> bool {
        self.redis.is_some()
    }

    pub(crate) fn put_ws_ticket(
        &self,
        ticket: &str,
        record: &WsInboxTicketRecord,
        ttl_seconds: usize,
    ) -> Result<(), AppError> {
        let Some(redis) = &self.redis else {
            return Ok(());
        };
        let mut connection = redis_connection(redis)?;
        let payload = serde_json::to_string(record)
            .map_err(|_| AppError::internal("serialize websocket ticket"))?;
        redis::cmd("SETEX")
            .arg(redis_key(&redis.key_prefix, &format!("ws_ticket:{ticket}")))
            .arg(ttl_seconds)
            .arg(payload)
            .query::<()>(&mut connection)
            .map_err(|_| AppError::internal("persist websocket ticket"))?;
        Ok(())
    }

    pub(crate) fn consume_ws_ticket(
        &self,
        ticket: &str,
    ) -> Result<Option<WsInboxTicketRecord>, AppError> {
        let Some(redis) = &self.redis else {
            return Ok(None);
        };
        let mut connection = redis_connection(redis)?;
        let key = redis_key(&redis.key_prefix, &format!("ws_ticket:{ticket}"));
        let payload: Option<String> = redis::cmd("GETDEL")
            .arg(&key)
            .query(&mut connection)
            .or_else(|_| {
                let payload: Option<String> = redis::cmd("GET").arg(&key).query(&mut connection)?;
                let _: () = redis::cmd("DEL").arg(&key).query(&mut connection)?;
                Ok::<Option<String>, redis::RedisError>(payload)
            })
            .map_err(|_| AppError::internal("consume websocket ticket"))?;
        payload
            .map(|value| {
                serde_json::from_str::<WsInboxTicketRecord>(&value)
                    .map_err(|_| AppError::internal("decode websocket ticket"))
            })
            .transpose()
    }

    pub(crate) fn set_presence(
        &self,
        record: &PresenceRecord,
        ttl_seconds: usize,
    ) -> Result<(), AppError> {
        let Some(redis) = &self.redis else {
            return Ok(());
        };
        let mut connection = redis_connection(redis)?;
        let payload =
            serde_json::to_string(record).map_err(|_| AppError::internal("serialize presence"))?;
        redis::cmd("SETEX")
            .arg(redis_key(
                &redis.key_prefix,
                &format!("presence:{}", record.user_id),
            ))
            .arg(ttl_seconds)
            .arg(payload)
            .query::<()>(&mut connection)
            .map_err(|_| AppError::internal("persist presence"))?;
        Ok(())
    }

    pub(crate) fn clear_presence(&self, user_id: &str) -> Result<(), AppError> {
        let Some(redis) = &self.redis else {
            return Ok(());
        };
        let mut connection = redis_connection(redis)?;
        let _: () = redis::cmd("DEL")
            .arg(redis_key(&redis.key_prefix, &format!("presence:{user_id}")))
            .query(&mut connection)
            .map_err(|_| AppError::internal("delete presence"))?;
        Ok(())
    }

    pub(crate) fn get_presence(&self, user_id: &str) -> Result<Option<PresenceRecord>, AppError> {
        let Some(redis) = &self.redis else {
            return Ok(None);
        };
        let mut connection = redis_connection(redis)?;
        let payload: Option<String> = redis::cmd("GET")
            .arg(redis_key(&redis.key_prefix, &format!("presence:{user_id}")))
            .query(&mut connection)
            .map_err(|_| AppError::internal("read presence"))?;
        payload
            .map(|value| {
                serde_json::from_str::<PresenceRecord>(&value)
                    .map_err(|_| AppError::internal("decode presence"))
            })
            .transpose()
    }

    pub(crate) fn set_typing(
        &self,
        recipient_user_id: &str,
        indicator: &TypingIndicator,
        ttl_seconds: usize,
    ) -> Result<(), AppError> {
        let Some(redis) = &self.redis else {
            return Ok(());
        };
        let mut connection = redis_connection(redis)?;
        let payload =
            serde_json::to_string(indicator).map_err(|_| AppError::internal("serialize typing"))?;
        redis::cmd("SETEX")
            .arg(redis_key(
                &redis.key_prefix,
                &format!(
                    "typing:{recipient_user_id}:{}:{}",
                    indicator.sender_user_id, indicator.sender_device_id
                ),
            ))
            .arg(ttl_seconds)
            .arg(payload)
            .query::<()>(&mut connection)
            .map_err(|_| AppError::internal("persist typing"))?;
        Ok(())
    }

    pub(crate) fn clear_typing(
        &self,
        recipient_user_id: &str,
        sender_user_id: &str,
        sender_device_id: &str,
    ) -> Result<(), AppError> {
        let Some(redis) = &self.redis else {
            return Ok(());
        };
        let mut connection = redis_connection(redis)?;
        let _: () = redis::cmd("DEL")
            .arg(redis_key(
                &redis.key_prefix,
                &format!("typing:{recipient_user_id}:{sender_user_id}:{sender_device_id}"),
            ))
            .query(&mut connection)
            .map_err(|_| AppError::internal("delete typing"))?;
        Ok(())
    }

    pub(crate) fn list_typing(
        &self,
        user_id: &str,
        limit: usize,
    ) -> Result<Option<Vec<TypingIndicator>>, AppError> {
        let Some(redis) = &self.redis else {
            return Ok(None);
        };
        let mut connection = redis_connection(redis)?;
        let pattern = redis_key(&redis.key_prefix, &format!("typing:{user_id}:*"));
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query(&mut connection)
            .map_err(|_| AppError::internal("list typing keys"))?;
        if keys.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let mut typing = Vec::new();
        for key in keys.into_iter().take(limit) {
            let payload: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query(&mut connection)
                .map_err(|_| AppError::internal("read typing"))?;
            let Some(payload) = payload else {
                continue;
            };
            let indicator = serde_json::from_str::<TypingIndicator>(&payload)
                .map_err(|_| AppError::internal("decode typing"))?;
            typing.push(indicator);
        }
        typing.sort_by(|lhs, rhs| rhs.updated_at.cmp(&lhs.updated_at));
        Ok(Some(typing))
    }
}

fn redis_connection(redis: &RedisEphemeralState) -> Result<redis::Connection, AppError> {
    redis
        .client
        .get_connection()
        .map_err(|_| AppError::internal("connect redis ephemeral state"))
}

fn redis_key(prefix: &str, suffix: &str) -> String {
    format!("{prefix}{suffix}")
}
