mod util;
mod identity;
mod discovery;
mod groups;
mod profile;
mod prekeys;
mod messaging;

pub(crate) use util::*;
pub(crate) use identity::*;
pub(crate) use discovery::*;
pub(crate) use groups::*;
pub(crate) use profile::*;
pub(crate) use prekeys::*;
pub(crate) use messaging::*;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::types::*;
use crate::AppState;

pub(crate) async fn health(State(state): State<AppState>) -> Json<StatusResponse> {
    let db_ready = sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(state.pool())
        .await
        .is_ok();
    Json(StatusResponse {
        status: if db_ready { "ok" } else { "degraded" },
        security_profile: state.security_profile().as_str().to_string(),
        db_backend: state.db_backend().as_str().to_string(),
        db_ready,
        db_pool_size: state.pool().size(),
        db_pool_idle: state.pool().num_idle(),
        push_enabled: state.push_notifier().is_enabled(),
        push_providers: state.push_notifier().enabled_providers(),
        audit_logger_enabled: state.audit_logger().is_enabled(),
        rate_limiter_mode: if state.rate_limiter.is_distributed() {
            "redis"
        } else {
            "in_memory"
        },
        replay_cache_mode: if state.auth_replay().is_distributed() {
            "redis"
        } else {
            "in_memory"
        },
        registration_pow_bits: state.dos_policy().registration_pow_bits(),
        prekey_publish_min_interval_seconds: state
            .dos_policy()
            .prekey_publish_min_interval_seconds(),
        prekey_bundle_reserve_count: state.dos_policy().prekey_bundle_reserve_count(),
        pq_ratchet_interval: state.dos_policy().pq_ratchet_interval(),
    })
}

pub(crate) async fn metrics(State(state): State<AppState>) -> Response {
    let body = state.metrics().render_prometheus();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}
