mod backups;
mod calls;
mod channels;
mod discovery;
mod ephemeral;
mod groups;
mod identity;
mod invites;
mod messaging;
mod prekeys;
mod profile;
mod receipts;
mod stories;
mod transparency;
mod util;

pub(crate) use backups::*;
pub(crate) use calls::*;
pub(crate) use channels::*;
pub(crate) use discovery::*;
pub use ephemeral::run_message_expiry_reaper;
pub(crate) use ephemeral::*;
pub(crate) use groups::*;
pub(crate) use identity::*;
pub(crate) use invites::*;
pub(crate) use messaging::*;
pub(crate) use prekeys::*;
pub(crate) use profile::*;
pub(crate) use receipts::*;
pub(crate) use stories::*;
pub(crate) use transparency::*;
pub(crate) use util::*;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::types::*;
use crate::AppState;

fn capabilities_response(state: &AppState) -> ServerCapabilitiesResponse {
    ServerCapabilitiesResponse {
        capability_schema_version: 1,
        security_profile: state.security_profile().as_str().to_string(),
        deployment_mode: state.deployment_mode().as_str().to_string(),
        tls_required: state.security_profile().requires_tls(),
        tls_enabled: state.tls_enabled(),
        supported_suite_ids: state.supported_suite_ids(),
        runtime_crypto_profile: state.runtime_crypto_profile(),
        production_baseline_met: state.production_baseline_met(),
        registration_pow_bits: state.dos_policy().registration_pow_bits(),
        prekey_bundle_reserve_count: state.dos_policy().prekey_bundle_reserve_count(),
        pq_ratchet_interval: state.dos_policy().pq_ratchet_interval(),
        contact_discovery_supported: state.contact_discovery_supported(),
        contact_discovery_mode: state.contact_discovery_mode().to_string(),
        contact_discovery_ticket_supported: state.contact_discovery_ticket_supported(),
        contact_discovery_service_origin: state.contact_discovery_service_origin(),
        presence_supported: state.presence_supported(),
        typing_indicators_supported: state.typing_indicators_supported(),
        read_receipts_supported: state.read_receipts_supported(),
        calling_supported: state.calling_supported(),
        stories_supported: state.stories_supported(),
        channels_supported: state.channels_supported(),
        group_messaging_supported: state.group_messaging_supported(),
        sealed_sender_required: state.sealed_sender_required(),
        sender_certificate_supported: state.sender_certificate_supported(),
        key_transparency_supported: state.key_transparency_supported(),
        sealed_delivery_tokens_supported: true,
        sender_certificate_issuer_ed25519_pub: state.sender_certificate_issuer_public_key_b64(),
        transparency_log_issuer_ed25519_pub: state.transparency_log_issuer_public_key_b64(),
        authenticated_direct_messaging_supported: state.authenticated_direct_messaging_supported(),
        ephemeral_messaging_supported: state.ephemeral_messaging_supported(),
        web_client_policy: "demo_only",
    }
}

pub(crate) async fn health(State(state): State<AppState>) -> Json<StatusResponse> {
    let db_ready = sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(state.pool())
        .await
        .is_ok();
    let capabilities = capabilities_response(&state);
    Json(StatusResponse {
        status: if db_ready { "ok" } else { "degraded" },
        security_profile: capabilities.security_profile,
        deployment_mode: capabilities.deployment_mode,
        db_backend: state.db_backend().as_str().to_string(),
        db_ready,
        db_pool_size: state.pool().size(),
        db_pool_idle: state.pool().num_idle(),
        push_enabled: state.push_notifier().is_enabled(),
        push_providers: state.push_notifier().enabled_providers(),
        audit_logger_enabled: state.audit_logger().is_enabled(),
        tls_enabled: capabilities.tls_enabled,
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
        realtime_mode: if state.realtime_hub().is_distributed() {
            "redis"
        } else {
            "in_memory"
        },
        supported_suite_ids: capabilities.supported_suite_ids,
        runtime_crypto_profile: capabilities.runtime_crypto_profile,
        production_baseline_met: capabilities.production_baseline_met,
        registration_pow_bits: capabilities.registration_pow_bits,
        prekey_publish_min_interval_seconds: state
            .dos_policy()
            .prekey_publish_min_interval_seconds(),
        prekey_bundle_reserve_count: capabilities.prekey_bundle_reserve_count,
        pq_ratchet_interval: capabilities.pq_ratchet_interval,
    })
}

pub(crate) async fn capabilities(
    State(state): State<AppState>,
) -> Json<ServerCapabilitiesResponse> {
    Json(capabilities_response(&state))
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
