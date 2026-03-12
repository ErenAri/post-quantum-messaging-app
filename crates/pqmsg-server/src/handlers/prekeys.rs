use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use sqlx::Row;
use uuid::Uuid;

use super::util::*;
use crate::auth::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::{
    AppState, MAX_IDENTITY_LOG_ITEMS, MAX_PQ_KEY_LEN, MIN_PQ_KEY_LEN, PREKEY_REPLENISH_TARGET,
    PQ_SIG_LEN, PQ_SIG_PUB_KEY_LEN, ROTATION_CHALLENGE_BYTES, ROTATION_CHALLENGE_TTL_MINUTES,
    SIG_LEN, SIG_PUB_KEY_LEN, X25519_KEY_LEN,
};

pub(crate) async fn publish_prekeys(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PublishPrekeysRequest>,
) -> Result<Json<PublishPrekeysResponse>, AppError> {
    check_rate_limit(&state, &format!("prekeys:{user_id}"))?;
    validate_id("user_id", &user_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = prekeys_auth_message(&auth, &request)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    enforce_prekey_publish_interval(&state, &user_id, &auth.device_id).await?;
    validate_one_time_count(
        "one_time_prekeys_x25519",
        request.one_time_prekeys_x25519.len(),
    )?;
    validate_one_time_count(
        "one_time_prekeys_mlkem768",
        request.one_time_prekeys_mlkem768.len(),
    )?;

    // Enforce PQ prekey presence when PQ ratchet interval is active
    if state.dos_policy().pq_ratchet_interval() > 0 && request.one_time_prekeys_mlkem768.is_empty()
    {
        return Err(AppError::bad_request(
            "PQ one-time prekeys required when pq_ratchet_interval > 0",
        ));
    }

    let signed_prekey_x = decode_base64_exact(
        "signed_prekey_x25519_pub",
        &request.signed_prekey_x25519_pub,
        X25519_KEY_LEN,
    )?;
    let sig_over_spk =
        decode_base64_range("sig_over_spk", &request.sig_over_spk, SIG_LEN, SIG_LEN)?;
    let pq_signed_prekey = decode_base64_range(
        "pq_signed_prekey_pub_mlkem768",
        &request.pq_signed_prekey_pub_mlkem768,
        MIN_PQ_KEY_LEN,
        MAX_PQ_KEY_LEN,
    )?;
    let sig_over_pqspk =
        decode_base64_range("sig_over_pqspk", &request.sig_over_pqspk, SIG_LEN, SIG_LEN)?;
    let pq_sig_over_spk = decode_base64_exact(
        "pq_sig_over_spk",
        &request.pq_sig_over_spk,
        PQ_SIG_LEN,
    )?;
    let pq_sig_over_pqspk = decode_base64_exact(
        "pq_sig_over_pqspk",
        &request.pq_sig_over_pqspk,
        PQ_SIG_LEN,
    )?;

    let mut one_time_x = Vec::with_capacity(request.one_time_prekeys_x25519.len());
    for key in &request.one_time_prekeys_x25519 {
        one_time_x.push(decode_base64_exact(
            "one_time_prekeys_x25519[]",
            key,
            X25519_KEY_LEN,
        )?);
    }

    let mut one_time_pq = Vec::with_capacity(request.one_time_prekeys_mlkem768.len());
    for key in &request.one_time_prekeys_mlkem768 {
        one_time_pq.push(decode_base64_range(
            "one_time_prekeys_mlkem768[]",
            key,
            MIN_PQ_KEY_LEN,
            MAX_PQ_KEY_LEN,
        )?);
    }

    let user_row = sqlx::query(
        "SELECT identity_sig_pub, identity_pq_sig_pub FROM users WHERE user_id = $1",
    )
        .bind(&user_id)
        .fetch_optional(&state.pool)
        .await?;
    let Some(user_row) = user_row else {
        return Err(AppError::not_found("user not found"));
    };

    let identity_sig_pub: Vec<u8> = user_row.try_get("identity_sig_pub")?;
    let identity_pq_sig_pub: Option<Vec<u8>> = user_row.try_get("identity_pq_sig_pub")?;
    let Some(identity_pq_sig_pub) = identity_pq_sig_pub else {
        return Err(AppError::conflict(
            "user must re-register with a PQ identity key before publishing prekeys",
        ));
    };
    validate_ml_dsa_public_key(&identity_pq_sig_pub)?;
    verify_hybrid_prekey_signatures(
        &identity_sig_pub,
        &identity_pq_sig_pub,
        &signed_prekey_x,
        &sig_over_spk,
        &pq_signed_prekey,
        &sig_over_pqspk,
        &pq_sig_over_spk,
        &pq_sig_over_pqspk,
    )?;

    let device_id = auth.device_id.clone();
    let now = Utc::now().to_rfc3339();
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        "INSERT INTO prekeys (
            user_id, device_id, signed_prekey_x25519_pub, sig_over_spk,
            pq_signed_prekey_pub_mlkem768, sig_over_pqspk, pq_sig_over_spk, pq_sig_over_pqspk, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT(user_id, device_id) DO UPDATE SET
            signed_prekey_x25519_pub = EXCLUDED.signed_prekey_x25519_pub,
            sig_over_spk = EXCLUDED.sig_over_spk,
            pq_signed_prekey_pub_mlkem768 = EXCLUDED.pq_signed_prekey_pub_mlkem768,
            sig_over_pqspk = EXCLUDED.sig_over_pqspk,
            pq_sig_over_spk = EXCLUDED.pq_sig_over_spk,
            pq_sig_over_pqspk = EXCLUDED.pq_sig_over_pqspk,
            updated_at = EXCLUDED.updated_at",
    )
    .bind(&user_id)
    .bind(&device_id)
    .bind(&signed_prekey_x)
    .bind(&sig_over_spk)
    .bind(&pq_signed_prekey)
    .bind(&sig_over_pqspk)
    .bind(&pq_sig_over_spk)
    .bind(&pq_sig_over_pqspk)
    .bind(&now)
    .execute(&mut *tx)
    .await?;

    sqlx::query("DELETE FROM one_time_prekeys_x25519 WHERE user_id = $1 AND device_id = $2")
        .bind(&user_id)
        .bind(&device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM one_time_prekeys_mlkem768 WHERE user_id = $1 AND device_id = $2")
        .bind(&user_id)
        .bind(&device_id)
        .execute(&mut *tx)
        .await?;

    for key in &one_time_x {
        sqlx::query(
            "INSERT INTO one_time_prekeys_x25519 (user_id, device_id, prekey, consumed, created_at)
             VALUES ($1, $2, $3, 0, $4)",
        )
        .bind(&user_id)
        .bind(&device_id)
        .bind(key)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }
    for key in &one_time_pq {
        sqlx::query(
            "INSERT INTO one_time_prekeys_mlkem768 (user_id, device_id, prekey, consumed, created_at)
             VALUES ($1, $2, $3, 0, $4)",
        )
        .bind(&user_id)
        .bind(&device_id)
        .bind(key)
        .bind(&now)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    let (remaining_x, remaining_pq) =
        load_remaining_one_time_counts(state.pool(), &user_id, &device_id).await?;
    let low_one_time_prekeys = is_prekey_inventory_low(remaining_x, remaining_pq);

    Ok(Json(PublishPrekeysResponse {
        user_id,
        device_id,
        uploaded_one_time_prekeys_x25519: one_time_x.len(),
        uploaded_one_time_prekeys_mlkem768: one_time_pq.len(),
        remaining_one_time_prekeys_x25519: usize::try_from(remaining_x)
            .map_err(|_| AppError::internal("remaining_one_time_prekeys_x25519 overflow"))?,
        remaining_one_time_prekeys_mlkem768: usize::try_from(remaining_pq)
            .map_err(|_| AppError::internal("remaining_one_time_prekeys_mlkem768 overflow"))?,
        low_one_time_prekeys,
        minimum_recommended_one_time_prekeys: usize::try_from(PREKEY_REPLENISH_TARGET)
            .map_err(|_| AppError::internal("minimum_recommended_one_time_prekeys overflow"))?,
        updated_at: now,
    }))
}

pub(crate) async fn get_prekeys_status(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PrekeysStatusResponse>, AppError> {
    check_rate_limit(&state, &format!("prekeys-status:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = prekeys_status_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let device_id = auth.device_id.clone();
    let (remaining_x, remaining_pq) =
        load_remaining_one_time_counts(state.pool(), &user_id, &device_id).await?;
    let low_one_time_prekeys = is_prekey_inventory_low(remaining_x, remaining_pq);

    Ok(Json(PrekeysStatusResponse {
        user_id,
        device_id,
        remaining_one_time_prekeys_x25519: usize::try_from(remaining_x)
            .map_err(|_| AppError::internal("remaining_one_time_prekeys_x25519 overflow"))?,
        remaining_one_time_prekeys_mlkem768: usize::try_from(remaining_pq)
            .map_err(|_| AppError::internal("remaining_one_time_prekeys_mlkem768 overflow"))?,
        low_one_time_prekeys,
        minimum_recommended_one_time_prekeys: usize::try_from(PREKEY_REPLENISH_TARGET)
            .map_err(|_| AppError::internal("minimum_recommended_one_time_prekeys overflow"))?,
        checked_at: Utc::now().to_rfc3339(),
    }))
}

pub(crate) async fn get_bundle(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Query(query): Query<BundleQuery>,
) -> Result<Json<BundleResponse>, AppError> {
    check_rate_limit(&state, &format!("bundle:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    if let Some(device_id) = &query.device_id {
        validate_id("device_id", device_id)?;
    }

    let mut tx = state.pool.begin().await?;

    let row = if let Some(target_device_id) = &query.device_id {
        sqlx::query(
            "SELECT
                u.user_id,
                ud.device_id,
                u.identity_x25519_pub,
                u.identity_sig_pub,
                u.identity_pq_sig_pub,
                p.signed_prekey_x25519_pub,
                p.sig_over_spk,
                p.pq_signed_prekey_pub_mlkem768,
                p.sig_over_pqspk,
                p.pq_sig_over_spk,
                p.pq_sig_over_pqspk,
                p.updated_at,
                COALESCE((
                    SELECT MAX(ie.version)
                    FROM identity_events ie
                    WHERE ie.user_id = u.user_id
                ), 1) AS identity_key_version
             FROM users u
             JOIN user_devices ud ON ud.user_id = u.user_id
             JOIN prekeys p ON p.user_id = u.user_id AND p.device_id = ud.device_id
             WHERE u.user_id = $1 AND ud.device_id = $2 AND ud.active = 1
             LIMIT 1",
        )
        .bind(&user_id)
        .bind(target_device_id)
        .fetch_optional(&mut *tx)
        .await?
    } else {
        sqlx::query(
            "SELECT
                u.user_id,
                ud.device_id,
                u.identity_x25519_pub,
                u.identity_sig_pub,
                u.identity_pq_sig_pub,
                p.signed_prekey_x25519_pub,
                p.sig_over_spk,
                p.pq_signed_prekey_pub_mlkem768,
                p.sig_over_pqspk,
                p.pq_sig_over_spk,
                p.pq_sig_over_pqspk,
                p.updated_at,
                COALESCE((
                    SELECT MAX(ie.version)
                    FROM identity_events ie
                    WHERE ie.user_id = u.user_id
                ), 1) AS identity_key_version
             FROM users u
             JOIN user_devices ud ON ud.user_id = u.user_id
             JOIN prekeys p ON p.user_id = u.user_id AND p.device_id = ud.device_id
             WHERE u.user_id = $1 AND ud.active = 1
             ORDER BY ud.linked_at ASC, ud.device_id ASC
             LIMIT 1",
        )
        .bind(&user_id)
        .fetch_optional(&mut *tx)
        .await?
    };
    let Some(row) = row else {
        return Err(AppError::not_found("bundle not found"));
    };
    let device_id: String = row.try_get("device_id")?;
    let identity_pq_sig_pub_bytes = row
        .try_get::<Option<Vec<u8>>, _>("identity_pq_sig_pub")?
        .ok_or_else(|| {
            AppError::conflict(
                "bundle missing mandatory PQ identity key; user must re-register",
            )
        })?;
    validate_ml_dsa_public_key(&identity_pq_sig_pub_bytes)?;
    let pq_sig_over_spk_bytes = row
        .try_get::<Option<Vec<u8>>, _>("pq_sig_over_spk")?
        .ok_or_else(|| {
            AppError::conflict(
                "bundle missing mandatory PQ signature over signed prekey; user must republish prekeys",
            )
        })?;
    let pq_sig_over_pqspk_bytes = row
        .try_get::<Option<Vec<u8>>, _>("pq_sig_over_pqspk")?
        .ok_or_else(|| {
            AppError::conflict(
                "bundle missing mandatory PQ signature over PQ signed prekey; user must republish prekeys",
            )
        })?;

    // Check signed prekey staleness for high-assurance profiles
    if state.security_profile().requires_tls() {
        if let Ok(updated_str) = row.try_get::<String, _>("updated_at") {
            if let Ok(updated_at) = chrono::DateTime::parse_from_rfc3339(&updated_str) {
                let age = Utc::now().signed_duration_since(updated_at).num_seconds();
                if age > crate::SIGNED_PREKEY_MAX_AGE_SECONDS {
                    record_security_event(
                        &state,
                        "signed_prekey_stale",
                        "warn",
                        None,
                        Some(&user_id),
                        Some(&device_id),
                        Some(format!("age_seconds={age}")),
                    );
                }
            }
        }
    }

    let remaining_x_before =
        count_available_one_time_keys(&mut tx, "one_time_prekeys_x25519", &user_id, &device_id)
            .await?;
    let remaining_pq_before =
        count_available_one_time_keys(&mut tx, "one_time_prekeys_mlkem768", &user_id, &device_id)
            .await?;
    let reserve_count = state.dos_policy().prekey_bundle_reserve_count().max(0);
    let consume_one_time =
        remaining_x_before > reserve_count && remaining_pq_before > reserve_count;
    let x25519_otk = if consume_one_time {
        select_one_time_key(&mut tx, "one_time_prekeys_x25519", &user_id, &device_id).await?
    } else {
        None
    };
    let mlkem_otk = if consume_one_time {
        select_one_time_key(&mut tx, "one_time_prekeys_mlkem768", &user_id, &device_id).await?
    } else {
        None
    };
    let remaining_x =
        count_available_one_time_keys(&mut tx, "one_time_prekeys_x25519", &user_id, &device_id)
            .await?;
    let remaining_pq =
        count_available_one_time_keys(&mut tx, "one_time_prekeys_mlkem768", &user_id, &device_id)
            .await?;
    tx.commit().await?;

    let identity_x25519_pub_bytes = row.try_get::<Vec<u8>, _>("identity_x25519_pub")?;
    let identity_fingerprint = identity_fingerprint_sha256(
        &identity_x25519_pub_bytes,
        Some(&identity_pq_sig_pub_bytes),
    );
    let identity_key_version_i64: i64 = row.try_get("identity_key_version")?;
    let identity_key_version = u32::try_from(identity_key_version_i64)
        .map_err(|_| AppError::internal("identity_key_version overflow"))?;
    let low_one_time_prekeys = is_prekey_inventory_low(remaining_x, remaining_pq);
    let last_resort_prekey_only = x25519_otk.is_none() || mlkem_otk.is_none();

    if last_resort_prekey_only && state.dos_policy().pq_ratchet_interval() > 0 {
        record_security_event(
            &state,
            "pq_bundle_last_resort_served",
            "warn",
            None,
            Some(&user_id),
            Some(&device_id),
            None,
        );
    }

    Ok(Json(BundleResponse {
        user_id: row.try_get("user_id")?,
        device_id,
        identity_x25519_pub: B64.encode(identity_x25519_pub_bytes),
        identity_sig_pub: B64.encode(row.try_get::<Vec<u8>, _>("identity_sig_pub")?),
        identity_pq_sig_pub: B64.encode(identity_pq_sig_pub_bytes),
        signed_prekey_x25519_pub: B64
            .encode(row.try_get::<Vec<u8>, _>("signed_prekey_x25519_pub")?),
        sig_over_spk: B64.encode(row.try_get::<Vec<u8>, _>("sig_over_spk")?),
        pq_signed_prekey_pub_mlkem768: B64
            .encode(row.try_get::<Vec<u8>, _>("pq_signed_prekey_pub_mlkem768")?),
        sig_over_pqspk: B64.encode(row.try_get::<Vec<u8>, _>("sig_over_pqspk")?),
        pq_sig_over_spk: B64.encode(pq_sig_over_spk_bytes),
        pq_sig_over_pqspk: B64.encode(pq_sig_over_pqspk_bytes),
        one_time_prekey_x25519: x25519_otk.map(|bytes| B64.encode(bytes)),
        one_time_prekey_mlkem768: mlkem_otk.map(|bytes| B64.encode(bytes)),
        remaining_one_time_prekeys_x25519: usize::try_from(remaining_x)
            .map_err(|_| AppError::internal("remaining_one_time_prekeys_x25519 overflow"))?,
        remaining_one_time_prekeys_mlkem768: usize::try_from(remaining_pq)
            .map_err(|_| AppError::internal("remaining_one_time_prekeys_mlkem768 overflow"))?,
        low_one_time_prekeys,
        minimum_recommended_one_time_prekeys: usize::try_from(PREKEY_REPLENISH_TARGET)
            .map_err(|_| AppError::internal("minimum_recommended_one_time_prekeys overflow"))?,
        last_resort_prekey_only,
        identity_key_version,
        identity_fingerprint_sha256: identity_fingerprint,
        bundle_generated_at: Utc::now().to_rfc3339(),
    }))
}

pub(crate) async fn rotate_init(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RotateInitRequest>,
) -> Result<Json<RotateInitResponse>, AppError> {
    check_rate_limit(&state, &format!("rotate-init:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_id("new_device_id", &request.new_device_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = rotate_init_auth_message(&auth, &request)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let new_identity_x25519 = decode_base64_exact(
        "new_identity_x25519_pub",
        &request.new_identity_x25519_pub,
        X25519_KEY_LEN,
    )?;
    let new_identity_sig = decode_base64_exact(
        "new_identity_sig_pub",
        &request.new_identity_sig_pub,
        SIG_PUB_KEY_LEN,
    )?;
    validate_ed25519_public_key(&new_identity_sig)?;
    let new_identity_pq_sig = decode_base64_exact(
        "new_identity_pq_sig_pub",
        &request.new_identity_pq_sig_pub,
        PQ_SIG_PUB_KEY_LEN,
    )?;
    validate_ml_dsa_public_key(&new_identity_pq_sig)?;

    let user_row = sqlx::query(
        "SELECT identity_x25519_pub, identity_sig_pub, identity_pq_sig_pub, device_id
         FROM users
         WHERE user_id = $1",
    )
    .bind(&user_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(user_row) = user_row else {
        return Err(AppError::not_found("user not found"));
    };

    let current_identity_x25519: Vec<u8> = user_row.try_get("identity_x25519_pub")?;
    let current_identity_sig: Vec<u8> = user_row.try_get("identity_sig_pub")?;
    let current_identity_pq_sig: Option<Vec<u8>> = user_row.try_get("identity_pq_sig_pub")?;
    let current_device_id: String = user_row.try_get("device_id")?;
    if current_identity_pq_sig.is_none() {
        return Err(AppError::conflict(
            "rotation requires an existing PQ identity key; re-register first",
        ));
    }
    if current_identity_x25519 == new_identity_x25519
        && current_identity_sig == new_identity_sig
        && current_identity_pq_sig
            .as_ref()
            .is_some_and(|current_key| current_key == &new_identity_pq_sig)
        && current_device_id == request.new_device_id
    {
        return Err(AppError::bad_request(
            "rotation request matches current identity material",
        ));
    }

    let mut nonce = [0u8; ROTATION_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let challenge_id = Uuid::new_v4().to_string();
    let created_at = Utc::now();
    let expires_at = created_at + Duration::minutes(ROTATION_CHALLENGE_TTL_MINUTES);
    let created_at_rfc3339 = created_at.to_rfc3339();
    let expires_at_rfc3339 = expires_at.to_rfc3339();

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
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0)",
    )
    .bind(&challenge_id)
    .bind(&user_id)
    .bind(nonce.to_vec())
    .bind(new_identity_x25519)
    .bind(new_identity_sig)
    .bind(new_identity_pq_sig)
    .bind(&request.new_device_id)
    .bind(created_at_rfc3339)
    .bind(&expires_at_rfc3339)
    .execute(&state.pool)
    .await?;

    record_security_event(
        &state,
        "rotation_initiated",
        "success",
        None,
        Some(&user_id),
        Some(&request.new_device_id),
        Some(format!("challenge_id={challenge_id}")),
    );
    Ok(Json(RotateInitResponse {
        user_id,
        challenge_id,
        challenge_nonce: B64.encode(nonce),
        expires_at: expires_at_rfc3339,
    }))
}

pub(crate) async fn rotate_confirm(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RotateConfirmRequest>,
) -> Result<Json<RotateConfirmResponse>, AppError> {
    check_rate_limit(&state, &format!("rotate-confirm:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    validate_rotation_challenge_id(&request.challenge_id)?;

    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = rotate_confirm_auth_message(&auth, &request)?;
    verify_request_auth(&state, &auth, &auth_message).await?;

    let sig_by_current = decode_base64_exact(
        "sig_by_current_identity",
        &request.sig_by_current_identity,
        SIG_LEN,
    )?;
    let sig_by_new =
        decode_base64_exact("sig_by_new_identity", &request.sig_by_new_identity, SIG_LEN)?;
    let pq_sig_by_current = decode_base64_exact(
        "pq_sig_by_current_identity",
        &request.pq_sig_by_current_identity,
        PQ_SIG_LEN,
    )?;
    let pq_sig_by_new = decode_base64_exact(
        "pq_sig_by_new_identity",
        &request.pq_sig_by_new_identity,
        PQ_SIG_LEN,
    )?;

    let now = Utc::now();
    let mut tx = state.pool.begin().await?;

    let challenge_row = sqlx::query(
        "SELECT nonce, new_identity_x25519_pub, new_identity_sig_pub, new_identity_pq_sig_pub, new_device_id, expires_at
         FROM identity_rotation_challenges
         WHERE challenge_id = $1 AND user_id = $2 AND consumed = 0",
    )
    .bind(&request.challenge_id)
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(challenge_row) = challenge_row else {
        return Err(AppError::not_found("rotation challenge not found"));
    };

    let nonce: Vec<u8> = challenge_row.try_get("nonce")?;
    let new_identity_x25519: Vec<u8> = challenge_row.try_get("new_identity_x25519_pub")?;
    let new_identity_sig: Vec<u8> = challenge_row.try_get("new_identity_sig_pub")?;
    let new_identity_pq_sig: Option<Vec<u8>> = challenge_row.try_get("new_identity_pq_sig_pub")?;
    let new_device_id: String = challenge_row.try_get("new_device_id")?;
    let expires_at_str: String = challenge_row.try_get("expires_at")?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(&expires_at_str)
        .map_err(|_| AppError::internal("invalid rotation challenge expiry"))?
        .with_timezone(&Utc);
    if now > expires_at {
        return Err(AppError::bad_request("rotation challenge expired"));
    }

    let new_identity_pq_sig = new_identity_pq_sig.ok_or_else(|| {
        AppError::conflict("rotation challenge missing PQ identity key; restart rotation")
    })?;

    let user_row = sqlx::query("SELECT identity_sig_pub, identity_pq_sig_pub FROM users WHERE user_id = $1")
        .bind(&user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(user_row) = user_row else {
        return Err(AppError::not_found("user not found"));
    };
    let current_identity_sig: Vec<u8> = user_row.try_get("identity_sig_pub")?;
    let current_identity_pq_sig: Option<Vec<u8>> = user_row.try_get("identity_pq_sig_pub")?;
    let current_identity_pq_sig = current_identity_pq_sig.ok_or_else(|| {
        AppError::conflict("current identity is missing PQ key material; re-register first")
    })?;

    let message = rotation_signature_message(
        &user_id,
        &request.challenge_id,
        &nonce,
        &new_identity_x25519,
        &new_identity_sig,
        &new_identity_pq_sig,
        &new_device_id,
    )?;
    verify_ed25519_signature(
        &current_identity_sig,
        &sig_by_current,
        &message,
        "sig_by_current_identity",
    )?;
    verify_ed25519_signature(
        &new_identity_sig,
        &sig_by_new,
        &message,
        "sig_by_new_identity",
    )?;
    verify_ml_dsa_signature(
        &current_identity_pq_sig,
        &pq_sig_by_current,
        &message,
        "pq_sig_by_current_identity",
    )?;
    verify_ml_dsa_signature(
        &new_identity_pq_sig,
        &pq_sig_by_new,
        &message,
        "pq_sig_by_new_identity",
    )?;

    let consume_result = sqlx::query(
        "UPDATE identity_rotation_challenges
         SET consumed = 1
         WHERE challenge_id = $1 AND user_id = $2 AND consumed = 0",
    )
    .bind(&request.challenge_id)
    .bind(&user_id)
    .execute(&mut *tx)
    .await?;
    if consume_result.rows_affected() != 1 {
        return Err(AppError::conflict("rotation challenge already consumed"));
    }

    let rotated_at = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE users
         SET identity_x25519_pub = $1, identity_sig_pub = $2, identity_pq_sig_pub = $3, device_id = $4, updated_at = $5
         WHERE user_id = $6",
    )
    .bind(&new_identity_x25519)
    .bind(&new_identity_sig)
    .bind(&new_identity_pq_sig)
    .bind(&new_device_id)
    .bind(&rotated_at)
    .bind(&user_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE user_devices
         SET active = 0, revoked_at = $1
         WHERE user_id = $2",
    )
    .bind(&rotated_at)
    .bind(&user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO user_devices (user_id, device_id, active, linked_at, revoked_at)
         VALUES ($1, $2, 1, $3, NULL)
         ON CONFLICT (user_id, device_id) DO UPDATE SET
            active = 1,
            linked_at = EXCLUDED.linked_at,
            revoked_at = NULL",
    )
    .bind(&user_id)
    .bind(&new_device_id)
    .bind(&rotated_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM prekeys WHERE user_id = $1 AND device_id <> $2")
        .bind(&user_id)
        .bind(&new_device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM one_time_prekeys_x25519 WHERE user_id = $1 AND device_id <> $2")
        .bind(&user_id)
        .bind(&new_device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM one_time_prekeys_mlkem768 WHERE user_id = $1 AND device_id <> $2")
        .bind(&user_id)
        .bind(&new_device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM push_tokens WHERE user_id = $1 AND device_id <> $2")
        .bind(&user_id)
        .bind(&new_device_id)
        .execute(&mut *tx)
        .await?;

    let next_version_i64: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1
         FROM identity_events
         WHERE user_id = $1",
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await?;
    let next_version = u32::try_from(next_version_i64)
        .map_err(|_| AppError::internal("identity version overflow"))?;

    sqlx::query(
        "INSERT INTO identity_events (
            user_id,
            version,
            identity_x25519_pub,
            identity_sig_pub,
            identity_pq_sig_pub,
            device_id,
            event_type,
            changed_at
         ) VALUES ($1, $2, $3, $4, $5, $6, 'rotation', $7)",
    )
    .bind(&user_id)
    .bind(i64::from(next_version))
    .bind(&new_identity_x25519)
    .bind(&new_identity_sig)
    .bind(&new_identity_pq_sig)
    .bind(&new_device_id)
    .bind(&rotated_at)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    record_security_event(
        &state,
        "rotation_confirmed",
        "success",
        None,
        Some(&user_id),
        Some(&new_device_id),
        Some(format!("version={next_version}")),
    );
    Ok(Json(RotateConfirmResponse {
        user_id,
        identity_key_version: next_version,
        identity_fingerprint_sha256: identity_fingerprint_sha256(
            &new_identity_x25519,
            Some(&new_identity_pq_sig),
        ),
        rotated_at,
    }))
}

pub(crate) async fn get_identity_log(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<IdentityLogResponse>, AppError> {
    check_rate_limit(&state, &format!("identity-log:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    let auth = parse_request_auth(&headers)?;
    if auth.user_id != user_id {
        return Err(AppError::bad_request("auth user_id mismatch"));
    }
    let auth_message = identity_log_auth_message(&auth, &user_id)?;
    verify_request_auth(&state, &auth, &auth_message).await?;
    ensure_user_exists(&state.pool, &user_id).await?;

    let rows = sqlx::query(
        "SELECT
            version,
            identity_x25519_pub,
            identity_sig_pub,
            identity_pq_sig_pub,
            device_id,
            event_type,
            changed_at
         FROM identity_events
         WHERE user_id = $1
         ORDER BY version DESC
         LIMIT $2",
    )
    .bind(&user_id)
    .bind(MAX_IDENTITY_LOG_ITEMS)
    .fetch_all(&state.pool)
    .await?;

    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let version_i64: i64 = row.try_get("version")?;
        let version = u32::try_from(version_i64)
            .map_err(|_| AppError::internal("identity version overflow"))?;
        let identity_x25519_pub: Vec<u8> = row.try_get("identity_x25519_pub")?;
        let identity_sig_pub: Vec<u8> = row.try_get("identity_sig_pub")?;
        let identity_pq_sig_pub: Option<Vec<u8>> = row.try_get("identity_pq_sig_pub")?;
        events.push(IdentityLogItem {
            version,
            identity_x25519_pub: B64.encode(&identity_x25519_pub),
            identity_sig_pub: B64.encode(identity_sig_pub),
            identity_pq_sig_pub: identity_pq_sig_pub.as_ref().map(|value| B64.encode(value)),
            device_id: row.try_get("device_id")?,
            event_type: row.try_get("event_type")?,
            changed_at: row.try_get("changed_at")?,
            identity_fingerprint_sha256: identity_fingerprint_sha256(
                &identity_x25519_pub,
                identity_pq_sig_pub.as_deref(),
            ),
        });
    }

    Ok(Json(IdentityLogResponse { user_id, events }))
}
