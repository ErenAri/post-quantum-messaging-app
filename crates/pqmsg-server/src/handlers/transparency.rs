use axum::extract::{Path, Query, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::DateTime;
use chrono::Utc;
use ed25519_dalek::Signer;
use pqmsg_core::key_transparency::{
    build_consistency_proof, build_inclusion_proof, build_tree_root, SignedTreeHead,
    TransparencyLeaf,
};
use sqlx::Row;

use super::util::*;
use crate::db::*;
use crate::error::AppError;
use crate::types::*;
use crate::validation::*;
use crate::AppState;

pub(crate) async fn get_transparency_proof(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Query(query): Query<TransparencyProofQuery>,
) -> Result<Json<TransparencyProofResponse>, AppError> {
    check_rate_limit(&state, &format!("transparency-proof:{user_id}"))?;
    validate_id("user_id", &user_id)?;
    ensure_user_exists(state.pool(), &user_id).await?;

    let rows = sqlx::query(
        "SELECT
            id,
            user_id,
            version,
            identity_x25519_pub,
            identity_sig_pub,
            identity_pq_sig_pub,
            changed_at
         FROM identity_events
         ORDER BY id ASC",
    )
    .fetch_all(state.pool())
    .await?;

    if rows.is_empty() {
        return Err(AppError::not_found("transparency log is empty"));
    }

    let mut leaf_hashes = Vec::with_capacity(rows.len());
    let mut latest_leaf_for_user: Option<TransparencyLeafRecord> = None;
    let mut latest_leaf_index: Option<usize> = None;
    let mut last_event_id: u64 = 0;

    for (idx, row) in rows.iter().enumerate() {
        let event_id: i64 = row.try_get("id")?;
        let event_id = u64::try_from(event_id)
            .map_err(|_| AppError::internal("identity event id overflow"))?;
        last_event_id = event_id;

        let row_user_id: String = row.try_get("user_id")?;
        let version_i64: i64 = row.try_get("version")?;
        let version = u64::try_from(version_i64)
            .map_err(|_| AppError::internal("identity version overflow"))?;
        let identity_x25519_pub: Vec<u8> = row.try_get("identity_x25519_pub")?;
        let identity_sig_pub: Vec<u8> = row.try_get("identity_sig_pub")?;
        let identity_pq_sig_pub: Option<Vec<u8>> = row.try_get("identity_pq_sig_pub")?;
        let changed_at: String = row.try_get("changed_at")?;
        let parsed_changed_at = DateTime::parse_from_rfc3339(&changed_at)
            .map_err(|_| AppError::internal("invalid identity_events.changed_at timestamp"))?
            .with_timezone(&Utc);
        let timestamp = u64::try_from(parsed_changed_at.timestamp())
            .map_err(|_| AppError::internal("identity event timestamp before unix epoch"))?;

        let identity_x25519_pub: [u8; 32] = identity_x25519_pub
            .try_into()
            .map_err(|_| AppError::internal("invalid identity_events.identity_x25519_pub"))?;
        let leaf = TransparencyLeaf {
            user_id: row_user_id.clone(),
            version,
            identity_x25519_pub,
            identity_sig_pub: identity_sig_pub.clone(),
            identity_pq_sig_pub: identity_pq_sig_pub.clone(),
            timestamp,
        };
        leaf_hashes.push(leaf.hash());

        if row_user_id == user_id {
            latest_leaf_index = Some(idx);
            latest_leaf_for_user = Some(TransparencyLeafRecord {
                user_id: row_user_id,
                version,
                identity_x25519_pub: B64.encode(identity_x25519_pub),
                identity_sig_pub: B64.encode(identity_sig_pub),
                identity_pq_sig_pub: identity_pq_sig_pub.map(|value| B64.encode(value)),
                timestamp,
            });
        }
    }

    let latest_leaf_index =
        latest_leaf_index.ok_or_else(|| AppError::not_found("no transparency leaf for user"))?;
    let latest_leaf_for_user =
        latest_leaf_for_user.ok_or_else(|| AppError::not_found("no transparency leaf for user"))?;

    let root_hash = build_tree_root(&leaf_hashes)
        .ok_or_else(|| AppError::internal("failed to build tree root"))?;
    let tree_size = leaf_hashes.len() as u64;
    let mut sth = SignedTreeHead {
        epoch: last_event_id.max(tree_size),
        tree_size,
        root_hash,
        signature: Vec::new(),
    };
    sth.signature = state
        .sender_certificate_signing_key()
        .sign(&sth.signing_body())
        .to_bytes()
        .to_vec();

    let inclusion_proof = build_inclusion_proof(&leaf_hashes, latest_leaf_index)
        .ok_or_else(|| AppError::internal("failed to build inclusion proof"))?;

    let consistency_proof = match query.previous_tree_size {
        None => None,
        Some(previous_tree_size) => {
            let previous_tree_size = usize::try_from(previous_tree_size)
                .map_err(|_| AppError::bad_request("previous_tree_size overflow"))?;
            let proof =
                build_consistency_proof(&leaf_hashes, previous_tree_size).ok_or_else(|| {
                    AppError::bad_request("previous_tree_size must be in 1..=current tree size")
                })?;
            Some(TransparencyConsistencyProofResponse {
                old_size: proof.old_size,
                new_size: proof.new_size,
                proof_hashes: proof
                    .proof_hashes
                    .into_iter()
                    .map(|hash| B64.encode(hash))
                    .collect(),
            })
        }
    };

    Ok(Json(TransparencyProofResponse {
        user_id,
        leaf: latest_leaf_for_user,
        inclusion_proof: TransparencyInclusionProofResponse {
            leaf_index: inclusion_proof.leaf_index,
            path: inclusion_proof
                .path
                .into_iter()
                .map(|(hash, is_left)| TransparencyPathItem {
                    hash: B64.encode(hash),
                    is_left,
                })
                .collect(),
        },
        signed_tree_head: TransparencySignedTreeHeadResponse {
            epoch: sth.epoch,
            tree_size: sth.tree_size,
            root_hash: B64.encode(sth.root_hash),
            signature: B64.encode(sth.signature),
        },
        consistency_proof,
    }))
}
