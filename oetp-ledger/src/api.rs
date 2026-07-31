// HTTP handlers for the ledger API
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use oetp_core::envelope::KeyEnvelope;
use oetp_core::merkle::MerkleTree;
use oetp_core::packet::EncryptedPacket;
use oetp_core::platform::{Anchor, AnchorType, Store};
use oetp_core::validation;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(serde::Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;

fn api_error(code: &str, status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: ErrorDetail {
                code: code.into(),
                message: msg.into(),
            },
        }),
    )
}

fn unauthorized() -> (StatusCode, Json<ErrorResponse>) {
    api_error("UNAUTHORIZED", StatusCode::UNAUTHORIZED, "invalid api key")
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error("INVALID_INPUT", StatusCode::BAD_REQUEST, msg)
}

fn not_found(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error("NOT_FOUND", StatusCode::NOT_FOUND, msg)
}

fn forbidden(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error("FORBIDDEN", StatusCode::FORBIDDEN, msg)
}

fn internal_error(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error("INTERNAL_ERROR", StatusCode::INTERNAL_SERVER_ERROR, msg)
}

fn check_api_key(state: &AppState, headers: &axum::http::HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let provided = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != state.api_key {
        return Err(unauthorized());
    }
    Ok(())
}

pub struct AppState {
    pub store: Arc<dyn Store>,
    #[allow(dead_code)]
    pub signing_key: ed25519_dalek::SigningKey,
    pub packets: RwLock<HashMap<String, (EncryptedPacket, KeyEnvelope)>>,
    pub anchors: RwLock<Vec<Anchor>>,
    pub receipt_index: RwLock<HashMap<String, u64>>,
    pub api_key: String,
    pub exam_window_start: u64,
    pub exam_window_end: u64,
}

#[derive(Deserialize)]
pub struct CommitRequest {
    pub tenant_id: String,
    pub exam_id: String,
    pub packet_hashes: Vec<[u8; 32]>,
}

#[derive(Serialize)]
pub struct CommitResponse {
    pub merkle_root: [u8; 32],
    pub anchor: Anchor,
}

pub async fn handle_commit(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CommitRequest>,
) -> ApiResult<CommitResponse> {
    check_api_key(&state, &headers)?;
    if let Err(e) = validation::validate_identifier("tenant_id", &req.tenant_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(bad_request(e.to_string()));
    }
    tracing::info!(
        "commit {} packet hashes for {}/{}",
        req.packet_hashes.len(),
        req.tenant_id,
        req.exam_id
    );
    let tree = MerkleTree::new(req.packet_hashes).map_err(|e| bad_request(e.to_string()))?;
    let root = *tree.root();

    let anchor = Anchor {
        chain_id: "polygon".into(),
        tx_hash: format!("0x{}", hex::encode(root)),
        anchored_root: root,
        anchor_type: AnchorType::PreExam,
        timestamp: oetp_core::release::current_timestamp_secs(),
        signature: vec![],
    };

    state
        .store
        .append(&req.tenant_id, &req.exam_id, &root)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    let mut anchors = state.anchors.write().await;
    anchors.push(anchor.clone());

    Ok(Json(CommitResponse {
        merkle_root: root,
        anchor,
    }))
}

#[derive(Deserialize)]
pub struct IngestRequest {
    pub tenant_id: String,
    pub exam_id: String,
    pub student_uuid: Uuid,
    pub packet_hash: [u8; 32],
    pub answers_hash: [u8; 32],
    pub merkle_leaf: [u8; 32],
    pub timestamp: u64,
    #[allow(dead_code)]
    pub signature: Vec<u8>,
    pub receipt_id: String,
}

#[derive(Serialize)]
pub struct IngestResponse {
    pub leaf_index: u64,
    pub status: String,
}

pub async fn handle_ingest(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<IngestRequest>,
) -> ApiResult<IngestResponse> {
    check_api_key(&state, &headers)?;
    if let Err(e) = validation::validate_identifier("tenant_id", &req.tenant_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("receipt_id", &req.receipt_id) {
        return Err(bad_request(e.to_string()));
    }
    tracing::info!(
        "ingest submission for student {} ({}/{}): hash={:?}..., answers={:?}..., ts={}",
        short_uuid(req.student_uuid),
        req.tenant_id,
        req.exam_id,
        &req.packet_hash[..4],
        &req.answers_hash[..4],
        req.timestamp,
    );

    // Enforce exam window
    let now = oetp_core::release::current_timestamp_secs();
    if now < state.exam_window_start {
        return Err(forbidden("exam has not started yet"));
    }
    if now > state.exam_window_end {
        return Err(forbidden("exam window has ended"));
    }

    // Verify the edge signature against the merkle_leaf
    // In production, the edge_public_key should be looked up from the manifest
    // For now, we accept the signature as-is (the edge signs with its device key)
    // and store the receipt_id for proof lookup
    let leaf_index = state
        .store
        .append(&req.tenant_id, &req.exam_id, &req.merkle_leaf)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    // Populate receipt_index for /proof lookup
    let mut index = state.receipt_index.write().await;
    index.insert(req.receipt_id.clone(), leaf_index);

    Ok(Json(IngestResponse {
        leaf_index,
        status: "ingested".into(),
    }))
}

#[derive(Deserialize)]
pub struct ProofRequest {
    pub tenant_id: String,
    pub exam_id: String,
    pub receipt_id: String,
}

#[derive(Serialize)]
pub struct ProofResponse {
    pub merkle_leaf: Option<[u8; 32]>,
    pub leaf_index: Option<u64>,
    pub total_leaves: u64,
    pub siblings: Vec<[u8; 32]>,
    pub root: Option<[u8; 32]>,
}

pub async fn handle_proof(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProofRequest>,
) -> ApiResult<ProofResponse> {
    if let Err(e) = validation::validate_identifier("tenant_id", &req.tenant_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("receipt_id", &req.receipt_id) {
        return Err(bad_request(e.to_string()));
    }
    tracing::info!(
        "proof request for receipt {} ({}/{})",
        req.receipt_id, req.tenant_id, req.exam_id
    );

    let total = state
        .store
        .count(&req.tenant_id, &req.exam_id)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    if total == 0 {
        return Ok(Json(ProofResponse {
            merkle_leaf: None,
            leaf_index: None,
            total_leaves: 0,
            siblings: vec![],
            root: None,
        }));
    }

    let mut leaves = Vec::with_capacity(total as usize);
    for i in 0..total {
        if let Some(leaf) = state
            .store
            .get(&req.tenant_id, &req.exam_id, i)
            .await
            .map_err(|e| internal_error(e.to_string()))?
        {
            leaves.push(leaf);
        }
    }

    let tree = oetp_core::merkle::MerkleTree::new(leaves)
        .map_err(|e| internal_error(e.to_string()))?;
    let root = *tree.root();

    // Look up leaf_index by receipt_id
    let receipt_index = state.receipt_index.read().await;
    let (merkle_leaf, leaf_index, proof_siblings) = match receipt_index.get(&req.receipt_id) {
        Some(idx) => {
            let proof = tree
                .prove(*idx as usize)
                .map_err(|e| internal_error(e.to_string()))?;
            (Some(proof.leaf), Some(*idx), proof.siblings)
        }
        None => (None, None, vec![]),
    };
    drop(receipt_index);

    Ok(Json(ProofResponse {
        merkle_leaf,
        leaf_index,
        total_leaves: total,
        siblings: proof_siblings,
        root: Some(root),
    }))
}

#[derive(Deserialize)]
pub struct KeyCommitRequest {
    pub tenant_id: String,
    pub exam_id: String,
    pub answer_key_hash: [u8; 32],
}

#[derive(Serialize)]
pub struct KeyCommitResponse {
    pub anchor: Anchor,
}

pub async fn handle_key_commit(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<KeyCommitRequest>,
) -> ApiResult<KeyCommitResponse> {
    check_api_key(&state, &headers)?;
    if let Err(e) = validation::validate_identifier("tenant_id", &req.tenant_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(bad_request(e.to_string()));
    }
    tracing::info!("commit answer key for {}/{}", req.tenant_id, req.exam_id);
    let anchor = Anchor {
        chain_id: "polygon".into(),
        tx_hash: format!("0x{}", hex::encode(req.answer_key_hash)),
        anchored_root: req.answer_key_hash,
        anchor_type: AnchorType::AnswerKey,
        timestamp: oetp_core::release::current_timestamp_secs(),
        signature: vec![],
    };

    state
        .store
        .append(&req.tenant_id, &req.exam_id, &req.answer_key_hash)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    let mut anchors = state.anchors.write().await;
    anchors.push(anchor.clone());

    Ok(Json(KeyCommitResponse { anchor }))
}

#[derive(Deserialize)]
pub struct FetchPacketRequest {
    pub tenant_id: String,
    pub exam_id: String,
    pub student_uuid: Uuid,
}

#[derive(Serialize)]
pub struct FetchPacketResponse {
    pub encrypted_packet: EncryptedPacket,
    pub key_envelope: KeyEnvelope,
}

pub async fn handle_fetch_packet(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FetchPacketRequest>,
) -> ApiResult<FetchPacketResponse> {
    check_api_key(&state, &headers)?;
    if let Err(e) = validation::validate_identifier("tenant_id", &req.tenant_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(bad_request(e.to_string()));
    }
    tracing::info!(
        "fetch packet for student {} ({}/{})",
        short_uuid(req.student_uuid),
        req.tenant_id,
        req.exam_id
    );
    let key = format!("{}:{}:{}", req.tenant_id, req.exam_id, req.student_uuid);
    let packets = state.packets.read().await;
    let (encrypted_packet, key_envelope) = packets
        .get(&key)
        .ok_or(not_found("packet not found"))?
        .clone();
    Ok(Json(FetchPacketResponse {
        encrypted_packet,
        key_envelope,
    }))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub tenant_id: String,
    pub exam_id: String,
    pub student_uuid: Uuid,
    pub packet_hash: [u8; 32],
    pub answers_hash: [u8; 32],
    pub timestamp: u64,
    pub merkle_leaf: [u8; 32],
    pub edge_signature: Vec<u8>,
    pub edge_public_key: [u8; 32],
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub reason: String,
    pub leaf_index: Option<u64>,
    pub total_leaves: u64,
    pub anchored_root: Option<[u8; 32]>,
}

pub async fn handle_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> ApiResult<VerifyResponse> {
    if let Err(e) = validation::validate_identifier("tenant_id", &req.tenant_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(bad_request(e.to_string()));
    }
    tracing::info!(
        "verify submission for student {} ({}/{})",
        short_uuid(req.student_uuid),
        req.tenant_id,
        req.exam_id
    );

    let computed_leaf = oetp_core::hashing::compute_submission_leaf(
        req.student_uuid,
        &req.packet_hash,
        &req.answers_hash,
        req.timestamp,
        &req.tenant_id,
        &req.exam_id,
    );
    if computed_leaf != req.merkle_leaf {
        return Ok(Json(VerifyResponse {
            valid: false,
            reason: "submission leaf mismatch".into(),
            leaf_index: None,
            total_leaves: 0,
            anchored_root: None,
        }));
    }

    let vk = match oetp_core::signing::verifying_key_from_bytes(&req.edge_public_key) {
        Ok(k) => k,
        Err(_) => {
            return Ok(Json(VerifyResponse {
                valid: false,
                reason: "invalid edge public key".into(),
                leaf_index: None,
                total_leaves: 0,
                anchored_root: None,
            }))
        }
    };
    let sig = match ed25519_dalek::Signature::from_slice(&req.edge_signature) {
        Ok(s) => s,
        Err(_) => {
            return Ok(Json(VerifyResponse {
                valid: false,
                reason: "invalid signature bytes".into(),
                leaf_index: None,
                total_leaves: 0,
                anchored_root: None,
            }))
        }
    };
    if oetp_core::signing::verify(&vk, &req.merkle_leaf, &sig).is_err() {
        return Ok(Json(VerifyResponse {
            valid: false,
            reason: "edge signature verification failed".into(),
            leaf_index: None,
            total_leaves: 0,
            anchored_root: None,
        }));
    }

    let total = state
        .store
        .count(&req.tenant_id, &req.exam_id)
        .await
        .map_err(|e| internal_error(e.to_string()))?;

    let mut leaf_index = None;
    for i in 0..total {
        if state
            .store
            .get(&req.tenant_id, &req.exam_id, i)
            .await
            .map_err(|e| internal_error(e.to_string()))?
            .is_some_and(|leaf| leaf == req.merkle_leaf)
        {
            leaf_index = Some(i);
            break;
        }
    }

    let anchored_root = match state
        .store
        .latest_root(&req.tenant_id, &req.exam_id)
        .await
        .map_err(|e| internal_error(e.to_string()))?
    {
        Some(root) => Some(root),
        None => {
            // Compute root on-the-fly if Merkle worker hasn't persisted one yet
            let total = state
                .store
                .count(&req.tenant_id, &req.exam_id)
                .await
                .map_err(|e| internal_error(e.to_string()))?;
            if total == 0 {
                None
            } else {
                let mut leaves = Vec::with_capacity(total as usize);
                for i in 0..total {
                    if let Some(leaf) = state
                        .store
                        .get(&req.tenant_id, &req.exam_id, i)
                        .await
                        .map_err(|e| internal_error(e.to_string()))?
                    {
                        leaves.push(leaf);
                    }
                }
                let tree = oetp_core::merkle::MerkleTree::new(leaves)
                    .map_err(|e| internal_error(e.to_string()))?;
                Some(*tree.root())
            }
        }
    };

    Ok(Json(VerifyResponse {
        valid: leaf_index.is_some(),
        reason: if leaf_index.is_some() { "verified".into() } else { "leaf not found in ledger".into() },
        leaf_index,
        total_leaves: total,
        anchored_root,
    }))
}

#[derive(Deserialize)]
pub struct AnchorsRequest {
    pub tenant_id: String,
    pub exam_id: String,
}

#[derive(Serialize)]
pub struct AnchorsResponse {
    pub anchors: Vec<Anchor>,
}

pub async fn handle_anchors(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AnchorsRequest>,
) -> ApiResult<AnchorsResponse> {
    if let Err(e) = validation::validate_identifier("tenant_id", &req.tenant_id) {
        return Err(bad_request(e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(bad_request(e.to_string()));
    }
    tracing::info!("anchors request for {}/{}", req.tenant_id, req.exam_id);
    let anchors = state.anchors.read().await;
    let filtered: Vec<Anchor> = anchors.iter().cloned().collect();
    Ok(Json(AnchorsResponse { anchors: filtered }))
}

#[derive(Deserialize)]
pub struct LoadPacketsRequest {
    pub key: String,
    pub encrypted_packet: EncryptedPacket,
    pub key_envelope: KeyEnvelope,
}

#[derive(Serialize)]
pub struct LoadPacketsResponse {
    pub status: String,
}

pub async fn handle_load_packets(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoadPacketsRequest>,
) -> ApiResult<LoadPacketsResponse> {
    check_api_key(&state, &headers)?;
    let mut packets = state.packets.write().await;
    packets.insert(req.key, (req.encrypted_packet, req.key_envelope));
    Ok(Json(LoadPacketsResponse {
        status: "loaded".into(),
    }))
}

#[derive(Deserialize)]
pub struct SystemClockRequest {
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct SystemClockResponse {
    pub status: String,
    pub previous_timestamp: u64,
}

pub async fn handle_system_set_clock(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SystemClockRequest>,
) -> ApiResult<SystemClockResponse> {
    check_api_key(&state, &headers)?;
    let prev = oetp_core::release::current_timestamp_secs();
    oetp_core::clock::set_clock(req.timestamp);
    tracing::warn!("system clock set from {} to {}", prev, req.timestamp);
    Ok(Json(SystemClockResponse {
        status: "ok".into(),
        previous_timestamp: prev,
    }))
}

/// Returns a short, non-sensitive representation of a UUID for logging.
fn short_uuid(uuid: Uuid) -> String {
    let s = uuid.to_string();
    format!("{}...", &s[..8])
}
