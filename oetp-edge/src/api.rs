// HTTP handlers for the edge daemon's 4 API endpoints
use crate::beacon::BeaconClient;
use crate::state::{AppState, CachedExamData};
use axum::{extract::State, http::StatusCode, Json};
use oetp_core::envelope;
use oetp_core::hashing;
use oetp_core::packet;
use oetp_core::receipt;
use oetp_core::signing;
use oetp_core::validation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
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

fn bad_gateway(msg: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    api_error("BAD_GATEWAY", StatusCode::BAD_GATEWAY, msg)
}

fn check_api_key(state: &AppState, headers: &axum::http::HeaderMap) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let provided = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != state.config.api_key {
        return Err(unauthorized());
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct FetchRequest {
    pub student_uuid: Uuid,
    #[allow(dead_code)]
    pub application_number: String,
}

#[derive(Serialize)]
pub struct FetchResponse {
    pub status: String,
    pub packet_hash: [u8; 32],
}

pub async fn handle_fetch(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<FetchRequest>,
) -> ApiResult<FetchResponse> {
    check_api_key(&state, &headers)?;
    tracing::info!("fetch packet for student {}", short_uuid(req.student_uuid));
    let ledger_url = &state.config.ledger_url;
    let tenant_id = &state.config.tenant_id;
    let exam_id = &state.config.exam_id;

    let resp = state
        .http_client
        .post(format!("{}/v1/ledger/fetch", ledger_url))
        .header("x-api-key", &state.config.api_key)
        .json(&serde_json::json!({
            "tenant_id": tenant_id,
            "exam_id": exam_id,
            "student_uuid": req.student_uuid,
        }))
        .send()
        .await
        .map_err(|e| bad_gateway(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(not_found("packet not found"));
    }

    #[derive(Deserialize)]
    struct FetchData {
        encrypted_packet: packet::EncryptedPacket,
        key_envelope: envelope::KeyEnvelope,
    }

    let data: FetchData = resp
        .json()
        .await
        .map_err(|e| bad_gateway(e.to_string()))?;

    // verify packet hash against the anchored Merkle root (best-effort)
    #[derive(serde::Serialize)]
    struct VerifyCheck {
        tenant_id: String,
        exam_id: String,
        student_uuid: String,
        packet_hash: [u8; 32],
        answers_hash: [u8; 32],
        timestamp: u64,
        merkle_leaf: [u8; 32],
        edge_signature: Vec<u8>,
        edge_public_key: [u8; 32],
    }
    let _ = state
        .http_client
        .post(format!("{}/v1/ledger/verify", ledger_url))
        .header("x-api-key", &state.config.api_key)
        .json(&VerifyCheck {
            tenant_id: tenant_id.clone(),
            exam_id: exam_id.clone(),
            student_uuid: req.student_uuid.to_string(),
            packet_hash: data.encrypted_packet.packet_hash,
            answers_hash: [0; 32],
            timestamp: 0,
            merkle_leaf: [0; 32],
            edge_signature: vec![],
            edge_public_key: [0; 32],
        })
        .send()
        .await;

    // If ledger is reachable, verify the packet hash is committed
    // (best-effort; the response is ignored for now)

    let mut cache = state.cache.lock().await;
    cache.insert(
        req.student_uuid.to_string(),
        CachedExamData {
            encrypted_packet: data.encrypted_packet.clone(),
            key_envelope: data.key_envelope,
            release_token: None,
            variant_seed: None,
        },
    );

    Ok(Json(FetchResponse {
        status: "cached".into(),
        packet_hash: data.encrypted_packet.packet_hash,
    }))
}

#[derive(Deserialize)]
pub struct ReleaseRequest {
    pub student_uuid: Uuid,
}

#[derive(Serialize)]
pub struct ReleaseResponse {
    pub status: String,
}

pub async fn handle_release(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ReleaseRequest>,
) -> ApiResult<ReleaseResponse> {
    check_api_key(&state, &headers)?;
    tracing::info!("release token for student {}", short_uuid(req.student_uuid));
    let mut cache = state.cache.lock().await;
    let entry = cache
        .get_mut(&req.student_uuid.to_string())
        .ok_or(not_found("no cached packet"))?;

    // Use the configured beacon public key, NOT the device key
    let beacon = BeaconClient::new(
        &state.config.beacon_url,
        &state.config.beacon_public_key,
        &state.config.api_key,
    )
    .map_err(|e| internal_error(e.to_string()))?;
    let release_token = beacon
        .request_token(&state.config.center_id, &state.config.exam_id, &state.config.device_id)
        .await
        .map_err(|e| forbidden(e.to_string()))?;

    // verify center_id, exam_id, and device_id match our config
    if release_token.center_id != state.config.center_id {
        return Err(forbidden("token center_id mismatch"));
    }
    if release_token.exam_id != state.config.exam_id {
        return Err(forbidden("token exam_id mismatch"));
    }
    if release_token.device_id != state.config.device_id {
        return Err(forbidden("token device_id mismatch"));
    }

    // replay prevention: reject already-consumed nonce
    let mut consumed = state.consumed_nonces.lock().await;
    if consumed.contains(&release_token.nonce) {
        return Err(forbidden("release token already consumed"));
    }
    consumed.insert(release_token.nonce);

    entry.release_token = Some(release_token);
    Ok(Json(ReleaseResponse {
        status: "released".into(),
    }))
}

#[derive(Deserialize)]
pub struct UnlockRequest {
    pub student_uuid: Uuid,
}

#[derive(Serialize)]
pub struct UnlockResponse {
    pub questions: Vec<packet::PacketQuestion>,
}

pub async fn handle_unlock(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<UnlockResponse> {
    check_api_key(&state, &headers)?;
    tracing::info!("unlock packet for student {}", short_uuid(req.student_uuid));
    let mut cache = state.cache.lock().await;
    let entry = cache
        .get_mut(&req.student_uuid.to_string())
        .ok_or(not_found("no cached packet"))?;

    if entry.release_token.is_none() {
        return Err(forbidden("no release token"));
    }

    let device_key_bytes = state.device_x25519_key.private_key.as_ref();
    let ephemeral_key = envelope::open_key_envelope(
        &entry.key_envelope,
        device_key_bytes,
        &state.config.device_id,
        req.student_uuid,
        &state.config.exam_id,
    )
    .map_err(|e| internal_error(e.to_string()))?;

    let exam_packet = packet::decrypt_packet(&entry.encrypted_packet, &ephemeral_key)
        .map_err(|e| internal_error(e.to_string()))?;

    // verify packet tenant_id matches our config
    if exam_packet.tenant_id != state.config.tenant_id {
        return Err(forbidden("packet tenant_id mismatch"));
    }
    if exam_packet.exam_id != state.config.exam_id {
        return Err(forbidden("packet exam_id mismatch"));
    }

    // cache variant_seed for answer sealing
    entry.variant_seed = Some(exam_packet.variant_seed);

    // Return the decrypted questions; exam_packet will be dropped and zeroized
    // (PacketQuestion fields are String/Vec which are heap-allocated; in production
    //  a LockedBuffer-based response type should be used for full protection)

    Ok(Json(UnlockResponse {
        questions: exam_packet.questions,
    }))
}

#[derive(Deserialize)]
pub struct SubmitRequest {
    pub student_uuid: Uuid,
    pub application_number: String,
    pub dob: Option<String>,
    pub answers: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub struct SubmitResponse {
    pub receipt_id: String,
    pub receipt: receipt::StudentReceipt,
    pub personal_copy: receipt::PersonalAnswerCopy,
}

pub async fn handle_submit(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SubmitRequest>,
) -> ApiResult<SubmitResponse> {
    check_api_key(&state, &headers)?;
    tracing::info!("submit answers for student {}", short_uuid(req.student_uuid));

    if let Err(e) = validation::validate_identifier("application_number", &req.application_number) {
        return Err(bad_request(e.to_string()));
    }

    // Enforce exam window
    let now = oetp_core::release::current_timestamp_secs();
    if now < state.config.exam_window_start {
        return Err(forbidden("exam has not started yet"));
    }
    if now > state.config.exam_window_end {
        return Err(forbidden("exam window has ended"));
    }

    let cache_entry = {
        let cache = state.cache.lock().await;
        cache.get(&req.student_uuid.to_string()).cloned()
    };
    let entry = cache_entry.ok_or(not_found("no cached packet"))?;

    // enforce that the packet was actually unlocked (variant_seed present)
    let variant_seed = entry.variant_seed.ok_or(forbidden("packet not unlocked; call /v1/exam/unlock first"))?;

    let timestamp = oetp_core::release::current_timestamp_secs();
    let packet_hash = entry.encrypted_packet.packet_hash;

    let answers_hash = hashing::compute_answers_hash(
        &packet_hash,
        &req.answers,
        req.student_uuid,
        &variant_seed,
        timestamp,
        &state.config.tenant_id,
        &state.config.exam_id,
    );

    let merkle_leaf = hashing::compute_submission_leaf(
        req.student_uuid,
        &packet_hash,
        &answers_hash,
        timestamp,
        &state.config.tenant_id,
        &state.config.exam_id,
    );

    let signature = signing::sign(&state.device_key.signing_key(), &merkle_leaf);

    let receipt_id = receipt::generate_receipt_id();

    let answers_json = serde_json::to_vec(&req.answers)
        .map_err(|e| internal_error(e.to_string()))?;

    let student_key = hashing::derive_student_answer_key(
        &req.application_number,
        req.dob.as_deref().unwrap_or(""),
        &state.config.exam_salt,
        &state.config.server_pepper,
        &state.config.tenant_id,
        &state.config.exam_id,
    );
    let personal_copy = receipt::create_personal_answer_copy(&receipt_id, &answers_json, &student_key)
        .map_err(|e| internal_error(e.to_string()))?;

    let queued = crate::queue::QueuedSubmission {
        tenant_id: state.config.tenant_id.clone(),
        exam_id: state.config.exam_id.clone(),
        student_uuid: req.student_uuid,
        packet_hash,
        answers_hash,
        merkle_leaf,
        timestamp,
        signature: signature.to_bytes().to_vec(),
        receipt_id: receipt_id.clone(),
    };

    // Try to ingest immediately; only queue if it fails
    let ingest_ok = state
        .http_client
        .post(format!("{}/v1/ledger/ingest", state.config.ledger_url))
        .header("x-api-key", &state.config.api_key)
        .json(&serde_json::json!({
            "tenant_id": state.config.tenant_id,
            "exam_id": state.config.exam_id,
            "student_uuid": req.student_uuid,
            "packet_hash": packet_hash,
            "answers_hash": answers_hash,
            "merkle_leaf": merkle_leaf,
            "timestamp": timestamp,
            "signature": signature.to_bytes().to_vec(),
            "receipt_id": receipt_id,
        }))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success());

    if !ingest_ok {
        state
            .queue
            .enqueue(&queued)
            .await
            .map_err(|e| internal_error(e.to_string()))?;
    }

    // Build receipt with a placeholder proof; the real proof is fetched later
    // from the ledger via /v1/ledger/proof using the receipt_id
    let merkle_proof = oetp_core::merkle::MerkleProof {
        leaf_index: 0,
        leaf: merkle_leaf,
        siblings: vec![],
        root: merkle_leaf,
    };

    let student_receipt = receipt::StudentReceipt {
        receipt_id: receipt_id.clone(),
        tenant_id: state.config.tenant_id.clone(),
        exam_id: state.config.exam_id.clone(),
        application_number: req.application_number.clone(),
        student_uuid: req.student_uuid,
        packet_hash,
        answers_hash,
        timestamp,
        merkle_proof,
        edge_signature: signature.to_bytes().to_vec(),
        ledger_signature: vec![],
        qr_payload: format!("oetp:receipt:{}", receipt_id),
    };

    Ok(Json(SubmitResponse {
        receipt_id,
        receipt: student_receipt,
        personal_copy,
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

#[derive(Serialize)]
pub struct FlushResponse {
    pub status: String,
    pub flushed: usize,
}

pub async fn handle_system_flush(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> ApiResult<FlushResponse> {
    check_api_key(&state, &headers)?;
    let ledger_url = state.config.ledger_url.clone();
    match state.queue.flush(&ledger_url).await {
        Ok(n) => Ok(Json(FlushResponse {
            status: "ok".into(),
            flushed: n,
        })),
        Err(e) => Err(internal_error(e.to_string())),
    }
}

/// Returns a short, non-sensitive representation of a UUID for logging.
fn short_uuid(uuid: Uuid) -> String {
    let s = uuid.to_string();
    format!("{}...", &s[..8])
}
