// End-to-end integration test: real HTTP servers with separate identities
// Spawns ledger and beacon servers, then runs full exam lifecycle via HTTP
use oetp_core::device::DeviceKeyPair;
use oetp_core::hashing;
use oetp_core::packet::{self, ExamPacket, PacketQuestion};
use oetp_core::question_bank::{
    self, DifficultyRatio, QuestionBank, QuestionItem, QuestionVariant,
};
use oetp_core::release::ReleaseToken;
use oetp_core::signing;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::{BTreeMap, HashMap};
use std::net::TcpListener;
use uuid::Uuid;

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn sample_bank() -> QuestionBank {
    let items: Vec<QuestionItem> = (1..=30)
        .map(|i| {
            let difficulty = match i % 3 {
                0 => oetp_core::question_bank::Difficulty::Easy,
                1 => oetp_core::question_bank::Difficulty::Medium,
                _ => oetp_core::question_bank::Difficulty::Hard,
            };
            QuestionItem {
                id: i as u64,
                difficulty,
                stem: format!("question {}", i),
                variants: vec![QuestionVariant {
                    id: 0,
                    substitutions: HashMap::new(),
                    options: vec!["A".into(), "B".into(), "C".into(), "D".into()],
                    correct_index: 0,
                }],
            }
        })
        .collect();
    QuestionBank::new(items).unwrap()
}

#[tokio::test]
async fn test_end_to_end_deployment() {
    let tenant_id = "nta";
    let exam_id = "jee-2027";
    let student_uuid = Uuid::from_u128(42);
    let device = DeviceKeyPair::generate("device-01");
    let device_x25519_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let device_x25519_public = x25519_dalek::PublicKey::from(&device_x25519_secret);

    // -- GENERATE PACKET ---------------------------------------------
    let bank = sample_bank();
    let tenant_secret = b"test-tenant-secret";
    let exam_master_key = [0xab; 32];
    let ratio = DifficultyRatio::new(0.3, 0.4, 0.3).unwrap();
    let variant_seed = hashing::derive_variant_seed(tenant_secret, student_uuid, exam_id);
    let mut rng = StdRng::from_seed(variant_seed);
    let selected = question_bank::select_questions(&bank, 6, &ratio, &mut rng).unwrap();
    let questions: Vec<PacketQuestion> = selected
        .iter()
        .enumerate()
        .map(|(i, item)| PacketQuestion {
            bank_item_id: item.id,
            variant_id: 0,
            stem: item.stem.clone(),
            options: vec!["A".into(), "B".into(), "C".into(), "D".into()],
            question_ref: format!("q_{}", i + 1),
        })
        .collect();
    let exam_packet = ExamPacket {
        tenant_id: tenant_id.to_string(),
        student_uuid,
        exam_id: exam_id.to_string(),
        variant_seed,
        questions,
    };
    let ephemeral_key = hashing::derive_ephemeral_key(&exam_master_key, &variant_seed);
    let encrypted = packet::encrypt_packet(&exam_packet, &ephemeral_key).unwrap();
    let _key_envelope = oetp_core::envelope::seal_key_to_device(
        &ephemeral_key,
        device_x25519_public.as_bytes(),
        "device-01",
        student_uuid,
        exam_id,
    )
    .unwrap();

    // -- START LEDGER ------------------------------------------------
    let ledger_port = pick_port();
    let ledger_store = TestStore::new();
    let ledger_signing_key = signing::generate_keypair();
    let ledger_state = Arc::new(LedgerState {
        store: ledger_store,
        signing_key: ledger_signing_key,
    });

    let ledger_app = axum::Router::new()
        .route("/v1/ledger/commit", axum::routing::post(handle_commit))
        .route("/v1/ledger/ingest", axum::routing::post(handle_ingest))
        .route("/v1/ledger/proof", axum::routing::post(handle_proof))
        .route("/v1/ledger/key", axum::routing::post(handle_key_commit))
        .route("/v1/ledger/verify", axum::routing::post(handle_verify))
        .with_state(ledger_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", ledger_port))
            .await
            .unwrap();
        axum::serve(listener, ledger_app).await.unwrap();
    });

    // -- START BEACON -----------------------------------------------
    let beacon_port = pick_port();
    let beacon_key = Arc::new(signing::generate_keypair());
    let beacon_app = axum::Router::new()
        .route(
            "/v1/beacon/token",
            axum::routing::post(
                |axum::extract::State(key): axum::extract::State<
                    Arc<ed25519_dalek::SigningKey>,
                >,
                 axum::Json(body): axum::Json<serde_json::Value>| async move {
                    let token = ReleaseToken::new(
                        body["center_id"].as_str().unwrap_or("center-01"),
                        body["exam_id"].as_str().unwrap_or("jee-2027"),
                        body["device_id"].as_str().unwrap_or("device-01"),
                        0,
                        300,
                        &key,
                    );
                    axum::Json(token)
                },
            ),
        )
        .with_state(beacon_key);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", beacon_port))
            .await
            .unwrap();
        axum::serve(listener, beacon_app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let ledger_url = format!("http://127.0.0.1:{}", ledger_port);
    let client = reqwest::Client::new();

    // -- COMMIT ------------------------------------------------------
    let resp = client
        .post(format!("{}/v1/ledger/commit", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "packet_hashes": [encrypted.packet_hash],
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "commit: {}", resp.status());

    // -- INGEST ------------------------------------------------------
    let timestamp = 1_700_000_000;
    let mut answers = BTreeMap::new();
    answers.insert("q_1".to_string(), "A".to_string());
    answers.insert("q_2".to_string(), "B".to_string());
    let answers_hash = hashing::compute_answers_hash(
        &encrypted.packet_hash,
        &answers,
        student_uuid,
        &variant_seed,
        timestamp,
        tenant_id,
        exam_id,
    );
    let merkle_leaf = hashing::compute_submission_leaf(
        student_uuid,
        &encrypted.packet_hash,
        &answers_hash,
        timestamp,
        tenant_id,
        exam_id,
    );
    let signature = signing::sign(&device.signing_key(), &merkle_leaf);
    let sig_vec: Vec<u8> = signature.to_bytes().to_vec();

    let resp = client
        .post(format!("{}/v1/ledger/ingest", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "student_uuid": student_uuid,
            "packet_hash": encrypted.packet_hash,
            "answers_hash": answers_hash,
            "merkle_leaf": merkle_leaf,
            "timestamp": timestamp,
            "signature": sig_vec,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "ingest: {}", resp.status());

    // -- VERIFY ------------------------------------------------------
    let resp = client
        .post(format!("{}/v1/ledger/verify", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "student_uuid": student_uuid,
            "packet_hash": encrypted.packet_hash,
            "answers_hash": answers_hash,
            "timestamp": timestamp,
            "merkle_leaf": merkle_leaf,
            "edge_signature": sig_vec,
            "edge_public_key": device.public_key,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "verify: {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], true, "verify failed: {}", body["reason"]);
    assert_eq!(body["leaf_index"], 1);

    // -- PROOF -------------------------------------------------------
    let resp = client
        .post(format!("{}/v1/ledger/proof", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id, "receipt_id": "test",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total_leaves"], 2);
    assert!(body["root"].is_array());

    // -- ANSWER KEY --------------------------------------------------
    let answer_key_hash: [u8; 32] = [0xef; 32];
    let resp = client
        .post(format!("{}/v1/ledger/key", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "answer_key_hash": answer_key_hash,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // -- BEACON TOKEN ------------------------------------------------
    let resp = client
        .post(format!("http://127.0.0.1:{}/v1/beacon/token", beacon_port))
        .json(&serde_json::json!({
            "center_id": "center-01", "exam_id": exam_id, "device_id": "device-01",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let token: serde_json::Value = resp.json().await.unwrap();
    assert!(!token["signature"].as_array().unwrap().is_empty());

    tracing::info!("E2E test passed: commit → ingest → verify → proof → key → beacon");
}

#[tokio::test]
async fn test_verify_wrong_leaf_fails() {
    let tenant_id = "nta";
    let exam_id = "jee-2027";
    let student_uuid = Uuid::from_u128(42);
    let device = DeviceKeyPair::generate("device-01");

    let ledger_port = pick_port();
    let ledger_store = TestStore::new();
    let ledger_signing_key = signing::generate_keypair();
    let ledger_state = Arc::new(LedgerState {
        store: ledger_store,
        signing_key: ledger_signing_key,
    });

    let ledger_app = axum::Router::new()
        .route("/v1/ledger/ingest", axum::routing::post(handle_ingest))
        .route("/v1/ledger/verify", axum::routing::post(handle_verify))
        .with_state(ledger_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", ledger_port))
            .await
            .unwrap();
        axum::serve(listener, ledger_app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let ledger_url = format!("http://127.0.0.1:{}", ledger_port);
    let client = reqwest::Client::new();
    let timestamp = 1_700_000_000;
    let mut answers = BTreeMap::new();
    answers.insert("q1".to_string(), "A".to_string());
    let packet_hash = [0x01; 32];
    let variant_seed = [0xcd; 32];
    let answers_hash = hashing::compute_answers_hash(
        &packet_hash,
        &answers,
        student_uuid,
        &variant_seed,
        timestamp,
        tenant_id,
        exam_id,
    );
    let merkle_leaf = hashing::compute_submission_leaf(
        student_uuid,
        &packet_hash,
        &answers_hash,
        timestamp,
        tenant_id,
        exam_id,
    );
    let signature = signing::sign(&device.signing_key(), &merkle_leaf);
    let sig_vec: Vec<u8> = signature.to_bytes().to_vec();

    // Ingest the real leaf
    let resp = client
        .post(format!("{}/v1/ledger/ingest", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "student_uuid": student_uuid,
            "packet_hash": packet_hash,
            "answers_hash": answers_hash,
            "merkle_leaf": merkle_leaf,
            "timestamp": timestamp,
            "signature": sig_vec,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Verify with wrong leaf should fail
    let wrong_leaf = [0xff; 32];
    let wrong_sig = signing::sign(&device.signing_key(), &wrong_leaf);
    let wrong_sig_vec: Vec<u8> = wrong_sig.to_bytes().to_vec();
    let resp = client
        .post(format!("{}/v1/ledger/verify", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "student_uuid": student_uuid,
            "packet_hash": packet_hash,
            "answers_hash": answers_hash,
            "timestamp": timestamp,
            "merkle_leaf": wrong_leaf,
            "edge_signature": wrong_sig_vec,
            "edge_public_key": device.public_key,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], false);
}

#[tokio::test]
async fn test_verify_wrong_key_fails() {
    let tenant_id = "nta";
    let exam_id = "jee-2027";
    let student_uuid = Uuid::from_u128(42);
    let device = DeviceKeyPair::generate("device-01");
    let wrong_device = DeviceKeyPair::generate("device-02");

    let ledger_port = pick_port();
    let ledger_store = TestStore::new();
    let ledger_signing_key = signing::generate_keypair();
    let ledger_state = Arc::new(LedgerState {
        store: ledger_store,
        signing_key: ledger_signing_key,
    });

    let ledger_app = axum::Router::new()
        .route("/v1/ledger/verify", axum::routing::post(handle_verify))
        .with_state(ledger_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", ledger_port))
            .await
            .unwrap();
        axum::serve(listener, ledger_app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let ledger_url = format!("http://127.0.0.1:{}", ledger_port);
    let client = reqwest::Client::new();
    let timestamp = 1_700_000_000;
    let mut answers = BTreeMap::new();
    answers.insert("q1".to_string(), "A".to_string());
    let packet_hash = [0x01; 32];
    let variant_seed = [0xcd; 32];
    let answers_hash = hashing::compute_answers_hash(
        &packet_hash,
        &answers,
        student_uuid,
        &variant_seed,
        timestamp,
        tenant_id,
        exam_id,
    );
    let merkle_leaf = hashing::compute_submission_leaf(
        student_uuid,
        &packet_hash,
        &answers_hash,
        timestamp,
        tenant_id,
        exam_id,
    );
    // Sign with wrong device key
    let wrong_sig = signing::sign(&wrong_device.signing_key(), &merkle_leaf);
    let wrong_sig_vec: Vec<u8> = wrong_sig.to_bytes().to_vec();

    let resp = client
        .post(format!("{}/v1/ledger/verify", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "student_uuid": student_uuid,
            "packet_hash": packet_hash,
            "answers_hash": answers_hash,
            "timestamp": timestamp,
            "merkle_leaf": merkle_leaf,
            "edge_signature": wrong_sig_vec,
            "edge_public_key": device.public_key,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["valid"], false);
}

#[tokio::test]
async fn test_proof_unknown_receipt_returns_empty() {
    let tenant_id = "nta";
    let exam_id = "jee-2027";

    let ledger_port = pick_port();
    let ledger_store = TestStore::new();
    let ledger_signing_key = signing::generate_keypair();
    let ledger_state = Arc::new(LedgerState {
        store: ledger_store,
        signing_key: ledger_signing_key,
    });

    let ledger_app = axum::Router::new()
        .route("/v1/ledger/proof", axum::routing::post(handle_proof))
        .with_state(ledger_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", ledger_port))
            .await
            .unwrap();
        axum::serve(listener, ledger_app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let ledger_url = format!("http://127.0.0.1:{}", ledger_port);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/ledger/proof", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": tenant_id, "exam_id": exam_id,
            "receipt_id": "nonexistent-receipt",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["total_leaves"], 0);
    assert!(body["merkle_leaf"].is_null());
}

#[tokio::test]
async fn test_commit_empty_hashes_fails() {
    let ledger_port = pick_port();
    let ledger_store = TestStore::new();
    let ledger_signing_key = signing::generate_keypair();
    let ledger_state = Arc::new(LedgerState {
        store: ledger_store,
        signing_key: ledger_signing_key,
    });

    let ledger_app = axum::Router::new()
        .route("/v1/ledger/commit", axum::routing::post(handle_commit))
        .with_state(ledger_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", ledger_port))
            .await
            .unwrap();
        axum::serve(listener, ledger_app).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let ledger_url = format!("http://127.0.0.1:{}", ledger_port);
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/v1/ledger/commit", ledger_url))
        .json(&serde_json::json!({
            "tenant_id": "nta", "exam_id": "jee-2027",
            "packet_hashes": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// -- IN-MEMORY STORE --------------------------------------------------
use dashmap::DashMap;
use oetp_core::error::Result;
use oetp_core::platform::Store;
use std::sync::Arc;

struct TestStore {
    leaves: Arc<DashMap<String, Vec<[u8; 32]>>>,
}

impl TestStore {
    fn new() -> Self {
        Self {
            leaves: Arc::new(DashMap::new()),
        }
    }
    fn ns(tenant_id: &str, exam_id: &str) -> String {
        format!("{}:{}", tenant_id, exam_id)
    }
}

#[async_trait::async_trait]
impl Store for TestStore {
    async fn append(&self, tenant_id: &str, exam_id: &str, leaf: &[u8; 32]) -> Result<u64> {
        let mut entries = self
            .leaves
            .entry(Self::ns(tenant_id, exam_id))
            .or_default();
        let idx = entries.len() as u64;
        entries.push(*leaf);
        Ok(idx)
    }
    async fn get(&self, tenant_id: &str, exam_id: &str, index: u64) -> Result<Option<[u8; 32]>> {
        Ok(self
            .leaves
            .get(&Self::ns(tenant_id, exam_id))
            .and_then(|e| e.get(index as usize).copied()))
    }
    async fn count(&self, tenant_id: &str, exam_id: &str) -> Result<u64> {
        Ok(self
            .leaves
            .get(&Self::ns(tenant_id, exam_id))
            .map(|e| e.len() as u64)
            .unwrap_or(0))
    }
    async fn latest_root(&self, tenant_id: &str, exam_id: &str) -> Result<Option<[u8; 32]>> {
        Ok(self
            .leaves
            .get(&Self::ns(tenant_id, exam_id))
            .and_then(|e| e.last().copied()))
    }

    async fn set_root(&self, _tenant_id: &str, _exam_id: &str, _root: &[u8; 32]) -> Result<()> {
        Ok(())
    }
}

// -- LEDGER HANDLERS --------------------------------------------------
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

struct LedgerState {
    store: TestStore,
    #[allow(dead_code)]
    signing_key: ed25519_dalek::SigningKey,
}

type ApiResult<T> = std::result::Result<Json<T>, (StatusCode, &'static str)>;

#[derive(Deserialize)]
struct CommitReq {
    tenant_id: String,
    exam_id: String,
    packet_hashes: Vec<[u8; 32]>,
}
#[derive(Serialize)]
struct CommitRes {
    merkle_root: [u8; 32],
}

async fn handle_commit(
    State(state): State<Arc<LedgerState>>,
    Json(req): Json<CommitReq>,
) -> ApiResult<CommitRes> {
    let tree = oetp_core::merkle::MerkleTree::new(req.packet_hashes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad tree"))?;
    let root = *tree.root();
    state
        .store
        .append(&req.tenant_id, &req.exam_id, &root)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "store error"))?;
    Ok(Json(CommitRes { merkle_root: root }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct IngestReq {
    tenant_id: String,
    exam_id: String,
    merkle_leaf: [u8; 32],
    student_uuid: Uuid,
    packet_hash: [u8; 32],
    answers_hash: [u8; 32],
    timestamp: u64,
    signature: Vec<u8>,
}
#[derive(Serialize)]
struct IngestRes {
    leaf_index: u64,
    status: &'static str,
}

async fn handle_ingest(
    State(state): State<Arc<LedgerState>>,
    Json(req): Json<IngestReq>,
) -> ApiResult<IngestRes> {
    let idx = state
        .store
        .append(&req.tenant_id, &req.exam_id, &req.merkle_leaf)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "store error"))?;
    Ok(Json(IngestRes {
        leaf_index: idx,
        status: "ingested",
    }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ProofReq {
    tenant_id: String,
    exam_id: String,
    receipt_id: String,
}
#[derive(Serialize)]
struct ProofRes {
    merkle_leaf: Option<[u8; 32]>,
    leaf_index: Option<u64>,
    total_leaves: u64,
    siblings: Vec<[u8; 32]>,
    root: Option<[u8; 32]>,
}

async fn handle_proof(
    State(state): State<Arc<LedgerState>>,
    Json(_req): Json<ProofReq>,
) -> ApiResult<ProofRes> {
    let total = state
        .store
        .count(&_req.tenant_id, &_req.exam_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "store error"))?;
    if total == 0 {
        return Ok(Json(ProofRes {
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
            .get(&_req.tenant_id, &_req.exam_id, i)
            .await
            .unwrap()
        {
            leaves.push(leaf);
        }
    }
    let tree = oetp_core::merkle::MerkleTree::new(leaves).unwrap();
    let root = *tree.root();
    let proof = tree.prove((total - 1) as usize).unwrap();
    Ok(Json(ProofRes {
        merkle_leaf: Some(proof.leaf),
        leaf_index: Some(total - 1),
        total_leaves: total,
        siblings: proof.siblings,
        root: Some(root),
    }))
}

#[derive(Deserialize)]
struct KeyCommitReq {
    tenant_id: String,
    exam_id: String,
    answer_key_hash: [u8; 32],
}
#[derive(Serialize)]
struct KeyCommitRes {
    status: &'static str,
}

async fn handle_key_commit(
    State(state): State<Arc<LedgerState>>,
    Json(req): Json<KeyCommitReq>,
) -> ApiResult<KeyCommitRes> {
    state
        .store
        .append(&req.tenant_id, &req.exam_id, &req.answer_key_hash)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "store error"))?;
    Ok(Json(KeyCommitRes {
        status: "committed",
    }))
}

#[derive(Deserialize)]
struct VerifyReq {
    tenant_id: String,
    exam_id: String,
    student_uuid: Uuid,
    packet_hash: [u8; 32],
    answers_hash: [u8; 32],
    timestamp: u64,
    merkle_leaf: [u8; 32],
    edge_signature: Vec<u8>,
    edge_public_key: [u8; 32],
}
#[derive(Serialize)]
struct VerifyRes {
    valid: bool,
    reason: String,
    leaf_index: Option<u64>,
    total_leaves: u64,
    anchored_root: Option<[u8; 32]>,
}

async fn handle_verify(
    State(state): State<Arc<LedgerState>>,
    Json(req): Json<VerifyReq>,
) -> ApiResult<VerifyRes> {
    let computed = hashing::compute_submission_leaf(
        req.student_uuid,
        &req.packet_hash,
        &req.answers_hash,
        req.timestamp,
        &req.tenant_id,
        &req.exam_id,
    );
    if computed != req.merkle_leaf {
        return Ok(Json(VerifyRes {
            valid: false,
            reason: "leaf mismatch".into(),
            leaf_index: None,
            total_leaves: 0,
            anchored_root: None,
        }));
    }
    let vk = match signing::verifying_key_from_bytes(&req.edge_public_key) {
        Ok(k) => k,
        Err(_) => {
            return Ok(Json(VerifyRes {
                valid: false,
                reason: "invalid key".into(),
                leaf_index: None,
                total_leaves: 0,
                anchored_root: None,
            }));
        }
    };
    let sig = match ed25519_dalek::Signature::from_slice(&req.edge_signature) {
        Ok(s) => s,
        Err(_) => {
            return Ok(Json(VerifyRes {
                valid: false,
                reason: "invalid sig".into(),
                leaf_index: None,
                total_leaves: 0,
                anchored_root: None,
            }));
        }
    };
    if signing::verify(&vk, &req.merkle_leaf, &sig).is_err() {
        return Ok(Json(VerifyRes {
            valid: false,
            reason: "bad signature".into(),
            leaf_index: None,
            total_leaves: 0,
            anchored_root: None,
        }));
    }
    let total = state
        .store
        .count(&req.tenant_id, &req.exam_id)
        .await
        .unwrap_or(0);
    let mut found = None;
    for i in 0..total {
        if state
            .store
            .get(&req.tenant_id, &req.exam_id, i)
            .await
            .unwrap()
            .is_some_and(|leaf| leaf == req.merkle_leaf)
        {
            found = Some(i);
            break;
        }
    }
    let root = state
        .store
        .latest_root(&req.tenant_id, &req.exam_id)
        .await
        .unwrap_or(None);
    Ok(Json(VerifyRes {
        valid: found.is_some(),
        reason: if found.is_some() {
            "verified".into()
        } else {
            "not found".into()
        },
        leaf_index: found,
        total_leaves: total,
        anchored_root: root,
    }))
}
