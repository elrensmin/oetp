pub mod api;
pub mod config;
pub mod generator;
pub mod merkle_worker;
pub mod anchor_worker;
pub mod sqlite_store;
pub mod storage;

use axum::{Router, routing::get, routing::post};
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::cors::CorsLayer;

/// Builds a rate-limit layer shared across all services.
/// Conservative pilot default: 10 requests/s with burst of 1000 keyed by peer IP.
/// Configurable via OETP_RATE_LIMIT_PER_SECOND and OETP_RATE_LIMIT_BURST.
pub fn rate_limit_layer() -> GovernorLayer
<tower_governor::key_extractor::PeerIpKeyExtractor,
 governor::middleware::NoOpMiddleware> {
    let per_second = std::env::var("OETP_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10u64);
    let burst_size = std::env::var("OETP_RATE_LIMIT_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000u32);
    let config = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst_size)
        .finish()
        .expect("valid governor config");
    GovernorLayer { config: Arc::new(config) }
}

pub fn build_app_state(
    store: Arc<dyn oetp_core::platform::Store>,
    signing_key: ed25519_dalek::SigningKey,
    api_key: String,
    exam_window_start: u64,
    exam_window_end: u64,
) -> Arc<api::AppState> {
    Arc::new(api::AppState {
        store,
        signing_key,
        packets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        anchors: tokio::sync::RwLock::new(Vec::new()),
        receipt_index: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        api_key,
        exam_window_start,
        exam_window_end,
    })
}

pub fn build_router(app_state: Arc<api::AppState>) -> Router {
    let cors = CorsLayer::new().allow_origin(tower_http::cors::AllowOrigin::predicate(
        |origin: &axum::http::HeaderValue, _| {
            origin.as_bytes().starts_with(b"http://127.0.0.1")
                || origin.as_bytes().starts_with(b"http://localhost")
        },
    ));

    Router::new()
        .route("/v1/ledger/commit", post(api::handle_commit))
        .route("/v1/ledger/ingest", post(api::handle_ingest))
        .route("/v1/ledger/proof", post(api::handle_proof))
        .route("/v1/ledger/key", post(api::handle_key_commit))
        .route("/v1/ledger/fetch", post(api::handle_fetch_packet))
        .route("/v1/ledger/verify", post(api::handle_verify))
        .route("/v1/ledger/anchors", post(api::handle_anchors))
        .route("/v1/ledger/load", post(api::handle_load_packets))
        .route(
            "/health",
            get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
        )
        .route("/v1/system/clock", post(api::handle_system_set_clock))
        .layer(cors)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1_048_576))
        .layer(rate_limit_layer())
        .with_state(app_state)
}
