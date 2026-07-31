pub mod api;
pub mod beacon;
pub mod config;
pub mod platform_impl;
pub mod queue;
pub mod state;

use axum::{Router, routing::get, routing::post};
use std::sync::Arc;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;

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

pub async fn build_app_state(
    config: config::EdgeConfig,
    device_key: oetp_core::device::DeviceKeyPair,
    device_x25519_key: oetp_core::device_x25519::DeviceX25519Key,
) -> Arc<state::AppState> {
    Arc::new(state::AppState::new(config, device_key, device_x25519_key).await)
}

pub fn build_router(app_state: Arc<state::AppState>) -> Router {
    let cors = CorsLayer::new().allow_origin(tower_http::cors::AllowOrigin::predicate(
        |origin: &axum::http::HeaderValue, _| {
            origin.as_bytes().starts_with(b"http://127.0.0.1")
                || origin.as_bytes().starts_with(b"http://localhost")
        },
    ));

    Router::new()
        .route("/v1/exam/fetch", post(api::handle_fetch))
        .route("/v1/exam/release", post(api::handle_release))
        .route("/v1/exam/unlock", post(api::handle_unlock))
        .route("/v1/exam/submit", post(api::handle_submit))
        .route(
            "/health",
            get(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
        )
        .route("/v1/system/clock", post(api::handle_system_set_clock))
        .route("/v1/system/flush", post(api::handle_system_flush))
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(1_048_576))
        .layer(rate_limit_layer())
        .with_state(app_state)
}
