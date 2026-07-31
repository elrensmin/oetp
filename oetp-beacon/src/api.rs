use axum::{Json, extract::State, http::StatusCode};
use oetp_core::release::ReleaseToken;
use oetp_core::validation;
use std::sync::Arc;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

pub struct BeaconState {
    pub signing_key: ed25519_dalek::SigningKey,
    pub exam_window_start: u64,
    pub exam_window_end: u64,
    pub api_key: String,
}

#[derive(serde::Deserialize)]
pub struct TokenRequest {
    pub center_id: String,
    pub exam_id: String,
    pub device_id: String,
}

#[derive(serde::Serialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(serde::Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(serde::Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

pub type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;

fn invalid_input(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: ErrorDetail {
                code: "INVALID_INPUT".into(),
                message: msg.into(),
            },
        }),
    )
}

fn check_api_key(
    state: &BeaconState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let provided = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != state.api_key {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: ErrorDetail {
                    code: "UNAUTHORIZED".into(),
                    message: "invalid api key".into(),
                },
            }),
        ));
    }
    Ok(())
}

pub async fn handle_token(
    State(state): State<Arc<BeaconState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<TokenRequest>,
) -> ApiResult<ReleaseToken> {
    check_api_key(&state, &headers)?;

    if let Err(e) = validation::validate_identifier("center_id", &req.center_id) {
        return Err(invalid_input(&e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("exam_id", &req.exam_id) {
        return Err(invalid_input(&e.to_string()));
    }
    if let Err(e) = validation::validate_identifier("device_id", &req.device_id) {
        return Err(invalid_input(&e.to_string()));
    }

    let now = oetp_core::release::current_timestamp_secs();
    // Clamp token window to the exam window
    let window_start = state.exam_window_start.max(now);
    let window_end = state.exam_window_end.min(now + 300);
    let token = ReleaseToken::new(
        &req.center_id,
        &req.exam_id,
        &req.device_id,
        window_start,
        window_end,
        &state.signing_key,
    );
    Ok(Json(token))
}

pub async fn handle_health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

/// Builds a rate-limit layer shared across all services.
/// Conservative pilot default: 10 requests/s with burst of 1000 keyed by peer IP.
/// Configurable via OETP_RATE_LIMIT_PER_SECOND and OETP_RATE_LIMIT_BURST.
pub fn rate_limit_layer() -> GovernorLayer<
    tower_governor::key_extractor::PeerIpKeyExtractor,
    governor::middleware::NoOpMiddleware,
> {
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
    GovernorLayer {
        config: Arc::new(config),
    }
}

pub fn build_router(state: Arc<BeaconState>) -> axum::Router {
    use axum::routing::post;

    axum::Router::new()
        .route("/v1/beacon/token", post(handle_token))
        .route("/health", axum::routing::get(handle_health))
        .route("/v1/system/clock", post(handle_system_set_clock))
        .layer(rate_limit_layer())
        .with_state(state)
}

#[derive(serde::Deserialize)]
pub struct SystemClockRequest {
    pub timestamp: u64,
}

#[derive(serde::Serialize)]
pub struct SystemClockResponse {
    pub status: String,
    pub previous_timestamp: u64,
}

pub async fn handle_system_set_clock(
    State(state): State<Arc<BeaconState>>,
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
