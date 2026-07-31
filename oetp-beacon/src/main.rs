use oetp_beacon::api::{BeaconState, build_router};
use oetp_core::validation;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let listen_addr =
        std::env::var("OETP_BEACON_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9090".into());

    let key_hex = match std::env::var("OETP_BEACON_SIGNING_KEY") {
        Ok(k) => k,
        Err(_) => {
            tracing::error!("OETP_BEACON_SIGNING_KEY required");
            std::process::exit(1);
        }
    };
    let mut key_bytes = [0u8; 32];
    if let Err(e) = validation::validate_hex_secret("OETP_BEACON_SIGNING_KEY", &key_hex, &mut key_bytes) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    let exam_window_start = std::env::var("OETP_EXAM_WINDOW_START")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let exam_window_end = std::env::var("OETP_EXAM_WINDOW_END")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(u64::MAX);
    if let Err(e) = validation::validate_exam_window(exam_window_start, exam_window_end) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }

    let api_key = match std::env::var("OETP_API_KEY") {
        Ok(k) => k,
        Err(_) => {
            tracing::error!("OETP_API_KEY required");
            std::process::exit(1);
        }
    };
    if let Err(e) = validation::validate_api_key(&api_key) {
        tracing::error!("{}", e);
        std::process::exit(1);
    }

    let state = Arc::new(BeaconState { signing_key, exam_window_start, exam_window_end, api_key });
    let app = build_router(state);

    tracing::info!("beacon starting on {}", listen_addr);

    let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("failed to bind: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    {
        tracing::error!("server error: {}", e);
        std::process::exit(1);
    }
}
