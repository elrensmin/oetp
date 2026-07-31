// edge daemon entry point - panic hook, signal handlers, HTTP server startup
use oetp_edge::config;
use oetp_edge::platform_impl;
use oetp_edge::{build_app_state, build_router};
use oetp_core::platform::ProcessGuard;
use tracing_subscriber::EnvFilter;

fn setup_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        tracing::error!("panic: {}", panic_info);
        prev(panic_info);
    }));
}

#[tokio::main]
async fn main() {
    setup_panic_hook();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = match config::EdgeConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to load config: {}", e);
            std::process::exit(1);
        }
    };
    let device_key = match config.load_device_key() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("failed to load device key: {}", e);
            std::process::exit(1);
        }
    };
    let device_x25519_key = match config.load_device_x25519_key() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("failed to load device X25519 key: {}", e);
            std::process::exit(1);
        }
    };

    let guard = platform_impl::LinuxProcessGuard;
    let _ = guard.disable_core_dumps();
    let _ = guard.restrict_ptrace();

    let app_state = build_app_state(config, device_key, device_x25519_key).await;
    let addr = app_state.config.listen_addr.clone();

    // background task: flush offline queue every 30 seconds
    let flush_state = app_state.clone();
    let ledger_url = flush_state.config.ledger_url.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            ticker.tick().await;
            match flush_state.queue.flush(&ledger_url).await {
                Ok(n) if n > 0 => tracing::info!("flushed {} queued submissions", n),
                Ok(_) => {}
                Err(e) => tracing::warn!("queue flush error: {}", e),
            }
        }
    });

    let app = build_router(app_state);

    tracing::info!("edge daemon starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {
            tracing::warn!("SIGINT received, zeroizing sensitive state and shutting down");
        }
        _ = terminate => {
            tracing::warn!("SIGTERM received, zeroizing sensitive state and shutting down");
        }
    }
}
