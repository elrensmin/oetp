// ledger entry point - HTTP server with CLI subcommands
use clap::{Parser, Subcommand};
use oetp_ledger::config;
use oetp_ledger::generator;
use oetp_ledger::storage;
use oetp_ledger::sqlite_store;
use oetp_ledger::merkle_worker;
use oetp_ledger::anchor_worker;
use oetp_ledger::{build_app_state, build_router};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

fn setup_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        tracing::error!("panic: {}", panic_info);
        prev(panic_info);
    }));
}

#[derive(Parser)]
#[command(name = "oetp-ledger", about = "OETP central ledger server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Generate {
        #[arg(short, long)]
        bank: String,
        #[arg(short, long, default_value = "90")]
        num_questions: usize,
        #[arg(short, long)]
        students: String,
        #[arg(short, long, default_value = "./output")]
        output: String,
        #[arg(short, long, default_value = "abababababababababababababababababababababababababababababababab")]
        tenant_master_key: String,
        #[arg(short = 'x', long, default_value = "exam-1")]
        exam_id: String,
        #[arg(short = 't', long, default_value = "dev-tenant")]
        tenant_id: String,
        #[arg(short = 'd', long)]
        device_x25519_pub: Option<String>,
    },
    Serve,
    Load {
        #[arg(short, long)]
        input: String,
    },
    Keygen,
}

#[tokio::main]
async fn main() {
    setup_panic_hook();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Generate { bank, num_questions, students, output, tenant_master_key, exam_id, tenant_id, device_x25519_pub } => {
            let mut master_key = [0u8; 32];
            if let Err(e) = hex::decode_to_slice(tenant_master_key.trim(), &mut master_key) {
                tracing::error!("invalid tenant master key hex: {}", e);
                std::process::exit(1);
            }
            let device_pk = device_x25519_pub.as_ref().map(|hex_str| {
                let mut pk = [0u8; 32];
                hex::decode_to_slice(hex_str.trim(), &mut pk)
                    .expect("invalid device X25519 public key hex");
                pk
            });
            let gen_cfg = generator::GeneratorConfig {
                bank_path: &bank,
                num_questions,
                students_path: &students,
                output_dir: &output,
                tenant_master_key: &master_key,
                exam_id: &exam_id,
                tenant_id: &tenant_id,
                device_x25519_public_key: device_pk.as_ref(),
            };
            if let Err(e) = generator::run_generator(gen_cfg) {
                tracing::error!("generator failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Serve => {
            let cfg = match config::LedgerConfig::from_env() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("failed to load config: {}", e);
                    std::process::exit(1);
                }
            };

            let mut key_bytes = [0u8; 32];
            if let Err(e) = hex::decode_to_slice(cfg.signing_key_hex.trim(), &mut key_bytes) {
                tracing::error!("invalid signing key hex: {}", e);
                std::process::exit(1);
            }
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

            let store: Arc<dyn oetp_core::platform::Store> =
                if cfg.db_path.to_str().is_some_and(|p| !p.is_empty()) {
                    let path = cfg.db_path.clone();
                    match sqlite_store::SqliteStore::new(&path) {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            tracing::error!("failed to open SQLite store: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    Arc::new(storage::MemStore::new())
                };
            let store_arc = store;
            let exam_id = cfg.exam_id.clone();

            let mw_store = store_arc.clone();
            let mw_tenant = cfg.tenant_id.clone();
            let mw_exam = exam_id.clone();
            tokio::spawn(async move {
                let worker = merkle_worker::MerkleWorker::new(mw_store, &mw_tenant, &mw_exam);
                worker.run().await;
            });

            let aw_store = store_arc.clone();
            let aw_tenant = cfg.tenant_id.clone();
            let aw_exam = exam_id.clone();
            tokio::spawn(async move {
                let backend = anchor_worker::MockAnchorBackend;
                let worker = anchor_worker::AnchorWorker::new(Arc::new(backend), aw_store, &aw_tenant, &aw_exam);
                worker.run_rolling().await;
            });

            let app_state = build_app_state(store_arc, signing_key, cfg.api_key.clone(), 0, u64::MAX);
            let app = build_router(app_state);

            let addr = cfg.listen_addr.clone();
            tracing::info!("ledger starting on {}", addr);

            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("failed to bind address: {}", e);
                    std::process::exit(1);
                }
            };

            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await
            {
                tracing::error!("server error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Load { input } => {
            let cfg = match config::LedgerConfig::from_env() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("failed to load config: {}", e);
                    std::process::exit(1);
                }
            };
            let ledger_url = format!("http://{}", cfg.listen_addr);
            let client = reqwest::Client::new();
            let input_path = std::path::Path::new(&input);
            let entries = match std::fs::read_dir(input_path) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!("failed to read input dir: {}", e);
                    std::process::exit(1);
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!("failed to read entry: {}", e);
                        continue;
                    }
                };
                let path = entry.path();
                let fname = match path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                if fname.starts_with("packet_") && fname.ends_with(".enc") {
                    let uuid_str = match fname.strip_prefix("packet_").and_then(|s| s.strip_suffix(".enc")) {
                        Some(s) => s,
                        None => continue,
                    };
                    let student_uuid = match uuid::Uuid::parse_str(uuid_str) {
                        Ok(u) => u,
                        Err(e) => {
                            tracing::warn!("invalid uuid {}: {}", uuid_str, e);
                            continue;
                        }
                    };
                    let packet_json = match std::fs::read_to_string(&path) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("failed to read packet {}: {}", path.display(), e);
                            continue;
                        }
                    };
                    let encrypted_packet: oetp_core::packet::EncryptedPacket = match serde_json::from_str(&packet_json) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("invalid packet json {}: {}", path.display(), e);
                            continue;
                        }
                    };
                    let envelope_path = input_path.join(format!("envelope_{}.enc", uuid_str));
                    let envelope_json = match std::fs::read_to_string(&envelope_path) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("failed to read envelope {}: {}", envelope_path.display(), e);
                            continue;
                        }
                    };
                    let key_envelope: oetp_core::envelope::KeyEnvelope = match serde_json::from_str(&envelope_json) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!("invalid envelope json {}: {}", envelope_path.display(), e);
                            continue;
                        }
                    };
                    let key = format!("{}:{}:{}", cfg.tenant_id, cfg.exam_id, student_uuid);
                    let resp = match client
                        .post(format!("{}/v1/ledger/load", ledger_url))
                        .header("x-api-key", &cfg.api_key)
                        .json(&serde_json::json!({
                            "key": key,
                            "encrypted_packet": encrypted_packet,
                            "key_envelope": key_envelope,
                        }))
                        .send()
                        .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("failed to send load request for {}: {}", student_uuid, e);
                            continue;
                        }
                    };
                    if resp.status().is_success() {
                        tracing::info!("loaded packet for {}", student_uuid);
                    } else {
                        tracing::warn!("failed to load packet for {}: {}", student_uuid, resp.status());
                    }
                }
            }
        }
        Commands::Keygen => {
            let key = oetp_core::signing::generate_keypair();
            let sk_hex = hex::encode(key.to_bytes());
            let pk_hex = hex::encode(key.verifying_key().to_bytes());
            println!("{}", sk_hex);
            println!("{}", pk_hex);
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("failed to install Ctrl+C handler: {}", e);
        }
    };

    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => tracing::error!("failed to install SIGTERM handler: {}", e),
        }
    };

    tokio::select! {
        _ = ctrl_c => tracing::warn!("SIGINT received, shutting down"),
        _ = terminate => tracing::warn!("SIGTERM received, shutting down"),
    }
}
