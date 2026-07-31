// shared daemon state - config, device key, caches, HTTP client, offline queue
use crate::config::EdgeConfig;
use crate::queue::OfflineQueue;
use oetp_core::device::DeviceKeyPair;
use oetp_core::device_x25519::DeviceX25519Key;
use oetp_core::envelope::KeyEnvelope;
use oetp_core::packet::EncryptedPacket;
use oetp_core::release::ReleaseToken;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct CachedExamData {
    pub encrypted_packet: EncryptedPacket,
    pub key_envelope: KeyEnvelope,
    pub release_token: Option<ReleaseToken>,
    pub variant_seed: Option<[u8; 32]>,
}

pub struct AppState {
    pub config: EdgeConfig,
    pub device_key: DeviceKeyPair,
    pub device_x25519_key: DeviceX25519Key,
    pub http_client: reqwest::Client,
    pub cache: Mutex<HashMap<String, CachedExamData>>,
    pub queue: OfflineQueue,
    pub consumed_nonces: Mutex<PersistentNonceSet>,
}

pub struct PersistentNonceSet {
    nonces: HashSet<[u8; 16]>,
    path: PathBuf,
}

fn load_nonces_blocking(path: &PathBuf) -> HashSet<[u8; 16]> {
    if !path.exists() {
        return HashSet::new();
    }
    std::fs::read_to_string(path)
        .ok()
        .map(|s| {
            s.lines()
                .filter_map(|l| {
                    let trimmed = l.trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    let mut bytes = [0u8; 16];
                    hex::decode_to_slice(trimmed, &mut bytes).ok()?;
                    Some(bytes)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn append_nonce_blocking(path: &PathBuf, nonce: [u8; 16]) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{}", hex::encode(nonce));
    }
}

fn clear_nonces_blocking(path: &PathBuf) {
    let _ = std::fs::write(path, "");
}

impl PersistentNonceSet {
    pub fn new(path: PathBuf) -> Self {
        let nonces = load_nonces_blocking(&path);
        Self { nonces, path }
    }

    pub fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.nonces.contains(nonce)
    }

    pub fn insert(&mut self, nonce: [u8; 16]) {
        if self.nonces.insert(nonce) {
            append_nonce_blocking(&self.path, nonce);
        }
    }

    pub fn clear(&mut self) {
        self.nonces.clear();
        clear_nonces_blocking(&self.path);
    }
}

impl AppState {
    pub async fn new(
        config: EdgeConfig,
        device_key: DeviceKeyPair,
        device_x25519_key: DeviceX25519Key,
    ) -> Self {
        let queue = OfflineQueue::new(&config.queue_dir, &device_key, &config.api_key);
        let nonce_path = config.queue_dir.join("consumed_nonces.log");
        // Ensure the nonce log file directory exists without blocking the runtime.
        let _ = tokio::fs::create_dir_all(&config.queue_dir).await;
        Self {
            http_client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            cache: Mutex::new(HashMap::new()),
            config,
            device_key,
            device_x25519_key,
            queue,
            consumed_nonces: Mutex::new(PersistentNonceSet::new(nonce_path)),
        }
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.cache.try_lock() {
            cache.clear();
        }
        if let Ok(mut nonces) = self.consumed_nonces.try_lock() {
            nonces.clear();
        }
    }
}
