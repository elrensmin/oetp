// encrypted offline submission queue - survives process restart
use oetp_core::device::DeviceKeyPair;
use oetp_core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedSubmission {
    pub tenant_id: String,
    pub exam_id: String,
    pub student_uuid: Uuid,
    pub packet_hash: [u8; 32],
    pub answers_hash: [u8; 32],
    pub merkle_leaf: [u8; 32],
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub receipt_id: String,
}

pub struct OfflineQueue {
    path: PathBuf,
    queue_key: [u8; 32],
    api_key: String,
}

impl OfflineQueue {
    pub fn new(dir: &PathBuf, device_key: &DeviceKeyPair, api_key: &str) -> Self {
        // Use HKDF to derive queue key from device key with a distinct context
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha3_256>::new(Some(b"oetp-queue-key"), &*device_key.private_key);
        let mut queue_key = [0u8; 32];
        hk.expand(b"offline-queue", &mut queue_key)
            .expect("32 bytes is a valid length for HKDF");
        let _ = std::fs::create_dir_all(dir);
        Self {
            path: dir.join("queue.enc"),
            queue_key,
            api_key: api_key.to_string(),
        }
    }

    pub async fn enqueue(&self, submission: &QueuedSubmission) -> Result<()> {
        let path = self.path.clone();
        let queue_key = self.queue_key;
        let submission = submission.clone();
        tokio::task::spawn_blocking(move || {
            let mut queue = read_queue_blocking(&path, &queue_key).unwrap_or_default();
            // deduplicate by leaf hash
            if !queue.iter().any(|s| s.merkle_leaf == submission.merkle_leaf) {
                queue.push(submission);
            }
            write_queue_blocking(&path, &queue, &queue_key)
        })
        .await
        .map_err(|e| Error::OfflineQueue(format!("spawn_blocking error: {}", e)))?
    }

    pub async fn dequeue_all(&self) -> Result<Vec<QueuedSubmission>> {
        let path = self.path.clone();
        let queue_key = self.queue_key;
        tokio::task::spawn_blocking(move || read_queue_blocking(&path, &queue_key))
            .await
            .map_err(|e| Error::OfflineQueue(format!("spawn_blocking error: {}", e)))?
    }

    #[allow(dead_code)]
    pub async fn len(&self) -> usize {
        self.dequeue_all().await.map(|q| q.len()).unwrap_or(0)
    }

    #[allow(dead_code)]
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub async fn flush(&self, ledger_url: &str) -> Result<usize> {
        let submissions = self.dequeue_all().await?;
        if submissions.is_empty() {
            return Ok(0);
        }
        let client = reqwest::Client::new();
        let mut flushed = 0;
        let mut remaining = Vec::new();
        for sub in &submissions {
            let resp = client
                .post(format!("{}/v1/ledger/ingest", ledger_url))
                .header("x-api-key", &self.api_key)
                .json(&serde_json::json!({
                    "tenant_id": sub.tenant_id,
                    "exam_id": sub.exam_id,
                    "student_uuid": sub.student_uuid,
                    "packet_hash": sub.packet_hash,
                    "answers_hash": sub.answers_hash,
                    "merkle_leaf": sub.merkle_leaf,
                    "timestamp": sub.timestamp,
                    "signature": sub.signature,
                    "receipt_id": sub.receipt_id,
                }))
                .send()
                .await;
            #[allow(clippy::collapsible_if)]
            if let Ok(r) = resp {
                if r.status().is_success() {
                    flushed += 1;
                } else {
                    remaining.push(sub.clone());
                }
            } else {
                remaining.push(sub.clone());
            }
        }
        // Write back any remaining (failed) submissions
        let path = self.path.clone();
        let queue_key = self.queue_key;
        tokio::task::spawn_blocking(move || write_queue_blocking(&path, &remaining, &queue_key))
            .await
            .map_err(|e| Error::OfflineQueue(format!("spawn_blocking error: {}", e)))??;
        Ok(flushed)
    }
}

fn read_queue_blocking(path: &std::path::PathBuf, queue_key: &[u8; 32]) -> Result<Vec<QueuedSubmission>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let encrypted = std::fs::read(path).map_err(Error::Io)?;
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    let plaintext = decrypt_bytes(&encrypted, queue_key)?;
    let queue: Vec<QueuedSubmission> =
        bincode::deserialize(&plaintext).map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(queue)
}

fn write_queue_blocking(path: &std::path::PathBuf, queue: &[QueuedSubmission], queue_key: &[u8; 32]) -> Result<()> {
    let plaintext =
        bincode::serialize(queue).map_err(|e| Error::Serialization(e.to_string()))?;
    let encrypted = encrypt_bytes(&plaintext, queue_key)?;
    std::fs::write(path, &encrypted).map_err(Error::Io)?;
    Ok(())
}

fn encrypt_bytes(data: &[u8], queue_key: &[u8; 32]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use rand::RngCore;
    use rand::rngs::OsRng;

    let cipher = Aes256Gcm::new(queue_key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_bytes(data: &[u8], queue_key: &[u8; 32]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};

    if data.len() < 12 {
        return Err(Error::OfflineQueue("corrupt queue file".into()));
    }
    let (nonce_slice, ciphertext) = data.split_at(12);
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(nonce_slice);
    let nonce = Nonce::from(nonce_arr);
    let cipher = Aes256Gcm::new(queue_key.into());
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| Error::OfflineQueue("decryption failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oetp_core::device::DeviceKeyPair;
    use tempfile::TempDir;

    fn sample_submission() -> QueuedSubmission {
        QueuedSubmission {
            tenant_id: "nta".into(),
            exam_id: "jee-2027".into(),
            student_uuid: Uuid::from_u128(42),
            packet_hash: [0x01; 32],
            answers_hash: [0x02; 32],
            merkle_leaf: [0x03; 32],
            timestamp: 1_700_000_000,
            signature: vec![1, 2, 3],
            receipt_id: "receipt-1".into(),
        }
    }

    #[tokio::test]
    async fn test_queue_enqueue_dequeue() {
        let dir = TempDir::new().unwrap();
        let device = DeviceKeyPair::generate("device-01");
        let queue = OfflineQueue::new(&dir.path().to_path_buf(), &device, "test-key");
        let sub = sample_submission();
        queue.enqueue(&sub).await.unwrap();
        assert_eq!(queue.len().await, 1);
        let items = queue.dequeue_all().await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].receipt_id, "receipt-1");
    }

    #[tokio::test]
    async fn test_queue_deduplicates() {
        let dir = TempDir::new().unwrap();
        let device = DeviceKeyPair::generate("device-01");
        let queue = OfflineQueue::new(&dir.path().to_path_buf(), &device, "test-key");
        let sub = sample_submission();
        queue.enqueue(&sub).await.unwrap();
        queue.enqueue(&sub).await.unwrap();
        assert_eq!(queue.len().await, 1);
    }

    #[tokio::test]
    async fn test_queue_persistence() {
        let dir = TempDir::new().unwrap();
        let device = DeviceKeyPair::generate("device-01");
        let sub = sample_submission();
        {
            let queue = OfflineQueue::new(&dir.path().to_path_buf(), &device, "test-key");
            queue.enqueue(&sub).await.unwrap();
        }
        {
            let queue = OfflineQueue::new(&dir.path().to_path_buf(), &device, "test-key");
            assert_eq!(queue.len().await, 1);
        }
    }

    #[tokio::test]
    async fn test_queue_empty() {
        let dir = TempDir::new().unwrap();
        let device = DeviceKeyPair::generate("device-01");
        let queue = OfflineQueue::new(&dir.path().to_path_buf(), &device, "test-key");
        assert!(queue.is_empty().await);
    }
}
