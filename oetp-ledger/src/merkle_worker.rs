// MMR maintenance worker - builds Merkle trees from ingested leaves
use oetp_core::error::Result;
use oetp_core::merkle::MerkleTree;
use oetp_core::platform::Store;
use std::sync::Arc;
use tokio::time::{Duration, interval};

pub struct MerkleWorker {
    store: Arc<dyn Store>,
    tenant_id: String,
    exam_id: String,
}

impl MerkleWorker {
    pub fn new(store: Arc<dyn Store>, tenant_id: &str, exam_id: &str) -> Self {
        Self {
            store,
            tenant_id: tenant_id.to_string(),
            exam_id: exam_id.to_string(),
        }
    }

    pub async fn build_root(&self) -> Result<[u8; 32]> {
        let count = self.store.count(&self.tenant_id, &self.exam_id).await?;
        if count == 0 {
            return Err(oetp_core::error::Error::InvalidInput(
                "no leaves to build tree".into(),
            ));
        }

        let mut leaves = Vec::with_capacity(count as usize);
        for i in 0..count {
            if let Some(leaf) = self.store.get(&self.tenant_id, &self.exam_id, i).await? {
                leaves.push(leaf);
            }
        }

        let tree = MerkleTree::new(leaves)?;
        Ok(*tree.root())
    }

    pub async fn run(&self) {
        let mut ticker = interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            match self.build_root().await {
                Ok(root) => {
                    // Persist the root so latest_root() returns it
                    let _ = self
                        .store
                        .set_root(&self.tenant_id, &self.exam_id, &root)
                        .await;
                    tracing::info!(
                        "merkle root for {}/{}: {}",
                        self.tenant_id,
                        self.exam_id,
                        hex::encode(root)
                    );
                }
                Err(e) => {
                    tracing::warn!("merkle worker error: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemStore;

    #[tokio::test]
    async fn test_merkle_worker_build_root() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        store.append("nta", "jee-2027", &[0x01; 32]).await.unwrap();
        store.append("nta", "jee-2027", &[0x02; 32]).await.unwrap();

        let worker = MerkleWorker::new(store, "nta", "jee-2027");
        let root = worker.build_root().await.unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_merkle_worker_empty() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let worker = MerkleWorker::new(store, "nta", "jee-2027");
        let result = worker.build_root().await;
        assert!(result.is_err());
    }
}
