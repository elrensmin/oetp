// ledger anchoring worker - periodically anchors Merkle roots to Polygon
use oetp_core::error::Result;
use oetp_core::platform::{Anchor, AnchorBackend, AnchorType, Store};
use std::sync::Arc;
use tokio::time::{Duration, interval};

pub struct AnchorWorker {
    backend: Arc<dyn AnchorBackend>,
    store: Arc<dyn Store>,
    tenant_id: String,
    exam_id: String,
}

impl AnchorWorker {
    pub fn new(
        backend: Arc<dyn AnchorBackend>,
        store: Arc<dyn Store>,
        tenant_id: &str,
        exam_id: &str,
    ) -> Self {
        Self {
            backend,
            store,
            tenant_id: tenant_id.to_string(),
            exam_id: exam_id.to_string(),
        }
    }

    #[allow(dead_code)]
    pub async fn anchor_pre_exam(root: &[u8; 32], backend: &dyn AnchorBackend) -> Result<Anchor> {
        backend.anchor(root, AnchorType::PreExam).await
    }

    #[allow(dead_code)]
    pub async fn anchor_rolling(root: &[u8; 32], backend: &dyn AnchorBackend) -> Result<Anchor> {
        backend.anchor(root, AnchorType::Rolling).await
    }

    #[allow(dead_code)]
    pub async fn anchor_final(root: &[u8; 32], backend: &dyn AnchorBackend) -> Result<Anchor> {
        backend.anchor(root, AnchorType::Final).await
    }

    #[allow(dead_code)]
    pub async fn anchor_answer_key(hash: &[u8; 32], backend: &dyn AnchorBackend) -> Result<Anchor> {
        backend.anchor(hash, AnchorType::AnswerKey).await
    }

    pub async fn run_rolling(&self) {
        let mut ticker = interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;
            let count = self
                .store
                .count(&self.tenant_id, &self.exam_id)
                .await
                .unwrap_or(0);
            if count == 0 {
                continue;
            }
            if let Ok(Some(root)) = self.store.latest_root(&self.tenant_id, &self.exam_id).await {
                match self.backend.anchor(&root, AnchorType::Rolling).await {
                    Ok(anchor) => {
                        tracing::info!(
                            "anchored rolling root {} at tx {}",
                            hex::encode(root),
                            anchor.tx_hash
                        );
                    }
                    Err(e) => {
                        tracing::warn!("rolling anchor failed: {}", e);
                    }
                }
            }
        }
    }
}

/// Mock anchor backend for development - records anchors in memory
pub struct MockAnchorBackend;

#[async_trait::async_trait]
impl AnchorBackend for MockAnchorBackend {
    async fn anchor(&self, root: &[u8; 32], anchor_type: AnchorType) -> Result<Anchor> {
        Ok(Anchor {
            chain_id: "mock".into(),
            tx_hash: format!("0x{}", hex::encode(root)),
            anchored_root: *root,
            anchor_type,
            timestamp: 1_700_000_000,
            signature: vec![],
        })
    }

    async fn verify(&self, anchor: &Anchor) -> Result<bool> {
        Ok(anchor.chain_id == "mock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anchor_pre_exam() {
        let backend = MockAnchorBackend;
        let root = [0xab; 32];
        let anchor = AnchorWorker::anchor_pre_exam(&root, &backend)
            .await
            .unwrap();
        assert_eq!(anchor.anchored_root, root);
        assert!(matches!(anchor.anchor_type, AnchorType::PreExam));
    }

    #[tokio::test]
    async fn test_anchor_answer_key() {
        let backend = MockAnchorBackend;
        let hash = [0xcd; 32];
        let anchor = AnchorWorker::anchor_answer_key(&hash, &backend)
            .await
            .unwrap();
        assert_eq!(anchor.anchored_root, hash);
        assert!(matches!(anchor.anchor_type, AnchorType::AnswerKey));
    }

    #[tokio::test]
    async fn test_mock_verify() {
        let backend = MockAnchorBackend;
        let root = [0xab; 32];
        let anchor = backend.anchor(&root, AnchorType::PreExam).await.unwrap();
        assert!(backend.verify(&anchor).await.unwrap());
    }
}
