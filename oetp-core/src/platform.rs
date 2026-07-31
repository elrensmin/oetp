// traits that abstract storage, ledger anchoring, and OS process hardening
use crate::error::Result;
use serde::{Deserialize, Serialize};

pub trait ProcessGuard: Send + Sync {
    fn disable_core_dumps(&self) -> Result<()>;
    fn restrict_ptrace(&self) -> Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnchorType {
    PreExam,
    Rolling,
    Final,
    AnswerKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub chain_id: String,
    pub tx_hash: String,
    pub anchored_root: [u8; 32],
    pub anchor_type: AnchorType,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[async_trait::async_trait]
pub trait AnchorBackend: Send + Sync {
    async fn anchor(&self, root: &[u8; 32], anchor_type: AnchorType) -> Result<Anchor>;
    async fn verify(&self, anchor: &Anchor) -> Result<bool>;
}

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn append(&self, tenant_id: &str, exam_id: &str, leaf: &[u8; 32]) -> Result<u64>;
    async fn get(&self, tenant_id: &str, exam_id: &str, index: u64) -> Result<Option<[u8; 32]>>;
    async fn count(&self, tenant_id: &str, exam_id: &str) -> Result<u64>;
    async fn latest_root(&self, tenant_id: &str, exam_id: &str) -> Result<Option<[u8; 32]>>;
    async fn set_root(&self, tenant_id: &str, exam_id: &str, root: &[u8; 32]) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_type_serde() {
        let at = AnchorType::PreExam;
        let json = serde_json::to_string(&at).unwrap();
        let back: AnchorType = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, AnchorType::PreExam));
    }

    #[test]
    fn test_anchor_roundtrip() {
        let anchor = Anchor {
            chain_id: "polygon".into(),
            tx_hash: "0xabc".into(),
            anchored_root: [0xab; 32],
            anchor_type: AnchorType::Final,
            timestamp: 1_700_000_000,
            signature: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&anchor).unwrap();
        let back: Anchor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.chain_id, "polygon");
        assert_eq!(back.anchored_root, [0xab; 32]);
    }

    #[test]
    fn test_anchor_type_display() {
        assert_eq!(format!("{:?}", AnchorType::PreExam), "PreExam");
        assert_eq!(format!("{:?}", AnchorType::Rolling), "Rolling");
        assert_eq!(format!("{:?}", AnchorType::Final), "Final");
        assert_eq!(format!("{:?}", AnchorType::AnswerKey), "AnswerKey");
    }
}
