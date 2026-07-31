// in-memory Store implementation - swap for RocksDB/ScyllaDB in production
use async_trait::async_trait;
use dashmap::DashMap;
use oetp_core::error::Result;
use oetp_core::platform::Store;
use std::sync::Arc;

pub struct MemStore {
    leaves: Arc<DashMap<String, Vec<[u8; 32]>>>,
    roots: Arc<DashMap<String, [u8; 32]>>,
}

impl Default for MemStore {
    fn default() -> Self {
        Self {
            leaves: Arc::new(DashMap::new()),
            roots: Arc::new(DashMap::new()),
        }
    }
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn ns(tenant_id: &str, exam_id: &str) -> String {
        format!("{}:{}", tenant_id, exam_id)
    }
}

#[async_trait]
impl Store for MemStore {
    async fn append(&self, tenant_id: &str, exam_id: &str, leaf: &[u8; 32]) -> Result<u64> {
        let ns = Self::ns(tenant_id, exam_id);
        let mut entries = self.leaves.entry(ns.clone()).or_default();
        let idx = entries.len() as u64;
        entries.push(*leaf);
        Ok(idx)
    }

    async fn get(&self, tenant_id: &str, exam_id: &str, index: u64) -> Result<Option<[u8; 32]>> {
        let ns = Self::ns(tenant_id, exam_id);
        let guard = match self.leaves.get(&ns) {
            Some(g) => g,
            None => return Ok(None),
        };
        let entries = guard.value();
        Ok(entries.get(index as usize).copied())
    }

    async fn count(&self, tenant_id: &str, exam_id: &str) -> Result<u64> {
        let ns = Self::ns(tenant_id, exam_id);
        Ok(self.leaves.get(&ns).map(|e| e.len() as u64).unwrap_or(0))
    }

    async fn latest_root(&self, tenant_id: &str, exam_id: &str) -> Result<Option<[u8; 32]>> {
        let ns = Self::ns(tenant_id, exam_id);
        Ok(self.roots.get(&ns).map(|r| *r.value()))
    }

    async fn set_root(&self, tenant_id: &str, exam_id: &str, root: &[u8; 32]) -> Result<()> {
        let ns = Self::ns(tenant_id, exam_id);
        self.roots.insert(ns, *root);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mem_store_append_and_get() {
        let store = MemStore::new();
        let leaf = [0xab; 32];
        let idx = store.append("nta", "jee-2027", &leaf).await.unwrap();
        assert_eq!(idx, 0);
        let retrieved = store.get("nta", "jee-2027", 0).await.unwrap().unwrap();
        assert_eq!(retrieved, leaf);
    }

    #[tokio::test]
    async fn test_mem_store_count() {
        let store = MemStore::new();
        assert_eq!(store.count("nta", "jee-2027").await.unwrap(), 0);
        store.append("nta", "jee-2027", &[0x01; 32]).await.unwrap();
        store.append("nta", "jee-2027", &[0x02; 32]).await.unwrap();
        assert_eq!(store.count("nta", "jee-2027").await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_mem_store_tenant_isolation() {
        let store = MemStore::new();
        store.append("nta", "jee-2027", &[0x01; 32]).await.unwrap();
        store.append("cbse", "exam-1", &[0x02; 32]).await.unwrap();
        assert_eq!(store.count("nta", "jee-2027").await.unwrap(), 1);
        assert_eq!(store.count("cbse", "exam-1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_mem_store_get_nonexistent() {
        let store = MemStore::new();
        store.append("nta", "jee-2027", &[0x01; 32]).await.unwrap();
        let result = store.get("nta", "jee-2027", 99).await.unwrap();
        assert!(result.is_none());
    }
}
