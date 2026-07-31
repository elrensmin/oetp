// SQLite-backed persistent Store implementation
use async_trait::async_trait;
use oetp_core::error::{Error, Result};
use oetp_core::platform::Store;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;

fn map_err(e: rusqlite::Error) -> Error {
    Error::Storage(e.to_string())
}

fn lock_err(e: impl std::fmt::Display) -> Error {
    Error::Storage(format!("lock error: {}", e))
}

#[derive(Clone)]
pub struct SqliteStore {
    conn: Arc<std::sync::Mutex<Connection>>,
}

impl SqliteStore {
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(map_err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS leaves (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                exam_id TEXT NOT NULL,
                leaf BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_leaves_ns ON leaves(tenant_id, exam_id);
            CREATE TABLE IF NOT EXISTS roots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                exam_id TEXT NOT NULL,
                root BLOB NOT NULL,
                seq INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_roots_ns ON roots(tenant_id, exam_id);"
        ).map_err(map_err)?;
        Ok(Self { conn: Arc::new(std::sync::Mutex::new(conn)) })
    }

}

#[async_trait]
impl Store for SqliteStore {
    async fn append(&self, tenant_id: &str, exam_id: &str, leaf: &[u8; 32]) -> Result<u64> {
        let tenant_id = tenant_id.to_string();
        let exam_id = exam_id.to_string();
        let leaf = *leaf;
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(lock_err)?;
            let leaf_slice: &[u8] = &leaf;
            conn.execute(
                "INSERT INTO leaves (tenant_id, exam_id, leaf) VALUES (?1, ?2, ?3)",
                rusqlite::params![tenant_id, exam_id, leaf_slice],
            )
            .map_err(map_err)?;
            let id = conn.last_insert_rowid() as u64;
            Ok(id - 1)
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking error: {}", e)))?
    }

    async fn get(&self,
        tenant_id: &str,
        exam_id: &str,
        index: u64,
    ) -> Result<Option<[u8; 32]>> {
        let tenant_id = tenant_id.to_string();
        let exam_id = exam_id.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(lock_err)?;
            let mut stmt = conn
                .prepare(
                    "SELECT leaf FROM leaves WHERE tenant_id = ?1 AND exam_id = ?2 ORDER BY id LIMIT 1 OFFSET ?3",
                )
                .map_err(map_err)?;
            let result = stmt.query_row(
                rusqlite::params![tenant_id, exam_id, index],
                |row| {
                    let blob: Vec<u8> = row.get(0)?;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&blob);
                    Ok(arr)
                },
            );
            match result {
                Ok(arr) => Ok(Some(arr)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(map_err(e)),
            }
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking error: {}", e)))?
    }

    async fn count(&self, tenant_id: &str, exam_id: &str) -> Result<u64> {
        let tenant_id = tenant_id.to_string();
        let exam_id = exam_id.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(lock_err)?;
            let count: u64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM leaves WHERE tenant_id = ?1 AND exam_id = ?2",
                    rusqlite::params![tenant_id, exam_id],
                    |row| row.get(0),
                )
                .map_err(map_err)?;
            Ok(count)
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking error: {}", e)))?
    }

    async fn latest_root(
        &self,
        tenant_id: &str,
        exam_id: &str,
    ) -> Result<Option<[u8; 32]>> {
        let tenant_id = tenant_id.to_string();
        let exam_id = exam_id.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(lock_err)?;
            let result = conn.query_row(
                "SELECT root FROM roots WHERE tenant_id = ?1 AND exam_id = ?2 ORDER BY id DESC LIMIT 1",
                rusqlite::params![tenant_id, exam_id],
                |row| {
                    let blob: Vec<u8> = row.get(0)?;
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&blob);
                    Ok(arr)
                },
            );
            match result {
                Ok(root) => Ok(Some(root)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(map_err(e)),
            }
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking error: {}", e)))?
    }

    async fn set_root(&self, tenant_id: &str, exam_id: &str, root: &[u8; 32]) -> Result<()> {
        let tenant_id = tenant_id.to_string();
        let exam_id = exam_id.to_string();
        let root = *root;
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().map_err(lock_err)?;
            let root_slice: &[u8] = &root;
            let seq: u64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(seq), 0) + 1 FROM roots WHERE tenant_id = ?1 AND exam_id = ?2",
                    rusqlite::params![tenant_id, exam_id],
                    |row| row.get(0),
                )
                .map_err(map_err)?;
            conn.execute(
                "INSERT INTO roots (tenant_id, exam_id, root, seq) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![tenant_id, exam_id, root_slice, seq],
            )
            .map_err(map_err)?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Storage(format!("spawn_blocking error: {}", e)))?
    }
}
