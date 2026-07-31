// defines who the exam is for

use crate::error::{Error, Result};
use ed25519_dalek::SigningKey;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(id: &str) -> Result<Self> {
        if id.is_empty() {
            return Err(Error::InvalidInput("Tenant ID cannot be empty".into()));
        };
        Ok(Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
pub struct TenantKeys {
    pub tenant_id: TenantId,
    pub signing_key: SigningKey,
}

impl TenantKeys {
    pub fn generate(tenant_id: TenantId) -> Self {
        let signing_key = crate::signing::generate_keypair();
        Self {
            tenant_id,
            signing_key,
        }
    }
}

#[derive(Debug)]
pub struct ExamKeys {
    pub tenant_id: TenantId,
    pub exam_id: String,
    pub signing_key: SigningKey,
    pub master_key: [u8; 32],
}

impl ExamKeys {
    // deterministic key derivation - delegates to hashing module
    pub fn derive_master_key(tenant_master_key: &[u8; 32], exam_id: &str) -> [u8; 32] {
        crate::hashing::derive_exam_master_key(tenant_master_key, exam_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_new() {
        let id = TenantId::new("NTA").unwrap();
        assert_eq!(id.as_str(), "NTA");
    }
    #[test]
    fn test_tenant_id_empty() {
        let err = TenantId::new("").unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_tenant_id_display() {
        let id = TenantId::new("NTA").unwrap();
        assert_eq!(format!("{}", id), "NTA");
    }

    #[test]
    fn test_tenant_keys_generate() {
        let id = TenantId::new("NTA").unwrap();
        let keys = TenantKeys::generate(id.clone());
        assert_eq!(keys.tenant_id, id);

        let verify = keys.signing_key.verifying_key();
        assert_eq!(verify.as_bytes().len(), 32);
    }

    #[test]
    fn test_exam_keys_derive_master_deterministic() {
        let master = [0xab; 32];
        let k1 = ExamKeys::derive_master_key(&master, "jee-2027");
        let k2 = ExamKeys::derive_master_key(&master, "jee-2027");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_exam_keys_derive_master_different_exam() {
        let master = [0xab; 32];
        let k1 = ExamKeys::derive_master_key(&master, "jee-2027");
        let k2 = ExamKeys::derive_master_key(&master, "neet-2027");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_exam_keys_derive_master_different_tenant() {
        let k1 = ExamKeys::derive_master_key(&[0xab; 32], "jee-2027");
        let k2 = ExamKeys::derive_master_key(&[0xcb; 32], "neet-2027");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_exam_keys_derive_master_output_size() {
        let master = [0xab; 32];
        let k1 = ExamKeys::derive_master_key(&master, "jee-2027");
        assert_eq!(k1.len(), 32);
    }
}
