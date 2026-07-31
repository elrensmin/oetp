// records the mapping of student → packet_hash → device_id, signed by the generator
use crate::error::{Error, Result};
use crate::merkle::MerkleTree;
use crate::signing;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub student_uuid: Uuid,
    pub packet_hash: [u8; 32],
    pub variant_seed: [u8; 32],
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub tenant_id: String,
    pub exam_id: String,
    pub entries: Vec<ManifestEntry>,
    pub merkle_root: [u8; 32],
    pub signature: Vec<u8>,
}

impl Manifest {
    pub fn new(
        tenant_id: &str,
        exam_id: &str,
        entries: Vec<ManifestEntry>,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        if entries.is_empty() {
            return Err(Error::InvalidInput(
                "manifest must have at least one entry".into(),
            ));
        }

        let leaves: Vec<[u8; 32]> = entries.iter().map(|e| e.packet_hash).collect();
        let tree = MerkleTree::new(leaves)?;
        let merkle_root = *tree.root();

        let mut manifest = Self {
            tenant_id: tenant_id.to_string(),
            exam_id: exam_id.to_string(),
            entries,
            merkle_root,
            signature: Vec::new(),
        };

        manifest.sign(signing_key);
        Ok(manifest)
    }

    fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.tenant_id.as_bytes());
        bytes.extend_from_slice(self.exam_id.as_bytes());
        bytes.extend_from_slice(&self.merkle_root);
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.student_uuid.to_bytes_le());
            bytes.extend_from_slice(&entry.packet_hash);
            bytes.extend_from_slice(&entry.variant_seed);
            bytes.extend_from_slice(entry.device_id.as_bytes());
        }
        bytes
    }

    fn sign(&mut self, signing_key: &SigningKey) {
        let sig = signing::sign(signing_key, &self.payload_bytes());
        self.signature = sig.to_bytes().to_vec();
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        if self.entries.is_empty() {
            return Err(Error::InvalidInput("manifest has no entries".into()));
        }

        let leaves: Vec<[u8; 32]> = self.entries.iter().map(|e| e.packet_hash).collect();
        let tree = MerkleTree::new(leaves)?;
        if *tree.root() != self.merkle_root {
            return Err(Error::InvalidInput("merkle root mismatch".into()));
        }

        let sig =
            Signature::from_slice(&self.signature).map_err(|_| Error::SignatureVerification)?;

        signing::verify(verifying_key, &self.payload_bytes(), &sig)
    }

    pub fn get_entry(&self, student_uuid: Uuid) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| e.student_uuid == student_uuid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(student_uuid: Uuid) -> ManifestEntry {
        ManifestEntry {
            student_uuid,
            packet_hash: [0xab; 32],
            variant_seed: [0xcd; 32],
            device_id: "device-01".into(),
        }
    }

    #[test]
    fn test_manifest_new() {
        let key = signing::generate_keypair();
        let entries = vec![
            sample_entry(Uuid::from_u128(1)),
            sample_entry(Uuid::from_u128(2)),
        ];
        let manifest = Manifest::new("nta", "jee-2027", entries, &key).unwrap();
        assert_eq!(manifest.tenant_id, "nta");
        assert_eq!(manifest.exam_id, "jee-2027");
        assert_eq!(manifest.len(), 2);
        assert!(!manifest.signature.is_empty());
    }

    #[test]
    fn test_manifest_empty_entries() {
        let key = signing::generate_keypair();
        let err = Manifest::new("nta", "jee-2027", vec![], &key).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_manifest_verify() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let entries = vec![
            sample_entry(Uuid::from_u128(1)),
            sample_entry(Uuid::from_u128(2)),
            sample_entry(Uuid::from_u128(3)),
        ];
        let manifest = Manifest::new("nta", "jee-2027", entries, &key).unwrap();
        assert!(manifest.verify(&vk).is_ok());
    }

    #[test]
    fn test_manifest_verify_wrong_key() {
        let key1 = signing::generate_keypair();
        let key2 = signing::generate_keypair();
        let vk2 = key2.verifying_key();
        let entries = vec![sample_entry(Uuid::from_u128(1))];
        let manifest = Manifest::new("nta", "jee-2027", entries, &key1).unwrap();
        let result = manifest.verify(&vk2);
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_verify_tampered_entry() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let entries = vec![sample_entry(Uuid::from_u128(1))];
        let mut manifest = Manifest::new("nta", "jee-2027", entries, &key).unwrap();
        manifest.entries[0].packet_hash = [0xff; 32];
        let result = manifest.verify(&vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_verify_tampered_merkle_root() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let entries = vec![sample_entry(Uuid::from_u128(1))];
        let mut manifest = Manifest::new("nta", "jee-2027", entries, &key).unwrap();
        manifest.merkle_root = [0xff; 32];
        let result = manifest.verify(&vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_manifest_get_entry() {
        let key = signing::generate_keypair();
        let uuid = Uuid::from_u128(42);
        let entries = vec![
            sample_entry(Uuid::from_u128(1)),
            sample_entry(uuid),
            sample_entry(Uuid::from_u128(3)),
        ];
        let manifest = Manifest::new("nta", "jee-2027", entries, &key).unwrap();
        let entry = manifest.get_entry(uuid).unwrap();
        assert_eq!(entry.student_uuid, uuid);
        assert_eq!(entry.device_id, "device-01");
    }

    #[test]
    fn test_manifest_get_entry_not_found() {
        let key = signing::generate_keypair();
        let entries = vec![sample_entry(Uuid::from_u128(1))];
        let manifest = Manifest::new("nta", "jee-2027", entries, &key).unwrap();
        assert!(manifest.get_entry(Uuid::from_u128(99)).is_none());
    }

    #[test]
    fn test_manifest_different_entries_different_root() {
        let key = signing::generate_keypair();
        let e1 = vec![ManifestEntry {
            student_uuid: Uuid::from_u128(1),
            packet_hash: [0xab; 32],
            variant_seed: [0xcd; 32],
            device_id: "device-01".into(),
        }];
        let e2 = vec![ManifestEntry {
            student_uuid: Uuid::from_u128(2),
            packet_hash: [0xef; 32],
            variant_seed: [0xcd; 32],
            device_id: "device-01".into(),
        }];
        let m1 = Manifest::new("nta", "jee-2027", e1, &key).unwrap();
        let m2 = Manifest::new("nta", "jee-2027", e2, &key).unwrap();
        assert_ne!(m1.merkle_root, m2.merkle_root);
    }
}
