// produces the StudentReceipt and PersonalAnswerCopy for the student

use crate::error::{Error, Result};
use crate::merkle::MerkleProof;
use crate::signing;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StudentReceipt {
    pub receipt_id: String,
    pub tenant_id: String,
    pub exam_id: String,
    pub application_number: String,
    pub student_uuid: Uuid,
    pub packet_hash: [u8; 32],
    pub answers_hash: [u8; 32],
    pub timestamp: u64,
    pub merkle_proof: MerkleProof,
    pub edge_signature: Vec<u8>,
    pub ledger_signature: Vec<u8>,
    pub qr_payload: String,
}

impl StudentReceipt {
    pub fn verify_edge_signature(&self, edge_verifying_key: &VerifyingKey) -> Result<()> {
        let sig = Signature::from_slice(&self.edge_signature)
            .map_err(|_| Error::SignatureVerification)?;
        signing::verify(edge_verifying_key, &self.verification_payload(), &sig)
    }

    pub fn verify_ledger_signature(&self, ledger_verifying_key: &VerifyingKey) -> Result<()> {
        let sig = Signature::from_slice(&self.ledger_signature)
            .map_err(|_| Error::SignatureVerification)?;
        signing::verify(ledger_verifying_key, &self.verification_payload(), &sig)
    }

    pub fn verification_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(0x01u8); // version
        bytes.extend_from_slice(self.receipt_id.as_bytes());
        bytes.extend_from_slice(self.tenant_id.as_bytes());
        bytes.extend_from_slice(self.exam_id.as_bytes());
        bytes.extend_from_slice(self.application_number.as_bytes());
        bytes.extend_from_slice(&self.student_uuid.to_bytes_le());
        bytes.extend_from_slice(&self.packet_hash);
        bytes.extend_from_slice(&self.answers_hash);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.merkle_proof.root);
        bytes.extend_from_slice(&self.merkle_proof.leaf);
        bytes.extend_from_slice(&self.merkle_proof.leaf_index.to_be_bytes());
        bytes.extend_from_slice(self.qr_payload.as_bytes());
        bytes
    }
}

pub fn generate_receipt_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalAnswerCopy {
    pub receipt_id: String,
    pub encrypted_answers: Vec<u8>,
    pub nonce: [u8; 12],
    pub answers_hash: [u8; 32],
}

pub fn create_personal_answer_copy(
    receipt_id: &str,
    raw_answers: &[u8],
    student_key: &[u8; 32],
) -> Result<PersonalAnswerCopy> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let cipher = Aes256Gcm::new(student_key.into());

    let encrypted = cipher
        .encrypt(&nonce, raw_answers)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let answers_hash = Sha3_256::digest(raw_answers).into();

    Ok(PersonalAnswerCopy {
        receipt_id: receipt_id.to_string(),
        encrypted_answers: encrypted,
        nonce: nonce_bytes,
        answers_hash,
    })
}

pub fn decrypt_personal_answer_copy(
    copy: &PersonalAnswerCopy,
    student_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let nonce = Nonce::from(copy.nonce);

    let cipher = Aes256Gcm::new(student_key.into());

    let plaintext = cipher
        .decrypt(&nonce, copy.encrypted_answers.as_ref())
        .map_err(|_| Error::PacketDecryption)?;

    let computed_hash: [u8; 32] = Sha3_256::digest(&plaintext).into();
    if computed_hash != copy.answers_hash {
        return Err(Error::PacketDecryption);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use ed25519_dalek::SigningKey;

    fn sample_receipt(edge_key: &SigningKey, ledger_key: &SigningKey) -> StudentReceipt {
        let leaf = [0xab; 32];
        let tree = MerkleTree::new(vec![leaf]).unwrap();
        let proof = tree.prove(0).unwrap();

        let receipt_id = generate_receipt_id();

        let mut receipt = StudentReceipt {
            receipt_id: receipt_id.clone(),
            tenant_id: "nta".into(),
            exam_id: "jee-2027".into(),
            application_number: "APP123".into(),
            student_uuid: Uuid::from_u128(42),
            packet_hash: [0x01; 32],
            answers_hash: [0x02; 32],
            timestamp: 1_700_000_000,
            merkle_proof: proof,
            edge_signature: vec![],
            ledger_signature: vec![],
            qr_payload: "qr-data".into(),
        };

        let payload = receipt.verification_payload();
        let edge_sig = signing::sign(edge_key, &payload);
        let ledger_sig = signing::sign(ledger_key, &payload);
        receipt.edge_signature = edge_sig.to_bytes().to_vec();
        receipt.ledger_signature = ledger_sig.to_bytes().to_vec();
        receipt
    }

    #[test]
    fn test_receipt_verify_edge_signature() {
        let edge_key = signing::generate_keypair();
        let ledger_key = signing::generate_keypair();
        let receipt = sample_receipt(&edge_key, &ledger_key);
        assert!(
            receipt
                .verify_edge_signature(&edge_key.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_receipt_verify_ledger_signature() {
        let edge_key = signing::generate_keypair();
        let ledger_key = signing::generate_keypair();
        let receipt = sample_receipt(&edge_key, &ledger_key);
        assert!(
            receipt
                .verify_ledger_signature(&ledger_key.verifying_key())
                .is_ok()
        );
    }

    #[test]
    fn test_receipt_verify_edge_signature_wrong_key() {
        let edge_key = signing::generate_keypair();
        let ledger_key = signing::generate_keypair();
        let wrong_key = signing::generate_keypair();
        let receipt = sample_receipt(&edge_key, &ledger_key);
        let result = receipt.verify_edge_signature(&wrong_key.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_receipt_verify_ledger_signature_wrong_key() {
        let edge_key = signing::generate_keypair();
        let ledger_key = signing::generate_keypair();
        let wrong_key = signing::generate_keypair();
        let receipt = sample_receipt(&edge_key, &ledger_key);
        let result = receipt.verify_ledger_signature(&wrong_key.verifying_key());
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_receipt_id_unique() {
        let id1 = generate_receipt_id();
        let id2 = generate_receipt_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_personal_answer_copy_roundtrip() {
        let answers = b"q1=A&q2=B&q3=C";
        let student_key = [0xab; 32];
        let receipt_id = generate_receipt_id();

        let copy = create_personal_answer_copy(&receipt_id, answers, &student_key).unwrap();
        assert_eq!(copy.receipt_id, receipt_id);

        let decrypted = decrypt_personal_answer_copy(&copy, &student_key).unwrap();
        assert_eq!(decrypted, answers);
    }

    #[test]
    fn test_personal_answer_copy_wrong_key() {
        let answers = b"q1=A";
        let key1 = [0xab; 32];
        let key2 = [0xcd; 32];
        let receipt_id = generate_receipt_id();

        let copy = create_personal_answer_copy(&receipt_id, answers, &key1).unwrap();
        let result = decrypt_personal_answer_copy(&copy, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_personal_answer_copy_tampered() {
        let answers = b"q1=A";
        let student_key = [0xab; 32];
        let receipt_id = generate_receipt_id();

        let mut copy = create_personal_answer_copy(&receipt_id, answers, &student_key).unwrap();
        copy.encrypted_answers[0] ^= 0xff;
        let result = decrypt_personal_answer_copy(&copy, &student_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_personal_answer_copy_hash_verification() {
        let answers = b"q1=A";
        let student_key = [0xab; 32];
        let receipt_id = generate_receipt_id();

        let mut copy = create_personal_answer_copy(&receipt_id, answers, &student_key).unwrap();
        copy.answers_hash = [0xff; 32];
        let result = decrypt_personal_answer_copy(&copy, &student_key);
        assert!(result.is_err());
    }
}
