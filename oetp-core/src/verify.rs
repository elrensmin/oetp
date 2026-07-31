// public verification helpers - anyone can verify receipts, proofs, and anchors
use crate::error::{Error, Result};
use crate::hashing;
use crate::merkle::MerkleProof;
use crate::platform::Anchor;
use crate::receipt::StudentReceipt;
use ed25519_dalek::VerifyingKey;
use uuid::Uuid;

pub fn verify_packet_commitment(
    packet_hash: &[u8; 32],
    merkle_proof: &MerkleProof,
    anchored_root: &[u8; 32],
) -> Result<()> {
    if !merkle_proof.verify() {
        return Err(Error::InvalidInput(
            "Merkle proof verification failed".into(),
        ));
    }
    if merkle_proof.root != *anchored_root {
        return Err(Error::InvalidInput(
            "Merkle root does not match anchored root".into(),
        ));
    }
    if merkle_proof.leaf != *packet_hash {
        return Err(Error::InvalidInput(
            "proof leaf does not match packet hash".into(),
        ));
    }
    Ok(())
}

pub fn verify_submission(
    student_uuid: Uuid,
    packet_hash: &[u8; 32],
    answers_hash: &[u8; 32],
    timestamp: u64,
    merkle_leaf: &[u8; 32],
    tenant_id: &str,
    exam_id: &str,
) -> Result<()> {
    let computed = hashing::compute_submission_leaf(
        student_uuid,
        packet_hash,
        answers_hash,
        timestamp,
        tenant_id,
        exam_id,
    );
    if computed != *merkle_leaf {
        return Err(Error::InvalidInput("submission leaf mismatch".into()));
    }
    Ok(())
}

pub fn verify_receipt(
    receipt: &StudentReceipt,
    edge_public_key: &VerifyingKey,
    ledger_public_key: &VerifyingKey,
) -> Result<()> {
    receipt.verify_edge_signature(edge_public_key)?;
    receipt.verify_ledger_signature(ledger_public_key)?;
    Ok(())
}

pub fn verify_answer_key_commitment(answer_key_hash: &[u8; 32], anchor: &Anchor) -> Result<()> {
    if anchor.anchored_root != *answer_key_hash {
        return Err(Error::InvalidInput(
            "answer key hash does not match anchored root".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_full_chain(
    student_uuid: Uuid,
    packet_hash: &[u8; 32],
    answers_hash: &[u8; 32],
    timestamp: u64,
    merkle_proof: &MerkleProof,
    anchored_root: &[u8; 32],
    receipt: &StudentReceipt,
    edge_public_key: &VerifyingKey,
    ledger_public_key: &VerifyingKey,
) -> Result<()> {
    verify_packet_commitment(packet_hash, merkle_proof, anchored_root)?;
    let merkle_leaf = hashing::compute_submission_leaf(
        student_uuid,
        packet_hash,
        answers_hash,
        timestamp,
        "nta",
        "jee-2027",
    );
    verify_submission(
        student_uuid,
        packet_hash,
        answers_hash,
        timestamp,
        &merkle_leaf,
        "nta",
        "jee-2027",
    )?;
    verify_receipt(receipt, edge_public_key, ledger_public_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use uuid::Uuid;

    #[test]
    fn test_verify_packet_commitment_valid() {
        let leaves = vec![[0x01; 32], [0x02; 32]];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.prove(0).unwrap();
        assert!(verify_packet_commitment(&[0x01; 32], &proof, tree.root()).is_ok());
    }

    #[test]
    fn test_verify_packet_commitment_wrong_leaf() {
        let leaves = vec![[0x01; 32], [0x02; 32]];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.prove(0).unwrap();
        let result = verify_packet_commitment(&[0xff; 32], &proof, tree.root());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_submission_valid() {
        let uuid = Uuid::from_u128(42);
        let packet_hash = [0x01; 32];
        let answers_hash = [0x02; 32];
        let timestamp = 1_700_000_000;
        let leaf = hashing::compute_submission_leaf(
            uuid,
            &packet_hash,
            &answers_hash,
            timestamp,
            "nta",
            "jee-2027",
        );
        assert!(
            verify_submission(
                uuid,
                &packet_hash,
                &answers_hash,
                timestamp,
                &leaf,
                "nta",
                "jee-2027"
            )
            .is_ok()
        );
    }

    #[test]
    fn test_verify_submission_wrong_leaf() {
        let uuid = Uuid::from_u128(42);
        let packet_hash = [0x01; 32];
        let answers_hash = [0x02; 32];
        let timestamp = 1_700_000_000;
        let result = verify_submission(
            uuid,
            &packet_hash,
            &answers_hash,
            timestamp,
            &[0xff; 32],
            "nta",
            "jee-2027",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_answer_key_commitment_valid() {
        let hash = [0xab; 32];
        let anchor = Anchor {
            chain_id: "polygon".into(),
            tx_hash: "0xabc".into(),
            anchored_root: hash,
            anchor_type: crate::platform::AnchorType::AnswerKey,
            timestamp: 1_700_000_000,
            signature: vec![],
        };
        assert!(verify_answer_key_commitment(&hash, &anchor).is_ok());
    }

    #[test]
    fn test_verify_answer_key_commitment_mismatch() {
        let anchor = Anchor {
            chain_id: "polygon".into(),
            tx_hash: "0xabc".into(),
            anchored_root: [0xab; 32],
            anchor_type: crate::platform::AnchorType::AnswerKey,
            timestamp: 1_700_000_000,
            signature: vec![],
        };
        let result = verify_answer_key_commitment(&[0xcd; 32], &anchor);
        assert!(result.is_err());
    }
}
