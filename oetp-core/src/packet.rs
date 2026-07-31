// creates and decrypts per-student encrypted exam packets
use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketQuestion {
    pub bank_item_id: u64,
    pub variant_id: u64,
    pub stem: String,
    pub options: Vec<String>,
    pub question_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExamPacket {
    pub tenant_id: String,
    pub student_uuid: Uuid,
    pub exam_id: String,
    pub variant_seed: [u8; 32],
    pub questions: Vec<PacketQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPacket {
    pub tenant_id: String,
    pub student_uuid: Uuid,
    pub exam_id: String,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub packet_hash: [u8; 32],
}

pub fn encrypt_packet(packet: &ExamPacket, key: &[u8; 32]) -> Result<EncryptedPacket> {
    let plaintext = bincode::serialize(packet).map_err(|e| Error::Serialization(e.to_string()))?;

    let cipher = Aes256Gcm::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_e| Error::PacketDecryption)?;

    let packet_hash = Sha3_256::digest(&ciphertext).into();

    Ok(EncryptedPacket {
        tenant_id: packet.tenant_id.clone(),
        student_uuid: packet.student_uuid,
        exam_id: packet.exam_id.clone(),
        ciphertext,
        nonce: nonce_bytes,
        packet_hash,
    })
}

pub fn decrypt_packet(encrypted: &EncryptedPacket, key: &[u8; 32]) -> Result<ExamPacket> {
    let cipher = Aes256Gcm::new(key.into());

    let nonce = Nonce::from(encrypted.nonce);

    let plaintext = cipher
        .decrypt(&nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| Error::PacketDecryption)?;

    let packet: ExamPacket =
        bincode::deserialize(&plaintext).map_err(|e| Error::Serialization(e.to_string()))?;

    // detects tampering even if AES-GCM auth tag passes
    let computed_hash: [u8; 32] = Sha3_256::digest(&encrypted.ciphertext).into();
    if computed_hash != encrypted.packet_hash {
        return Err(Error::PacketDecryption);
    }

    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packet() -> ExamPacket {
        ExamPacket {
            tenant_id: "nta".into(),
            student_uuid: Uuid::from_u128(42),
            exam_id: "jee-2027".into(),
            variant_seed: [0xcd; 32],
            questions: vec![PacketQuestion {
                bank_item_id: 1,
                variant_id: 0,
                stem: "What is 2+2?".into(),
                options: vec!["3".into(), "4".into(), "5".into(), "6".into()],
                question_ref: "q_1".into(),
            }],
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let packet = sample_packet();
        let key = [0xab; 32];
        let encrypted = encrypt_packet(&packet, &key).unwrap();
        let decrypted = decrypt_packet(&encrypted, &key).unwrap();
        assert_eq!(decrypted.student_uuid, packet.student_uuid);
        assert_eq!(decrypted.questions.len(), packet.questions.len());
        assert_eq!(decrypted.questions[0].stem, packet.questions[0].stem);
    }

    #[test]
    fn test_encrypt_produces_hash() {
        let packet = sample_packet();
        let key = [0xab; 32];
        let encrypted = encrypt_packet(&packet, &key).unwrap();
        assert_ne!(encrypted.packet_hash, [0u8; 32]);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let packet = sample_packet();
        let key1 = [0xab; 32];
        let key2 = [0xcd; 32];
        let encrypted = encrypt_packet(&packet, &key1).unwrap();
        let result = decrypt_packet(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let packet = sample_packet();
        let key = [0xab; 32];
        let mut encrypted = encrypt_packet(&packet, &key).unwrap();
        encrypted.ciphertext[0] ^= 0xff;
        let result = decrypt_packet(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_different_keys_different_ciphertext() {
        let packet = sample_packet();
        let e1 = encrypt_packet(&packet, &[0xab; 32]).unwrap();
        let e2 = encrypt_packet(&packet, &[0xcd; 32]).unwrap();
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_encrypt_deterministic_nonce() {
        // nonces are random, so two encryptions of same packet differ
        let packet = sample_packet();
        let key = [0xab; 32];
        let e1 = encrypt_packet(&packet, &key).unwrap();
        let e2 = encrypt_packet(&packet, &key).unwrap();
        assert_ne!(e1.nonce, e2.nonce);
    }

    #[test]
    fn test_packet_hash_verification_on_decrypt() {
        let packet = sample_packet();
        let key = [0xab; 32];
        let mut encrypted = encrypt_packet(&packet, &key).unwrap();
        encrypted.packet_hash = [0xff; 32];
        let result = decrypt_packet(&encrypted, &key);
        assert!(result.is_err());
    }
}
