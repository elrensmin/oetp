// derives per-student variant_seed and per-packet ephemeral_key

use argon2::Argon2;
use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub fn derive_exam_master_key(tenant_master_key: &[u8; 32], exam_id: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(None, tenant_master_key);
    let mut okm = [0u8; 32];
    hk.expand(b"oetp-exam-master", &mut okm)
        .expect("32 bytes is a valid length for HKDF");
    let hk2 = Hkdf::<Sha3_256>::new(Some(&okm), exam_id.as_bytes());
    let mut okm2 = [0u8; 32];
    hk2.expand(b"oetp-exam-key", &mut okm2)
        .expect("32 bytes is a valid length for HKDF");
    okm2
}

pub fn derive_variant_seed(tenant_secret: &[u8], student_uuid: Uuid, exam_id: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(b"oetp-variant-seed"), tenant_secret);
    let mut okm = [0u8; 32];
    let mut info = b"variant:".to_vec();
    info.extend_from_slice(&student_uuid.to_bytes_le());
    info.push(b':');
    info.extend_from_slice(exam_id.as_bytes());
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid length for HKDF");
    okm
}

pub fn derive_ephemeral_key(exam_master_key: &[u8; 32], variant_seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(b"oetp-packet-key"), exam_master_key);
    let mut okm = [0u8; 32];
    hk.expand(variant_seed, &mut okm)
        .expect("32 bytes is a valid length for HKDF");
    okm
}

pub fn compute_answers_hash(
    packet_hash: &[u8; 32],
    raw_answers: &BTreeMap<String, String>,
    student_uuid: Uuid,
    variant_seed: &[u8; 32],
    timestamp: u64,
    tenant_id: &str,
    exam_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"oetp-answers-v1");
    hasher.update(packet_hash);
    hasher.update(serde_json::to_vec(raw_answers).expect("canonical JSON serialization"));
    hasher.update(student_uuid.to_bytes_le());
    hasher.update(variant_seed);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(tenant_id.as_bytes());
    hasher.update(exam_id.as_bytes());
    hasher.finalize().into()
}

pub fn compute_submission_leaf(
    student_uuid: Uuid,
    packet_hash: &[u8; 32],
    answers_hash: &[u8; 32],
    timestamp: u64,
    tenant_id: &str,
    exam_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"oetp-submission-leaf-v1");
    hasher.update(student_uuid.to_bytes_le());
    hasher.update(packet_hash);
    hasher.update(answers_hash);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(tenant_id.as_bytes());
    hasher.update(exam_id.as_bytes());
    hasher.finalize().into()
}

pub fn derive_student_answer_key(
    application_number: &str,
    dob: &str,
    exam_salt: &[u8; 32],
    server_pepper: &[u8; 32],
    tenant_id: &str,
    exam_id: &str,
) -> [u8; 32] {
    // Use Argon2id for memory-hard key derivation from low-entropy inputs
    let salt_input = format!("{}:{}:{}:{}", application_number, dob, tenant_id, exam_id);
    let mut salt = [0u8; 32];
    let hk = Hkdf::<Sha3_256>::new(Some(exam_salt), salt_input.as_bytes());
    hk.expand(b"argon2-salt", &mut salt)
        .expect("32 bytes is a valid length for HKDF");

    let mut okm = [0u8; 32];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).expect("valid Argon2 params"),
    );
    argon2
        .hash_password_into(server_pepper, &salt, &mut okm)
        .expect("Argon2id hashing should succeed");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_exam_master_key_deterministic() {
        let master = [0xab; 32];
        let k1 = derive_exam_master_key(&master, "jee-2027");
        let k2 = derive_exam_master_key(&master, "jee-2027");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_exam_master_key_different_exam() {
        let master = [0xab; 32];
        let k1 = derive_exam_master_key(&master, "jee-2027");
        let k2 = derive_exam_master_key(&master, "neet-2027");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_exam_master_key_different_tenant() {
        let k1 = derive_exam_master_key(&[0xab; 32], "jee-2027");
        let k2 = derive_exam_master_key(&[0xba; 32], "jee-2027");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_variant_seed_deterministic() {
        let secret = b"tenant-secret";
        let uuid = Uuid::new_v4();
        let s1 = derive_variant_seed(secret, uuid, "jee-2027");
        let s2 = derive_variant_seed(secret, uuid, "jee-2027");
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_variant_seed_different_student() {
        let secret = b"tenant-secret";
        let s1 = derive_variant_seed(secret, Uuid::from_u128(1), "jee-2027");
        let s2 = derive_variant_seed(secret, Uuid::from_u128(2), "jee-2027");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_variant_seed_different_exam() {
        let secret = b"tenant-secret";
        let uuid = Uuid::from_u128(69);
        let s1 = derive_variant_seed(secret, uuid, "jee-2027");
        let s2 = derive_variant_seed(secret, uuid, "neet-2027");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_derive_ephemeral_key_output_size() {
        let master = [0xab; 32];
        let seed = [0xcd; 32];
        let key = derive_ephemeral_key(&master, &seed);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_ephemeral_key_deterministic() {
        let master = [0xab; 32];
        let seed = [0xcd; 32];
        let k1 = derive_ephemeral_key(&master, &seed);
        let k2 = derive_ephemeral_key(&master, &seed);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_ephemeral_key_different_seed() {
        let master = [0xab; 32];
        let k1 = derive_ephemeral_key(&master, &[0xcd; 32]);
        let k2 = derive_ephemeral_key(&master, &[0xef; 32]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_compute_answer_hash_golden() {
        let packet_hash = [0x01; 32];
        let mut answers = BTreeMap::new();
        answers.insert("q1".to_string(), "A".to_string());
        answers.insert("q2".to_string(), "D".to_string());

        let uuid = Uuid::from_u128(1);
        let variant_seed = [0xab; 32];
        let timestamp = 1_700_000_000;
        let hash1 = compute_answers_hash(&packet_hash, &answers, uuid, &variant_seed, timestamp, "nta", "jee-2027");
        assert_eq!(hash1.len(), 32);

        let hash2 = compute_answers_hash(&packet_hash, &answers, uuid, &variant_seed, timestamp, "nta", "jee-2027");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_answer_hash_different_answers() {
        let uuid = Uuid::from_u128(1);
        let variant_seed = [0xab; 32];
        let timestamp = 1_700_000_000;
        let packet_hash = [0x01; 32];

        let mut answers_a = BTreeMap::new();
        let mut answers_b = BTreeMap::new();
        answers_a.insert("q1".to_string(), "A".to_string());
        answers_b.insert("q1".to_string(), "D".to_string());

        let hash1 = compute_answers_hash(&packet_hash, &answers_a, uuid, &variant_seed, timestamp, "nta", "jee-2027");
        let hash2 = compute_answers_hash(&packet_hash, &answers_b, uuid, &variant_seed, timestamp, "nta", "jee-2027");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_answer_hash_different_student() {
        let packet_hash = [0x01; 32];
        let mut answers = BTreeMap::new();
        answers.insert("q1".to_string(), "A".to_string());

        let variant_seed = [0xab; 32];
        let timestamp = 1_700_000_000;

        let hash1 = compute_answers_hash(
            &packet_hash, &answers, Uuid::from_u128(1), &variant_seed, timestamp, "nta", "jee-2027",
        );
        let hash2 = compute_answers_hash(
            &packet_hash, &answers, Uuid::from_u128(2), &variant_seed, timestamp, "nta", "jee-2027",
        );
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_compute_submission_leaf_golden() {
        let uuid = Uuid::from_u128(1);
        let packet_hash = [0x01; 32];
        let answers_hash = [0x02; 32];
        let timestamp = 1_700_000_000;

        let leaf1 = compute_submission_leaf(uuid, &packet_hash, &answers_hash, timestamp, "nta", "jee-2027");
        assert_eq!(leaf1.len(), 32);

        let leaf2 = compute_submission_leaf(uuid, &packet_hash, &answers_hash, timestamp, "nta", "jee-2027");
        assert_eq!(leaf1, leaf2);
    }

    #[test]
    fn test_compute_submission_leaf_different_student() {
        let packet_hash = [0x01; 32];
        let answers_hash = [0x02; 32];
        let timestamp = 1_700_000_000;

        let l1 = compute_submission_leaf(Uuid::from_u128(1), &packet_hash, &answers_hash, timestamp, "nta", "jee-2027");
        let l2 = compute_submission_leaf(Uuid::from_u128(2), &packet_hash, &answers_hash, timestamp, "nta", "jee-2027");
        assert_ne!(l1, l2);
    }

    #[test]
    fn test_compute_submission_leaf_different_packet() {
        let uuid = Uuid::from_u128(42);
        let answers_hash = [0x02; 32];
        let timestamp = 1_700_000_000;

        let l1 = compute_submission_leaf(uuid, &[0x01; 32], &answers_hash, timestamp, "nta", "jee-2027");
        let l2 = compute_submission_leaf(uuid, &[0xff; 32], &answers_hash, timestamp, "nta", "jee-2027");
        assert_ne!(l1, l2);
    }

    #[test]
    fn test_derive_student_answer_key_deterministic() {
        let salt = [0xab; 32];
        let k1 = derive_student_answer_key("APP123", "2000-01-01", &salt, &[0xcd; 32], "nta", "jee-2027");
        let k2 = derive_student_answer_key("APP123", "2000-01-01", &salt, &[0xcd; 32], "nta", "jee-2027");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_student_answer_key_different_student() {
        let salt = [0xab; 32];
        let k1 = derive_student_answer_key("APP123", "2000-01-01", &salt, &[0xcd; 32], "nta", "jee-2027");
        let k2 = derive_student_answer_key("APP456", "2000-01-01", &salt, &[0xcd; 32], "nta", "jee-2027");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_student_answer_key_different_salt() {
        let k1 = derive_student_answer_key("APP123", "2000-01-01", &[0xab; 32], &[0xcd; 32], "nta", "jee-2027");
        let k2 = derive_student_answer_key("APP123", "2000-01-01", &[0xcd; 32], &[0xcd; 32], "nta", "jee-2027");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_student_answer_key_output_size() {
        let key = derive_student_answer_key("APP123", "2000-01-01", &[0xab; 32], &[0xcd; 32], "nta", "jee-2027");
        assert_eq!(key.len(), 32);
    }
}
