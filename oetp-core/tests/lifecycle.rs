// Full lifecycle integration test: generate → commit → fetch → release → unlock → submit → verify
use oetp_core::device::DeviceKeyPair;
use oetp_core::envelope;
use oetp_core::hashing;
use oetp_core::manifest::Manifest;
use oetp_core::merkle::MerkleTree;
use oetp_core::packet::{self, ExamPacket, PacketQuestion};
use oetp_core::question_bank::{
    self, DifficultyRatio, QuestionBank, QuestionItem, QuestionVariant,
};
use oetp_core::receipt;
use oetp_core::release::ReleaseToken;
use oetp_core::signing;
use oetp_core::verify;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

fn sample_bank() -> QuestionBank {
    let items: Vec<QuestionItem> = (1..=30)
        .map(|i| {
            let difficulty = match i % 3 {
                0 => oetp_core::question_bank::Difficulty::Easy,
                1 => oetp_core::question_bank::Difficulty::Medium,
                _ => oetp_core::question_bank::Difficulty::Hard,
            };
            QuestionItem {
                id: i as u64,
                difficulty,
                stem: format!("question {}", i),
                variants: vec![QuestionVariant {
                    id: 0,
                    substitutions: HashMap::new(),
                    options: vec!["A".into(), "B".into(), "C".into(), "D".into()],
                    correct_index: 0,
                }],
            }
        })
        .collect();
    QuestionBank::new(items).unwrap()
}

#[test]
fn test_full_lifecycle() {
    // 1. SETUP
    let bank = sample_bank();
    let tenant_secret = b"test-tenant-secret";
    let exam_master_key = [0xab; 32];
    let ratio = DifficultyRatio::new(0.3, 0.4, 0.3).unwrap();
    let tenant_key = signing::generate_keypair();
    let device = DeviceKeyPair::generate("device-01");
    let device_x25519_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let device_x25519_public = PublicKey::from(&device_x25519_secret);
    let student_uuid = Uuid::from_u128(42);
    let exam_id = "jee-2027";
    let center_id = "center-01";
    let beacon_key = signing::generate_keypair();

    // 2. GENERATE PACKET
    let variant_seed = hashing::derive_variant_seed(tenant_secret, student_uuid, exam_id);
    let mut rng = StdRng::from_seed(variant_seed);
    let selected = question_bank::select_questions(&bank, 6, &ratio, &mut rng).unwrap();

    let questions: Vec<PacketQuestion> = selected
        .iter()
        .enumerate()
        .map(|(i, item)| PacketQuestion {
            bank_item_id: item.id,
            variant_id: 0,
            stem: item.stem.clone(),
            options: vec!["A".into(), "B".into(), "C".into(), "D".into()],
            question_ref: format!("q_{}", i + 1),
        })
        .collect();

    let exam_packet = ExamPacket {
        tenant_id: "nta".into(),
        student_uuid,
        exam_id: exam_id.to_string(),
        variant_seed,
        questions: questions.clone(),
    };

    let ephemeral_key = hashing::derive_ephemeral_key(&exam_master_key, &variant_seed);
    let encrypted = packet::encrypt_packet(&exam_packet, &ephemeral_key).unwrap();
    let envelope = envelope::seal_key_to_device(
        &ephemeral_key,
        device_x25519_public.as_bytes(),
        "device-01",
        student_uuid,
        exam_id,
    )
    .unwrap();

    // 3. MERKLE COMMITMENT
    let tree = MerkleTree::new(vec![encrypted.packet_hash]).unwrap();
    let anchored_root = *tree.root();

    // 4. RELEASE TOKEN
    let token = ReleaseToken::new(center_id, exam_id, "device-01", 0, 300, &beacon_key);

    // 5. UNLOCK
    token.verify(&beacon_key.verifying_key(), 150).unwrap();
    let device_key_bytes = device_x25519_secret.to_bytes();
    let recovered_key = envelope::open_key_envelope(
        &envelope,
        &device_key_bytes,
        "device-01",
        student_uuid,
        exam_id,
    )
    .unwrap();
    assert_eq!(recovered_key, ephemeral_key);

    let decrypted = packet::decrypt_packet(&encrypted, &recovered_key).unwrap();
    assert_eq!(decrypted.questions.len(), questions.len());
    assert_eq!(decrypted.questions[0].stem, questions[0].stem);

    // 6. SUBMIT
    let mut answers = BTreeMap::new();
    answers.insert("q_1".to_string(), "A".to_string());
    answers.insert("q_2".to_string(), "B".to_string());
    let timestamp = 150;

    let answers_hash = hashing::compute_answers_hash(
        &encrypted.packet_hash,
        &answers,
        student_uuid,
        &variant_seed,
        timestamp,
        "nta",
        exam_id,
    );
    let merkle_leaf = hashing::compute_submission_leaf(
        student_uuid,
        &encrypted.packet_hash,
        &answers_hash,
        timestamp,
        "nta",
        exam_id,
    );

    let signature = signing::sign(&device.signing_key(), &merkle_leaf);
    assert!(signing::verify(&device.verifying_key().unwrap(), &merkle_leaf, &signature).is_ok());

    // 7. RECEIPT
    let receipt_id = receipt::generate_receipt_id();
    let proof = tree.prove(0).unwrap();
    let student_receipt = receipt::StudentReceipt {
        receipt_id: receipt_id.clone(),
        tenant_id: "nta".into(),
        exam_id: exam_id.to_string(),
        application_number: "APP123".into(),
        student_uuid,
        packet_hash: encrypted.packet_hash,
        answers_hash,
        timestamp,
        merkle_proof: proof,
        edge_signature: vec![],
        ledger_signature: vec![],
        qr_payload: "qr-data".into(),
    };

    // sign the receipt's verification payload
    let payload = student_receipt.verification_payload();
    let edge_sig = signing::sign(&device.signing_key(), &payload);
    let mut signed_receipt = student_receipt;
    signed_receipt.edge_signature = edge_sig.to_bytes().to_vec();

    // 8. VERIFY
    assert!(
        signed_receipt
            .verify_edge_signature(&device.verifying_key().unwrap())
            .is_ok()
    );

    // verify packet commitment
    assert!(
        verify::verify_packet_commitment(
            &encrypted.packet_hash,
            &tree.prove(0).unwrap(),
            &anchored_root
        )
        .is_ok()
    );

    // verify submission
    assert!(
        verify::verify_submission(
            student_uuid,
            &encrypted.packet_hash,
            &answers_hash,
            timestamp,
            &merkle_leaf,
            "nta",
            exam_id,
        )
        .is_ok()
    );

    // 9. MANIFEST
    let manifest = Manifest::new(
        "nta",
        exam_id,
        vec![oetp_core::manifest::ManifestEntry {
            student_uuid,
            packet_hash: encrypted.packet_hash,
            variant_seed,
            device_id: "device-01".into(),
        }],
        &tenant_key,
    )
    .unwrap();
    assert!(manifest.verify(&tenant_key.verifying_key()).is_ok());
}

#[test]
fn test_two_step_release() {
    let _device = DeviceKeyPair::generate("device-01");
    let beacon_key = signing::generate_keypair();
    let center_id = "center-01";
    let exam_id = "jee-2027";

    // token issued 2 min before exam, valid for 4 hours
    let window_start = 1_700_000_000;
    let window_end = window_start + 240; // 4 minutes (within 300s max)

    let token = ReleaseToken::new(
        center_id,
        exam_id,
        "device-01",
        window_start,
        window_end,
        &beacon_key,
    );

    // verify at correct time
    assert!(
        token
            .verify(&beacon_key.verifying_key(), window_start + 60)
            .is_ok()
    );

    // verify before window
    assert!(
        token
            .verify(&beacon_key.verifying_key(), window_start - 1)
            .is_err()
    );

    // verify after window
    assert!(
        token
            .verify(&beacon_key.verifying_key(), window_end + 1)
            .is_err()
    );

    // verify with wrong key
    let wrong_key = signing::generate_keypair();
    assert!(
        token
            .verify(&wrong_key.verifying_key(), window_start + 60)
            .is_err()
    );
}

#[test]
fn test_tenant_isolation() {
    let tenant1_secret = b"tenant-1-secret";
    let tenant2_secret = b"tenant-2-secret";
    let student = Uuid::from_u128(42);
    let exam_id = "exam-1";

    let seed1 = hashing::derive_variant_seed(tenant1_secret, student, exam_id);
    let seed2 = hashing::derive_variant_seed(tenant2_secret, student, exam_id);
    assert_ne!(seed1, seed2);

    let master1 = hashing::derive_exam_master_key(&[0xab; 32], exam_id);
    let master2 = hashing::derive_exam_master_key(&[0xcd; 32], exam_id);
    assert_ne!(master1, master2);
}

#[test]
fn test_answer_substitution_detection() {
    let student_uuid = Uuid::from_u128(42);
    let packet_hash = [0x01; 32];
    let variant_seed = [0xcd; 32];
    let timestamp = 1_700_000_000;

    let mut real_answers = BTreeMap::new();
    real_answers.insert("q1".to_string(), "A".to_string());

    let mut fake_answers = BTreeMap::new();
    fake_answers.insert("q1".to_string(), "B".to_string());

    let real_hash = hashing::compute_answers_hash(
        &packet_hash,
        &real_answers,
        student_uuid,
        &variant_seed,
        timestamp,
        "nta",
        "jee-2027",
    );
    let fake_hash = hashing::compute_answers_hash(
        &packet_hash,
        &fake_answers,
        student_uuid,
        &variant_seed,
        timestamp,
        "nta",
        "jee-2027",
    );

    assert_ne!(real_hash, fake_hash);

    // verify that the real submission leaf matches
    let real_leaf = hashing::compute_submission_leaf(
        student_uuid,
        &packet_hash,
        &real_hash,
        timestamp,
        "nta",
        "jee-2027",
    );
    assert!(
        verify::verify_submission(
            student_uuid,
            &packet_hash,
            &real_hash,
            timestamp,
            &real_leaf,
            "nta",
            "jee-2027",
        )
        .is_ok()
    );

    // verify that fake answers produce a different leaf
    let fake_leaf = hashing::compute_submission_leaf(
        student_uuid,
        &packet_hash,
        &fake_hash,
        timestamp,
        "nta",
        "jee-2027",
    );
    assert_ne!(real_leaf, fake_leaf);
}

#[test]
fn test_personal_answer_copy() {
    let answers = b"q1=A&q2=B";
    let student_key = hashing::derive_student_answer_key(
        "APP123",
        "2000-01-01",
        &[0xab; 32],
        &[0xcd; 32],
        "nta",
        "jee-2027",
    );
    let receipt_id = receipt::generate_receipt_id();

    let copy = receipt::create_personal_answer_copy(&receipt_id, answers, &student_key).unwrap();
    let decrypted = receipt::decrypt_personal_answer_copy(&copy, &student_key).unwrap();
    assert_eq!(decrypted, answers);

    // wrong key fails
    let wrong_key = [0xcd; 32];
    assert!(receipt::decrypt_personal_answer_copy(&copy, &wrong_key).is_err());
}
