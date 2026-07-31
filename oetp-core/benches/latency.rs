// Latency benchmarks for OETP core cryptographic operations
// Run with: cargo bench -p oetp-core
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use oetp_core::envelope;
use oetp_core::hashing;
use oetp_core::merkle::MerkleTree;
use oetp_core::packet::{self, ExamPacket, PacketQuestion};
use oetp_core::receipt;
use oetp_core::signing;
use rand::rngs::OsRng;
use std::collections::BTreeMap;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};

fn bench_packet_encryption(c: &mut Criterion) {
    let packet = ExamPacket {
        tenant_id: "nta".into(),
        student_uuid: Uuid::from_u128(42),
        exam_id: "jee-2027".into(),
        variant_seed: [0xcd; 32],
        questions: (0..90)
            .map(|i| PacketQuestion {
                bank_item_id: i as u64,
                variant_id: 0,
                stem: format!("long question stem number {} that simulates a real exam question with sufficient text", i),
                options: vec!["A".into(), "B".into(), "C".into(), "D".into()],
                question_ref: format!("q_{}", i + 1),
            })
            .collect(),
    };
    let key = [0xab; 32];

    c.bench_function("packet_encrypt_90q", |b| {
        b.iter(|| packet::encrypt_packet(black_box(&packet), black_box(&key)))
    });
}

fn bench_packet_decryption(c: &mut Criterion) {
    let packet = ExamPacket {
        tenant_id: "nta".into(),
        student_uuid: Uuid::from_u128(42),
        exam_id: "jee-2027".into(),
        variant_seed: [0xcd; 32],
        questions: (0..90)
            .map(|i| PacketQuestion {
                bank_item_id: i as u64,
                variant_id: 0,
                stem: format!("long question stem number {} that simulates a real exam question with sufficient text", i),
                options: vec!["A".into(), "B".into(), "C".into(), "D".into()],
                question_ref: format!("q_{}", i + 1),
            })
            .collect(),
    };
    let key = [0xab; 32];
    let encrypted = packet::encrypt_packet(&packet, &key).unwrap();

    c.bench_function("packet_decrypt_90q", |b| {
        b.iter(|| packet::decrypt_packet(black_box(&encrypted), black_box(&key)))
    });
}

fn bench_answer_hashing(c: &mut Criterion) {
    let packet_hash = [0x01; 32];
    let mut answers = BTreeMap::new();
    for i in 0..90 {
        answers.insert(format!("q_{}", i + 1), "A".to_string());
    }
    let uuid = Uuid::from_u128(42);
    let variant_seed = [0xcd; 32];
    let timestamp = 1_700_000_000;

    c.bench_function("answers_hash_90q", |b| {
        b.iter(|| {
            hashing::compute_answers_hash(
                black_box(&packet_hash),
                black_box(&answers),
                black_box(uuid),
                black_box(&variant_seed),
                black_box(timestamp),
                "nta",
                "jee-2027",
            )
        })
    });
}

fn bench_submission_leaf(c: &mut Criterion) {
    let uuid = Uuid::from_u128(42);
    let packet_hash = [0x01; 32];
    let answers_hash = [0x02; 32];
    let timestamp = 1_700_000_000;

    c.bench_function("submission_leaf", |b| {
        b.iter(|| {
            hashing::compute_submission_leaf(
                black_box(uuid),
                black_box(&packet_hash),
                black_box(&answers_hash),
                black_box(timestamp),
                "nta",
                "jee-2027",
            )
        })
    });
}

fn bench_signing(c: &mut Criterion) {
    let key = signing::generate_keypair();
    let msg = &[0xab; 32];

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| signing::sign(black_box(&key), black_box(msg)))
    });
}

fn bench_verification(c: &mut Criterion) {
    let key = signing::generate_keypair();
    let vk = key.verifying_key();
    let msg = &[0xab; 32];
    let sig = signing::sign(&key, msg);

    c.bench_function("ed25519_verify", |b| {
        b.iter(|| signing::verify(black_box(&vk), black_box(msg), black_box(&sig)))
    });
}

fn bench_envelope_seal(c: &mut Criterion) {
    let packet_key = [0xab; 32];
    let device_secret = StaticSecret::random_from_rng(OsRng);
    let device_public = PublicKey::from(&device_secret);
    let student_uuid = Uuid::from_u128(42);

    c.bench_function("envelope_seal", |b| {
        b.iter(|| envelope::seal_key_to_device(black_box(&packet_key), black_box(device_public.as_bytes()), "device-01", student_uuid, "jee-2027"))
    });
}

fn bench_envelope_open(c: &mut Criterion) {
    let packet_key = [0xab; 32];
    let device_secret = StaticSecret::random_from_rng(OsRng);
    let device_public = PublicKey::from(&device_secret);
    let student_uuid = Uuid::from_u128(42);
    let envelope = envelope::seal_key_to_device(&packet_key, device_public.as_bytes(), "device-01", student_uuid, "jee-2027").unwrap();
    let device_bytes = device_secret.to_bytes();

    c.bench_function("envelope_open", |b| {
        b.iter(|| envelope::open_key_envelope(black_box(&envelope), black_box(&device_bytes), "device-01", student_uuid, "jee-2027"))
    });
}

fn bench_merkle_proof(c: &mut Criterion) {
    let leaves: Vec<[u8; 32]> = (0..100_000).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::new(leaves).unwrap();

    c.bench_function("merkle_prove_100k", |b| {
        b.iter(|| tree.prove(black_box(0)))
    });
}

fn bench_receipt_generation(c: &mut Criterion) {
    let answers_json = b"q1=A&q2=B&q3=C";
    let student_key = [0xab; 32];
    let receipt_id = receipt::generate_receipt_id();

    c.bench_function("receipt_generation", |b| {
        b.iter(|| {
            receipt::create_personal_answer_copy(
                black_box(&receipt_id),
                black_box(answers_json),
                black_box(&student_key),
            )
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = bench_packet_encryption, bench_packet_decryption, bench_answer_hashing,
              bench_submission_leaf, bench_signing, bench_verification,
              bench_envelope_seal, bench_envelope_open, bench_merkle_proof,
              bench_receipt_generation
);
criterion_main!(benches);
