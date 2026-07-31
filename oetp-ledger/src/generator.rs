// CLI subcommand: generate per-student packets and produce a manifest
use oetp_core::device_x25519::DeviceX25519Key;
use oetp_core::envelope;
use oetp_core::error::Result;
use oetp_core::hashing;
use oetp_core::manifest::{Manifest, ManifestEntry};
use oetp_core::packet::{self, ExamPacket, PacketQuestion};
use oetp_core::question_bank::{self, DifficultyRatio, QuestionBank, QuestionItem};
use oetp_core::signing;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use std::path::Path;
use uuid::Uuid;

pub struct GeneratorConfig<'a> {
    pub bank_path: &'a str,
    pub num_questions: usize,
    pub students_path: &'a str,
    pub output_dir: &'a str,
    pub tenant_master_key: &'a [u8; 32],
    pub exam_id: &'a str,
    pub tenant_id: &'a str,
    pub device_x25519_public_key: Option<&'a [u8; 32]>,
}

pub fn run_generator(cfg: GeneratorConfig<'_>) -> Result<()> {
    let bank_json =
        std::fs::read_to_string(cfg.bank_path).map_err(oetp_core::error::Error::Io)?;
    let items: Vec<QuestionItem> = serde_json::from_str(&bank_json)
        .map_err(|e| oetp_core::error::Error::Serialization(e.to_string()))?;
    let bank = QuestionBank::new(items)?;

    let students_csv =
        std::fs::read_to_string(cfg.students_path).map_err(oetp_core::error::Error::Io)?;
    let students: Vec<(Uuid, String)> = students_csv
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let parts: Vec<&str> = l.split(',').collect();
            let uuid = Uuid::parse_str(parts[0]).unwrap_or_else(|_| Uuid::new_v4());
            let device_id = parts.get(1).unwrap_or(&"default-device").to_string();
            (uuid, device_id)
        })
        .collect();

    if students.is_empty() {
        return Err(oetp_core::error::Error::InvalidInput(
            "no students in CSV".into(),
        ));
    }

    let tenant_master_key = cfg.tenant_master_key;
    let exam_id = cfg.exam_id;
    let tenant_id = cfg.tenant_id;
    let output_dir = cfg.output_dir;

    let tenant_secret = tenant_master_key;
    let exam_master_key = hashing::derive_exam_master_key(tenant_master_key, exam_id);
    let ratio = DifficultyRatio::new(0.3, 0.4, 0.3)?;
    let signing_key = signing::generate_keypair();

    std::fs::create_dir_all(output_dir).map_err(oetp_core::error::Error::Io)?;

    // Persist the signing key so the manifest can be verified later
    let signing_key_path = Path::new(output_dir).join("signing_key.hex");
    std::fs::write(&signing_key_path, hex::encode(signing_key.to_bytes()))
        .map_err(oetp_core::error::Error::Io)?;

    let mut entries = Vec::with_capacity(students.len());

    for (student_uuid, device_id) in &students {
        let variant_seed = hashing::derive_variant_seed(tenant_secret, *student_uuid, exam_id);
        let mut rng = StdRng::from_seed(variant_seed);
        let selected = question_bank::select_questions(&bank, cfg.num_questions, &ratio, &mut rng)?;

        let questions: Vec<PacketQuestion> = selected
            .iter()
            .enumerate()
            .map(|(i, item)| {
                // Select a variant deterministically using the variant_seed
                let variant_idx = (variant_seed[0] as usize) % item.variants.len();
                let variant = &item.variants[variant_idx];

                // Apply stem substitutions
                let mut stem = item.stem.clone();
                for (key, value) in &variant.substitutions {
                    stem = stem.replace(&format!("{{{{{}}}}}", key), value);
                }

                // Shuffle options deterministically using a per-question seed
                let mut option_indices: Vec<usize> = (0..variant.options.len()).collect();
                let mut option_rng = StdRng::from_seed({
                    let mut seed = variant_seed;
                    seed[0] ^= (i + 1) as u8;
                    seed[1] ^= ((i + 1) >> 8) as u8;
                    seed
                });
                option_indices.shuffle(&mut option_rng);

                let shuffled_options: Vec<String> = option_indices
                    .iter()
                    .map(|&idx| variant.options[idx].clone())
                    .collect();

                PacketQuestion {
                    bank_item_id: item.id,
                    variant_id: variant.id,
                    stem,
                    options: shuffled_options,
                    question_ref: format!("q_{}", i + 1),
                }
            })
            .collect();

        let exam_packet = ExamPacket {
            tenant_id: tenant_id.to_string(),
            student_uuid: *student_uuid,
            exam_id: exam_id.to_string(),
            variant_seed,
            questions,
        };

        let ephemeral_key = hashing::derive_ephemeral_key(&exam_master_key, &variant_seed);
        let encrypted = packet::encrypt_packet(&exam_packet, &ephemeral_key)?;

        // Use the device's X25519 public key for the envelope, or generate a random one
        let device_x25519_pub = if let Some(pk) = cfg.device_x25519_public_key {
            *pk
        } else {
            let device_x25519 = DeviceX25519Key::generate(device_id);
            // Save the X25519 public key alongside the envelope for the device
            let x25519_pub_path = Path::new(output_dir).join(format!("x25519_pub_{}.hex", student_uuid));
            std::fs::write(&x25519_pub_path, hex::encode(device_x25519.public_key))
                .map_err(oetp_core::error::Error::Io)?;
            *device_x25519.public_key_bytes()
        };
        let envelope = envelope::seal_key_to_device(
            &ephemeral_key,
            &device_x25519_pub,
            device_id,
            *student_uuid,
            exam_id,
        )?;

        let packet_path = Path::new(output_dir).join(format!("packet_{}.enc", student_uuid));
        let packet_json = serde_json::to_string(&encrypted)
            .map_err(|e| oetp_core::error::Error::Serialization(e.to_string()))?;
        std::fs::write(&packet_path, &packet_json).map_err(oetp_core::error::Error::Io)?;

        let envelope_path = Path::new(output_dir).join(format!("envelope_{}.enc", student_uuid));
        let envelope_json = serde_json::to_string(&envelope)
            .map_err(|e| oetp_core::error::Error::Serialization(e.to_string()))?;
        std::fs::write(&envelope_path, &envelope_json)
            .map_err(oetp_core::error::Error::Io)?;

        entries.push(ManifestEntry {
            student_uuid: *student_uuid,
            packet_hash: encrypted.packet_hash,
            variant_seed,
            device_id: device_id.clone(),
        });
    }

    let manifest = Manifest::new(tenant_id, exam_id, entries, &signing_key)?;
    let manifest_path = Path::new(output_dir).join("manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| oetp_core::error::Error::Serialization(e.to_string()))?;
    std::fs::write(&manifest_path, &manifest_json).map_err(oetp_core::error::Error::Io)?;

    println!(
        "Generated {} packets and manifest at {}",
        students.len(),
        output_dir
    );
    println!("Signing key saved to {}/signing_key.hex", output_dir);
    Ok(())
}
