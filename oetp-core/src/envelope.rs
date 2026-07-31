// wraps the packet key so only the assigned device can open it (ECDH + HKDF + AES-GCM with canonical AAD)
use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEnvelope {
    pub version: u16,
    pub device_id: String,
    pub student_uuid: Uuid,
    pub exam_id: String,
    pub sender_public_key: [u8; 32],
    pub encrypted_ephemeral_key: Vec<u8>,
    pub nonce: [u8; 12],
}

fn derive_envelope_key(
    shared_secret: &[u8; 32],
    device_id: &str,
    student_uuid: Uuid,
    exam_id: &str,
) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(Some(b"oetp-envelope-key"), shared_secret);
    let mut okm = [0u8; 32];
    let info = format!("{}:{}:{}", device_id, student_uuid, exam_id);
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid length for HKDF");
    okm
}

fn build_canonical_aad(device_id: &str, student_uuid: Uuid, exam_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.push(0x01u8); // version
    let did = device_id.as_bytes();
    aad.extend_from_slice(&(did.len() as u16).to_be_bytes());
    aad.extend_from_slice(did);
    aad.extend_from_slice(&student_uuid.to_bytes_le());
    let eid = exam_id.as_bytes();
    aad.extend_from_slice(&(eid.len() as u16).to_be_bytes());
    aad.extend_from_slice(eid);
    aad
}

pub fn seal_key_to_device(
    packet_key: &[u8; 32],
    device_public_key: &[u8; 32],
    device_id: &str,
    student_uuid: Uuid,
    exam_id: &str,
) -> Result<KeyEnvelope> {
    let device_pk = PublicKey::from(*device_public_key);

    // Validate device public key
    if *device_pk.as_bytes() == [0u8; 32] {
        return Err(Error::InvalidInput("device public key is all-zero".into()));
    }

    let sender_secret = EphemeralSecret::random_from_rng(OsRng);
    let sender_public = PublicKey::from(&sender_secret);

    let shared = sender_secret.diffie_hellman(&device_pk);

    let envelope_key = derive_envelope_key(shared.as_bytes(), device_id, student_uuid, exam_id);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let cipher = Aes256Gcm::new((&envelope_key).into());

    let aad = build_canonical_aad(device_id, student_uuid, exam_id);
    let payload = Payload {
        msg: packet_key.as_ref(),
        aad: &aad,
    };

    let encrypted = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    // Zeroize envelope key
    let mut envelope_key_mut = envelope_key;
    envelope_key_mut.zeroize();

    Ok(KeyEnvelope {
        version: 1,
        device_id: device_id.to_string(),
        student_uuid,
        exam_id: exam_id.to_string(),
        sender_public_key: *sender_public.as_bytes(),
        encrypted_ephemeral_key: encrypted,
        nonce: nonce_bytes,
    })
}

pub fn open_key_envelope(
    envelope: &KeyEnvelope,
    device_secret_key: &[u8; 32],
    expected_device_id: &str,
    expected_student_uuid: Uuid,
    expected_exam_id: &str,
) -> Result<[u8; 32]> {
    // Verify identity fields match expected values
    if envelope.device_id != expected_device_id {
        return Err(Error::PacketDecryption);
    }
    if envelope.student_uuid != expected_student_uuid {
        return Err(Error::PacketDecryption);
    }
    if envelope.exam_id != expected_exam_id {
        return Err(Error::PacketDecryption);
    }

    let device_secret = StaticSecret::from(*device_secret_key);
    let sender_public = PublicKey::from(envelope.sender_public_key);

    let shared = device_secret.diffie_hellman(&sender_public);

    let envelope_key = derive_envelope_key(
        shared.as_bytes(),
        &envelope.device_id,
        envelope.student_uuid,
        &envelope.exam_id,
    );

    let nonce = Nonce::from(envelope.nonce);

    let cipher = Aes256Gcm::new((&envelope_key).into());

    let aad = build_canonical_aad(
        &envelope.device_id,
        envelope.student_uuid,
        &envelope.exam_id,
    );
    let payload = Payload {
        msg: envelope.encrypted_ephemeral_key.as_ref(),
        aad: &aad,
    };

    let plaintext = cipher
        .decrypt(&nonce, payload)
        .map_err(|_| Error::PacketDecryption)?;

    // Zeroize envelope key
    let mut envelope_key_mut = envelope_key;
    envelope_key_mut.zeroize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_and_open_roundtrip() {
        let packet_key = [0xab; 32];
        let device_secret = StaticSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&device_secret);
        let student_uuid = Uuid::from_u128(42);

        let envelope = seal_key_to_device(
            &packet_key,
            device_public.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        let device_bytes = device_secret.to_bytes();
        let recovered = open_key_envelope(
            &envelope,
            &device_bytes,
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        assert_eq!(recovered, packet_key);
    }

    #[test]
    fn test_open_with_wrong_device_id_fails() {
        let packet_key = [0xab; 32];
        let device_secret = StaticSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&device_secret);
        let student_uuid = Uuid::from_u128(42);

        let envelope = seal_key_to_device(
            &packet_key,
            device_public.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        let device_bytes = device_secret.to_bytes();
        let result = open_key_envelope(
            &envelope,
            &device_bytes,
            "device-02",
            student_uuid,
            "jee-2027",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_seal_wrong_key_fails() {
        let packet_key = [0xab; 32];
        let device_secret1 = StaticSecret::random_from_rng(OsRng);
        let device_secret2 = StaticSecret::random_from_rng(OsRng);
        let device_public1 = PublicKey::from(&device_secret1);
        let student_uuid = Uuid::from_u128(42);

        let envelope = seal_key_to_device(
            &packet_key,
            device_public1.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        let device2_bytes = device_secret2.to_bytes();
        let result = open_key_envelope(
            &envelope,
            &device2_bytes,
            "device-01",
            student_uuid,
            "jee-2027",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_seal_produces_different_ciphertexts() {
        let packet_key = [0xab; 32];
        let device_secret = StaticSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&device_secret);
        let student_uuid = Uuid::from_u128(42);

        let e1 = seal_key_to_device(
            &packet_key,
            device_public.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        let e2 = seal_key_to_device(
            &packet_key,
            device_public.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        assert_ne!(e1.encrypted_ephemeral_key, e2.encrypted_ephemeral_key);
    }

    #[test]
    fn test_envelope_includes_sender_public_key() {
        let packet_key = [0xab; 32];
        let device_secret = StaticSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&device_secret);
        let student_uuid = Uuid::from_u128(42);

        let envelope = seal_key_to_device(
            &packet_key,
            device_public.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        assert_ne!(envelope.sender_public_key, [0u8; 32]);
    }

    #[test]
    fn test_tampered_sender_public_key_fails() {
        let packet_key = [0xab; 32];
        let device_secret = StaticSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&device_secret);
        let student_uuid = Uuid::from_u128(42);

        let mut envelope = seal_key_to_device(
            &packet_key,
            device_public.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        envelope.sender_public_key[0] ^= 0xff;
        let device_bytes = device_secret.to_bytes();
        let result = open_key_envelope(
            &envelope,
            &device_bytes,
            "device-01",
            student_uuid,
            "jee-2027",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_identity_fails_decryption() {
        let packet_key = [0xab; 32];
        let device_secret = StaticSecret::random_from_rng(OsRng);
        let device_public = PublicKey::from(&device_secret);
        let student_uuid = Uuid::from_u128(42);

        let mut envelope = seal_key_to_device(
            &packet_key,
            device_public.as_bytes(),
            "device-01",
            student_uuid,
            "jee-2027",
        )
        .unwrap();
        envelope.device_id = "device-02".into();
        let device_bytes = device_secret.to_bytes();
        let result = open_key_envelope(
            &envelope,
            &device_bytes,
            "device-01",
            student_uuid,
            "jee-2027",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_all_zero_public_key() {
        let packet_key = [0xab; 32];
        let student_uuid = Uuid::from_u128(42);
        let result = seal_key_to_device(
            &packet_key,
            &[0u8; 32],
            "device-01",
            student_uuid,
            "jee-2027",
        );
        assert!(result.is_err());
    }
}
