// device identity - each exam-center machine has a unique keypair
use crate::error::Result;
use crate::signing;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyPair {
    pub device_id: String,
    pub public_key: [u8; 32],
    #[serde(skip)]
    pub private_key: Box<[u8; 32]>,
}

impl DeviceKeyPair {
    pub fn generate(device_id: &str) -> Self {
        let signing_key = signing::generate_keypair();
        let public_key = signing_key.verifying_key().to_bytes();
        let private_key = Box::new(signing_key.to_bytes());
        Self {
            device_id: device_id.to_string(),
            public_key,
            private_key,
        }
    }

    pub fn from_bytes(device_id: &str, private_key_bytes: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key_bytes);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            device_id: device_id.to_string(),
            public_key,
            private_key: Box::new(private_key_bytes),
        }
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        signing::verifying_key_from_bytes(&self.public_key)
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.private_key)
    }
}

impl Drop for DeviceKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_keypair_generate() {
        let device = DeviceKeyPair::generate("device-01");
        assert_eq!(device.device_id, "device-01");
        assert_eq!(device.public_key.len(), 32);
        assert_eq!(device.private_key.len(), 32);
    }

    #[test]
    fn test_device_keypair_verifying_key() {
        let device = DeviceKeyPair::generate("device-01");
        let vk = device.verifying_key().unwrap();
        assert_eq!(vk.to_bytes(), device.public_key);
    }

    #[test]
    fn test_device_keypair_signing_key() {
        let device = DeviceKeyPair::generate("device-01");
        let sk = device.signing_key();
        assert_eq!(sk.verifying_key().to_bytes(), device.public_key);
    }

    #[test]
    fn test_device_keypair_sign_and_verify() {
        let device = DeviceKeyPair::generate("device-01");
        let sk = device.signing_key();
        let vk = device.verifying_key().unwrap();
        let msg = b"hello";
        let sig = signing::sign(&sk, msg);
        assert!(signing::verify(&vk, msg, &sig).is_ok());
    }

    #[test]
    fn test_device_keypair_unique_keys() {
        let d1 = DeviceKeyPair::generate("device-01");
        let d2 = DeviceKeyPair::generate("device-02");
        assert_ne!(d1.public_key, d2.public_key);
    }
}
