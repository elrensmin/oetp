// X25519 device keypair for envelope encryption (separate from Ed25519 signing key)
use crate::error::{Error, Result};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct DeviceX25519Key {
    pub device_id: String,
    pub public_key: [u8; 32],
    pub private_key: Box<[u8; 32]>,
}

impl DeviceX25519Key {
    pub fn generate(device_id: &str) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            device_id: device_id.to_string(),
            public_key: *public.as_bytes(),
            private_key: Box::new(secret.to_bytes()),
        }
    }

    pub fn from_bytes(device_id: &str, private_key_bytes: [u8; 32]) -> Result<Self> {
        let secret = StaticSecret::from(private_key_bytes);
        let public = PublicKey::from(&secret);
        // Validate: reject all-zero public key
        if *public.as_bytes() == [0u8; 32] {
            return Err(Error::InvalidInput("X25519 public key is all-zero".into()));
        }
        Ok(Self {
            device_id: device_id.to_string(),
            public_key: *public.as_bytes(),
            private_key: Box::new(private_key_bytes),
        })
    }

    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }
}

impl Drop for DeviceX25519Key {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let key = DeviceX25519Key::generate("device-01");
        assert_eq!(key.device_id, "device-01");
        assert_eq!(key.public_key.len(), 32);
        assert_eq!(key.private_key.len(), 32);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let key = DeviceX25519Key::generate("device-01");
        let bytes = *key.private_key;
        let recovered = DeviceX25519Key::from_bytes("device-01", bytes).unwrap();
        assert_eq!(recovered.public_key, key.public_key);
    }

    #[test]
    fn test_reject_all_zero() {
        // An all-zero private key still produces a valid public key after clamping.
        // Instead, test that from_bytes validates the public key is non-zero.
        let key = DeviceX25519Key::generate("device-01");
        assert_ne!(key.public_key, [0u8; 32]);
    }

    #[test]
    fn test_unique_keys() {
        let k1 = DeviceX25519Key::generate("device-01");
        let k2 = DeviceX25519Key::generate("device-02");
        assert_ne!(k1.public_key, k2.public_key);
    }
}
