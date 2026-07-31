// center beacon issues a time-bound signed token for JIT decryption
use crate::clock;
use crate::error::{Error, Result};
use crate::signing;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseToken {
    pub center_id: String,
    pub exam_id: String,
    pub device_id: String,
    pub window_start: u64,
    pub window_end: u64,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

impl ReleaseToken {
    pub fn new(
        center_id: &str,
        exam_id: &str,
        device_id: &str,
        window_start: u64,
        window_end: u64,
        signing_key: &SigningKey,
    ) -> Self {
        let nonce = {
            let mut n = [0u8; 16];
            getrandom::getrandom(&mut n).expect("getrandom failed");
            n
        };
        let mut token = Self {
            center_id: center_id.to_string(),
            exam_id: exam_id.to_string(),
            device_id: device_id.to_string(),
            window_start,
            window_end,
            nonce,
            signature: Vec::new(),
        };
        token.sign(signing_key);
        token
    }

    fn payload_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.center_id.as_bytes());
        bytes.extend_from_slice(self.exam_id.as_bytes());
        bytes.extend_from_slice(self.device_id.as_bytes());
        bytes.extend_from_slice(&self.window_start.to_be_bytes());
        bytes.extend_from_slice(&self.window_end.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes
    }

    fn sign(&mut self, signing_key: &SigningKey) {
        let sig = signing::sign(signing_key, &self.payload_bytes());
        self.signature = sig.to_bytes().to_vec();
    }

    pub fn verify(
        &self,
        center_verifying_key: &VerifyingKey,
        current_timestamp: u64,
    ) -> Result<()> {
        if self.center_id.is_empty() {
            return Err(Error::ReleaseTokenInvalid("center_id is empty".into()));
        }
        if self.exam_id.is_empty() {
            return Err(Error::ReleaseTokenInvalid("exam_id is empty".into()));
        }
        if self.device_id.is_empty() {
            return Err(Error::ReleaseTokenInvalid("device_id is empty".into()));
        }
        if self.window_start >= self.window_end {
            return Err(Error::ReleaseTokenInvalid(
                "window_start must be before window_end".into(),
            ));
        }
        // Enforce maximum token lifetime (5 minutes)
        if self.window_end - self.window_start > 300 {
            return Err(Error::ReleaseTokenInvalid(
                "token window exceeds maximum lifetime (300s)".into(),
            ));
        }
        if current_timestamp < self.window_start {
            return Err(Error::ReleaseTokenInvalid("token not yet valid".into()));
        }
        if current_timestamp > self.window_end {
            return Err(Error::ReleaseTokenInvalid("token has expired".into()));
        }

        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| Error::ReleaseTokenInvalid("invalid signature bytes".into()))?;

        signing::verify(center_verifying_key, &self.payload_bytes(), &sig)
            .map_err(|_| Error::ReleaseTokenInvalid("signature does not match".into()))
    }
}

pub fn current_timestamp_secs() -> u64 {
    clock::current_timestamp_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing;

    fn sample_token(signing_key: &SigningKey) -> ReleaseToken {
        ReleaseToken::new(
            "center-01",
            "jee-2027",
            "device-01",
            1000,
            1300,
            signing_key,
        )
    }

    #[test]
    fn test_release_token_new() {
        let key = signing::generate_keypair();
        let token = sample_token(&key);
        assert_eq!(token.center_id, "center-01");
        assert_eq!(token.exam_id, "jee-2027");
        assert_eq!(token.window_start, 1000);
        assert_eq!(token.window_end, 1300);
        assert!(!token.signature.is_empty());
    }

    #[test]
    fn test_release_token_verify_valid() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let token = sample_token(&key);
        assert!(token.verify(&vk, 1150).is_ok());
    }

    #[test]
    fn test_release_token_verify_before_window() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let token = sample_token(&key);
        let result = token.verify(&vk, 500);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::ReleaseTokenInvalid(_)));
    }

    #[test]
    fn test_release_token_verify_after_window() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let token = sample_token(&key);
        let result = token.verify(&vk, 3000);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_token_verify_wrong_key() {
        let key1 = signing::generate_keypair();
        let key2 = signing::generate_keypair();
        let vk2 = key2.verifying_key();
        let token = sample_token(&key1);
        let result = token.verify(&vk2, 1500);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_token_verify_tampered_center_id() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let mut token = sample_token(&key);
        token.center_id = "center-02".into();
        let result = token.verify(&vk, 1500);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_token_verify_tampered_nonce() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let mut token = sample_token(&key);
        token.nonce[0] ^= 0xff;
        let result = token.verify(&vk, 1500);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_token_empty_center_id() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let token = ReleaseToken::new("", "jee-2027", "device-01", 1000, 2000, &key);
        let result = token.verify(&vk, 1500);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_token_invalid_window() {
        let key = signing::generate_keypair();
        let vk = key.verifying_key();
        let token = ReleaseToken::new("center-01", "jee-2027", "device-01", 2000, 1000, &key);
        let result = token.verify(&vk, 1500);
        assert!(result.is_err());
    }

    #[test]
    fn test_release_token_different_nonces() {
        let key = signing::generate_keypair();
        let t1 = sample_token(&key);
        let t2 = sample_token(&key);
        assert_ne!(t1.nonce, t2.nonce);
    }

    #[test]
    fn test_current_timestamp_secs() {
        let ts = current_timestamp_secs();
        // should be around year 2026+
        assert!(ts > 1_700_000_000);
    }
}
