// Ed25519 sign/verify - used by edge, ledger, and release tokens
use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

pub fn generate_keypair() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
    verifying_key
        .verify_strict(message, signature)
        .map_err(|_| Error::SignatureVerification)
}

pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).map_err(|e| Error::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let key = generate_keypair();
        let verifying = key.verifying_key();
        assert_eq!(verifying.as_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let key = generate_keypair();
        let msg = b"hola";
        let sig = sign(&key, msg);
        assert!(verify(&key.verifying_key(), msg, &sig).is_ok());
    }

    #[test]
    fn test_verify_wrong_message() {
        let key = generate_keypair();
        let sig = sign(&key, b"correct message");
        let result = verify(&key.verifying_key(), b"wrong message", &sig);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::SignatureVerification));
    }

    #[test]
    fn test_verify_wrong_key() {
        let key1 = generate_keypair();
        let key2 = generate_keypair();
        let msg = b"hello";
        let sig = sign(&key1, msg);
        let result = verify(&key2.verifying_key(), msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_verifying_key_from_bytes() {
        let key = generate_keypair();
        let vk = key.verifying_key();
        let bytes = vk.to_bytes();
        let recovered = verifying_key_from_bytes(&bytes).unwrap();
        assert_eq!(recovered, vk);
    }

    #[test]
    fn test_verify_tampered_signature() {
        let key = generate_keypair();
        let msg = b"hello";
        let mut sig = sign(&key, msg).to_bytes();
        sig[0] ^= 0x01; // flip one bit
        let tampered = Signature::from_bytes(&sig);
        let result = verify(&key.verifying_key(), msg, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_and_verify_empty_message() {
        let key = generate_keypair();
        let sig = sign(&key, b"");
        assert!(verify(&key.verifying_key(), b"", &sig).is_ok());
    }

    #[test]
    fn test_sign_and_verify_large_message() {
        let key = generate_keypair();
        let msg = &[0xab; 10_000];
        let sig = sign(&key, msg);
        assert!(verify(&key.verifying_key(), msg, &sig).is_ok());
    }
}
