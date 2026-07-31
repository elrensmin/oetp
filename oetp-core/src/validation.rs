// Shared input validation and identifier rules used across edge/ledger/beacon.

use crate::error::{Error, Result};
use regex::Regex;

/// Maximum length for any free-form identifier string.
const MAX_ID_LEN: usize = 64;

/// Identifier characters allowed: alphanumeric, hyphen, underscore.
const ID_PATTERN: &str = r"^[A-Za-z0-9_-]+$";

/// Validates a string identifier (tenant_id, exam_id, device_id, center_id, etc.).
pub fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidInput(format!("{} is required", name)));
    }
    if value.len() > MAX_ID_LEN {
        return Err(Error::InvalidInput(format!(
            "{} exceeds {} characters",
            name, MAX_ID_LEN
        )));
    }
    let re = Regex::new(ID_PATTERN).expect("static regex is valid");
    if !re.is_match(value) {
        return Err(Error::InvalidInput(format!(
            "{} contains invalid characters (allowed: A-Z a-z 0-9 _ -)",
            name
        )));
    }
    Ok(())
}

/// Validates an API key: must be at least 32 characters and printable ASCII only.
pub fn validate_api_key(value: &str) -> Result<()> {
    if value.len() < 32 {
        return Err(Error::InvalidInput(
            "API key must be at least 32 characters".into(),
        ));
    }
    if !value.is_ascii() || value.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::InvalidInput(
            "API key must be printable ASCII".into(),
        ));
    }
    Ok(())
}

/// Validates a 32-byte hex secret and decodes it into the provided buffer.
pub fn validate_hex_secret(name: &str, hex_str: &str, out: &mut [u8; 32]) -> Result<()> {
    let trimmed = hex_str.trim();
    if trimmed.len() != 64 {
        return Err(Error::InvalidInput(format!(
            "{} must be exactly 64 hex characters (32 bytes)",
            name
        )));
    }
    hex::decode_to_slice(trimmed, out).map_err(|_| {
        Error::InvalidInput(format!("{} is not valid 32-byte hex", name))
    })
}

/// Validates an exam window.
pub fn validate_exam_window(start: u64, end: u64) -> Result<()> {
    if start == 0 && end == u64::MAX {
        // Allow unrestricted windows only in dev/test contexts when explicitly set.
        return Ok(());
    }
    if end <= start {
        return Err(Error::InvalidInput(
            "exam_window_end must be greater than exam_window_start".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_identifier() {
        validate_identifier("tenant_id", "nta").unwrap();
        validate_identifier("exam_id", "jee-2027").unwrap();
        validate_identifier("device_id", "device_01").unwrap();
    }

    #[test]
    fn test_empty_identifier() {
        assert!(validate_identifier("tenant_id", "")
            .unwrap_err()
            .to_string()
            .contains("tenant_id is required"));
    }

    #[test]
    fn test_too_long_identifier() {
        let long = "a".repeat(65);
        assert!(validate_identifier("tenant_id", &long)
            .unwrap_err()
            .to_string()
            .contains("exceeds"));
    }

    #[test]
    fn test_invalid_chars_identifier() {
        assert!(validate_identifier("exam_id", "jee.2027")
            .unwrap_err()
            .to_string()
            .contains("invalid characters"));
    }

    #[test]
    fn test_api_key_validation() {
        validate_api_key("this-is-a-long-api-key-with-more-than-32-chars").unwrap();
        assert!(validate_api_key("short")
            .unwrap_err()
            .to_string()
            .contains("32 characters"));
    }

    #[test]
    fn test_hex_secret_validation() {
        let mut out = [0u8; 32];
        let hex = "ab".repeat(32);
        validate_hex_secret("signing_key", &hex, &mut out).unwrap();
        assert_eq!(out, [0xab; 32]);

        assert!(validate_hex_secret("signing_key", "0102", &mut out)
            .unwrap_err()
            .to_string()
            .contains("64 hex"));
    }

    #[test]
    fn test_exam_window_validation() {
        validate_exam_window(1000, 2000).unwrap();
        assert!(validate_exam_window(2000, 1000)
            .unwrap_err()
            .to_string()
            .contains("exam_window_end"));
    }
}
