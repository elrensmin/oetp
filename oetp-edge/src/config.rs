// edge daemon configuration - loaded from env vars and key files
use oetp_core::device::DeviceKeyPair;
use oetp_core::device_x25519::DeviceX25519Key;
use oetp_core::error::Result;
use oetp_core::validation;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeConfig {
    pub device_id: String,
    pub center_id: String,
    pub tenant_id: String,
    pub exam_id: String,
    pub ledger_url: String,
    pub beacon_url: String,
    pub listen_addr: String,
    pub cache_dir: PathBuf,
    pub queue_dir: PathBuf,
    pub device_key_path: PathBuf,
    pub device_x25519_key_path: PathBuf,
    pub beacon_public_key: [u8; 32],
    pub exam_salt: [u8; 32],
    pub server_pepper: [u8; 32],
    pub api_key: String,
    pub exam_window_start: u64,
    pub exam_window_end: u64,
}

impl EdgeConfig {
    pub fn from_env() -> Result<Self> {
        let device_id = std::env::var("OETP_DEVICE_ID").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_DEVICE_ID required".into())
        })?;
        validation::validate_identifier("OETP_DEVICE_ID", &device_id)?;

        let center_id = std::env::var("OETP_CENTER_ID").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_CENTER_ID required".into())
        })?;
        validation::validate_identifier("OETP_CENTER_ID", &center_id)?;

        let tenant_id = std::env::var("OETP_TENANT_ID").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_TENANT_ID required".into())
        })?;
        validation::validate_identifier("OETP_TENANT_ID", &tenant_id)?;

        let exam_id = std::env::var("OETP_EXAM_ID").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_EXAM_ID required".into())
        })?;
        validation::validate_identifier("OETP_EXAM_ID", &exam_id)?;

        let mut beacon_pk = [0u8; 32];
        let beacon_hex = std::env::var("OETP_BEACON_PUBLIC_KEY").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_BEACON_PUBLIC_KEY required".into())
        })?;
        validation::validate_hex_secret("OETP_BEACON_PUBLIC_KEY", &beacon_hex, &mut beacon_pk)?;

        let mut exam_salt = [0u8; 32];
        let salt_hex = std::env::var("OETP_EXAM_SALT").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_EXAM_SALT required (32-byte hex)".into())
        })?;
        validation::validate_hex_secret("OETP_EXAM_SALT", &salt_hex, &mut exam_salt)?;

        let mut server_pepper = [0u8; 32];
        let pepper_hex = std::env::var("OETP_SERVER_PEPPER").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_SERVER_PEPPER required (32-byte hex)".into())
        })?;
        validation::validate_hex_secret("OETP_SERVER_PEPPER", &pepper_hex, &mut server_pepper)?;

        let api_key = std::env::var("OETP_API_KEY").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_API_KEY required".into())
        })?;
        validation::validate_api_key(&api_key)?;

        let exam_window_start: u64 = std::env::var("OETP_EXAM_WINDOW_START")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let exam_window_end: u64 = std::env::var("OETP_EXAM_WINDOW_END")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(u64::MAX);
        validation::validate_exam_window(exam_window_start, exam_window_end)?;

        Ok(Self {
            device_id,
            center_id,
            tenant_id,
            exam_id,
            ledger_url: std::env::var("OETP_LEDGER_URL")
                .unwrap_or_else(|_| "http://localhost:8081".into()),
            beacon_url: std::env::var("OETP_BEACON_URL")
                .unwrap_or_else(|_| "http://localhost:9090".into()),
            listen_addr: std::env::var("OETP_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".into()),
            cache_dir: std::env::var("OETP_CACHE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/cache/oetp")),
            queue_dir: std::env::var("OETP_QUEUE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/spool/oetp")),
            device_key_path: std::env::var("OETP_DEVICE_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/oetp/device.key")),
            device_x25519_key_path: std::env::var("OETP_DEVICE_X25519_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/oetp/device_x25519.key")),
            beacon_public_key: beacon_pk,
            exam_salt,
            server_pepper,
            api_key,
            exam_window_start,
            exam_window_end,
        })
    }

    pub fn load_device_key(&self) -> Result<DeviceKeyPair> {
        let metadata = std::fs::metadata(&self.device_key_path).map_err(|e| {
            oetp_core::error::Error::Io(e)
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(oetp_core::error::Error::InvalidInput(
                    "device key file permissions too permissive; expected 0600".into(),
                ));
            }
        }
        let bytes =
            std::fs::read(&self.device_key_path).map_err(oetp_core::error::Error::Io)?;
        let hex_str = String::from_utf8(bytes).map_err(|_| {
            oetp_core::error::Error::InvalidInput("device key not valid UTF-8".into())
        })?;
        let trimmed = hex_str.trim();
        let mut key_bytes = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut key_bytes).map_err(|_| {
            oetp_core::error::Error::InvalidInput("device key not valid hex".into())
        })?;
        Ok(DeviceKeyPair::from_bytes(&self.device_id, key_bytes))
    }

    pub fn load_device_x25519_key(&self) -> Result<DeviceX25519Key> {
        let metadata = std::fs::metadata(&self.device_x25519_key_path).map_err(|e| {
            oetp_core::error::Error::Io(e)
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(oetp_core::error::Error::InvalidInput(
                    "device X25519 key file permissions too permissive; expected 0600".into(),
                ));
            }
        }
        let bytes =
            std::fs::read(&self.device_x25519_key_path).map_err(oetp_core::error::Error::Io)?;
        let hex_str = String::from_utf8(bytes).map_err(|_| {
            oetp_core::error::Error::InvalidInput("device X25519 key not valid UTF-8".into())
        })?;
        let trimmed = hex_str.trim();
        let mut key_bytes = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut key_bytes).map_err(|_| {
            oetp_core::error::Error::InvalidInput("device X25519 key not valid hex".into())
        })?;
        DeviceX25519Key::from_bytes(&self.device_id, key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env_defaults() {
        temp_env::with_vars(
            [
                ("OETP_TENANT_ID", Some("nta")),
                ("OETP_EXAM_ID", Some("jee-2027")),
                ("OETP_DEVICE_ID", Some("device-01")),
                ("OETP_CENTER_ID", Some("center-01")),
                ("OETP_BEACON_PUBLIC_KEY", Some("abababababababababababababababababababababababababababababababab")),
                ("OETP_API_KEY", Some("test-api-key-12345678-with-enough-chars")),
                ("OETP_SERVER_PEPPER", Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
                ("OETP_EXAM_SALT", Some("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")),
            ],
            || {
                let config = EdgeConfig::from_env().unwrap();
                assert_eq!(config.tenant_id, "nta");
                assert_eq!(config.exam_id, "jee-2027");
                assert_eq!(config.listen_addr, "127.0.0.1:8080");
            },
        );
    }

    #[test]
    fn test_config_missing_tenant() {
        temp_env::with_vars(
            [
                ("OETP_DEVICE_ID", Some("device-01")),
                ("OETP_CENTER_ID", Some("center-01")),
                ("OETP_BEACON_PUBLIC_KEY", Some("abababababababababababababababababababababababababababababababab")),
                ("OETP_API_KEY", Some("test-api-key-12345678-with-enough-chars")),
                ("OETP_SERVER_PEPPER", Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
                ("OETP_EXAM_SALT", Some("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")),
            ],
            || {
                let err = EdgeConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("OETP_TENANT_ID"));
            },
        );
    }

    #[test]
    fn test_config_invalid_exam_id() {
        temp_env::with_vars(
            [
                ("OETP_TENANT_ID", Some("nta")),
                ("OETP_EXAM_ID", Some("jee.2027")),
                ("OETP_DEVICE_ID", Some("device-01")),
                ("OETP_CENTER_ID", Some("center-01")),
                ("OETP_BEACON_PUBLIC_KEY", Some("abababababababababababababababababababababababababababababababab")),
                ("OETP_API_KEY", Some("test-api-key-12345678-with-enough-chars")),
                ("OETP_SERVER_PEPPER", Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
                ("OETP_EXAM_SALT", Some("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")),
            ],
            || {
                let err = EdgeConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("OETP_EXAM_ID"));
            },
        );
    }

    #[test]
    fn test_config_invalid_api_key() {
        temp_env::with_vars(
            [
                ("OETP_TENANT_ID", Some("nta")),
                ("OETP_EXAM_ID", Some("jee-2027")),
                ("OETP_DEVICE_ID", Some("device-01")),
                ("OETP_CENTER_ID", Some("center-01")),
                ("OETP_BEACON_PUBLIC_KEY", Some("abababababababababababababababababababababababababababababababab")),
                ("OETP_API_KEY", Some("short")),
                ("OETP_SERVER_PEPPER", Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
                ("OETP_EXAM_SALT", Some("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")),
            ],
            || {
                let err = EdgeConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("API key"));
            },
        );
    }
}
