// ledger configuration - loaded from env vars and CLI args
use oetp_core::error::Result;
use oetp_core::validation;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConfig {
    pub listen_addr: String,
    pub db_path: PathBuf,
    pub tenant_id: String,
    pub exam_id: String,
    pub signing_key_hex: String,
    pub anchor_rpc_url: String,
    pub api_key: String,
}

impl LedgerConfig {
    pub fn from_env() -> Result<Self> {
        let tenant_id = std::env::var("OETP_TENANT_ID").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_TENANT_ID required".into())
        })?;
        validation::validate_identifier("OETP_TENANT_ID", &tenant_id)?;

        let exam_id = std::env::var("OETP_EXAM_ID").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_EXAM_ID required".into())
        })?;
        validation::validate_identifier("OETP_EXAM_ID", &exam_id)?;

        let signing_key_hex = std::env::var("OETP_SIGNING_KEY").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_SIGNING_KEY required".into())
        })?;
        let mut _signing_key = [0u8; 32];
        validation::validate_hex_secret("OETP_SIGNING_KEY", &signing_key_hex, &mut _signing_key)?;

        let api_key = std::env::var("OETP_API_KEY").map_err(|_| {
            oetp_core::error::Error::InvalidInput("OETP_API_KEY required".into())
        })?;
        validation::validate_api_key(&api_key)?;

        Ok(Self {
            listen_addr: std::env::var("OETP_LEDGER_LISTEN_ADDR")
                .unwrap_or_else(|_| "0.0.0.0:8081".into()),
            db_path: std::env::var("OETP_LEDGER_DB_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/lib/oetp/ledger")),
            tenant_id,
            exam_id,
            signing_key_hex,
            anchor_rpc_url: std::env::var("OETP_ANCHOR_RPC_URL")
                .unwrap_or_else(|_| "http://localhost:8545".into()),
            api_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env() {
        temp_env::with_vars(
            [
                ("OETP_TENANT_ID", Some("nta")),
                ("OETP_EXAM_ID", Some("jee-2027")),
                ("OETP_SIGNING_KEY", Some("ab".repeat(32).as_str())),
                ("OETP_API_KEY", Some("test-api-key-12345678-with-enough-chars")),
            ],
            || {
                let config = LedgerConfig::from_env().unwrap();
                assert_eq!(config.tenant_id, "nta");
                assert_eq!(config.exam_id, "jee-2027");
                assert_eq!(config.listen_addr, "0.0.0.0:8081");
            },
        );
    }

    #[test]
    fn test_config_missing_tenant() {
        temp_env::with_vars(
            [
                ("OETP_EXAM_ID", Some("jee-2027")),
                ("OETP_SIGNING_KEY", Some("ab".repeat(32).as_str())),
                ("OETP_API_KEY", Some("test-api-key-12345678-with-enough-chars")),
            ],
            || {
                let err = LedgerConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("OETP_TENANT_ID"));
            },
        );
    }

    #[test]
    fn test_config_invalid_signing_key() {
        temp_env::with_vars(
            [
                ("OETP_TENANT_ID", Some("nta")),
                ("OETP_EXAM_ID", Some("jee-2027")),
                ("OETP_SIGNING_KEY", Some("tooshort")),
                ("OETP_API_KEY", Some("test-api-key-12345678-with-enough-chars")),
            ],
            || {
                let err = LedgerConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("OETP_SIGNING_KEY"));
            },
        );
    }

    #[test]
    fn test_config_invalid_api_key() {
        temp_env::with_vars(
            [
                ("OETP_TENANT_ID", Some("nta")),
                ("OETP_EXAM_ID", Some("jee-2027")),
                ("OETP_SIGNING_KEY", Some("ab".repeat(32).as_str())),
                ("OETP_API_KEY", Some("short")),
            ],
            || {
                let err = LedgerConfig::from_env().unwrap_err();
                assert!(err.to_string().contains("API key"));
            },
        );
    }
}
