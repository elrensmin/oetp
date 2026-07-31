// shared error types used by every module in the pipeline
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("signature verification failed")]
    SignatureVerification,

    #[error("tenant not found: {0}")]
    TenantNotFound(String),

    #[error("exam not found: {0}")]
    ExamNotFound(String),

    #[error("packet decryption failed")]
    PacketDecryption,

    #[error("release token invalid: {0}")]
    ReleaseTokenInvalid(String),

    #[error("memory operation failed: {0}")]
    Memory(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("anchor error: {0}")]
    Anchor(String),

    #[error("offline queue error: {0}")]
    OfflineQueue(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[test]
    fn test_error_display() {
        let err = Error::Crypto("bad key".into());
        assert!(!err.to_string().is_empty());
        assert!(err.to_string().contains("bad key"));
    }

    #[test]
    fn test_error_debug() {
        let err = Error::SignatureVerification;
        let debug = format!("{:?}", err);
        assert!(debug.contains("SignatureVerification"));
    }

    #[test]
    fn test_error_is_std_error() {
        let err = Error::InvalidInput("x".into());
        let std_err: &dyn StdError = &err;
        assert!(std_err.source().is_none());
    }

    #[test]
    fn test_error_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn test_result_type_alias() {
        let ok: Result<i32> = Ok(42);
        assert_eq!(*ok.as_ref().unwrap(), 42);

        let err: Result<i32> = Err(Error::Crypto("fail".into()));
        assert!(err.is_err());
    }
}
