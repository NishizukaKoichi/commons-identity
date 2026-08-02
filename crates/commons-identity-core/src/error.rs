use thiserror::Error;

/// Errors returned by the portable Commons Identity core.
#[derive(Debug, Error)]
pub enum CommonsError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("credential verification failed: {0}")]
    Credential(String),
    #[error("presentation verification failed: {0}")]
    Presentation(String),
    #[error("recovery operation failed: {0}")]
    Recovery(String),
    #[error("archive format is unsupported: {0}")]
    UnsupportedFormat(String),
    #[error("record was not found: {0}")]
    NotFound(String),
    #[error("storage operation failed: {0}")]
    Storage(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("operation is not authorized: {0}")]
    Unauthorized(String),
    #[error("request has already been consumed")]
    Replay,
}

pub type Result<T> = std::result::Result<T, CommonsError>;

impl From<serde_json::Error> for CommonsError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<rusqlite::Error> for CommonsError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value.to_string())
    }
}
