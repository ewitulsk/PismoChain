//! Error types for the event client

use thiserror::Error;

/// Errors that can occur when using the event client
#[derive(Error, Debug)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),
}

/// Result type alias for event client operations
pub type Result<T> = std::result::Result<T, Error>;
