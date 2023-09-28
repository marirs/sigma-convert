use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    IoError(io::Error),
    #[error("Invalid configuration provided.")]
    ConfigurationError,
    #[error("{0}")]
    GenericError(String),
}
