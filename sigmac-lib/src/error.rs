use crate::prelude::parsing::LogParsingError;
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;
// use crossbeam_channel:

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    IoError(io::Error),
    #[error("Invalid configuration provided.")]
    ConfigurationError,
    #[error("{0}")]
    SigmaValueError(String),
    #[error("Regular expression {0} is invalid")]
    SigmaRegularExpressionError(String),
    #[error("Sigma rule identifier must be an UUID")]
    SigmaIdentifierError,
    #[error("Serde Error: {0}")]
    SerdeError(serde_yaml::Error),
    #[error("Could not convert into the specified target ({0}), since it is not supported.")]
    InvalidDestination(String),
    #[error("{0}")]
    GenericError(String),
}

pub type SiemResult<T> = Result<T, SiemError>;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[non_exhaustive]
pub enum SiemError {
    /// Io Error
    Io(String),
    /// Seriaization/Deserialization error
    Serialization(String),
    /// Error parsing a log
    Parsing(LogParsingError),
    /// Error indexing a log
    Indexing(String),
    /// Error accessing the storage system
    Storage(StorageError),
    /// A task execution failed
    Task(String),
    /// A command executed failed
    Command(CommandExecutionError),
    /// A component sufered an error during the startup process
    Configuration(String),
    Messaging(MessagingError),
    Other(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[non_exhaustive]
pub enum CommandExecutionError {
    Communication(String),
    Other(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[non_exhaustive]
pub enum StorageError {
    NotExists,
    ConnectionError,
    AlredyExists,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[non_exhaustive]
pub enum MessagingError {
    Disconnected,
    TimeoutReached,
    Full,
}

impl From<std::io::Error> for SiemError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<serde_json::Error> for SiemError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl<T> From<crossbeam_channel::TrySendError<T>> for SiemError {
    fn from(e: crossbeam_channel::TrySendError<T>) -> Self {
        match e {
            crossbeam_channel::TrySendError::Full(_) => Self::Messaging(MessagingError::Full),
            crossbeam_channel::TrySendError::Disconnected(_) => {
                Self::Messaging(MessagingError::Disconnected)
            }
        }
    }
}
impl<T> From<crossbeam_channel::SendError<T>> for SiemError {
    fn from(_e: crossbeam_channel::SendError<T>) -> Self {
        Self::Messaging(MessagingError::Disconnected)
    }
}
impl<T> From<crossbeam_channel::SendTimeoutError<T>> for SiemError {
    fn from(e: crossbeam_channel::SendTimeoutError<T>) -> Self {
        match e {
            crossbeam_channel::SendTimeoutError::Timeout(_) => {
                Self::Messaging(MessagingError::TimeoutReached)
            }
            crossbeam_channel::SendTimeoutError::Disconnected(_) => {
                Self::Messaging(MessagingError::Disconnected)
            }
        }
    }
}
