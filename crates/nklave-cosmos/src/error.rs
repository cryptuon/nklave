//! Error types for Cosmos protocol handling

use thiserror::Error;

/// Errors that can occur during Cosmos protocol handling
#[derive(Debug, Error)]
pub enum CosmosError {
    /// Chain ID mismatch
    #[error("Chain ID mismatch: expected '{expected}', got '{actual}'")]
    ChainIdMismatch { expected: String, actual: String },

    /// Validator not found for the given public key
    #[error("Validator not found: {pubkey_hex}")]
    ValidatorNotFound { pubkey_hex: String },

    /// Double signing attempt detected
    #[error("Double signing attempt at height {height}, round {round}")]
    DoubleSigning { height: i64, round: i32 },

    /// Invalid vote type
    #[error("Invalid vote type: {0}")]
    InvalidVoteType(i32),

    /// Invalid block ID
    #[error("Invalid block ID: {0}")]
    InvalidBlockId(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    /// Server bind error
    #[error("Failed to bind server: {0}")]
    BindError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Service not available
    #[error("Service not available")]
    ServiceUnavailable,
}

impl From<CosmosError> for tonic::Status {
    fn from(err: CosmosError) -> Self {
        match err {
            CosmosError::ChainIdMismatch { .. } => {
                tonic::Status::invalid_argument(err.to_string())
            }
            CosmosError::ValidatorNotFound { .. } => {
                tonic::Status::not_found(err.to_string())
            }
            CosmosError::DoubleSigning { .. } => {
                tonic::Status::failed_precondition(err.to_string())
            }
            CosmosError::InvalidVoteType(_) | CosmosError::InvalidBlockId(_) => {
                tonic::Status::invalid_argument(err.to_string())
            }
            CosmosError::MissingField(_) => {
                tonic::Status::invalid_argument(err.to_string())
            }
            CosmosError::SigningFailed(_) => {
                tonic::Status::internal(err.to_string())
            }
            CosmosError::ServiceUnavailable => {
                tonic::Status::unavailable(err.to_string())
            }
            CosmosError::BindError(_) | CosmosError::Internal(_) => {
                tonic::Status::internal(err.to_string())
            }
        }
    }
}

/// Remote signer error codes (matching Tendermint's error codes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RemoteSignerCode {
    /// Unknown error
    Unknown = 0,
    /// Double sign attempt
    DoubleSign = 1,
    /// Height regression (not used in our implementation)
    HeightRegression = 2,
    /// Not found
    NotFound = 3,
    /// Connection error
    Connection = 4,
    /// Not implemented
    NotImplemented = 5,
}

impl From<RemoteSignerCode> for i32 {
    fn from(code: RemoteSignerCode) -> Self {
        code as i32
    }
}
