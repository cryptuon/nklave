//! API error handling

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use nklave_core::{RefusalCode, SigningServiceError};

use crate::types::ErrorResponse;

/// API error type
#[derive(Debug)]
pub enum ApiError {
    /// Slashing protection triggered
    SlashingProtection(RefusalCode),
    /// Validator not found
    ValidatorNotFound(String),
    /// Invalid request
    InvalidRequest(String),
    /// Genesis validators root mismatch
    GenesisRootMismatch(String),
    /// Internal error
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::SlashingProtection(code) => {
                (StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::PRECONDITION_FAILED), code.message().to_string())
            }
            ApiError::ValidatorNotFound(pubkey) => {
                (StatusCode::NOT_FOUND, format!("Key not found: {}", pubkey))
            }
            ApiError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::GenesisRootMismatch(root) => {
                (StatusCode::PRECONDITION_FAILED, format!("Genesis validators root mismatch: {}", root))
            }
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(ErrorResponse { error: message });
        (status, body).into_response()
    }
}

impl From<RefusalCode> for ApiError {
    fn from(code: RefusalCode) -> Self {
        match code {
            RefusalCode::UnknownValidator => {
                ApiError::ValidatorNotFound("unknown".to_string())
            }
            RefusalCode::InvalidRequest => {
                ApiError::InvalidRequest("Invalid signing request".to_string())
            }
            RefusalCode::InternalError => {
                ApiError::Internal("Internal error".to_string())
            }
            _ => ApiError::SlashingProtection(code),
        }
    }
}

impl From<SigningServiceError> for ApiError {
    fn from(err: SigningServiceError) -> Self {
        match err {
            SigningServiceError::UnknownValidator(pubkey) => {
                ApiError::ValidatorNotFound(format!("0x{}", hex::encode(pubkey)))
            }
            SigningServiceError::SlashingProtection(code) => {
                ApiError::SlashingProtection(code)
            }
            SigningServiceError::GenesisRootMismatch { expected, actual } => {
                ApiError::GenesisRootMismatch(format!(
                    "expected 0x{}, got 0x{}",
                    hex::encode(expected),
                    hex::encode(actual)
                ))
            }
            SigningServiceError::Integrity(e) => {
                ApiError::Internal(format!("State integrity error: {}", e))
            }
            SigningServiceError::InvalidSigningRoot(msg) => {
                ApiError::InvalidRequest(format!("Invalid signing root: {}", msg))
            }
        }
    }
}
