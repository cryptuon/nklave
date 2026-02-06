//! Authentication middleware for the API
//!
//! Supports multiple authentication modes:
//! - None: No authentication (development only)
//! - BearerToken: Static bearer token(s)
//! - MtlsOnly: Client certificate required
//! - BearerOrMtls: Either method accepted

use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

/// Authentication mode configuration
#[derive(Debug, Clone)]
pub enum AuthMode {
    /// No authentication required (development only)
    None,

    /// Bearer token authentication with one or more valid tokens
    BearerToken {
        /// Valid bearer tokens (compared securely)
        tokens: Vec<String>,
    },

    /// mTLS client certificate required
    /// Note: Certificate extraction happens at TLS layer
    MtlsOnly,

    /// Either bearer token or mTLS client certificate
    BearerOrMtls {
        /// Valid bearer tokens
        tokens: Vec<String>,
    },
}

impl Default for AuthMode {
    fn default() -> Self {
        AuthMode::None
    }
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Authentication mode
    pub mode: AuthMode,

    /// Paths that don't require authentication (e.g., health checks)
    pub unauthenticated_paths: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::None,
            unauthenticated_paths: vec![
                "/upcheck".to_string(),
                "/livez".to_string(),
                "/readyz".to_string(),
                "/health".to_string(),
            ],
        }
    }
}

impl AuthConfig {
    /// Create a new AuthConfig with bearer token authentication
    pub fn with_bearer_tokens(tokens: Vec<String>) -> Self {
        Self {
            mode: AuthMode::BearerToken { tokens },
            unauthenticated_paths: vec![
                "/upcheck".to_string(),
                "/livez".to_string(),
                "/readyz".to_string(),
                "/health".to_string(),
            ],
        }
    }

    /// Create a new AuthConfig with mTLS only
    pub fn with_mtls_only() -> Self {
        Self {
            mode: AuthMode::MtlsOnly,
            unauthenticated_paths: vec![
                "/upcheck".to_string(),
                "/livez".to_string(),
                "/readyz".to_string(),
                "/health".to_string(),
            ],
        }
    }

    /// Check if a path is exempt from authentication
    pub fn is_unauthenticated_path(&self, path: &str) -> bool {
        self.unauthenticated_paths.iter().any(|p| path == p || path.starts_with(&format!("{}?", p)))
    }
}

/// Authentication error response
#[derive(Debug)]
pub struct AuthError {
    pub status: StatusCode,
    pub message: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.message
        });
        (self.status, axum::Json(body)).into_response()
    }
}

/// Shared authentication state
#[derive(Clone)]
pub struct AuthState {
    pub config: Arc<AuthConfig>,
}

impl AuthState {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

/// Authentication middleware
///
/// Validates requests based on the configured authentication mode.
pub async fn auth_middleware(
    axum::extract::State(auth_state): axum::extract::State<AuthState>,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let path = request.uri().path();

    // Check if path is exempt from authentication
    if auth_state.config.is_unauthenticated_path(path) {
        return Ok(next.run(request).await);
    }

    // Perform authentication based on mode
    match &auth_state.config.mode {
        AuthMode::None => {
            // No authentication required
            Ok(next.run(request).await)
        }

        AuthMode::BearerToken { tokens } => {
            validate_bearer_token(&request, tokens)?;
            Ok(next.run(request).await)
        }

        AuthMode::MtlsOnly => {
            // mTLS validation happens at TLS layer
            // Here we just check if client cert info is present
            validate_mtls(&request)?;
            Ok(next.run(request).await)
        }

        AuthMode::BearerOrMtls { tokens } => {
            // Try bearer token first, then mTLS
            if validate_bearer_token(&request, tokens).is_ok() {
                return Ok(next.run(request).await);
            }

            if validate_mtls(&request).is_ok() {
                return Ok(next.run(request).await);
            }

            Err(AuthError {
                status: StatusCode::UNAUTHORIZED,
                message: "Authentication required: provide Bearer token or client certificate".to_string(),
            })
        }
    }
}

/// Validate bearer token from Authorization header
fn validate_bearer_token(request: &Request, valid_tokens: &[String]) -> Result<(), AuthError> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(auth_value) = auth_header else {
        return Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            message: "Missing Authorization header".to_string(),
        });
    };

    // Extract bearer token
    let token = if auth_value.to_lowercase().starts_with("bearer ") {
        &auth_value[7..]
    } else {
        return Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            message: "Invalid Authorization header format, expected 'Bearer <token>'".to_string(),
        });
    };

    // Constant-time comparison to prevent timing attacks
    let is_valid = valid_tokens.iter().any(|valid| constant_time_compare(token, valid));

    if is_valid {
        Ok(())
    } else {
        Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            message: "Invalid bearer token".to_string(),
        })
    }
}

/// Validate mTLS client certificate
fn validate_mtls(request: &Request) -> Result<(), AuthError> {
    // Check for client certificate info in request extensions
    // This is set by the TLS layer when client certificates are presented
    // For now, we check for a custom header that could be set by a reverse proxy
    // In production, this would be extracted from the TLS connection

    let has_client_cert = request
        .headers()
        .get("X-Client-Cert-DN")
        .is_some();

    // Also check request extensions for rustls client cert
    // This would be populated by axum-server with rustls
    let has_tls_client_cert = request.extensions().get::<ClientCertInfo>().is_some();

    if has_client_cert || has_tls_client_cert {
        Ok(())
    } else {
        Err(AuthError {
            status: StatusCode::UNAUTHORIZED,
            message: "Client certificate required".to_string(),
        })
    }
}

/// Client certificate information extracted from TLS connection
#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    /// Distinguished Name from client certificate
    pub dn: String,
    /// Common Name from client certificate
    pub cn: Option<String>,
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut result = 0u8;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("secret", "secret"));
        assert!(!constant_time_compare("secret", "secre"));
        assert!(!constant_time_compare("secret", "SECRET"));
        assert!(!constant_time_compare("secret", "other1"));
    }

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();
        assert!(matches!(config.mode, AuthMode::None));
        assert!(config.is_unauthenticated_path("/upcheck"));
        assert!(config.is_unauthenticated_path("/livez"));
        assert!(config.is_unauthenticated_path("/health"));
        assert!(!config.is_unauthenticated_path("/reload"));
    }

    #[test]
    fn test_auth_config_with_bearer() {
        let config = AuthConfig::with_bearer_tokens(vec!["token123".to_string()]);
        assert!(matches!(config.mode, AuthMode::BearerToken { .. }));
    }

    #[test]
    fn test_unauthenticated_path_with_query() {
        let config = AuthConfig::default();
        assert!(config.is_unauthenticated_path("/health"));
        assert!(config.is_unauthenticated_path("/health?foo=bar"));
    }
}
