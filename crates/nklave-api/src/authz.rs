//! Authorization layer for the API
//!
//! Defines permission levels and endpoint-to-permission mappings.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::sync::Arc;

/// Permission levels for API access
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read-only access: health checks, public keys list, status
    Read,

    /// Signing access: can sign messages
    Sign,

    /// Admin access: reload keys, create checkpoints, view state
    Admin,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Read => write!(f, "read"),
            Permission::Sign => write!(f, "sign"),
            Permission::Admin => write!(f, "admin"),
        }
    }
}

/// Role definition with a set of permissions
#[derive(Debug, Clone)]
pub struct Role {
    /// Role name
    pub name: String,
    /// Permissions granted to this role
    pub permissions: Vec<Permission>,
}

impl Role {
    /// Create a new role with the given permissions
    pub fn new(name: impl Into<String>, permissions: Vec<Permission>) -> Self {
        Self {
            name: name.into(),
            permissions,
        }
    }

    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Predefined read-only role
    pub fn read_only() -> Self {
        Self::new("read_only", vec![Permission::Read])
    }

    /// Predefined signer role (read + sign)
    pub fn signer() -> Self {
        Self::new("signer", vec![Permission::Read, Permission::Sign])
    }

    /// Predefined admin role (all permissions)
    pub fn admin() -> Self {
        Self::new("admin", vec![Permission::Read, Permission::Sign, Permission::Admin])
    }
}

/// Authorization configuration
#[derive(Debug, Clone)]
pub struct AuthzConfig {
    /// Endpoint to required permission mapping
    endpoint_permissions: HashMap<String, Permission>,

    /// Default permission for unknown endpoints
    default_permission: Permission,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        let mut endpoint_permissions = HashMap::new();

        // Read endpoints
        endpoint_permissions.insert("/upcheck".to_string(), Permission::Read);
        endpoint_permissions.insert("/health".to_string(), Permission::Read);
        endpoint_permissions.insert("/livez".to_string(), Permission::Read);
        endpoint_permissions.insert("/readyz".to_string(), Permission::Read);
        endpoint_permissions.insert("/status".to_string(), Permission::Read);
        endpoint_permissions.insert("/api/v1/eth2/publicKeys".to_string(), Permission::Read);

        // Admin endpoints
        endpoint_permissions.insert("/reload".to_string(), Permission::Admin);
        endpoint_permissions.insert("/admin/state".to_string(), Permission::Admin);
        endpoint_permissions.insert("/admin/checkpoint".to_string(), Permission::Admin);

        // Sign endpoints are handled by prefix matching

        Self {
            endpoint_permissions,
            default_permission: Permission::Sign, // Default to sign for unknown endpoints
        }
    }
}

impl AuthzConfig {
    /// Get the required permission for an endpoint
    pub fn required_permission(&self, path: &str) -> Permission {
        // Check exact match first
        if let Some(perm) = self.endpoint_permissions.get(path) {
            return *perm;
        }

        // Check for signing endpoints
        if path.starts_with("/api/v1/eth2/sign/") {
            return Permission::Sign;
        }

        // Return default
        self.default_permission
    }

    /// Add a custom endpoint permission
    pub fn add_permission(&mut self, path: impl Into<String>, permission: Permission) {
        self.endpoint_permissions.insert(path.into(), permission);
    }
}

/// Authorization error response
#[derive(Debug)]
pub struct AuthzError {
    pub status: StatusCode,
    pub message: String,
}

impl IntoResponse for AuthzError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.message
        });
        (self.status, axum::Json(body)).into_response()
    }
}

/// Caller identity with associated role
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    /// Identifier (e.g., token hash, certificate CN)
    pub id: String,
    /// Role assigned to this caller
    pub role: Role,
}

impl CallerIdentity {
    /// Create a new caller identity
    pub fn new(id: impl Into<String>, role: Role) -> Self {
        Self {
            id: id.into(),
            role,
        }
    }

    /// Check if this caller has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.role.has_permission(permission)
    }
}

/// Shared authorization state
#[derive(Clone)]
pub struct AuthzState {
    pub config: Arc<AuthzConfig>,
    /// Token to role mapping
    pub token_roles: Arc<HashMap<String, Role>>,
}

impl AuthzState {
    /// Create with default configuration and admin role for all tokens
    pub fn new(config: AuthzConfig) -> Self {
        Self {
            config: Arc::new(config),
            token_roles: Arc::new(HashMap::new()),
        }
    }

    /// Create with specific token-to-role mappings
    pub fn with_token_roles(config: AuthzConfig, token_roles: HashMap<String, Role>) -> Self {
        Self {
            config: Arc::new(config),
            token_roles: Arc::new(token_roles),
        }
    }

    /// Get role for a token (defaults to admin if not mapped)
    pub fn get_role_for_token(&self, token: &str) -> Role {
        self.token_roles
            .get(token)
            .cloned()
            .unwrap_or_else(Role::admin)
    }
}

/// Authorization middleware
///
/// Checks if the authenticated caller has permission for the requested endpoint.
/// This should run after authentication middleware.
pub async fn authz_middleware(
    axum::extract::State(authz_state): axum::extract::State<AuthzState>,
    request: Request,
    next: Next,
) -> Result<Response, AuthzError> {
    let path = request.uri().path();

    // Get required permission for this endpoint
    let required_permission = authz_state.config.required_permission(path);

    // Get caller identity from request extensions (set by auth middleware)
    let caller = request
        .extensions()
        .get::<CallerIdentity>()
        .cloned();

    // If no caller identity, allow if it's a read endpoint (public)
    // This handles the case where auth is disabled
    if caller.is_none() {
        if required_permission == Permission::Read {
            return Ok(next.run(request).await);
        }
        // For non-read endpoints without identity, allow (auth middleware handles this)
        return Ok(next.run(request).await);
    }

    let caller = caller.unwrap();

    // Check if caller has required permission
    if caller.has_permission(required_permission) {
        Ok(next.run(request).await)
    } else {
        Err(AuthzError {
            status: StatusCode::FORBIDDEN,
            message: format!(
                "Insufficient permissions: '{}' permission required, caller has role '{}'",
                required_permission, caller.role.name
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_display() {
        assert_eq!(Permission::Read.to_string(), "read");
        assert_eq!(Permission::Sign.to_string(), "sign");
        assert_eq!(Permission::Admin.to_string(), "admin");
    }

    #[test]
    fn test_role_permissions() {
        let read_only = Role::read_only();
        assert!(read_only.has_permission(Permission::Read));
        assert!(!read_only.has_permission(Permission::Sign));
        assert!(!read_only.has_permission(Permission::Admin));

        let signer = Role::signer();
        assert!(signer.has_permission(Permission::Read));
        assert!(signer.has_permission(Permission::Sign));
        assert!(!signer.has_permission(Permission::Admin));

        let admin = Role::admin();
        assert!(admin.has_permission(Permission::Read));
        assert!(admin.has_permission(Permission::Sign));
        assert!(admin.has_permission(Permission::Admin));
    }

    #[test]
    fn test_authz_config_default() {
        let config = AuthzConfig::default();

        // Read endpoints
        assert_eq!(config.required_permission("/upcheck"), Permission::Read);
        assert_eq!(config.required_permission("/health"), Permission::Read);
        assert_eq!(config.required_permission("/api/v1/eth2/publicKeys"), Permission::Read);

        // Admin endpoints
        assert_eq!(config.required_permission("/reload"), Permission::Admin);
        assert_eq!(config.required_permission("/admin/state"), Permission::Admin);

        // Sign endpoints
        assert_eq!(
            config.required_permission("/api/v1/eth2/sign/0x1234"),
            Permission::Sign
        );
    }

    #[test]
    fn test_caller_identity() {
        let caller = CallerIdentity::new("test-token", Role::signer());
        assert!(caller.has_permission(Permission::Read));
        assert!(caller.has_permission(Permission::Sign));
        assert!(!caller.has_permission(Permission::Admin));
    }
}
