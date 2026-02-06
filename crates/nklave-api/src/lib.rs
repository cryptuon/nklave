//! Nklave API - Web3Signer-compatible HTTP API
//!
//! This crate provides the HTTP API layer for Nklave, compatible with
//! Lighthouse and other validator clients that support the Web3Signer protocol.

pub mod auth;
pub mod authz;
pub mod error;
pub mod routes;
pub mod types;
pub mod ui;

pub use auth::{AuthConfig, AuthMode, AuthState};
pub use authz::{AuthzConfig, AuthzState, CallerIdentity, Permission, Role};
pub use routes::{
    create_router, create_router_with_config, create_router_with_auth,
    create_router_with_ui, create_router_with_ui_and_auth,
    ApiConfig, AppState, FullApiConfig, ReloadResult, StatusResponse,
    DecisionsResponse, DecisionSummary, MetricsSummary,
};
pub use ui::{serve_ui, ui_available};
