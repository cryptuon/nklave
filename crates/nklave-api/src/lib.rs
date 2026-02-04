//! Nklave API - Web3Signer-compatible HTTP API
//!
//! This crate provides the HTTP API layer for Nklave, compatible with
//! Lighthouse and other validator clients that support the Web3Signer protocol.

pub mod error;
pub mod routes;
pub mod types;

pub use routes::{create_router, create_router_with_config, ApiConfig, AppState, ReloadResult, StatusResponse};
