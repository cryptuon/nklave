//! Nklave Cosmos - Remote signer protocol handler for Cosmos/CometBFT
//!
//! This crate implements the Tendermint private validator protocol (privval),
//! allowing Nklave to serve as a remote signer for Cosmos validators.
//!
//! # Protocol Support
//!
//! - gRPC PrivValidatorAPI service
//! - PubKeyRequest/Response
//! - SignVoteRequest/Response
//! - SignProposalRequest/Response
//! - Ping/Pong keepalive
//!
//! # Usage
//!
//! ```ignore
//! use nklave_cosmos::{CosmosServer, CosmosServerConfig};
//! use nklave_core::SigningService;
//!
//! let config = CosmosServerConfig {
//!     listen_addr: "[::1]:26659".to_string(),
//!     chain_id: "cosmoshub-4".to_string(),
//! };
//!
//! let server = CosmosServer::new(signing_service, config);
//! server.serve().await?;
//! ```

pub mod error;
pub mod server;
pub mod service;
pub mod types;

pub use error::CosmosError;
pub use server::{CosmosServer, CosmosServerConfig, CosmosServerHandle};
pub use service::CosmosSigningService;
pub use types::{SignedMsgType, VoteInfo, ProposalInfo};
