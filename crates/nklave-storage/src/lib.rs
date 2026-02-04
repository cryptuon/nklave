//! Nklave Storage - Persistence layer
//!
//! This crate provides:
//! - Append-only decision log
//! - State checkpoints
//! - EIP-3076 slashing protection interchange format

pub mod checkpoint;
pub mod eip3076;
pub mod log;

pub use checkpoint::Checkpoint;
pub use eip3076::{Eip3076Interchange, Eip3076Error};
pub use log::{DecisionLog, LogError};
