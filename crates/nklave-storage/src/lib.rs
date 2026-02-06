//! Nklave Storage - Persistence layer
//!
//! This crate provides:
//! - Append-only decision log
//! - Secure logging with encryption and integrity chain
//! - Log rotation
//! - State checkpoints
//! - Checkpoint scheduling
//! - EIP-3076 slashing protection interchange format

pub mod checkpoint;
pub mod eip3076;
pub mod log;
pub mod rotation;
pub mod scheduler;
pub mod secure_log;

pub use checkpoint::{Checkpoint, CheckpointError};
pub use eip3076::{Eip3076Interchange, Eip3076Error};
pub use log::{DecisionLog, LogError};
pub use rotation::{LogRotator, RotationConfig, RotationError};
pub use scheduler::{CheckpointProvider, CheckpointScheduler, CheckpointSchedulerHandle, SchedulerConfig};
pub use secure_log::{SecureDecisionLog, SecureLogConfig, SecureLogError};
