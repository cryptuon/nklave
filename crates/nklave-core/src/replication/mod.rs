//! Active/Passive replication and failover management
//!
//! This module provides high-availability support for Nklave through
//! state replication and automatic failover.
//!
//! # Architecture
//!
//! The replication system uses a primary-passive architecture:
//!
//! - **Primary**: Handles all signing requests and streams decision records
//!   to passive nodes
//! - **Passive**: Receives and verifies decision records, maintains shadow state,
//!   ready to promote to primary on failover
//!
//! # Protocol
//!
//! Communication uses TCP with TLS, with the following message types:
//! - `Heartbeat`: Periodic liveness check with sequence number and state hash
//! - `DecisionRecord`: Streamed after each signing decision
//! - `SyncRequest`: Request to sync from a specific sequence number
//! - `SyncResponse`: Batch of decision records for catch-up
//!
//! # Failover
//!
//! Failover is triggered when the passive node detects heartbeat timeout.
//! Anti-split-brain protection uses fencing tokens and sequence numbers.

pub mod failover;
pub mod heartbeat;
pub mod passive;
pub mod primary;
pub mod protocol;
pub mod tls;

pub use failover::{FailoverCoordinator, FailoverConfig, FailoverState, NodeRole};
pub use heartbeat::{HeartbeatMonitor, HeartbeatConfig};
pub use passive::{PassiveReceiver, PassiveConfig};
pub use primary::{StateReplicator, ReplicatorConfig};
pub use protocol::{ReplicationMessage, Heartbeat, SyncRequest, SyncResponse};
pub use tls::{ReplicationTlsConfig, TlsError};
