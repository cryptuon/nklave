//! Nklave Core - Signing logic and slashing protection rules
//!
//! This crate provides the core functionality for the Nklave signing security layer:
//! - BLS key management and signing
//! - Ethereum slashing protection policy enforcement
//! - Validator state management
//! - State integrity and hash chaining
//! - Signing service orchestration
//! - Prometheus metrics

pub mod keys;
pub mod metrics;
pub mod policy;
pub mod replication;
pub mod service;
pub mod state;

pub use keys::bls::{BlsKeypair, BlsPublicKey, BlsSecretKey, BlsSignature};
pub use keys::ed25519::{Ed25519Keypair, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
pub use keys::keystore::{load_keystores_from_dir, Keystore, KeystoreError};
pub use policy::cosmos::CosmosPolicy;
pub use policy::ethereum::EthereumPolicy;
pub use policy::types::{ChainType, PolicyDecision, RefusalCode, SigningType};
pub use service::{SharedSigningService, SigningResult, SigningService, SigningServiceError};
pub use state::integrity::{DecisionRecord, StateIntegrity};
pub use state::validator::{
    AttestationHistory, ChainState, CosmosSignedMsgType, CosmosSignedVote, CosmosState,
    EthereumState, ValidatorState,
};

// Replication exports
pub use replication::failover::{
    FailoverConfig, FailoverCoordinator, FailoverError, FailoverState, NodeRole,
};
pub use replication::heartbeat::{HeartbeatCheckHandle, HeartbeatConfig, HeartbeatMonitor};
pub use replication::passive::{PassiveConfig, PassiveError, PassiveHandle, PassiveReceiver};
pub use replication::primary::{ReplicationError, ReplicatorConfig, ReplicatorHandle, StateReplicator};
pub use replication::protocol::{
    AckMessage, ErrorCode, ErrorMessage, FencingToken, Heartbeat, HelloMessage,
    ReplicationMessage, SyncRequest, SyncResponse, PROTOCOL_VERSION,
};
