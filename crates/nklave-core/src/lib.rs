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
pub mod service;
pub mod state;

pub use keys::bls::{BlsKeypair, BlsPublicKey, BlsSecretKey, BlsSignature};
pub use keys::keystore::{load_keystores_from_dir, Keystore, KeystoreError};
pub use policy::ethereum::EthereumPolicy;
pub use policy::types::{PolicyDecision, RefusalCode, SigningType};
pub use service::{SharedSigningService, SigningResult, SigningService, SigningServiceError};
pub use state::integrity::{DecisionRecord, StateIntegrity};
pub use state::validator::ValidatorState;
