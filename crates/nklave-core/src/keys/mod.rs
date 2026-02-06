//! Key management modules
//!
//! Supports multiple key types:
//! - BLS12-381 for Ethereum validators
//! - Ed25519 for Cosmos/CometBFT validators
//!
//! # Key Providers
//!
//! The `provider` module defines the `KeyProvider` trait for abstracting
//! key storage and signing. Available implementations:
//!
//! - `LocalKeyProvider`: Keys stored in memory, loaded from EIP-2335 keystores
//! - `AwsKmsKeyProvider`: Keys wrapped/protected by AWS KMS (with `aws-kms` feature)
//! - Vault: HashiCorp Vault integration (with `vault` feature)

pub mod aws_kms;
pub mod bls;
pub mod ed25519;
pub mod keystore;
pub mod local;
pub mod provider;

pub use aws_kms::{AwsKmsConfig, AwsKmsKeyProvider};
pub use local::LocalKeyProvider;
pub use provider::{KeyProvider, KeyProviderConfig, KeyProviderError};
