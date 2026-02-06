//! Key provider abstraction for signing operations
//!
//! This module defines the `KeyProvider` trait that abstracts how keys are stored
//! and how signing is performed. This allows for multiple backends:
//!
//! - Local: Keys stored in memory, loaded from EIP-2335 keystores
//! - AWS KMS: Keys wrapped/protected by AWS KMS
//! - HSM: Hardware security module integration
//! - Vault: HashiCorp Vault integration

use async_trait::async_trait;
use std::fmt;
use thiserror::Error;

/// Errors from key provider operations
#[derive(Debug, Error)]
pub enum KeyProviderError {
    /// The requested key was not found
    #[error("Key not found: 0x{}", hex::encode(.0))]
    KeyNotFound([u8; 48]),

    /// Signing operation failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Key loading/initialization failed
    #[error("Initialization failed: {0}")]
    InitializationFailed(String),

    /// Backend-specific error (e.g., network, permissions)
    #[error("Backend error: {0}")]
    BackendError(String),

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Timeout during operation
    #[error("Operation timed out")]
    Timeout,
}

/// Trait for key providers that abstract BLS key storage and signing
///
/// This trait allows the signing service to work with different key backends
/// without knowing the implementation details.
#[async_trait]
pub trait KeyProvider: Send + Sync + fmt::Debug {
    /// Get the name/type of this provider
    fn provider_name(&self) -> &str;

    /// Sign a message (signing root) with the specified key
    ///
    /// # Arguments
    /// * `pubkey` - The 48-byte compressed BLS public key
    /// * `message` - The 32-byte signing root to sign
    ///
    /// # Returns
    /// The 96-byte BLS signature, or an error
    async fn sign(&self, pubkey: &[u8; 48], message: &[u8; 32]) -> Result<[u8; 96], KeyProviderError>;

    /// List all public keys available in this provider
    async fn list_keys(&self) -> Result<Vec<[u8; 48]>, KeyProviderError>;

    /// Check if a key exists in this provider
    async fn has_key(&self, pubkey: &[u8; 48]) -> bool;

    /// Get the number of keys in this provider
    async fn key_count(&self) -> usize {
        self.list_keys().await.map(|keys| keys.len()).unwrap_or(0)
    }

    /// Verify a signature (optional, for testing/validation)
    ///
    /// Default implementation returns true (no verification).
    /// Providers that support verification should override this.
    async fn verify(
        &self,
        pubkey: &[u8; 48],
        message: &[u8; 32],
        signature: &[u8; 96],
    ) -> Result<bool, KeyProviderError> {
        // Default: no verification capability, assume valid
        let _ = (pubkey, message, signature);
        Ok(true)
    }
}

/// Configuration for key providers
#[derive(Debug, Clone)]
pub enum KeyProviderConfig {
    /// Local key provider with keys from keystores
    Local {
        /// Directory containing keystore files
        keystore_dir: String,
        /// Password for decrypting keystores
        password: String,
    },

    /// AWS KMS key provider
    #[cfg(feature = "aws-kms")]
    AwsKms {
        /// AWS region
        region: String,
        /// KMS key ID for wrapping/unwrapping
        key_id: String,
        /// Optional endpoint override (for LocalStack testing)
        endpoint: Option<String>,
    },

    /// HashiCorp Vault key provider
    #[cfg(feature = "vault")]
    Vault {
        /// Vault address
        address: String,
        /// Authentication token
        token: String,
        /// Secret path prefix
        path_prefix: String,
    },
}

impl Default for KeyProviderConfig {
    fn default() -> Self {
        KeyProviderConfig::Local {
            keystore_dir: "./keystores".to_string(),
            password: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_error_display() {
        let err = KeyProviderError::KeyNotFound([1u8; 48]);
        assert!(err.to_string().contains("Key not found"));

        let err = KeyProviderError::SigningFailed("test error".to_string());
        assert!(err.to_string().contains("Signing failed"));
    }

    #[test]
    fn test_default_config() {
        let config = KeyProviderConfig::default();
        match config {
            KeyProviderConfig::Local { keystore_dir, .. } => {
                assert_eq!(keystore_dir, "./keystores");
            }
            #[allow(unreachable_patterns)]
            _ => panic!("Expected Local config"),
        }
    }
}
