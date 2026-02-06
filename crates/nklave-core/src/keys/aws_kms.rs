//! AWS KMS key provider implementation
//!
//! This provider uses AWS KMS for key wrapping/unwrapping. Since AWS KMS doesn't
//! natively support BLS signatures, we use a hybrid approach:
//!
//! 1. BLS secret keys are encrypted (wrapped) using a KMS key
//! 2. Wrapped keys are stored locally (in files or database)
//! 3. At startup, keys are unwrapped using KMS and loaded into memory
//! 4. Signing operations happen locally with the unwrapped keys
//!
//! This provides defense-in-depth: even if an attacker accesses the wrapped keys,
//! they cannot use them without KMS access.

#[cfg(feature = "aws-kms")]
mod implementation {
    use crate::keys::bls::{BlsKeypair, BlsPublicKey, BlsSecretKey, BlsSignature};
    use crate::keys::provider::{KeyProvider, KeyProviderError};
    use async_trait::async_trait;
    use aws_sdk_kms::Client as KmsClient;
    use aws_sdk_kms::primitives::Blob;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::RwLock;
    use tracing::{debug, error, info, warn};

    /// Configuration for the AWS KMS key provider
    #[derive(Debug, Clone)]
    pub struct AwsKmsConfig {
        /// AWS region
        pub region: String,

        /// KMS key ID for wrapping/unwrapping
        pub key_id: String,

        /// Optional endpoint override (for LocalStack testing)
        pub endpoint: Option<String>,

        /// Directory containing wrapped key files
        pub wrapped_keys_dir: PathBuf,
    }

    /// AWS KMS key provider
    ///
    /// Uses KMS to unwrap BLS secret keys, then performs signing locally.
    #[derive(Debug)]
    pub struct AwsKmsKeyProvider {
        /// KMS client
        client: KmsClient,

        /// KMS key ID for wrapping/unwrapping
        key_id: String,

        /// Unwrapped keypairs (loaded at startup)
        keypairs: RwLock<HashMap<[u8; 48], BlsKeypair>>,

        /// Directory for wrapped keys
        wrapped_keys_dir: PathBuf,
    }

    impl AwsKmsKeyProvider {
        /// Create a new AWS KMS key provider
        pub async fn new(config: AwsKmsConfig) -> Result<Self, KeyProviderError> {
            // Build AWS config
            let mut aws_config_builder = aws_config::defaults(
                aws_config::BehaviorVersion::latest()
            );

            if let Some(endpoint) = &config.endpoint {
                aws_config_builder = aws_config_builder.endpoint_url(endpoint);
            }

            let aws_config = aws_config_builder.load().await;
            let client = KmsClient::new(&aws_config);

            info!(
                key_id = %config.key_id,
                region = %config.region,
                "AWS KMS key provider initialized"
            );

            Ok(Self {
                client,
                key_id: config.key_id,
                keypairs: RwLock::new(HashMap::new()),
                wrapped_keys_dir: config.wrapped_keys_dir,
            })
        }

        /// Load and unwrap all keys from the wrapped keys directory
        pub async fn load_keys(&self) -> Result<usize, KeyProviderError> {
            if !self.wrapped_keys_dir.exists() {
                warn!(
                    path = %self.wrapped_keys_dir.display(),
                    "Wrapped keys directory does not exist"
                );
                return Ok(0);
            }

            let mut loaded = 0;

            let entries = std::fs::read_dir(&self.wrapped_keys_dir)
                .map_err(|e| KeyProviderError::InitializationFailed(format!(
                    "Failed to read wrapped keys directory: {}", e
                )))?;

            for entry in entries {
                let entry = entry.map_err(|e| {
                    KeyProviderError::InitializationFailed(format!("Failed to read directory entry: {}", e))
                })?;

                let path = entry.path();
                if path.extension().map(|e| e == "wrapped").unwrap_or(false) {
                    match self.load_wrapped_key(&path).await {
                        Ok(keypair) => {
                            let pubkey = keypair.public_key_bytes();
                            let mut keypairs = self.keypairs.write().unwrap();
                            keypairs.insert(pubkey, keypair);
                            loaded += 1;
                            debug!(
                                path = %path.display(),
                                pubkey = %hex::encode(&pubkey[..8]),
                                "Loaded wrapped key"
                            );
                        }
                        Err(e) => {
                            error!(
                                path = %path.display(),
                                error = %e,
                                "Failed to load wrapped key"
                            );
                        }
                    }
                }
            }

            info!(loaded = loaded, "Loaded wrapped keys from KMS");
            Ok(loaded)
        }

        /// Load and unwrap a single key file
        async fn load_wrapped_key(&self, path: &std::path::Path) -> Result<BlsKeypair, KeyProviderError> {
            // Read the wrapped key
            let wrapped_key = std::fs::read(path)
                .map_err(|e| KeyProviderError::InitializationFailed(format!(
                    "Failed to read wrapped key file: {}", e
                )))?;

            // Unwrap using KMS
            let response = self.client
                .decrypt()
                .key_id(&self.key_id)
                .ciphertext_blob(Blob::new(wrapped_key))
                .send()
                .await
                .map_err(|e| KeyProviderError::BackendError(format!(
                    "KMS decrypt failed: {}", e
                )))?;

            let plaintext = response.plaintext()
                .ok_or_else(|| KeyProviderError::BackendError(
                    "KMS decrypt returned no plaintext".to_string()
                ))?;

            // Parse the secret key
            let secret = BlsSecretKey::from_bytes(plaintext.as_ref())
                .map_err(|e| KeyProviderError::InvalidKeyFormat(e.to_string()))?;

            Ok(BlsKeypair::from_secret(secret))
        }

        /// Wrap and save a key to the wrapped keys directory
        pub async fn wrap_and_save_key(&self, keypair: &BlsKeypair) -> Result<PathBuf, KeyProviderError> {
            let secret_bytes = keypair.secret.to_bytes();

            // Wrap using KMS
            let response = self.client
                .encrypt()
                .key_id(&self.key_id)
                .plaintext(Blob::new(secret_bytes.to_vec()))
                .send()
                .await
                .map_err(|e| KeyProviderError::BackendError(format!(
                    "KMS encrypt failed: {}", e
                )))?;

            let ciphertext = response.ciphertext_blob()
                .ok_or_else(|| KeyProviderError::BackendError(
                    "KMS encrypt returned no ciphertext".to_string()
                ))?;

            // Save to file
            let pubkey_hex = hex::encode(keypair.public_key_bytes());
            let filename = format!("{}.wrapped", pubkey_hex);
            let path = self.wrapped_keys_dir.join(&filename);

            std::fs::create_dir_all(&self.wrapped_keys_dir)
                .map_err(|e| KeyProviderError::InitializationFailed(format!(
                    "Failed to create wrapped keys directory: {}", e
                )))?;

            std::fs::write(&path, ciphertext.as_ref())
                .map_err(|e| KeyProviderError::InitializationFailed(format!(
                    "Failed to write wrapped key file: {}", e
                )))?;

            // Add to in-memory store
            let pubkey = keypair.public_key_bytes();
            let mut keypairs = self.keypairs.write().unwrap();
            keypairs.insert(pubkey, keypair.clone());

            info!(
                pubkey = %hex::encode(&pubkey[..8]),
                path = %path.display(),
                "Wrapped and saved key"
            );

            Ok(path)
        }
    }

    #[async_trait]
    impl KeyProvider for AwsKmsKeyProvider {
        fn provider_name(&self) -> &str {
            "aws-kms"
        }

        async fn sign(&self, pubkey: &[u8; 48], message: &[u8; 32]) -> Result<[u8; 96], KeyProviderError> {
            let keypairs = self.keypairs.read().unwrap();
            let keypair = keypairs
                .get(pubkey)
                .ok_or_else(|| KeyProviderError::KeyNotFound(*pubkey))?;

            let signature = keypair.sign(message);
            Ok(signature.to_bytes())
        }

        async fn list_keys(&self) -> Result<Vec<[u8; 48]>, KeyProviderError> {
            let keypairs = self.keypairs.read().unwrap();
            Ok(keypairs.keys().copied().collect())
        }

        async fn has_key(&self, pubkey: &[u8; 48]) -> bool {
            self.keypairs.read().unwrap().contains_key(pubkey)
        }

        async fn key_count(&self) -> usize {
            self.keypairs.read().unwrap().len()
        }

        async fn verify(
            &self,
            pubkey: &[u8; 48],
            message: &[u8; 32],
            signature: &[u8; 96],
        ) -> Result<bool, KeyProviderError> {
            let pk = BlsPublicKey::from_bytes(pubkey)
                .map_err(|e| KeyProviderError::InvalidKeyFormat(e.to_string()))?;

            let sig = BlsSignature::from_bytes(signature)
                .map_err(|e| KeyProviderError::InvalidKeyFormat(e.to_string()))?;

            Ok(pk.verify(message, &sig))
        }
    }
}

#[cfg(feature = "aws-kms")]
pub use implementation::{AwsKmsConfig, AwsKmsKeyProvider};

// Stub implementation when aws-kms feature is not enabled
#[cfg(not(feature = "aws-kms"))]
pub mod stub {
    use crate::keys::provider::{KeyProvider, KeyProviderError};
    use async_trait::async_trait;
    use std::path::PathBuf;

    /// Configuration for the AWS KMS key provider (stub)
    #[derive(Debug, Clone)]
    pub struct AwsKmsConfig {
        pub region: String,
        pub key_id: String,
        pub endpoint: Option<String>,
        pub wrapped_keys_dir: PathBuf,
    }

    /// AWS KMS key provider stub (returns errors when aws-kms feature not enabled)
    #[derive(Debug)]
    pub struct AwsKmsKeyProvider;

    impl AwsKmsKeyProvider {
        pub async fn new(_config: AwsKmsConfig) -> Result<Self, KeyProviderError> {
            Err(KeyProviderError::InitializationFailed(
                "AWS KMS support not enabled. Compile with --features aws-kms".to_string()
            ))
        }

        pub async fn load_keys(&self) -> Result<usize, KeyProviderError> {
            Err(KeyProviderError::InitializationFailed(
                "AWS KMS support not enabled".to_string()
            ))
        }
    }

    #[async_trait]
    impl KeyProvider for AwsKmsKeyProvider {
        fn provider_name(&self) -> &str {
            "aws-kms-stub"
        }

        async fn sign(&self, _pubkey: &[u8; 48], _message: &[u8; 32]) -> Result<[u8; 96], KeyProviderError> {
            Err(KeyProviderError::InitializationFailed(
                "AWS KMS support not enabled".to_string()
            ))
        }

        async fn list_keys(&self) -> Result<Vec<[u8; 48]>, KeyProviderError> {
            Err(KeyProviderError::InitializationFailed(
                "AWS KMS support not enabled".to_string()
            ))
        }

        async fn has_key(&self, _pubkey: &[u8; 48]) -> bool {
            false
        }
    }
}

#[cfg(not(feature = "aws-kms"))]
pub use stub::{AwsKmsConfig, AwsKmsKeyProvider};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = AwsKmsConfig {
            region: "us-east-1".to_string(),
            key_id: "alias/nklave-keys".to_string(),
            endpoint: None,
            wrapped_keys_dir: std::path::PathBuf::from("./wrapped-keys"),
        };

        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.key_id, "alias/nklave-keys");
    }

    #[test]
    fn test_config_with_localstack() {
        let config = AwsKmsConfig {
            region: "us-east-1".to_string(),
            key_id: "alias/test-key".to_string(),
            endpoint: Some("http://localhost:4566".to_string()),
            wrapped_keys_dir: std::path::PathBuf::from("./test-keys"),
        };

        assert!(config.endpoint.is_some());
    }
}
