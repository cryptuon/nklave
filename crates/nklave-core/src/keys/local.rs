//! Local key provider implementation
//!
//! This provider stores keys in memory, loaded from EIP-2335 keystores.
//! It wraps the existing `BlsKeypair` functionality and implements the `KeyProvider` trait.

use super::bls::{BlsKeypair, BlsPublicKey, BlsSignature};
use super::provider::{KeyProvider, KeyProviderError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, info};

/// Local key provider that stores keys in memory
///
/// Keys are loaded from EIP-2335 keystores and stored in a thread-safe map.
/// All signing operations are performed locally using the blst library.
#[derive(Debug)]
pub struct LocalKeyProvider {
    /// Keypairs indexed by public key
    keypairs: RwLock<HashMap<[u8; 48], BlsKeypair>>,
}

impl LocalKeyProvider {
    /// Create a new empty local key provider
    pub fn new() -> Self {
        Self {
            keypairs: RwLock::new(HashMap::new()),
        }
    }

    /// Create a local key provider from a list of keypairs
    pub fn from_keypairs(keypairs: Vec<BlsKeypair>) -> Self {
        let map: HashMap<[u8; 48], BlsKeypair> = keypairs
            .into_iter()
            .map(|kp| (kp.public_key_bytes(), kp))
            .collect();

        info!(count = map.len(), "LocalKeyProvider initialized with keys");

        Self {
            keypairs: RwLock::new(map),
        }
    }

    /// Add a keypair to the provider
    ///
    /// Returns true if the key was newly added, false if it already existed.
    pub fn add_keypair(&self, keypair: BlsKeypair) -> bool {
        let pubkey = keypair.public_key_bytes();
        let mut map = self.keypairs.write().unwrap();
        if map.contains_key(&pubkey) {
            false
        } else {
            map.insert(pubkey, keypair);
            debug!(pubkey = %hex::encode(pubkey), "Added keypair to LocalKeyProvider");
            true
        }
    }

    /// Add multiple keypairs to the provider
    ///
    /// Returns the number of new keys added.
    pub fn add_keypairs(&self, keypairs: Vec<BlsKeypair>) -> usize {
        let mut added = 0;
        for kp in keypairs {
            if self.add_keypair(kp) {
                added += 1;
            }
        }
        added
    }

    /// Remove a keypair from the provider
    ///
    /// Returns true if the key was removed, false if it didn't exist.
    pub fn remove_keypair(&self, pubkey: &[u8; 48]) -> bool {
        let mut map = self.keypairs.write().unwrap();
        map.remove(pubkey).is_some()
    }

    /// Get a reference to the keypair for synchronous operations
    ///
    /// This is useful for operations that need direct access to the keypair,
    /// like the existing SigningService methods.
    pub fn get_keypair(&self, pubkey: &[u8; 48]) -> Option<BlsKeypair> {
        self.keypairs.read().unwrap().get(pubkey).cloned()
    }

    /// Get all public keys as hex strings
    pub fn public_keys_hex(&self) -> Vec<String> {
        self.keypairs
            .read()
            .unwrap()
            .keys()
            .map(|pk| format!("0x{}", hex::encode(pk)))
            .collect()
    }
}

impl Default for LocalKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyProvider for LocalKeyProvider {
    fn provider_name(&self) -> &str {
        "local"
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
        // Parse the public key
        let pk = BlsPublicKey::from_bytes(pubkey)
            .map_err(|e| KeyProviderError::InvalidKeyFormat(e.to_string()))?;

        // Parse the signature
        let sig = BlsSignature::from_bytes(signature)
            .map_err(|e| KeyProviderError::InvalidKeyFormat(e.to_string()))?;

        // Verify
        Ok(pk.verify(message, &sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_provider_new() {
        let provider = LocalKeyProvider::new();
        assert_eq!(provider.keypairs.read().unwrap().len(), 0);
    }

    #[test]
    fn test_local_provider_from_keypairs() {
        let keypair = BlsKeypair::generate();
        let pubkey = keypair.public_key_bytes();

        let provider = LocalKeyProvider::from_keypairs(vec![keypair]);
        assert!(provider.keypairs.read().unwrap().contains_key(&pubkey));
    }

    #[test]
    fn test_add_keypair() {
        let provider = LocalKeyProvider::new();
        let keypair = BlsKeypair::generate();
        let pubkey = keypair.public_key_bytes();

        assert!(provider.add_keypair(keypair.clone()));
        assert!(!provider.add_keypair(keypair)); // Duplicate
        assert!(provider.keypairs.read().unwrap().contains_key(&pubkey));
    }

    #[test]
    fn test_remove_keypair() {
        let keypair = BlsKeypair::generate();
        let pubkey = keypair.public_key_bytes();

        let provider = LocalKeyProvider::from_keypairs(vec![keypair]);
        assert!(provider.remove_keypair(&pubkey));
        assert!(!provider.remove_keypair(&pubkey)); // Already removed
    }

    #[tokio::test]
    async fn test_sign_and_verify() {
        let keypair = BlsKeypair::generate();
        let pubkey = keypair.public_key_bytes();

        let provider = LocalKeyProvider::from_keypairs(vec![keypair]);
        let message = [1u8; 32];

        let signature = provider.sign(&pubkey, &message).await.unwrap();
        assert_eq!(signature.len(), 96);

        let valid = provider.verify(&pubkey, &message, &signature).await.unwrap();
        assert!(valid);

        // Wrong message should fail verification
        let wrong_message = [2u8; 32];
        let valid = provider
            .verify(&pubkey, &wrong_message, &signature)
            .await
            .unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_sign_unknown_key() {
        let provider = LocalKeyProvider::new();
        let unknown_pubkey = [99u8; 48];
        let message = [1u8; 32];

        let result = provider.sign(&unknown_pubkey, &message).await;
        assert!(matches!(result, Err(KeyProviderError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_list_keys() {
        let keypair1 = BlsKeypair::generate();
        let keypair2 = BlsKeypair::generate();
        let pubkey1 = keypair1.public_key_bytes();
        let pubkey2 = keypair2.public_key_bytes();

        let provider = LocalKeyProvider::from_keypairs(vec![keypair1, keypair2]);
        let keys = provider.list_keys().await.unwrap();

        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&pubkey1));
        assert!(keys.contains(&pubkey2));
    }

    #[tokio::test]
    async fn test_has_key() {
        let keypair = BlsKeypair::generate();
        let pubkey = keypair.public_key_bytes();

        let provider = LocalKeyProvider::from_keypairs(vec![keypair]);
        assert!(provider.has_key(&pubkey).await);
        assert!(!provider.has_key(&[99u8; 48]).await);
    }

    #[tokio::test]
    async fn test_key_count() {
        let provider = LocalKeyProvider::new();
        assert_eq!(provider.key_count().await, 0);

        provider.add_keypair(BlsKeypair::generate());
        assert_eq!(provider.key_count().await, 1);

        provider.add_keypair(BlsKeypair::generate());
        assert_eq!(provider.key_count().await, 2);
    }

    #[test]
    fn test_provider_name() {
        let provider = LocalKeyProvider::new();
        assert_eq!(provider.provider_name(), "local");
    }
}
