//! Ed25519 key management and signing operations for Cosmos/CometBFT
//!
//! Uses the ed25519-dalek library for cryptographic operations

use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey,
};
use thiserror::Error;

/// Ed25519 secret key wrapper
#[derive(Clone)]
pub struct Ed25519SecretKey {
    inner: SigningKey,
}

impl Ed25519SecretKey {
    /// Create from raw bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Ed25519Error> {
        if bytes.len() != 32 {
            return Err(Ed25519Error::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let inner = SigningKey::from_bytes(&key_bytes);
        Ok(Self { inner })
    }

    /// Generate a new random secret key
    pub fn random() -> Self {
        let mut csprng = rand::thread_rng();
        let inner = SigningKey::generate(&mut csprng);
        Self { inner }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let sig = self.inner.sign(message);
        Ed25519Signature { inner: sig }
    }

    /// Export the secret key as bytes (use with caution!)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

/// Ed25519 public key wrapper
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    inner: VerifyingKey,
}

impl Ed25519PublicKey {
    /// Create from bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Ed25519Error> {
        if bytes.len() != 32 {
            return Err(Ed25519Error::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let inner = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| Ed25519Error::InvalidKey(e.to_string()))?;

        Ok(Self { inner })
    }

    /// Export as bytes (32 bytes)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Export as hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

    /// Create from hex string (with or without 0x prefix)
    pub fn from_hex(s: &str) -> Result<Self, Ed25519Error> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| Ed25519Error::InvalidHex(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        self.inner.verify(message, &signature.inner).is_ok()
    }

    /// Get the Tendermint address (first 20 bytes of SHA256 hash of public key)
    pub fn tendermint_address(&self) -> [u8; 20] {
        use sha2::{Digest, Sha256};

        let hash = Sha256::digest(self.to_bytes());
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[..20]);
        address
    }
}

/// Ed25519 signature wrapper
#[derive(Clone, Debug)]
pub struct Ed25519Signature {
    inner: DalekSignature,
}

impl Ed25519Signature {
    /// Create from bytes (64 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Ed25519Error> {
        if bytes.len() != 64 {
            return Err(Ed25519Error::InvalidSignatureLength {
                expected: 64,
                actual: bytes.len(),
            });
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(bytes);

        let inner = DalekSignature::from_bytes(&sig_bytes);

        Ok(Self { inner })
    }

    /// Export as bytes (64 bytes)
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }

    /// Export as hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

/// A Ed25519 keypair (secret + public key) for Cosmos validators
#[derive(Clone)]
pub struct Ed25519Keypair {
    pub secret: Ed25519SecretKey,
    pub public: Ed25519PublicKey,
}

impl Ed25519Keypair {
    /// Create a new keypair from a secret key
    pub fn from_secret(secret: Ed25519SecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Generate a new random keypair
    pub fn random() -> Self {
        Self::from_secret(Ed25519SecretKey::random())
    }

    /// Generate a new random keypair (alias for random)
    pub fn generate() -> Self {
        Self::random()
    }

    /// Get the public key bytes (32 bytes)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get the public key bytes padded to 48 bytes (for compatibility with ValidatorState)
    pub fn public_key_bytes_padded(&self) -> [u8; 48] {
        let mut padded = [0u8; 48];
        padded[..32].copy_from_slice(&self.public.to_bytes());
        padded
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        self.secret.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> bool {
        self.public.verify(message, signature)
    }

    /// Get the Tendermint validator address
    pub fn tendermint_address(&self) -> [u8; 20] {
        self.public.tendermint_address()
    }
}

/// Errors related to Ed25519 operations
#[derive(Debug, Error)]
pub enum Ed25519Error {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid hex: {0}")]
    InvalidHex(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Ed25519Keypair::random();
        let pubkey_bytes = keypair.public.to_bytes();
        assert_eq!(pubkey_bytes.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Ed25519Keypair::random();
        let message = b"test message";

        let signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature));
        assert!(!keypair.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_public_key_hex() {
        let keypair = Ed25519Keypair::random();
        let hex = keypair.public.to_hex();

        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66); // 0x + 64 hex chars

        let recovered = Ed25519PublicKey::from_hex(&hex).unwrap();
        assert_eq!(recovered, keypair.public);
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = Ed25519Keypair::random();
        let message = b"test message";
        let signature = keypair.sign(message);

        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), 64);

        let recovered = Ed25519Signature::from_bytes(&bytes).unwrap();
        assert!(keypair.verify(message, &recovered));
    }

    #[test]
    fn test_tendermint_address() {
        let keypair = Ed25519Keypair::random();
        let address = keypair.tendermint_address();
        assert_eq!(address.len(), 20);
    }

    #[test]
    fn test_padded_pubkey() {
        let keypair = Ed25519Keypair::random();
        let padded = keypair.public_key_bytes_padded();

        assert_eq!(padded.len(), 48);
        assert_eq!(&padded[..32], &keypair.public.to_bytes());
        assert_eq!(&padded[32..], &[0u8; 16]);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let original = Ed25519SecretKey::random();
        let bytes = original.to_bytes();
        let recovered = Ed25519SecretKey::from_bytes(&bytes).unwrap();

        // Compare by signing the same message
        let message = b"test";
        let sig1 = original.sign(message);
        let sig2 = recovered.sign(message);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}
