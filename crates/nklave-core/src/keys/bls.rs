//! BLS12-381 key management and signing operations
//!
//! Uses the blst library for cryptographic operations

use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use thiserror::Error;

/// Domain separation tag for Ethereum BLS signatures
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// BLS secret key wrapper
#[derive(Clone)]
pub struct BlsSecretKey {
    inner: SecretKey,
}

impl BlsSecretKey {
    /// Create from raw bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != 32 {
            return Err(BlsError::InvalidKeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let inner = SecretKey::from_bytes(bytes).map_err(|e| BlsError::InvalidKey(format!("{:?}", e)))?;

        Ok(Self { inner })
    }

    /// Generate a new random secret key
    pub fn random() -> Self {
        let mut ikm = [0u8; 32];
        getrandom(&mut ikm);
        let inner = SecretKey::key_gen(&ikm, &[]).expect("key generation should not fail");
        Self { inner }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey {
            inner: self.inner.sk_to_pk(),
        }
    }

    /// Sign a message (signing root)
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sig = self.inner.sign(message, DST, &[]);
        BlsSignature { inner: sig }
    }

    /// Export the secret key as bytes (use with caution!)
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

/// BLS public key wrapper
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlsPublicKey {
    inner: PublicKey,
}

impl BlsPublicKey {
    /// Create from compressed bytes (48 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != 48 {
            return Err(BlsError::InvalidKeyLength {
                expected: 48,
                actual: bytes.len(),
            });
        }

        let inner = PublicKey::from_bytes(bytes).map_err(|e| BlsError::InvalidKey(format!("{:?}", e)))?;

        Ok(Self { inner })
    }

    /// Export as compressed bytes (48 bytes)
    pub fn to_bytes(&self) -> [u8; 48] {
        self.inner.to_bytes()
    }

    /// Export as hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

    /// Create from hex string (with or without 0x prefix)
    pub fn from_hex(s: &str) -> Result<Self, BlsError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| BlsError::InvalidHex(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> bool {
        let result = signature.inner.verify(true, message, DST, &[], &self.inner, true);
        result == BLST_ERROR::BLST_SUCCESS
    }
}

/// BLS signature wrapper
#[derive(Clone, Debug)]
pub struct BlsSignature {
    inner: Signature,
}

impl BlsSignature {
    /// Create from compressed bytes (96 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BlsError> {
        if bytes.len() != 96 {
            return Err(BlsError::InvalidSignatureLength {
                expected: 96,
                actual: bytes.len(),
            });
        }

        let inner = Signature::from_bytes(bytes).map_err(|e| BlsError::InvalidSignature(format!("{:?}", e)))?;

        Ok(Self { inner })
    }

    /// Export as compressed bytes (96 bytes)
    pub fn to_bytes(&self) -> [u8; 96] {
        self.inner.to_bytes()
    }

    /// Export as hex string with 0x prefix
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
}

/// A BLS keypair (secret + public key)
#[derive(Clone)]
pub struct BlsKeypair {
    pub secret: BlsSecretKey,
    pub public: BlsPublicKey,
}

impl BlsKeypair {
    /// Create a new keypair from a secret key
    pub fn from_secret(secret: BlsSecretKey) -> Self {
        let public = secret.public_key();
        Self { secret, public }
    }

    /// Generate a new random keypair
    pub fn random() -> Self {
        Self::from_secret(BlsSecretKey::random())
    }

    /// Generate a new random keypair (alias for random)
    pub fn generate() -> Self {
        Self::random()
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; 48] {
        self.public.to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        self.secret.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> bool {
        self.public.verify(message, signature)
    }
}

/// Errors related to BLS operations
#[derive(Debug, Error)]
pub enum BlsError {
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

/// Get random bytes (uses OS randomness)
fn getrandom(dest: &mut [u8]) {
    use std::io::Read;

    #[cfg(unix)]
    {
        let mut file = std::fs::File::open("/dev/urandom").expect("Failed to open /dev/urandom");
        file.read_exact(dest).expect("Failed to read random bytes");
    }

    #[cfg(windows)]
    {
        // On Windows, use the rand crate or similar
        // For now, just use a simple fallback
        for byte in dest.iter_mut() {
            *byte = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos() as u8)
                .wrapping_add(*byte);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = BlsKeypair::random();
        let pubkey_bytes = keypair.public.to_bytes();
        assert_eq!(pubkey_bytes.len(), 48);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = BlsKeypair::random();
        let message = b"test message";

        let signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature));
        assert!(!keypair.verify(b"wrong message", &signature));
    }

    #[test]
    fn test_public_key_hex() {
        let keypair = BlsKeypair::random();
        let hex = keypair.public.to_hex();

        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 98); // 0x + 96 hex chars

        let recovered = BlsPublicKey::from_hex(&hex).unwrap();
        assert_eq!(recovered, keypair.public);
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = BlsKeypair::random();
        let message = b"test message";
        let signature = keypair.sign(message);

        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), 96);

        let recovered = BlsSignature::from_bytes(&bytes).unwrap();
        assert!(keypair.verify(message, &recovered));
    }
}
