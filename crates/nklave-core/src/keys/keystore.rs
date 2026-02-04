//! EIP-2335 Keystore support
//!
//! Implements loading of validator keystores according to EIP-2335
//! https://eips.ethereum.org/EIPS/eip-2335

use crate::keys::bls::{BlsKeypair, BlsSecretKey};
use aes::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// EIP-2335 Keystore JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub crypto: KeystoreCrypto,
    #[serde(default)]
    pub description: Option<String>,
    pub pubkey: String,
    pub path: String,
    pub uuid: Uuid,
    pub version: u32,
}

/// Crypto section of the keystore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreCrypto {
    pub kdf: KeystoreKdf,
    pub checksum: KeystoreChecksum,
    pub cipher: KeystoreCipher,
}

/// KDF parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreKdf {
    pub function: String,
    pub params: KdfParams,
    pub message: String,
}

/// KDF parameters (either scrypt or pbkdf2)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParams {
    Scrypt(ScryptKdfParams),
    Pbkdf2(Pbkdf2KdfParams),
}

/// Scrypt KDF parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptKdfParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

/// PBKDF2 KDF parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2KdfParams {
    pub dklen: u32,
    pub c: u32,
    pub prf: String,
    pub salt: String,
}

/// Checksum section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreChecksum {
    pub function: String,
    pub params: serde_json::Value,
    pub message: String,
}

/// Cipher section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreCipher {
    pub function: String,
    pub params: CipherParams,
    pub message: String,
}

/// Cipher parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

impl Keystore {
    /// Load a keystore from a JSON file
    pub fn load(path: impl AsRef<Path>) -> Result<Self, KeystoreError> {
        let contents = fs::read_to_string(path.as_ref())
            .map_err(|e| KeystoreError::Io(e.to_string()))?;

        serde_json::from_str(&contents)
            .map_err(|e| KeystoreError::Parse(e.to_string()))
    }

    /// Decrypt the keystore and return the secret key
    pub fn decrypt(&self, password: &str) -> Result<BlsSecretKey, KeystoreError> {
        // Derive the decryption key
        let decryption_key = self.derive_key(password)?;

        // Verify checksum
        self.verify_checksum(&decryption_key)?;

        // Decrypt the secret key
        let secret_key_bytes = self.decrypt_secret(&decryption_key)?;

        // Create BLS secret key
        BlsSecretKey::from_bytes(&secret_key_bytes)
            .map_err(|e| KeystoreError::InvalidKey(e.to_string()))
    }

    /// Decrypt and return a full keypair
    pub fn decrypt_keypair(&self, password: &str) -> Result<BlsKeypair, KeystoreError> {
        let secret = self.decrypt(password)?;
        Ok(BlsKeypair::from_secret(secret))
    }

    /// Derive the decryption key using the specified KDF
    fn derive_key(&self, password: &str) -> Result<[u8; 32], KeystoreError> {
        let kdf = &self.crypto.kdf;

        match kdf.function.as_str() {
            "scrypt" => {
                let params = match &kdf.params {
                    KdfParams::Scrypt(p) => p,
                    _ => return Err(KeystoreError::InvalidKdf("Expected scrypt params".into())),
                };

                let salt = hex::decode(&params.salt)
                    .map_err(|e| KeystoreError::Parse(format!("Invalid salt hex: {}", e)))?;

                // Convert n to log2(n) for scrypt params
                let log_n = (params.n as f64).log2() as u8;
                let scrypt_params = ScryptParams::new(log_n, params.r, params.p, params.dklen as usize)
                    .map_err(|e| KeystoreError::InvalidKdf(format!("Invalid scrypt params: {:?}", e)))?;

                let mut dk = [0u8; 32];
                scrypt(password.as_bytes(), &salt, &scrypt_params, &mut dk)
                    .map_err(|e| KeystoreError::InvalidKdf(format!("Scrypt failed: {:?}", e)))?;

                Ok(dk)
            }
            "pbkdf2" => {
                let params = match &kdf.params {
                    KdfParams::Pbkdf2(p) => p,
                    _ => return Err(KeystoreError::InvalidKdf("Expected pbkdf2 params".into())),
                };

                let salt = hex::decode(&params.salt)
                    .map_err(|e| KeystoreError::Parse(format!("Invalid salt hex: {}", e)))?;

                let mut dk = [0u8; 32];
                pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, params.c, &mut dk);

                Ok(dk)
            }
            other => Err(KeystoreError::UnsupportedKdf(other.to_string())),
        }
    }

    /// Verify the checksum
    fn verify_checksum(&self, decryption_key: &[u8; 32]) -> Result<(), KeystoreError> {
        let cipher_message = hex::decode(&self.crypto.cipher.message)
            .map_err(|e| KeystoreError::Parse(format!("Invalid cipher message hex: {}", e)))?;

        // Checksum = SHA256(decryption_key[16:32] || cipher_message)
        let mut hasher = Sha256::new();
        hasher.update(&decryption_key[16..32]);
        hasher.update(&cipher_message);
        let computed_checksum = hasher.finalize();

        let expected_checksum = hex::decode(&self.crypto.checksum.message)
            .map_err(|e| KeystoreError::Parse(format!("Invalid checksum hex: {}", e)))?;

        if computed_checksum.as_slice() != expected_checksum.as_slice() {
            return Err(KeystoreError::InvalidPassword);
        }

        Ok(())
    }

    /// Decrypt the secret key bytes
    fn decrypt_secret(&self, decryption_key: &[u8; 32]) -> Result<[u8; 32], KeystoreError> {
        let cipher = &self.crypto.cipher;

        if cipher.function != "aes-128-ctr" {
            return Err(KeystoreError::UnsupportedCipher(cipher.function.clone()));
        }

        let iv = hex::decode(&cipher.params.iv)
            .map_err(|e| KeystoreError::Parse(format!("Invalid IV hex: {}", e)))?;

        let ciphertext = hex::decode(&cipher.message)
            .map_err(|e| KeystoreError::Parse(format!("Invalid ciphertext hex: {}", e)))?;

        // Use first 16 bytes of decryption key for AES-128
        let aes_key: [u8; 16] = decryption_key[0..16].try_into().unwrap();
        let iv_array: [u8; 16] = iv.try_into()
            .map_err(|_| KeystoreError::Parse("Invalid IV length".into()))?;

        let mut cipher = Aes128Ctr::new(&aes_key.into(), &iv_array.into());
        let mut plaintext = ciphertext;
        cipher.apply_keystream(&mut plaintext);

        if plaintext.len() != 32 {
            return Err(KeystoreError::InvalidKey(format!(
                "Expected 32 bytes, got {}",
                plaintext.len()
            )));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&plaintext);
        Ok(secret)
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> Result<[u8; 48], KeystoreError> {
        let pubkey = self.pubkey.strip_prefix("0x").unwrap_or(&self.pubkey);
        let bytes = hex::decode(pubkey)
            .map_err(|e| KeystoreError::Parse(format!("Invalid pubkey hex: {}", e)))?;

        if bytes.len() != 48 {
            return Err(KeystoreError::Parse(format!(
                "Expected 48 bytes for pubkey, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Load all keystores from a directory
pub fn load_keystores_from_dir(
    dir: impl AsRef<Path>,
    password: &str,
) -> Result<Vec<BlsKeypair>, KeystoreError> {
    let dir = dir.as_ref();

    if !dir.exists() {
        return Err(KeystoreError::Io(format!(
            "Directory does not exist: {}",
            dir.display()
        )));
    }

    let mut keypairs = Vec::new();

    for entry in fs::read_dir(dir).map_err(|e| KeystoreError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| KeystoreError::Io(e.to_string()))?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            match Keystore::load(&path) {
                Ok(keystore) => {
                    match keystore.decrypt_keypair(password) {
                        Ok(keypair) => {
                            tracing::info!(
                                pubkey = %keystore.pubkey,
                                path = %path.display(),
                                "Loaded validator key"
                            );
                            keypairs.push(keypair);
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "Failed to decrypt keystore"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        path = %path.display(),
                        error = %e,
                        "Failed to load keystore"
                    );
                }
            }
        }
    }

    Ok(keypairs)
}

/// Errors related to keystore operations
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Unsupported KDF: {0}")]
    UnsupportedKdf(String),

    #[error("Invalid KDF parameters: {0}")]
    InvalidKdf(String),

    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // Example keystore JSON (scrypt)
    const TEST_KEYSTORE_SCRYPT: &str = r#"{
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
        },
        "description": "Test keystore",
        "pubkey": "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/3600/0/0/0",
        "uuid": "1d85ae20-35c5-4611-8e4c-00a8c6c5fb55",
        "version": 4
    }"#;

    #[test]
    fn test_parse_keystore() {
        let keystore: Keystore = serde_json::from_str(TEST_KEYSTORE_SCRYPT).unwrap();
        assert_eq!(keystore.version, 4);
        assert!(keystore.pubkey.starts_with("0x"));
    }

    #[test]
    fn test_load_keystore_from_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("keystore.json");

        let mut file = fs::File::create(&path).unwrap();
        file.write_all(TEST_KEYSTORE_SCRYPT.as_bytes()).unwrap();

        let keystore = Keystore::load(&path).unwrap();
        assert_eq!(keystore.version, 4);
    }

    #[test]
    fn test_public_key_bytes() {
        let keystore: Keystore = serde_json::from_str(TEST_KEYSTORE_SCRYPT).unwrap();
        let pubkey = keystore.public_key_bytes().unwrap();
        assert_eq!(pubkey.len(), 48);
    }
}
