//! Secure decision log with encryption and integrity chain
//!
//! This module extends the basic decision log with:
//! - Optional AES-256-CTR encryption for confidentiality
//! - HMAC-SHA256 integrity chain for tamper detection
//!
//! Each log entry is formatted as:
//! `<sequence>|<hmac>|<encrypted_or_plain_data>`
//!
//! The HMAC chain ensures that any modification to past entries is detectable.

use hmac::{Hmac, Mac};
use nklave_core::state::integrity::DecisionRecord;
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::debug;

type HmacSha256 = Hmac<Sha256>;

/// Configuration for the secure log
#[derive(Debug, Clone)]
pub struct SecureLogConfig {
    /// Path to the log file
    pub path: PathBuf,

    /// Encryption key (32 bytes for AES-256). If None, no encryption.
    pub encryption_key: Option<[u8; 32]>,

    /// HMAC key for integrity chain (32 bytes)
    pub hmac_key: [u8; 32],
}

impl SecureLogConfig {
    /// Create a new config with encryption enabled
    pub fn with_encryption(path: impl AsRef<Path>, encryption_key: [u8; 32], hmac_key: [u8; 32]) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            encryption_key: Some(encryption_key),
            hmac_key,
        }
    }

    /// Create a new config with integrity only (no encryption)
    pub fn integrity_only(path: impl AsRef<Path>, hmac_key: [u8; 32]) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            encryption_key: None,
            hmac_key,
        }
    }
}

/// Secure append-only decision log with encryption and integrity chain
pub struct SecureDecisionLog {
    config: SecureLogConfig,
    writer: BufWriter<File>,
    last_sequence: u64,
    last_hmac: [u8; 32],
}

impl SecureDecisionLog {
    /// Open or create a secure decision log
    pub fn open(config: SecureLogConfig) -> Result<Self, SecureLogError> {
        // Determine last sequence and HMAC by reading existing log
        let (last_sequence, last_hmac) = if config.path.exists() {
            Self::read_last_entry(&config)?
        } else {
            // Initial HMAC is HMAC of the HMAC key itself (genesis)
            let mut mac = HmacSha256::new_from_slice(&config.hmac_key)
                .map_err(|e| SecureLogError::Crypto(e.to_string()))?;
            mac.update(b"nklave-secure-log-genesis");
            let genesis_hmac: [u8; 32] = mac.finalize().into_bytes().into();
            (0, genesis_hmac)
        };

        // Open for appending
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.path)
            .map_err(|e| SecureLogError::Io(e.to_string()))?;

        let writer = BufWriter::new(file);

        Ok(Self {
            config,
            writer,
            last_sequence,
            last_hmac,
        })
    }

    /// Read the last entry from an existing log
    fn read_last_entry(config: &SecureLogConfig) -> Result<(u64, [u8; 32]), SecureLogError> {
        let file = File::open(&config.path).map_err(|e| SecureLogError::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut last_sequence = 0u64;
        let mut last_hmac: [u8; 32] = {
            let mut mac = HmacSha256::new_from_slice(&config.hmac_key)
                .map_err(|e| SecureLogError::Crypto(e.to_string()))?;
            mac.update(b"nklave-secure-log-genesis");
            mac.finalize().into_bytes().into()
        };

        for line in reader.lines() {
            let line = line.map_err(|e| SecureLogError::Io(e.to_string()))?;
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.splitn(3, '|').collect();
            if parts.len() != 3 {
                return Err(SecureLogError::Parse("Invalid line format".to_string()));
            }

            let seq: u64 = parts[0]
                .parse()
                .map_err(|_| SecureLogError::Parse("Invalid sequence number".to_string()))?;

            let hmac_hex = parts[1];
            let hmac_bytes = hex::decode(hmac_hex)
                .map_err(|e| SecureLogError::Parse(format!("Invalid HMAC hex: {}", e)))?;

            if hmac_bytes.len() != 32 {
                return Err(SecureLogError::Parse("Invalid HMAC length".to_string()));
            }

            last_sequence = seq;
            last_hmac.copy_from_slice(&hmac_bytes);
        }

        Ok((last_sequence, last_hmac))
    }

    /// Append a decision record to the log
    pub fn append(&mut self, record: &DecisionRecord) -> Result<(), SecureLogError> {
        // Verify sequence continuity
        if record.sequence != self.last_sequence + 1 {
            return Err(SecureLogError::SequenceGap {
                expected: self.last_sequence + 1,
                actual: record.sequence,
            });
        }

        // Serialize the record
        let json =
            serde_json::to_string(record).map_err(|e| SecureLogError::Serialize(e.to_string()))?;

        // Optionally encrypt
        let data = if let Some(ref key) = self.config.encryption_key {
            Self::encrypt_data(key, record.sequence, json.as_bytes())?
        } else {
            json
        };

        // Compute HMAC chain: HMAC(prev_hmac || sequence || data)
        let mut mac = HmacSha256::new_from_slice(&self.config.hmac_key)
            .map_err(|e| SecureLogError::Crypto(e.to_string()))?;
        mac.update(&self.last_hmac);
        mac.update(&record.sequence.to_be_bytes());
        mac.update(data.as_bytes());
        let new_hmac: [u8; 32] = mac.finalize().into_bytes().into();

        // Write: sequence|hmac|data
        let line = format!(
            "{}|{}|{}",
            record.sequence,
            hex::encode(new_hmac),
            data
        );
        writeln!(self.writer, "{}", line).map_err(|e| SecureLogError::Io(e.to_string()))?;

        // Flush to ensure durability
        self.writer
            .flush()
            .map_err(|e| SecureLogError::Io(e.to_string()))?;

        self.last_sequence = record.sequence;
        self.last_hmac = new_hmac;

        Ok(())
    }

    /// Encrypt data using AES-256-CTR
    fn encrypt_data(key: &[u8; 32], nonce_base: u64, plaintext: &[u8]) -> Result<String, SecureLogError> {
        use aes::Aes256;
        use aes::cipher::{KeyIvInit, StreamCipher};
        use ctr::Ctr64BE;

        // Create nonce from sequence number (padded to 16 bytes)
        let mut nonce = [0u8; 16];
        nonce[8..16].copy_from_slice(&nonce_base.to_be_bytes());

        let mut cipher = Ctr64BE::<Aes256>::new(key.into(), &nonce.into());

        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        Ok(hex::encode(ciphertext))
    }

    /// Decrypt data using AES-256-CTR
    fn decrypt_data(key: &[u8; 32], nonce_base: u64, ciphertext_hex: &str) -> Result<String, SecureLogError> {
        use aes::Aes256;
        use aes::cipher::{KeyIvInit, StreamCipher};
        use ctr::Ctr64BE;

        let ciphertext = hex::decode(ciphertext_hex)
            .map_err(|e| SecureLogError::Parse(format!("Invalid ciphertext hex: {}", e)))?;

        // Create nonce from sequence number (padded to 16 bytes)
        let mut nonce = [0u8; 16];
        nonce[8..16].copy_from_slice(&nonce_base.to_be_bytes());

        let mut cipher = Ctr64BE::<Aes256>::new(key.into(), &nonce.into());

        let mut plaintext = ciphertext;
        cipher.apply_keystream(&mut plaintext);

        String::from_utf8(plaintext)
            .map_err(|e| SecureLogError::Parse(format!("Invalid UTF-8 after decryption: {}", e)))
    }

    /// Get the last recorded sequence number
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Verify and replay all records from the log
    ///
    /// This method verifies the HMAC chain integrity while replaying.
    /// Any tampering will be detected.
    pub fn replay_and_verify(&self) -> Result<Vec<DecisionRecord>, SecureLogError> {
        let file = File::open(&self.config.path).map_err(|e| SecureLogError::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut records = Vec::new();
        let mut expected_hmac = {
            let mut mac = HmacSha256::new_from_slice(&self.config.hmac_key)
                .map_err(|e| SecureLogError::Crypto(e.to_string()))?;
            mac.update(b"nklave-secure-log-genesis");
            mac.finalize().into_bytes()
        };

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| SecureLogError::Io(e.to_string()))?;
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.splitn(3, '|').collect();
            if parts.len() != 3 {
                return Err(SecureLogError::Parse(format!(
                    "Invalid line format at line {}",
                    line_num + 1
                )));
            }

            let seq: u64 = parts[0]
                .parse()
                .map_err(|_| SecureLogError::Parse("Invalid sequence number".to_string()))?;

            let hmac_hex = parts[1];
            let stored_hmac = hex::decode(hmac_hex)
                .map_err(|e| SecureLogError::Parse(format!("Invalid HMAC hex: {}", e)))?;

            let data = parts[2];

            // Verify HMAC chain
            let mut mac = HmacSha256::new_from_slice(&self.config.hmac_key)
                .map_err(|e| SecureLogError::Crypto(e.to_string()))?;
            mac.update(&expected_hmac);
            mac.update(&seq.to_be_bytes());
            mac.update(data.as_bytes());
            let computed_hmac = mac.finalize().into_bytes();

            if computed_hmac.as_slice() != stored_hmac.as_slice() {
                return Err(SecureLogError::IntegrityViolation {
                    sequence: seq,
                    expected: hex::encode(computed_hmac),
                    actual: hex::encode(&stored_hmac),
                });
            }

            // Decrypt if needed
            let json = if self.config.encryption_key.is_some() {
                Self::decrypt_data(self.config.encryption_key.as_ref().unwrap(), seq, data)?
            } else {
                data.to_string()
            };

            // Parse record
            let record: DecisionRecord =
                serde_json::from_str(&json).map_err(|e| SecureLogError::Parse(e.to_string()))?;

            if record.sequence != seq {
                return Err(SecureLogError::Parse(format!(
                    "Sequence mismatch: header says {}, record says {}",
                    seq, record.sequence
                )));
            }

            records.push(record);
            expected_hmac = computed_hmac;
        }

        debug!(
            record_count = records.len(),
            "Verified and replayed secure log"
        );

        Ok(records)
    }

    /// Replay records starting from a specific sequence (with verification)
    pub fn replay_from(&self, start_sequence: u64) -> Result<Vec<DecisionRecord>, SecureLogError> {
        let records = self.replay_and_verify()?;
        Ok(records
            .into_iter()
            .filter(|r| r.sequence >= start_sequence)
            .collect())
    }

    /// Sync the log to disk
    pub fn sync(&mut self) -> Result<(), SecureLogError> {
        self.writer
            .flush()
            .map_err(|e| SecureLogError::Io(e.to_string()))?;
        self.writer
            .get_ref()
            .sync_all()
            .map_err(|e| SecureLogError::Io(e.to_string()))?;
        Ok(())
    }

    /// Check if encryption is enabled
    pub fn is_encrypted(&self) -> bool {
        self.config.encryption_key.is_some()
    }
}

/// Errors related to the secure decision log
#[derive(Debug, Error)]
pub enum SecureLogError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Serialization error: {0}")]
    Serialize(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Sequence gap: expected {expected}, got {actual}")]
    SequenceGap { expected: u64, actual: u64 },

    #[error("Integrity violation at sequence {sequence}: expected HMAC {expected}, got {actual}")]
    IntegrityViolation {
        sequence: u64,
        expected: String,
        actual: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use nklave_core::policy::types::{PolicyDecision, SigningType};
    use tempfile::TempDir;

    fn make_record(seq: u64) -> DecisionRecord {
        DecisionRecord {
            sequence: seq,
            timestamp: 1234567890,
            validator_pubkey: [0u8; 48],
            request_type: SigningType::BlockProposal,
            decision: PolicyDecision::Allow,
            signing_root: [seq as u8; 32],
            prev_state_hash: [0u8; 32],
            signing_context: None,
        }
    }

    #[test]
    fn test_secure_log_integrity_only() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("secure.log");
        let hmac_key = [1u8; 32];

        let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
        let mut log = SecureDecisionLog::open(config).unwrap();

        assert_eq!(log.last_sequence(), 0);
        assert!(!log.is_encrypted());

        log.append(&make_record(1)).unwrap();
        log.append(&make_record(2)).unwrap();
        log.append(&make_record(3)).unwrap();

        assert_eq!(log.last_sequence(), 3);
    }

    #[test]
    fn test_secure_log_with_encryption() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("encrypted.log");
        let encryption_key = [2u8; 32];
        let hmac_key = [3u8; 32];

        let config = SecureLogConfig::with_encryption(&log_path, encryption_key, hmac_key);
        let mut log = SecureDecisionLog::open(config).unwrap();

        assert!(log.is_encrypted());

        log.append(&make_record(1)).unwrap();
        log.append(&make_record(2)).unwrap();

        assert_eq!(log.last_sequence(), 2);
    }

    #[test]
    fn test_secure_log_replay_and_verify() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("verify.log");
        let hmac_key = [4u8; 32];

        {
            let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
            let mut log = SecureDecisionLog::open(config).unwrap();
            log.append(&make_record(1)).unwrap();
            log.append(&make_record(2)).unwrap();
            log.append(&make_record(3)).unwrap();
        }

        // Reopen and verify
        let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
        let log = SecureDecisionLog::open(config).unwrap();

        let records = log.replay_and_verify().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].sequence, 1);
        assert_eq!(records[1].sequence, 2);
        assert_eq!(records[2].sequence, 3);
    }

    #[test]
    fn test_encrypted_log_replay() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("encrypted_replay.log");
        let encryption_key = [5u8; 32];
        let hmac_key = [6u8; 32];

        {
            let config = SecureLogConfig::with_encryption(&log_path, encryption_key, hmac_key);
            let mut log = SecureDecisionLog::open(config).unwrap();
            log.append(&make_record(1)).unwrap();
            log.append(&make_record(2)).unwrap();
        }

        // Reopen and verify
        let config = SecureLogConfig::with_encryption(&log_path, encryption_key, hmac_key);
        let log = SecureDecisionLog::open(config).unwrap();

        let records = log.replay_and_verify().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].signing_root, [1u8; 32]);
        assert_eq!(records[1].signing_root, [2u8; 32]);
    }

    #[test]
    fn test_tamper_detection() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("tamper.log");
        let hmac_key = [7u8; 32];

        {
            let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
            let mut log = SecureDecisionLog::open(config).unwrap();
            log.append(&make_record(1)).unwrap();
            log.append(&make_record(2)).unwrap();
        }

        // Tamper with the file - modify the JSON data portion
        let contents = std::fs::read_to_string(&log_path).unwrap();
        // Replace "sequence":1 with "sequence":9 to tamper with the data
        let tampered = contents.replace("\"sequence\":1", "\"sequence\":9");
        std::fs::write(&log_path, tampered).unwrap();

        // Verification should fail
        let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
        let log = SecureDecisionLog::open(config).unwrap();
        let result = log.replay_and_verify();

        assert!(matches!(result, Err(SecureLogError::IntegrityViolation { .. })));
    }

    #[test]
    fn test_wrong_hmac_key() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("wrong_key.log");
        let hmac_key1 = [8u8; 32];
        let hmac_key2 = [9u8; 32]; // Different key

        {
            let config = SecureLogConfig::integrity_only(&log_path, hmac_key1);
            let mut log = SecureDecisionLog::open(config).unwrap();
            log.append(&make_record(1)).unwrap();
        }

        // Try to verify with wrong key
        let config = SecureLogConfig::integrity_only(&log_path, hmac_key2);
        let log = SecureDecisionLog::open(config).unwrap();
        let result = log.replay_and_verify();

        assert!(matches!(result, Err(SecureLogError::IntegrityViolation { .. })));
    }

    #[test]
    fn test_sequence_gap_rejected() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("gap.log");
        let hmac_key = [10u8; 32];

        let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
        let mut log = SecureDecisionLog::open(config).unwrap();

        log.append(&make_record(1)).unwrap();
        let result = log.append(&make_record(5)); // Skip sequences

        assert!(matches!(result, Err(SecureLogError::SequenceGap { .. })));
    }

    #[test]
    fn test_replay_from_sequence() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("replay_from.log");
        let hmac_key = [11u8; 32];

        {
            let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
            let mut log = SecureDecisionLog::open(config).unwrap();
            for i in 1..=5 {
                log.append(&make_record(i)).unwrap();
            }
        }

        let config = SecureLogConfig::integrity_only(&log_path, hmac_key);
        let log = SecureDecisionLog::open(config).unwrap();

        let records = log.replay_from(3).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].sequence, 3);
        assert_eq!(records[2].sequence, 5);
    }
}
