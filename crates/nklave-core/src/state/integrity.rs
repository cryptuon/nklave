//! State integrity management with hash chaining
//!
//! Provides rollback detection through cryptographic chaining of decisions

use crate::policy::types::{PolicyDecision, SigningType};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Serialize a fixed-size byte array as hex
fn serialize_bytes<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserialize a fixed-size byte array from hex
fn deserialize_bytes<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    if bytes.len() != N {
        return Err(serde::de::Error::custom(format!(
            "expected {} bytes, got {}",
            N,
            bytes.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Serialize Option<[u8; N]> as hex
fn serialize_option_bytes<S, const N: usize>(
    bytes: &Option<[u8; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(b) => serializer.serialize_some(&hex::encode(b)),
        None => serializer.serialize_none(),
    }
}

/// Deserialize Option<[u8; N]> from hex
fn deserialize_option_bytes<'de, D, const N: usize>(
    deserializer: D,
) -> Result<Option<[u8; N]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            if bytes.len() != N {
                return Err(serde::de::Error::custom(format!(
                    "expected {} bytes, got {}",
                    N,
                    bytes.len()
                )));
            }
            let mut arr = [0u8; N];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

/// State integrity tracker
///
/// Maintains a hash chain of all signing decisions to detect rollback attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateIntegrity {
    /// Current state hash (hash of all decisions up to now)
    #[serde(serialize_with = "serialize_bytes::<_, 32>", deserialize_with = "deserialize_bytes::<_, 32>")]
    pub current_hash: [u8; 32],

    /// Sequence number of the last recorded decision
    pub sequence_number: u64,

    /// Genesis validators root (locked on first signing request)
    #[serde(serialize_with = "serialize_option_bytes::<_, 32>", deserialize_with = "deserialize_option_bytes::<_, 32>")]
    pub genesis_validators_root: Option<[u8; 32]>,
}

impl StateIntegrity {
    /// Create a new state integrity tracker
    pub fn new() -> Self {
        Self {
            current_hash: [0u8; 32], // Initial hash is all zeros
            sequence_number: 0,
            genesis_validators_root: None,
        }
    }

    /// Create from a checkpoint
    pub fn from_checkpoint(hash: [u8; 32], sequence: u64, genesis_root: Option<[u8; 32]>) -> Self {
        Self {
            current_hash: hash,
            sequence_number: sequence,
            genesis_validators_root: genesis_root,
        }
    }

    /// Lock the genesis validators root (can only be set once)
    pub fn set_genesis_validators_root(&mut self, root: [u8; 32]) -> Result<(), IntegrityError> {
        match self.genesis_validators_root {
            Some(existing) if existing != root => Err(IntegrityError::GenesisRootMismatch {
                expected: existing,
                actual: root,
            }),
            Some(_) => Ok(()), // Already set to same value
            None => {
                self.genesis_validators_root = Some(root);
                Ok(())
            }
        }
    }

    /// Record a new decision and update the hash chain
    ///
    /// Returns the new state hash after recording
    pub fn record_decision(&mut self, record: &DecisionRecord) -> Result<[u8; 32], IntegrityError> {
        // Verify sequence continuity
        let expected_sequence = self.sequence_number + 1;
        if record.sequence != expected_sequence {
            return Err(IntegrityError::SequenceGap {
                expected: expected_sequence,
                actual: record.sequence,
            });
        }

        // Verify hash chain continuity
        if record.prev_state_hash != self.current_hash {
            return Err(IntegrityError::HashMismatch {
                expected: self.current_hash,
                actual: record.prev_state_hash,
            });
        }

        // Compute new hash: H(prev_hash || record_bytes)
        let record_bytes = bincode::serialize(record).map_err(|e| IntegrityError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(self.current_hash);
        hasher.update(&record_bytes);
        let new_hash: [u8; 32] = hasher.finalize().into();

        // Update state
        self.current_hash = new_hash;
        self.sequence_number = record.sequence;

        Ok(new_hash)
    }

    /// Create a decision record with proper sequencing
    pub fn prepare_record(
        &self,
        validator_pubkey: [u8; 48],
        request_type: SigningType,
        decision: PolicyDecision,
        signing_root: [u8; 32],
    ) -> DecisionRecord {
        DecisionRecord {
            sequence: self.sequence_number + 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            validator_pubkey,
            request_type,
            decision,
            signing_root,
            prev_state_hash: self.current_hash,
        }
    }

    /// Verify a sequence of records against expected hash chain
    pub fn verify_records<'a, I>(&self, records: I) -> Result<(), IntegrityError>
    where
        I: IntoIterator<Item = &'a DecisionRecord>,
    {
        let mut expected_hash = self.current_hash;
        let mut expected_sequence = self.sequence_number;

        for record in records {
            expected_sequence += 1;

            if record.sequence != expected_sequence {
                return Err(IntegrityError::SequenceGap {
                    expected: expected_sequence,
                    actual: record.sequence,
                });
            }

            if record.prev_state_hash != expected_hash {
                return Err(IntegrityError::HashMismatch {
                    expected: expected_hash,
                    actual: record.prev_state_hash,
                });
            }

            // Compute expected new hash
            let record_bytes = bincode::serialize(record)
                .map_err(|e| IntegrityError::SerializationError(e.to_string()))?;

            let mut hasher = Sha256::new();
            hasher.update(expected_hash);
            hasher.update(&record_bytes);
            expected_hash = hasher.finalize().into();
        }

        Ok(())
    }
}

impl Default for StateIntegrity {
    fn default() -> Self {
        Self::new()
    }
}

/// A record of a signing decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    /// Sequence number (monotonically increasing)
    pub sequence: u64,

    /// Unix timestamp of the decision
    pub timestamp: u64,

    /// Validator public key
    #[serde(serialize_with = "serialize_bytes::<_, 48>", deserialize_with = "deserialize_bytes::<_, 48>")]
    pub validator_pubkey: [u8; 48],

    /// Type of signing request
    pub request_type: SigningType,

    /// Decision made (Allow or Refuse with code)
    pub decision: PolicyDecision,

    /// Signing root of the request
    #[serde(serialize_with = "serialize_bytes::<_, 32>", deserialize_with = "deserialize_bytes::<_, 32>")]
    pub signing_root: [u8; 32],

    /// Hash of state before this decision
    #[serde(serialize_with = "serialize_bytes::<_, 32>", deserialize_with = "deserialize_bytes::<_, 32>")]
    pub prev_state_hash: [u8; 32],
}

impl DecisionRecord {
    /// Compute the hash of this record
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("serialization should not fail");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }
}

/// Errors related to state integrity
#[derive(Debug, Clone, thiserror::Error)]
pub enum IntegrityError {
    #[error("Sequence gap: expected {expected}, got {actual}")]
    SequenceGap { expected: u64, actual: u64 },

    #[error("Hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch { expected: [u8; 32], actual: [u8; 32] },

    #[error("Genesis validators root mismatch: expected {expected:?}, got {actual:?}")]
    GenesisRootMismatch { expected: [u8; 32], actual: [u8; 32] },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Log truncated: missing records after sequence {last_seen}")]
    LogTruncated { last_seen: u64 },

    #[error("Log corrupted: invalid record at sequence {sequence}")]
    LogCorrupted { sequence: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root(val: u8) -> [u8; 32] {
        let mut root = [0u8; 32];
        root[0] = val;
        root
    }

    #[test]
    fn test_state_integrity_new() {
        let integrity = StateIntegrity::new();
        assert_eq!(integrity.current_hash, [0u8; 32]);
        assert_eq!(integrity.sequence_number, 0);
        assert!(integrity.genesis_validators_root.is_none());
    }

    #[test]
    fn test_record_decision() {
        let mut integrity = StateIntegrity::new();

        let record = integrity.prepare_record(
            [0u8; 48],
            SigningType::BlockProposal,
            PolicyDecision::Allow,
            make_root(1),
        );

        let new_hash = integrity.record_decision(&record).unwrap();

        assert_ne!(new_hash, [0u8; 32]);
        assert_eq!(integrity.sequence_number, 1);
        assert_eq!(integrity.current_hash, new_hash);
    }

    #[test]
    fn test_sequence_gap_detection() {
        let mut integrity = StateIntegrity::new();

        // Create a record with wrong sequence
        let mut record = integrity.prepare_record(
            [0u8; 48],
            SigningType::BlockProposal,
            PolicyDecision::Allow,
            make_root(1),
        );
        record.sequence = 5; // Wrong sequence

        let result = integrity.record_decision(&record);
        assert!(matches!(result, Err(IntegrityError::SequenceGap { .. })));
    }

    #[test]
    fn test_hash_mismatch_detection() {
        let mut integrity = StateIntegrity::new();

        // Create a record with wrong prev_state_hash
        let mut record = integrity.prepare_record(
            [0u8; 48],
            SigningType::BlockProposal,
            PolicyDecision::Allow,
            make_root(1),
        );
        record.prev_state_hash = make_root(99); // Wrong hash

        let result = integrity.record_decision(&record);
        assert!(matches!(result, Err(IntegrityError::HashMismatch { .. })));
    }

    #[test]
    fn test_genesis_root_locking() {
        let mut integrity = StateIntegrity::new();
        let root1 = make_root(1);
        let root2 = make_root(2);

        // First set should succeed
        assert!(integrity.set_genesis_validators_root(root1).is_ok());

        // Same root should succeed
        assert!(integrity.set_genesis_validators_root(root1).is_ok());

        // Different root should fail
        assert!(matches!(
            integrity.set_genesis_validators_root(root2),
            Err(IntegrityError::GenesisRootMismatch { .. })
        ));
    }

    #[test]
    fn test_verify_records() {
        let mut integrity = StateIntegrity::new();
        let mut records = Vec::new();

        // Create and record multiple decisions
        for i in 0..3 {
            let record = integrity.prepare_record(
                [0u8; 48],
                SigningType::BlockProposal,
                PolicyDecision::Allow,
                make_root(i),
            );
            integrity.record_decision(&record).unwrap();
            records.push(record);
        }

        // Verify from the beginning
        let fresh_integrity = StateIntegrity::new();
        assert!(fresh_integrity.verify_records(&records).is_ok());
    }
}
