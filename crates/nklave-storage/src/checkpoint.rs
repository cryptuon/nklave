//! State checkpoints for fast recovery
//!
//! Checkpoints allow the enclave to skip replaying the entire log on startup

use nklave_core::state::integrity::StateIntegrity;
use nklave_core::state::validator::ValidatorState;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use thiserror::Error;

/// Serialize [u8; 32] as hex
fn serialize_hash<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserialize [u8; 32] from hex
fn deserialize_hash<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Serialize Option<[u8; 32]> as hex
fn serialize_option_hash<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match bytes {
        Some(b) => serializer.serialize_some(&hex::encode(b)),
        None => serializer.serialize_none(),
    }
}

/// Deserialize Option<[u8; 32]> from hex
fn deserialize_option_hash<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Deserialize::deserialize(deserializer)?;
    match opt {
        Some(s) => {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

/// Serialize HashMap<[u8; 48], ValidatorState> with hex keys
fn serialize_validators<S>(
    validators: &HashMap<[u8; 48], ValidatorState>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeMap;
    let mut map = serializer.serialize_map(Some(validators.len()))?;
    for (k, v) in validators {
        map.serialize_entry(&hex::encode(k), v)?;
    }
    map.end()
}

/// Deserialize HashMap<[u8; 48], ValidatorState> with hex keys
fn deserialize_validators<'de, D>(
    deserializer: D,
) -> Result<HashMap<[u8; 48], ValidatorState>, D::Error>
where
    D: Deserializer<'de>,
{
    let string_map: HashMap<String, ValidatorState> = Deserialize::deserialize(deserializer)?;
    let mut result = HashMap::new();
    for (k, v) in string_map {
        let k = k.strip_prefix("0x").unwrap_or(&k);
        let bytes = hex::decode(k).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        result.insert(arr, v);
    }
    Ok(result)
}

/// A checkpoint of the enclave state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Sequence number at this checkpoint
    pub sequence: u64,

    /// State hash at this checkpoint
    #[serde(serialize_with = "serialize_hash", deserialize_with = "deserialize_hash")]
    pub state_hash: [u8; 32],

    /// Genesis validators root (if set)
    #[serde(serialize_with = "serialize_option_hash", deserialize_with = "deserialize_option_hash")]
    pub genesis_validators_root: Option<[u8; 32]>,

    /// All validator states
    #[serde(serialize_with = "serialize_validators", deserialize_with = "deserialize_validators")]
    pub validators: HashMap<[u8; 48], ValidatorState>,

    /// Unix timestamp when checkpoint was created
    pub timestamp: u64,
}

impl Checkpoint {
    /// Create a new checkpoint from current state
    pub fn new(
        integrity: &StateIntegrity,
        validators: HashMap<[u8; 48], ValidatorState>,
    ) -> Self {
        Self {
            sequence: integrity.sequence_number,
            state_hash: integrity.current_hash,
            genesis_validators_root: integrity.genesis_validators_root,
            validators,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Save checkpoint to a file (simple, non-atomic)
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CheckpointError> {
        let file = File::create(path).map_err(|e| CheckpointError::Io(e.to_string()))?;
        let writer = BufWriter::new(file);

        serde_json::to_writer_pretty(writer, self)
            .map_err(|e| CheckpointError::Serialize(e.to_string()))?;

        Ok(())
    }

    /// Save checkpoint atomically with backup rotation
    ///
    /// This method:
    /// 1. Writes to a temporary file
    /// 2. Rotates existing checkpoint to backup
    /// 3. Atomically renames temp to target
    /// 4. Syncs the parent directory for durability
    pub fn save_atomic(&self, path: impl AsRef<Path>, backup_count: u32) -> Result<(), CheckpointError> {
        let path = path.as_ref();
        let parent = path.parent().ok_or_else(|| {
            CheckpointError::Io("Checkpoint path has no parent directory".to_string())
        })?;

        // Ensure parent directory exists
        std::fs::create_dir_all(parent)
            .map_err(|e| CheckpointError::Io(format!("Failed to create directory: {}", e)))?;

        // Write to temporary file
        let temp_path = path.with_extension("json.tmp");
        {
            let file = File::create(&temp_path)
                .map_err(|e| CheckpointError::Io(format!("Failed to create temp file: {}", e)))?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, self)
                .map_err(|e| CheckpointError::Serialize(e.to_string()))?;
            writer.into_inner()
                .map_err(|e| CheckpointError::Io(format!("Failed to flush temp file: {}", e)))?
                .sync_all()
                .map_err(|e| CheckpointError::Io(format!("Failed to sync temp file: {}", e)))?;
        }

        // Rotate backups if the main checkpoint exists
        if path.exists() {
            Self::rotate_backups(path, backup_count)?;
        }

        // Atomic rename
        std::fs::rename(&temp_path, path)
            .map_err(|e| CheckpointError::Io(format!("Failed to rename temp to checkpoint: {}", e)))?;

        // Sync parent directory for durability
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }

        Ok(())
    }

    /// Rotate backup files
    ///
    /// Shifts checkpoint.json.1 -> checkpoint.json.2, etc.
    /// Then renames current checkpoint to checkpoint.json.1
    fn rotate_backups(path: &Path, backup_count: u32) -> Result<(), CheckpointError> {
        if backup_count == 0 {
            return Ok(());
        }

        // Remove oldest backup if it exists
        let oldest = path.with_extension(format!("json.{}", backup_count));
        if oldest.exists() {
            std::fs::remove_file(&oldest)
                .map_err(|e| CheckpointError::Io(format!("Failed to remove oldest backup: {}", e)))?;
        }

        // Shift existing backups
        for i in (1..backup_count).rev() {
            let from = path.with_extension(format!("json.{}", i));
            let to = path.with_extension(format!("json.{}", i + 1));
            if from.exists() {
                std::fs::rename(&from, &to)
                    .map_err(|e| CheckpointError::Io(format!("Failed to rotate backup: {}", e)))?;
            }
        }

        // Move current checkpoint to .1
        let backup1 = path.with_extension("json.1");
        std::fs::rename(path, &backup1)
            .map_err(|e| CheckpointError::Io(format!("Failed to create backup: {}", e)))?;

        Ok(())
    }

    /// Load checkpoint from a file
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CheckpointError> {
        let file = File::open(path).map_err(|e| CheckpointError::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).map_err(|e| CheckpointError::Parse(e.to_string()))
    }

    /// Load checkpoint with fallback to backups
    ///
    /// Tries to load from the primary checkpoint, then falls back to backups
    pub fn load_with_recovery(path: impl AsRef<Path>, backup_count: u32) -> Result<Self, CheckpointError> {
        let path = path.as_ref();

        // Try primary checkpoint
        if let Ok(checkpoint) = Self::load(path) {
            return Ok(checkpoint);
        }

        // Try backups in order
        for i in 1..=backup_count {
            let backup_path = path.with_extension(format!("json.{}", i));
            if let Ok(checkpoint) = Self::load(&backup_path) {
                tracing::warn!(
                    backup = i,
                    "Recovered checkpoint from backup"
                );
                return Ok(checkpoint);
            }
        }

        Err(CheckpointError::Io("No valid checkpoint found (tried primary and all backups)".to_string()))
    }

    /// Restore state integrity from this checkpoint
    pub fn restore_integrity(&self) -> StateIntegrity {
        StateIntegrity::from_checkpoint(
            self.state_hash,
            self.sequence,
            self.genesis_validators_root,
        )
    }
}

/// Errors related to checkpoints
#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Serialization error: {0}")]
    Serialize(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_checkpoint_save_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("checkpoint.json");

        let integrity = StateIntegrity::new();
        let validators = HashMap::new();

        let checkpoint = Checkpoint::new(&integrity, validators);
        checkpoint.save(&path).unwrap();

        let loaded = Checkpoint::load(&path).unwrap();
        assert_eq!(loaded.sequence, checkpoint.sequence);
        assert_eq!(loaded.state_hash, checkpoint.state_hash);
    }
}
