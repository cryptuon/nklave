//! Append-only decision log
//!
//! Records all signing decisions for audit and state recovery

use nklave_core::state::integrity::DecisionRecord;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Append-only decision log
pub struct DecisionLog {
    path: PathBuf,
    writer: BufWriter<File>,
    last_sequence: u64,
}

impl DecisionLog {
    /// Open or create a decision log at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LogError> {
        let path = path.as_ref().to_path_buf();

        // Determine last sequence by reading existing log
        let last_sequence = if path.exists() {
            Self::read_last_sequence(&path)?
        } else {
            0
        };

        // Open for appending
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| LogError::Io(e.to_string()))?;

        let writer = BufWriter::new(file);

        Ok(Self {
            path,
            writer,
            last_sequence,
        })
    }

    /// Read the last sequence number from an existing log
    fn read_last_sequence(path: &Path) -> Result<u64, LogError> {
        let file = File::open(path).map_err(|e| LogError::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut last_sequence = 0u64;

        for line in reader.lines() {
            let line = line.map_err(|e| LogError::Io(e.to_string()))?;
            if line.is_empty() {
                continue;
            }

            let record: DecisionRecord =
                serde_json::from_str(&line).map_err(|e| LogError::Parse(e.to_string()))?;

            last_sequence = record.sequence;
        }

        Ok(last_sequence)
    }

    /// Append a decision record to the log
    pub fn append(&mut self, record: &DecisionRecord) -> Result<(), LogError> {
        // Verify sequence continuity
        if record.sequence != self.last_sequence + 1 {
            return Err(LogError::SequenceGap {
                expected: self.last_sequence + 1,
                actual: record.sequence,
            });
        }

        // Serialize and write
        let json = serde_json::to_string(record).map_err(|e| LogError::Serialize(e.to_string()))?;

        writeln!(self.writer, "{}", json).map_err(|e| LogError::Io(e.to_string()))?;

        // Flush to ensure durability
        self.writer
            .flush()
            .map_err(|e| LogError::Io(e.to_string()))?;

        self.last_sequence = record.sequence;

        Ok(())
    }

    /// Get the last recorded sequence number
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Replay all records from the log
    pub fn replay(&self) -> Result<Vec<DecisionRecord>, LogError> {
        let file = File::open(&self.path).map_err(|e| LogError::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut records = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(|e| LogError::Io(e.to_string()))?;
            if line.is_empty() {
                continue;
            }

            let record: DecisionRecord =
                serde_json::from_str(&line).map_err(|e| LogError::Parse(e.to_string()))?;

            records.push(record);
        }

        Ok(records)
    }

    /// Replay records starting from a specific sequence
    pub fn replay_from(&self, start_sequence: u64) -> Result<Vec<DecisionRecord>, LogError> {
        let records = self.replay()?;
        Ok(records
            .into_iter()
            .filter(|r| r.sequence >= start_sequence)
            .collect())
    }

    /// Sync the log to disk
    pub fn sync(&mut self) -> Result<(), LogError> {
        self.writer
            .flush()
            .map_err(|e| LogError::Io(e.to_string()))?;
        self.writer
            .get_ref()
            .sync_all()
            .map_err(|e| LogError::Io(e.to_string()))?;
        Ok(())
    }
}

/// Errors related to the decision log
#[derive(Debug, Error)]
pub enum LogError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Serialization error: {0}")]
    Serialize(String),

    #[error("Sequence gap: expected {expected}, got {actual}")]
    SequenceGap { expected: u64, actual: u64 },
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
            signing_root: [0u8; 32],
            prev_state_hash: [0u8; 32],
        }
    }

    #[test]
    fn test_log_create_and_append() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("decisions.log");

        let mut log = DecisionLog::open(&log_path).unwrap();
        assert_eq!(log.last_sequence(), 0);

        log.append(&make_record(1)).unwrap();
        assert_eq!(log.last_sequence(), 1);

        log.append(&make_record(2)).unwrap();
        assert_eq!(log.last_sequence(), 2);
    }

    #[test]
    fn test_log_replay() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("decisions.log");

        {
            let mut log = DecisionLog::open(&log_path).unwrap();
            log.append(&make_record(1)).unwrap();
            log.append(&make_record(2)).unwrap();
            log.append(&make_record(3)).unwrap();
        }

        // Reopen and replay
        let log = DecisionLog::open(&log_path).unwrap();
        assert_eq!(log.last_sequence(), 3);

        let records = log.replay().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].sequence, 1);
        assert_eq!(records[2].sequence, 3);
    }

    #[test]
    fn test_log_sequence_gap() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("decisions.log");

        let mut log = DecisionLog::open(&log_path).unwrap();
        log.append(&make_record(1)).unwrap();

        // Try to append with wrong sequence
        let result = log.append(&make_record(5));
        assert!(matches!(result, Err(LogError::SequenceGap { .. })));
    }
}
