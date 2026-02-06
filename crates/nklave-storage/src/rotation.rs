//! Log rotation for decision logs
//!
//! This module provides size-based log rotation with optional compression.
//! Old log files are renamed with timestamps and optionally compressed.

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Configuration for log rotation
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Maximum size in bytes before rotation
    pub max_size_bytes: u64,

    /// Maximum number of rotated files to keep
    pub max_files: u32,

    /// Whether to compress rotated files
    pub compress: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_files: 10,
            compress: false, // Compression requires flate2 feature
        }
    }
}

impl RotationConfig {
    /// Create a configuration for small logs (good for testing)
    pub fn small() -> Self {
        Self {
            max_size_bytes: 1024 * 1024, // 1 MB
            max_files: 5,
            compress: false,
        }
    }

    /// Create a configuration for production use
    pub fn production() -> Self {
        Self {
            max_size_bytes: 100 * 1024 * 1024, // 100 MB
            max_files: 10,
            compress: false,
        }
    }
}

/// Log rotator that manages log file rotation
pub struct LogRotator {
    /// Base path for the log file (e.g., "/var/log/nklave/decisions.log")
    base_path: PathBuf,

    /// Rotation configuration
    config: RotationConfig,
}

impl LogRotator {
    /// Create a new log rotator
    pub fn new(base_path: impl AsRef<Path>, config: RotationConfig) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            config,
        }
    }

    /// Check if rotation is needed based on file size
    pub fn needs_rotation(&self) -> bool {
        if let Ok(metadata) = fs::metadata(&self.base_path) {
            metadata.len() >= self.config.max_size_bytes
        } else {
            false
        }
    }

    /// Get the current file size
    pub fn current_size(&self) -> u64 {
        fs::metadata(&self.base_path).map(|m| m.len()).unwrap_or(0)
    }

    /// Perform log rotation
    ///
    /// This will:
    /// 1. Rename the current log file with a timestamp
    /// 2. Optionally compress the rotated file
    /// 3. Clean up old rotated files beyond max_files
    ///
    /// Returns the path to the rotated file.
    pub fn rotate(&self) -> Result<PathBuf, RotationError> {
        if !self.base_path.exists() {
            return Err(RotationError::FileNotFound(
                self.base_path.display().to_string(),
            ));
        }

        // Generate timestamp suffix
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Create rotated filename
        let rotated_name = format!(
            "{}.{}",
            self.base_path.file_name().unwrap().to_string_lossy(),
            timestamp
        );

        let rotated_path = self
            .base_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&rotated_name);

        // Rename current log to rotated path
        fs::rename(&self.base_path, &rotated_path)
            .map_err(|e| RotationError::Io(format!("Failed to rename log: {}", e)))?;

        info!(
            from = %self.base_path.display(),
            to = %rotated_path.display(),
            "Rotated log file"
        );

        // Cleanup old files
        self.cleanup_old_files()?;

        Ok(rotated_path)
    }

    /// List all rotated log files, sorted by age (newest first)
    pub fn list_rotated_files(&self) -> Result<Vec<PathBuf>, RotationError> {
        let dir = self
            .base_path
            .parent()
            .unwrap_or(Path::new("."));

        let base_name = self
            .base_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        let mut files: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|e| RotationError::Io(format!("Failed to read directory: {}", e)))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    // Match patterns like "decisions.log.1234567890"
                    name_str.starts_with(&format!("{}.", base_name))
                        && name_str != base_name
                } else {
                    false
                }
            })
            .collect();

        // Sort by modification time (newest first)
        files.sort_by(|a, b| {
            let a_time = fs::metadata(a)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let b_time = fs::metadata(b)
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            b_time.cmp(&a_time)
        });

        Ok(files)
    }

    /// Cleanup old rotated files beyond max_files limit
    fn cleanup_old_files(&self) -> Result<(), RotationError> {
        let files = self.list_rotated_files()?;

        if files.len() as u32 > self.config.max_files {
            let to_delete = &files[self.config.max_files as usize..];

            for file in to_delete {
                debug!(path = %file.display(), "Deleting old rotated log");
                fs::remove_file(file).map_err(|e| {
                    RotationError::Io(format!("Failed to delete {}: {}", file.display(), e))
                })?;
            }

            info!(
                deleted = to_delete.len(),
                "Cleaned up old rotated log files"
            );
        }

        Ok(())
    }

    /// Get total size of all log files (current + rotated)
    pub fn total_log_size(&self) -> Result<u64, RotationError> {
        let mut total = self.current_size();

        for file in self.list_rotated_files()? {
            if let Ok(metadata) = fs::metadata(&file) {
                total += metadata.len();
            }
        }

        Ok(total)
    }

    /// Read records from a rotated log file
    ///
    /// This is useful for forensic analysis or state recovery.
    pub fn read_rotated_file<T, F>(&self, path: &Path, parse_fn: F) -> Result<Vec<T>, RotationError>
    where
        F: Fn(&str) -> Result<T, String>,
    {
        let file =
            File::open(path).map_err(|e| RotationError::Io(format!("Failed to open: {}", e)))?;

        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| RotationError::Io(e.to_string()))?;
            if line.is_empty() {
                continue;
            }

            match parse_fn(&line) {
                Ok(record) => records.push(record),
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        line = line_num + 1,
                        error = %e,
                        "Failed to parse record in rotated log"
                    );
                }
            }
        }

        Ok(records)
    }
}

/// Errors from log rotation
#[derive(Debug, Error)]
pub enum RotationError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_rotation_config_default() {
        let config = RotationConfig::default();
        assert_eq!(config.max_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_files, 10);
        assert!(!config.compress);
    }

    #[test]
    fn test_needs_rotation() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        // Create a small log
        {
            let mut file = File::create(&log_path).unwrap();
            file.write_all(b"test data").unwrap();
        }

        let config = RotationConfig {
            max_size_bytes: 100, // Very small for testing
            max_files: 5,
            compress: false,
        };

        let rotator = LogRotator::new(&log_path, config);
        assert!(!rotator.needs_rotation()); // 9 bytes < 100 bytes

        // Write more data
        {
            let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
            file.write_all(&[0u8; 200]).unwrap();
        }

        assert!(rotator.needs_rotation()); // Now > 100 bytes
    }

    #[test]
    fn test_rotate_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("decisions.log");

        // Create initial log
        {
            let mut file = File::create(&log_path).unwrap();
            file.write_all(b"original content").unwrap();
        }

        let config = RotationConfig::small();
        let rotator = LogRotator::new(&log_path, config);

        let rotated_path = rotator.rotate().unwrap();

        // Original should not exist
        assert!(!log_path.exists());

        // Rotated should exist
        assert!(rotated_path.exists());

        // Rotated content should match original
        let content = fs::read_to_string(&rotated_path).unwrap();
        assert_eq!(content, "original content");
    }

    #[test]
    fn test_list_rotated_files() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        // Create some rotated files
        for i in 1..=3 {
            let rotated = dir.path().join(format!("test.log.{}", 1000 + i));
            File::create(&rotated).unwrap();
            // Add small delay to ensure different timestamps
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Create current log
        File::create(&log_path).unwrap();

        let config = RotationConfig::small();
        let rotator = LogRotator::new(&log_path, config);

        let files = rotator.list_rotated_files().unwrap();
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_cleanup_old_files() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        // Create more rotated files than max_files
        for i in 1..=10 {
            let rotated = dir.path().join(format!("test.log.{}", 1000 + i));
            File::create(&rotated).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        // Create current log
        File::create(&log_path).unwrap();

        let config = RotationConfig {
            max_size_bytes: 1024,
            max_files: 3, // Keep only 3
            compress: false,
        };

        let rotator = LogRotator::new(&log_path, config);

        // Trigger cleanup
        rotator.cleanup_old_files().unwrap();

        // Should only have 3 files left
        let files = rotator.list_rotated_files().unwrap();
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_total_log_size() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");

        // Create current log with known size
        {
            let mut file = File::create(&log_path).unwrap();
            file.write_all(&[0u8; 100]).unwrap();
        }

        // Create rotated files
        for i in 1..=2 {
            let rotated = dir.path().join(format!("test.log.{}", 1000 + i));
            let mut file = File::create(&rotated).unwrap();
            file.write_all(&[0u8; 50]).unwrap();
        }

        let config = RotationConfig::small();
        let rotator = LogRotator::new(&log_path, config);

        let total = rotator.total_log_size().unwrap();
        assert_eq!(total, 100 + 50 + 50); // 200 bytes total
    }

    #[test]
    fn test_read_rotated_file() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("test.log");
        let rotated_path = dir.path().join("test.log.12345");

        // Create rotated file with parseable content
        {
            let mut file = File::create(&rotated_path).unwrap();
            writeln!(file, "line1").unwrap();
            writeln!(file, "line2").unwrap();
            writeln!(file, "line3").unwrap();
        }

        // Create current log
        File::create(&log_path).unwrap();

        let config = RotationConfig::small();
        let rotator = LogRotator::new(&log_path, config);

        let records: Vec<String> = rotator
            .read_rotated_file(&rotated_path, |line| Ok(line.to_string()))
            .unwrap();

        assert_eq!(records.len(), 3);
        assert_eq!(records[0], "line1");
        assert_eq!(records[2], "line3");
    }
}
