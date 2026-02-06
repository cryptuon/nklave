//! Checkpoint management commands

use crate::OutputFormat;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use comfy_table::{Cell, Table};
use nklave_storage::Checkpoint;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

/// Checkpoint information for display
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointInfo {
    pub path: String,
    pub created_at: String,
    pub sequence_number: u64,
    pub validator_count: usize,
    pub state_hash: String,
    pub genesis_root: Option<String>,
}

impl fmt::Display for CheckpointInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Checkpoint Information")?;
        writeln!(f, "======================")?;
        writeln!(f, "Path:         {}", self.path)?;
        writeln!(f, "Created:      {}", self.created_at)?;
        writeln!(f, "Sequence:     {}", self.sequence_number)?;
        writeln!(f, "Validators:   {}", self.validator_count)?;
        writeln!(f, "State Hash:   {}", self.state_hash)?;
        if let Some(ref root) = self.genesis_root {
            writeln!(f, "Genesis Root: {}", root)?;
        }
        Ok(())
    }
}

/// List of checkpoints for display
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointList {
    pub checkpoints: Vec<CheckpointSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointSummary {
    pub filename: String,
    pub size: u64,
    pub modified: String,
    pub sequence: Option<u64>,
}

impl fmt::Display for CheckpointList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.checkpoints.is_empty() {
            writeln!(f, "No checkpoint files found.")?;
            return Ok(());
        }

        let mut table = Table::new();
        table.set_header(vec!["Filename", "Size", "Modified", "Sequence"]);

        for cp in &self.checkpoints {
            table.add_row(vec![
                Cell::new(&cp.filename),
                Cell::new(format_size(cp.size)),
                Cell::new(&cp.modified),
                Cell::new(cp.sequence.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string())),
            ]);
        }

        write!(f, "{}", table)
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Create a manual checkpoint via the API
pub async fn create(api_url: &str, _path: Option<&str>, format: OutputFormat) -> Result<()> {
    let client = super::create_client();

    // Call the admin checkpoint endpoint
    let response = client
        .post(format!("{}/admin/checkpoint", api_url))
        .send()
        .await
        .context("Failed to connect to Nklave API")?;

    if response.status().is_success() {
        #[derive(Serialize)]
        struct CreateResult {
            success: bool,
            message: String,
        }

        impl fmt::Display for CreateResult {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                writeln!(f, "Checkpoint created successfully.")
            }
        }

        let result = CreateResult {
            success: true,
            message: "Checkpoint created successfully".to_string(),
        };
        super::print_output(&result, format);
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Failed to create checkpoint: {} - {}", status, body)
    }
}

/// Show information about a checkpoint file
pub async fn info(path: &str, format: OutputFormat) -> Result<()> {
    let checkpoint = Checkpoint::load(Path::new(path))
        .context(format!("Failed to load checkpoint from {}", path))?;

    let info = CheckpointInfo {
        path: path.to_string(),
        created_at: DateTime::<Utc>::from_timestamp(checkpoint.timestamp as i64, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string()),
        sequence_number: checkpoint.sequence,
        validator_count: checkpoint.validators.len(),
        state_hash: hex::encode(checkpoint.state_hash),
        genesis_root: checkpoint.genesis_validators_root.map(hex::encode),
    };

    super::print_output(&info, format);
    Ok(())
}

/// List checkpoint files in a directory
pub async fn list(dir: &str, format: OutputFormat) -> Result<()> {
    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        anyhow::bail!("{} is not a directory", dir);
    }

    let mut checkpoints = Vec::new();

    for entry in std::fs::read_dir(dir_path).context("Failed to read directory")? {
        let entry = entry?;
        let path = entry.path();

        // Look for .json files that might be checkpoints
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            let metadata = entry.metadata()?;
            let size = metadata.len();
            let modified = metadata.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| DateTime::<Utc>::from_timestamp(d.as_secs() as i64, 0))
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Unknown".to_string());

            // Try to load and get sequence number
            let sequence = Checkpoint::load(&path)
                .ok()
                .map(|cp| cp.sequence);

            // Only include files that look like checkpoints
            if filename.contains("checkpoint") || sequence.is_some() {
                checkpoints.push(CheckpointSummary {
                    filename,
                    size,
                    modified,
                    sequence,
                });
            }
        }
    }

    // Sort by sequence number (descending) or modified time
    checkpoints.sort_by(|a, b| {
        match (a.sequence, b.sequence) {
            (Some(sa), Some(sb)) => sb.cmp(&sa),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => b.modified.cmp(&a.modified),
        }
    });

    let list = CheckpointList { checkpoints };
    super::print_output(&list, format);
    Ok(())
}
