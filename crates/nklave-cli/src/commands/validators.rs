//! Validator management commands

use crate::OutputFormat;
use anyhow::{Context, Result};
use comfy_table::{Cell, Table};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Validator list for display
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorList {
    pub validators: Vec<ValidatorInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub pubkey: String,
    pub short_pubkey: String,
}

impl fmt::Display for ValidatorList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.validators.is_empty() {
            writeln!(f, "No validators registered.")?;
            return Ok(());
        }

        writeln!(f, "Registered Validators: {}", self.validators.len())?;
        writeln!(f)?;

        let mut table = Table::new();
        table.set_header(vec!["#", "Public Key"]);

        for (i, v) in self.validators.iter().enumerate() {
            table.add_row(vec![
                Cell::new(i + 1),
                Cell::new(&v.pubkey),
            ]);
        }

        write!(f, "{}", table)
    }
}

/// Validator watermarks for display
#[derive(Debug, Serialize, Deserialize)]
pub struct WatermarkInfo {
    pub pubkey: String,
    pub chain_type: String,
    pub last_signed_block_slot: Option<u64>,
    pub highest_source_epoch: u64,
    pub highest_target_epoch: u64,
    pub attestation_count: usize,
    pub block_count: usize,
}

impl fmt::Display for WatermarkInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Validator Watermarks")?;
        writeln!(f, "====================")?;
        writeln!(f, "Public Key:          {}...", &self.pubkey[..20])?;
        writeln!(f, "Chain Type:          {}", self.chain_type)?;
        if let Some(slot) = self.last_signed_block_slot {
            writeln!(f, "Last Block Slot:     {}", slot)?;
        }
        writeln!(f, "Highest Source Epoch: {}", self.highest_source_epoch)?;
        writeln!(f, "Highest Target Epoch: {}", self.highest_target_epoch)?;
        writeln!(f, "Attestations Tracked: {}", self.attestation_count)?;
        writeln!(f, "Blocks Tracked:       {}", self.block_count)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WatermarkList {
    pub validators: Vec<WatermarkInfo>,
}

impl fmt::Display for WatermarkList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.validators.is_empty() {
            writeln!(f, "No validators registered.")?;
            return Ok(());
        }

        for (i, v) in self.validators.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{}", v)?;
        }
        Ok(())
    }
}

/// Signing statistics
#[derive(Debug, Serialize, Deserialize)]
pub struct SigningStats {
    pub total_signatures: u64,
    pub total_refusals: u64,
    pub signatures_by_type: Vec<(String, u64)>,
    pub refusals_by_code: Vec<(String, u64)>,
}

impl fmt::Display for SigningStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Signing Statistics")?;
        writeln!(f, "==================")?;
        writeln!(f, "Total Signatures: {}", self.total_signatures)?;
        writeln!(f, "Total Refusals:   {}", self.total_refusals)?;
        writeln!(f)?;

        if !self.signatures_by_type.is_empty() {
            writeln!(f, "Signatures by Type:")?;
            for (sig_type, count) in &self.signatures_by_type {
                writeln!(f, "  {}: {}", sig_type, count)?;
            }
            writeln!(f)?;
        }

        if !self.refusals_by_code.is_empty() {
            writeln!(f, "Refusals by Code:")?;
            for (code, count) in &self.refusals_by_code {
                writeln!(f, "  {}: {}", code, count)?;
            }
        }

        Ok(())
    }
}

/// List registered validators
pub async fn list(api_url: &str, format: OutputFormat) -> Result<()> {
    let client = super::create_client();

    let response = client
        .get(format!("{}/api/v1/eth2/publicKeys", api_url))
        .send()
        .await
        .context("Failed to connect to Nklave API")?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to get validator list: {}", response.status());
    }

    let pubkeys: Vec<String> = response.json().await.context("Failed to parse response")?;

    let validators: Vec<ValidatorInfo> = pubkeys
        .into_iter()
        .map(|pubkey| {
            let short = if pubkey.len() > 20 {
                format!("{}...", &pubkey[..20])
            } else {
                pubkey.clone()
            };
            ValidatorInfo {
                pubkey,
                short_pubkey: short,
            }
        })
        .collect();

    let list = ValidatorList { validators };
    super::print_output(&list, format);
    Ok(())
}

/// Show validator watermarks
pub async fn watermarks(api_url: &str, pubkey: Option<&str>, format: OutputFormat) -> Result<()> {
    let client = super::create_client();

    // Get validator state from admin endpoint
    let response = client
        .get(format!("{}/admin/state", api_url))
        .send()
        .await
        .context("Failed to connect to Nklave API")?;

    if !response.status().is_success() {
        let status = response.status();
        // Try to get list from public keys endpoint as fallback
        if status.as_u16() == 404 {
            eprintln!("Note: Admin state endpoint not available. Showing basic validator info.");
            return list(api_url, format).await;
        }
        anyhow::bail!("Failed to get validator state: {}", status);
    }

    let state: serde_json::Value = response.json().await.context("Failed to parse response")?;

    let mut validators = Vec::new();

    if let Some(validator_states) = state.get("validators").and_then(|v| v.as_object()) {
        for (pk, vs) in validator_states {
            // Filter by pubkey if specified
            if let Some(filter_pk) = pubkey {
                let filter_pk = filter_pk.strip_prefix("0x").unwrap_or(filter_pk);
                let pk_clean = pk.strip_prefix("0x").unwrap_or(pk);
                if !pk_clean.to_lowercase().starts_with(&filter_pk.to_lowercase()) {
                    continue;
                }
            }

            let chain_type = vs.get("chain_state")
                .and_then(|cs| cs.get("chain_type"))
                .and_then(|ct| ct.as_str())
                .unwrap_or("Ethereum")
                .to_string();

            let last_signed_block_slot = vs.get("last_signed_block_slot")
                .and_then(|v| v.as_u64());

            let highest_source_epoch = vs.get("highest_source_epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let highest_target_epoch = vs.get("highest_target_epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let attestation_count = vs.get("attestation_history")
                .and_then(|ah| ah.get("signed_attestations"))
                .and_then(|sa| sa.as_object())
                .map(|o| o.len())
                .unwrap_or(0);

            let block_count = vs.get("block_signing_roots")
                .and_then(|bsr| bsr.as_object())
                .map(|o| o.len())
                .unwrap_or(0);

            validators.push(WatermarkInfo {
                pubkey: pk.clone(),
                chain_type,
                last_signed_block_slot,
                highest_source_epoch,
                highest_target_epoch,
                attestation_count,
                block_count,
            });
        }
    }

    if validators.is_empty() && pubkey.is_some() {
        anyhow::bail!("No validator found matching pubkey: {}", pubkey.unwrap());
    }

    let list = WatermarkList { validators };
    super::print_output(&list, format);
    Ok(())
}

/// Show signing statistics from metrics
pub async fn stats(api_url: &str, format: OutputFormat) -> Result<()> {
    let client = super::create_client();

    let response = client
        .get(format!("{}/metrics", api_url))
        .send()
        .await
        .context("Failed to connect to Nklave API")?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to get metrics: {}", response.status());
    }

    let metrics_text = response.text().await.context("Failed to read metrics")?;

    // Parse Prometheus metrics
    let mut total_signatures: u64 = 0;
    let mut total_refusals: u64 = 0;
    let mut signatures_by_type: Vec<(String, u64)> = Vec::new();
    let mut refusals_by_code: Vec<(String, u64)> = Vec::new();

    for line in metrics_text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        // Parse nklave_signatures_total
        if line.starts_with("nklave_signatures_total{") {
            if let Some((labels, value)) = parse_metric_line(line) {
                if let Ok(count) = value.parse::<u64>() {
                    total_signatures += count;
                    if let Some(sig_type) = labels.get("type") {
                        signatures_by_type.push((sig_type.clone(), count));
                    }
                }
            }
        }

        // Parse nklave_refusals_total
        if line.starts_with("nklave_refusals_total{") {
            if let Some((labels, value)) = parse_metric_line(line) {
                if let Ok(count) = value.parse::<u64>() {
                    total_refusals += count;
                    if let Some(code) = labels.get("code") {
                        refusals_by_code.push((code.clone(), count));
                    }
                }
            }
        }
    }

    let stats = SigningStats {
        total_signatures,
        total_refusals,
        signatures_by_type,
        refusals_by_code,
    };

    super::print_output(&stats, format);
    Ok(())
}

/// Parse a Prometheus metric line into labels and value
fn parse_metric_line(line: &str) -> Option<(std::collections::HashMap<String, String>, String)> {
    let open_brace = line.find('{')?;
    let close_brace = line.find('}')?;

    let labels_str = &line[open_brace + 1..close_brace];
    let value = line[close_brace + 1..].trim().to_string();

    let mut labels = std::collections::HashMap::new();

    for part in labels_str.split(',') {
        let part = part.trim();
        if let Some(eq_pos) = part.find('=') {
            let key = part[..eq_pos].trim().to_string();
            let val = part[eq_pos + 1..].trim().trim_matches('"').to_string();
            labels.insert(key, val);
        }
    }

    Some((labels, value))
}
