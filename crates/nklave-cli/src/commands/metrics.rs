//! Metrics command - access Prometheus metrics

use crate::OutputFormat;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Parsed metrics for display
#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub raw_metrics: String,
    pub key_metrics: Vec<KeyMetric>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyMetric {
    pub name: String,
    pub value: String,
    pub labels: Option<String>,
}

impl fmt::Display for MetricsSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Key Metrics")?;
        writeln!(f, "===========")?;

        for metric in &self.key_metrics {
            if let Some(ref labels) = metric.labels {
                writeln!(f, "{}{{{}}} = {}", metric.name, labels, metric.value)?;
            } else {
                writeln!(f, "{} = {}", metric.name, metric.value)?;
            }
        }

        writeln!(f)?;
        writeln!(f, "Full metrics available at /metrics endpoint")?;

        Ok(())
    }
}

/// Fetch and display metrics
pub async fn run(api_url: &str, format: OutputFormat) -> Result<()> {
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

    // Parse key metrics
    let mut key_metrics = Vec::new();

    // Metrics we want to highlight
    let important_prefixes = [
        "nklave_signatures_total",
        "nklave_refusals_total",
        "nklave_signing_latency",
        "nklave_checkpoint_age_seconds",
        "nklave_validators_loaded",
        "nklave_state_sequence_number",
    ];

    for line in metrics_text.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }

        for prefix in &important_prefixes {
            if line.starts_with(prefix) {
                if let Some((name, labels, value)) = parse_full_metric_line(line) {
                    key_metrics.push(KeyMetric {
                        name,
                        value,
                        labels,
                    });
                }
                break;
            }
        }
    }

    let summary = MetricsSummary {
        raw_metrics: metrics_text,
        key_metrics,
    };

    match format {
        OutputFormat::Text => println!("{}", summary),
        OutputFormat::Json => {
            // For JSON, include all metrics
            let output = serde_json::json!({
                "key_metrics": summary.key_metrics,
                "raw_metrics": summary.raw_metrics.lines().collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }

    Ok(())
}

/// Parse a Prometheus metric line into name, labels, and value
fn parse_full_metric_line(line: &str) -> Option<(String, Option<String>, String)> {
    if let Some(open_brace) = line.find('{') {
        let name = line[..open_brace].to_string();
        let close_brace = line.find('}')?;
        let labels = line[open_brace + 1..close_brace].to_string();
        let value = line[close_brace + 1..].trim().to_string();
        Some((name, Some(labels), value))
    } else {
        // Metric without labels
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            Some((parts[0].to_string(), None, parts[1].to_string()))
        } else {
            None
        }
    }
}
