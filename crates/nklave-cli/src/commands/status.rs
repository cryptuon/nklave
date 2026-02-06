//! Status command - check service health

use crate::OutputFormat;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Service status information
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub status: String,
    pub api_url: String,
    pub upcheck: bool,
    pub validator_count: Option<usize>,
    pub metrics_available: bool,
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Nklave Service Status")?;
        writeln!(f, "=====================")?;
        writeln!(f, "API URL:     {}", self.api_url)?;
        writeln!(f, "Status:      {}", self.status)?;
        writeln!(f, "Health:      {}", if self.upcheck { "OK" } else { "UNHEALTHY" })?;
        if let Some(count) = self.validator_count {
            writeln!(f, "Validators:  {}", count)?;
        }
        writeln!(f, "Metrics:     {}", if self.metrics_available { "Available" } else { "Unavailable" })?;
        Ok(())
    }
}

pub async fn run(api_url: &str, format: OutputFormat) -> Result<()> {
    let client = super::create_client();

    // Check upcheck endpoint
    let upcheck = client
        .get(format!("{}/upcheck", api_url))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    // Get validator count
    let validator_count = if upcheck {
        client
            .get(format!("{}/api/v1/eth2/publicKeys", api_url))
            .send()
            .await
            .ok()
            .and_then(|r| {
                if r.status().is_success() {
                    Some(r)
                } else {
                    None
                }
            })
            .and_then(|r| {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        r.json::<Vec<String>>().await.ok().map(|v| v.len())
                    })
                })
            })
    } else {
        None
    };

    // Check metrics endpoint
    let metrics_available = client
        .get(format!("{}/metrics", api_url))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);

    let status = ServiceStatus {
        status: if upcheck { "Running".to_string() } else { "Unreachable".to_string() },
        api_url: api_url.to_string(),
        upcheck,
        validator_count,
        metrics_available,
    };

    super::print_output(&status, format);

    if !upcheck {
        anyhow::bail!("Service is not healthy");
    }

    Ok(())
}
