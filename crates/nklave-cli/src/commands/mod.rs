//! CLI command implementations

pub mod checkpoint;
pub mod metrics;
pub mod status;
pub mod validators;

use crate::OutputFormat;
use serde::Serialize;

/// Format and print output based on the selected format
pub fn print_output<T: Serialize + std::fmt::Display>(value: &T, format: OutputFormat) {
    match format {
        OutputFormat::Text => println!("{}", value),
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(value) {
                println!("{}", json);
            }
        }
    }
}

/// Create an HTTP client
pub fn create_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client")
}
