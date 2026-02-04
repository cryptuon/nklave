//! Server configuration

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address to listen on
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Directory containing validator keystores
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,

    /// Directory for state data (logs, checkpoints)
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Optional TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Optional metrics endpoint
    #[serde(default)]
    pub metrics_addr: Option<SocketAddr>,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
}

fn default_listen_addr() -> SocketAddr {
    "127.0.0.1:9000".parse().unwrap()
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("./keys")
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            keys_dir: default_keys_dir(),
            data_dir: default_data_dir(),
            tls: None,
            metrics_addr: None,
        }
    }
}

impl Config {
    /// Load configuration from file or return defaults
    pub fn load_or_default() -> Result<Self> {
        let config_path = std::env::var("NKLAVE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config.toml"));

        if config_path.exists() {
            Self::load(&config_path)
        } else {
            tracing::info!("No config file found, using defaults");
            Ok(Self::default())
        }
    }

    /// Load configuration from a file
    pub fn load(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    /// Save configuration to a file
    #[allow(dead_code)]
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let contents = toml::to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(path, contents)
            .with_context(|| format!("Failed to write config file: {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen_addr, "127.0.0.1:9000".parse().unwrap());
    }

    #[test]
    fn test_config_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config.toml");

        let config = Config::default();
        config.save(&path).unwrap();

        let loaded = Config::load(&path).unwrap();
        assert_eq!(loaded.listen_addr, config.listen_addr);
    }
}
