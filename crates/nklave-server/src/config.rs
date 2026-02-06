//! Server configuration

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server settings
    #[serde(default)]
    pub server: ServerConfig,

    /// API settings
    #[serde(default)]
    pub api: ApiConfig,

    /// Replication settings (for HA deployments)
    #[serde(default)]
    pub replication: Option<ReplicationConfig>,

    /// Logging settings
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Security settings
    #[serde(default)]
    pub security: SecurityConfig,

    // Legacy fields for backwards compatibility
    /// Address to listen on (deprecated, use server.listen_addr)
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,

    /// Directory containing validator keystores (deprecated, use server.keys_dir)
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,

    /// Directory for state data (deprecated, use server.data_dir)
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Optional TLS configuration (deprecated, use server.tls)
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Optional metrics endpoint (deprecated, use server.metrics_addr)
    #[serde(default)]
    pub metrics_addr: Option<SocketAddr>,

    /// Checkpoint scheduler interval (deprecated, use server.checkpoint_interval_secs)
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval_secs: u64,

    /// Number of checkpoint backups (deprecated, use server.checkpoint_backup_count)
    #[serde(default = "default_checkpoint_backup_count")]
    pub checkpoint_backup_count: u32,

    /// API authentication (deprecated, use api.auth)
    #[serde(default)]
    pub auth: Option<AuthConfig>,
}

/// Server-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
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

    /// Checkpoint scheduler interval in seconds (0 to disable)
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval_secs: u64,

    /// Number of checkpoint backups to retain
    #[serde(default = "default_checkpoint_backup_count")]
    pub checkpoint_backup_count: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            keys_dir: default_keys_dir(),
            data_dir: default_data_dir(),
            tls: None,
            metrics_addr: None,
            checkpoint_interval_secs: default_checkpoint_interval(),
            checkpoint_backup_count: default_checkpoint_backup_count(),
        }
    }
}

/// API-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Authentication configuration
    #[serde(default)]
    pub auth: Option<AuthConfig>,

    /// Request timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,

    /// Maximum concurrent requests
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,

    /// Maximum request body size in bytes
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            auth: None,
            request_timeout_secs: default_request_timeout(),
            max_concurrent_requests: default_max_concurrent_requests(),
            max_body_size: default_max_body_size(),
        }
    }
}

fn default_request_timeout() -> u64 {
    30
}

fn default_max_concurrent_requests() -> usize {
    100
}

fn default_max_body_size() -> usize {
    1024 * 1024 // 1 MB
}

/// Replication configuration for HA deployments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Role of this node: "primary" or "passive"
    #[serde(default = "default_role")]
    pub role: String,

    /// Listen address for replication (primary only)
    #[serde(default)]
    pub listen_addr: Option<SocketAddr>,

    /// Address of the primary node (passive only)
    #[serde(default)]
    pub primary_addr: Option<String>,

    /// Heartbeat interval in milliseconds
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_ms: u64,

    /// Maximum records to buffer for slow passives
    #[serde(default = "default_max_buffer_size")]
    pub max_buffer_size: usize,

    /// Reconnect delay in milliseconds (passive only)
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay_ms: u64,

    /// Heartbeat timeout in milliseconds (before failover)
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout_ms: u64,

    /// Missed heartbeats before failover
    #[serde(default = "default_missed_heartbeat_threshold")]
    pub missed_heartbeat_threshold: u32,

    /// TLS configuration for replication
    #[serde(default)]
    pub tls: Option<ReplicationTlsConfig>,
}

fn default_role() -> String {
    "primary".to_string()
}

fn default_heartbeat_interval() -> u64 {
    1000 // 1 second
}

fn default_max_buffer_size() -> usize {
    10000
}

fn default_reconnect_delay() -> u64 {
    5000 // 5 seconds
}

fn default_heartbeat_timeout() -> u64 {
    5000 // 5 seconds
}

fn default_missed_heartbeat_threshold() -> u32 {
    3
}

/// TLS configuration for replication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationTlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,

    /// Path to private key file
    pub key_path: PathBuf,

    /// Path to CA certificate for peer verification
    pub ca_cert_path: PathBuf,

    /// Whether to require client certificates (mTLS)
    #[serde(default = "default_require_client_cert")]
    pub require_client_cert: bool,

    /// Server name for TLS verification (passive only)
    #[serde(default)]
    pub server_name: Option<String>,
}

fn default_require_client_cert() -> bool {
    true
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Enable audit log encryption
    #[serde(default)]
    pub encrypt: bool,

    /// HMAC key for log integrity (hex-encoded, 32 bytes)
    /// If not set, a random key will be generated
    #[serde(default)]
    pub hmac_key: Option<String>,

    /// Encryption key for logs (hex-encoded, 32 bytes)
    /// If not set, a random key will be generated when encrypt=true
    #[serde(default)]
    pub encryption_key: Option<String>,

    /// Log rotation configuration
    #[serde(default)]
    pub rotation: LogRotationConfig,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            encrypt: false,
            hmac_key: None,
            encryption_key: None,
            rotation: LogRotationConfig::default(),
        }
    }
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum log size in megabytes before rotation
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,

    /// Maximum number of rotated files to keep
    #[serde(default = "default_max_files")]
    pub max_files: u32,

    /// Compress rotated files
    #[serde(default)]
    pub compress: bool,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_size_mb: 100,
            max_files: 10,
            compress: false,
        }
    }
}

fn default_max_size_mb() -> u64 {
    100
}

fn default_max_files() -> u32 {
    10
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Key provider type: "local", "aws-kms", "vault"
    #[serde(default = "default_key_provider")]
    pub key_provider: String,

    /// AWS KMS configuration (when key_provider = "aws-kms")
    #[serde(default)]
    pub aws_kms: Option<AwsKmsConfig>,

    /// Vault configuration (when key_provider = "vault")
    #[serde(default)]
    pub vault: Option<VaultConfig>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            key_provider: default_key_provider(),
            aws_kms: None,
            vault: None,
        }
    }
}

fn default_key_provider() -> String {
    "local".to_string()
}

/// AWS KMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsKmsConfig {
    /// AWS region
    pub region: String,

    /// KMS key ID for key wrapping
    pub key_id: String,

    /// Optional endpoint override (for LocalStack testing)
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// HashiCorp Vault configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Vault server address
    pub address: String,

    /// Authentication token (can also use VAULT_TOKEN env var)
    #[serde(default)]
    pub token: Option<String>,

    /// Secret path prefix
    #[serde(default = "default_vault_path")]
    pub path_prefix: String,
}

fn default_vault_path() -> String {
    "secret/nklave".to_string()
}

/// API authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode")]
pub enum AuthConfig {
    /// No authentication (development only)
    #[serde(rename = "none")]
    None,

    /// Bearer token authentication
    #[serde(rename = "bearer")]
    Bearer {
        /// Valid bearer tokens (can also be set via NKLAVE_API_TOKENS env var)
        #[serde(default)]
        tokens: Vec<String>,
    },

    /// mTLS client certificate authentication
    #[serde(rename = "mtls")]
    Mtls,

    /// Bearer token or mTLS (either accepted)
    #[serde(rename = "bearer_or_mtls")]
    BearerOrMtls {
        /// Valid bearer tokens
        #[serde(default)]
        tokens: Vec<String>,
    },
}

impl AuthConfig {
    /// Get tokens, including from environment variable
    pub fn get_tokens(&self) -> Vec<String> {
        let env_tokens: Vec<String> = std::env::var("NKLAVE_API_TOKENS")
            .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
            .unwrap_or_default();

        match self {
            AuthConfig::Bearer { tokens } | AuthConfig::BearerOrMtls { tokens } => {
                let mut all_tokens = tokens.clone();
                all_tokens.extend(env_tokens);
                all_tokens
            }
            _ => env_tokens,
        }
    }
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
    std::env::var("NKLAVE_LISTEN_ADDR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap())
}

fn default_keys_dir() -> PathBuf {
    std::env::var("NKLAVE_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./keys"))
}

fn default_data_dir() -> PathBuf {
    std::env::var("NKLAVE_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./data"))
}

fn default_checkpoint_interval() -> u64 {
    std::env::var("NKLAVE_CHECKPOINT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300) // 5 minutes
}

fn default_checkpoint_backup_count() -> u32 {
    std::env::var("NKLAVE_CHECKPOINT_BACKUP_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            api: ApiConfig::default(),
            replication: None,
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
            // Legacy fields
            listen_addr: default_listen_addr(),
            keys_dir: default_keys_dir(),
            data_dir: default_data_dir(),
            tls: None,
            metrics_addr: None,
            checkpoint_interval_secs: default_checkpoint_interval(),
            checkpoint_backup_count: default_checkpoint_backup_count(),
            auth: None,
        }
    }
}

impl Config {
    /// Load configuration from file or return defaults
    pub fn load_or_default() -> Result<Self> {
        let config_path = std::env::var("NKLAVE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config.toml"));

        let mut config = if config_path.exists() {
            Self::load(&config_path)?
        } else {
            tracing::info!("No config file found, using defaults");
            Self::default()
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        Ok(config)
    }

    /// Load configuration from a file
    pub fn load(path: &PathBuf) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        // Server settings
        if let Ok(addr) = std::env::var("NKLAVE_LISTEN_ADDR") {
            if let Ok(parsed) = addr.parse() {
                self.server.listen_addr = parsed;
                self.listen_addr = parsed;
            }
        }

        if let Ok(dir) = std::env::var("NKLAVE_KEYS_DIR") {
            self.server.keys_dir = PathBuf::from(&dir);
            self.keys_dir = PathBuf::from(&dir);
        }

        if let Ok(dir) = std::env::var("NKLAVE_DATA_DIR") {
            self.server.data_dir = PathBuf::from(&dir);
            self.data_dir = PathBuf::from(&dir);
        }

        if let Ok(metrics) = std::env::var("NKLAVE_METRICS_ADDR") {
            if let Ok(parsed) = metrics.parse() {
                self.server.metrics_addr = Some(parsed);
                self.metrics_addr = Some(parsed);
            }
        }

        if let Ok(interval) = std::env::var("NKLAVE_CHECKPOINT_INTERVAL") {
            if let Ok(parsed) = interval.parse() {
                self.server.checkpoint_interval_secs = parsed;
                self.checkpoint_interval_secs = parsed;
            }
        }

        // API settings
        if let Ok(timeout) = std::env::var("NKLAVE_REQUEST_TIMEOUT") {
            if let Ok(parsed) = timeout.parse() {
                self.api.request_timeout_secs = parsed;
            }
        }

        if let Ok(max) = std::env::var("NKLAVE_MAX_CONCURRENT_REQUESTS") {
            if let Ok(parsed) = max.parse() {
                self.api.max_concurrent_requests = parsed;
            }
        }

        // Replication settings (if replication section exists)
        if let Some(ref mut repl) = self.replication {
            if let Ok(interval) = std::env::var("NKLAVE_HEARTBEAT_INTERVAL") {
                if let Ok(parsed) = interval.parse() {
                    repl.heartbeat_interval_ms = parsed;
                }
            }

            if let Ok(buffer) = std::env::var("NKLAVE_MAX_BUFFER_SIZE") {
                if let Ok(parsed) = buffer.parse() {
                    repl.max_buffer_size = parsed;
                }
            }

            if let Ok(addr) = std::env::var("NKLAVE_PRIMARY_ADDR") {
                repl.primary_addr = Some(addr);
            }

            if let Ok(role) = std::env::var("NKLAVE_ROLE") {
                repl.role = role;
            }
        }

        // Logging settings
        if let Ok(encrypt) = std::env::var("NKLAVE_LOG_ENCRYPT") {
            self.logging.encrypt = encrypt == "true" || encrypt == "1";
        }

        // Security settings
        if let Ok(provider) = std::env::var("NKLAVE_KEY_PROVIDER") {
            self.security.key_provider = provider;
        }
    }

    /// Save configuration to a file
    #[allow(dead_code)]
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let contents = toml::to_string_pretty(self).context("Failed to serialize config")?;

        std::fs::write(path, contents)
            .with_context(|| format!("Failed to write config file: {}", path.display()))
    }

    /// Get the effective listen address (prefers new config, falls back to legacy)
    pub fn effective_listen_addr(&self) -> SocketAddr {
        self.server.listen_addr
    }

    /// Get the effective keys directory
    pub fn effective_keys_dir(&self) -> &PathBuf {
        &self.server.keys_dir
    }

    /// Get the effective data directory
    pub fn effective_data_dir(&self) -> &PathBuf {
        &self.server.data_dir
    }

    /// Get the effective TLS configuration
    pub fn effective_tls(&self) -> Option<&TlsConfig> {
        self.server.tls.as_ref().or(self.tls.as_ref())
    }

    /// Get the effective metrics address
    pub fn effective_metrics_addr(&self) -> Option<SocketAddr> {
        self.server.metrics_addr.or(self.metrics_addr)
    }

    /// Get the effective auth configuration
    pub fn effective_auth(&self) -> Option<&AuthConfig> {
        self.api.auth.as_ref().or(self.auth.as_ref())
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
