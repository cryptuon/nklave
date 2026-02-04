//! Nklave Server - Main entry point
//!
//! A signing security layer for Ethereum validators

use anyhow::{Context, Result};
use metrics_exporter_prometheus::PrometheusBuilder;
use nklave_api::{create_router, AppState};
use nklave_core::{load_keystores_from_dir, metrics as core_metrics, SigningService};
use nklave_storage::{Checkpoint, DecisionLog};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;

use config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nklave=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Nklave signing security layer");

    // Load configuration
    let config = Config::load_or_default()?;

    tracing::info!(
        listen_addr = %config.listen_addr,
        keys_dir = %config.keys_dir.display(),
        data_dir = %config.data_dir.display(),
        "Configuration loaded"
    );

    // Initialize Prometheus metrics exporter if configured
    if let Some(metrics_addr) = config.metrics_addr {
        PrometheusBuilder::new()
            .with_http_listener(metrics_addr)
            .install()
            .context("Failed to install Prometheus metrics exporter")?;
        tracing::info!(metrics_addr = %metrics_addr, "Prometheus metrics endpoint started");
    }

    // Ensure directories exist
    std::fs::create_dir_all(&config.keys_dir)
        .with_context(|| format!("Failed to create keys directory: {}", config.keys_dir.display()))?;
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("Failed to create data directory: {}", config.data_dir.display()))?;

    // Get keystore password from environment
    let password = std::env::var("NKLAVE_KEYSTORE_PASSWORD").unwrap_or_default();

    // Load validator keys
    let keypairs = if config.keys_dir.exists() && config.keys_dir.is_dir() {
        match load_keystores_from_dir(&config.keys_dir, &password) {
            Ok(keys) => {
                tracing::info!(count = keys.len(), "Loaded validator keys");
                core_metrics::set_validators_count(keys.len());
                keys
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load keys from directory, starting with no keys");
                core_metrics::set_validators_count(0);
                vec![]
            }
        }
    } else {
        tracing::info!("Keys directory does not exist, starting with no keys");
        core_metrics::set_validators_count(0);
        vec![]
    };

    // Load or initialize state
    let checkpoint_path = config.data_dir.join("checkpoint.json");
    let log_path = config.data_dir.join("decisions.log");

    let signing_service = if checkpoint_path.exists() {
        // Load from checkpoint
        tracing::info!(path = %checkpoint_path.display(), "Loading state from checkpoint");
        let checkpoint = Checkpoint::load(&checkpoint_path)
            .with_context(|| "Failed to load checkpoint")?;

        let integrity = checkpoint.restore_integrity();
        let service = SigningService::with_state(keypairs, checkpoint.validators, integrity);

        // Replay log entries after checkpoint
        if log_path.exists() {
            let log = DecisionLog::open(&log_path)
                .with_context(|| "Failed to open decision log")?;

            if log.last_sequence() > checkpoint.sequence {
                tracing::info!(
                    checkpoint_seq = checkpoint.sequence,
                    log_seq = log.last_sequence(),
                    "Replaying log entries after checkpoint"
                );

                // Get records to replay
                let records = log.replay_from(checkpoint.sequence + 1)
                    .with_context(|| "Failed to replay log")?;

                // Replay them
                service.replay_records(records)
                    .with_context(|| "Failed to apply replayed records")?;
            }
        }

        service
    } else {
        // Start fresh
        tracing::info!("No checkpoint found, starting with fresh state");
        SigningService::new(keypairs)
    };

    let signing_service = Arc::new(signing_service);

    // Initialize decision log
    let decision_log = DecisionLog::open(&log_path)
        .with_context(|| format!("Failed to open decision log: {}", log_path.display()))?;
    tracing::info!(path = %log_path.display(), "Decision log opened");

    // Create app state
    let state = Arc::new(AppState::with_full_config(
        signing_service,
        config.keys_dir.clone(),
        password,
        decision_log,
        checkpoint_path.clone(),
    ));

    // Create router
    let app = create_router(state);

    // Start server (with or without TLS)
    if let Some(tls_config) = &config.tls {
        // Load TLS certificates
        let rustls_config = load_rustls_config(&tls_config.cert_path, &tls_config.key_path)
            .await
            .with_context(|| "Failed to load TLS configuration")?;

        tracing::info!(
            listen_addr = %config.listen_addr,
            cert_path = %tls_config.cert_path.display(),
            "Starting HTTPS server"
        );

        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();

        tokio::spawn(async move {
            shutdown_signal().await;
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        });

        axum_server::bind_rustls(config.listen_addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
        tracing::info!("Listening on http://{}", config.listen_addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    tracing::info!("Server shutdown complete");

    Ok(())
}

/// Load TLS configuration from certificate and key files
async fn load_rustls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<axum_server::tls_rustls::RustlsConfig> {
    use std::fs::File;
    use std::io::BufReader;

    // Read certificate chain
    let cert_file = File::open(cert_path)
        .with_context(|| format!("Failed to open certificate file: {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path.display());
    }

    // Read private key
    let key_file = File::open(key_path)
        .with_context(|| format!("Failed to open key file: {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);

    let key = rustls_pemfile::private_key(&mut key_reader)
        .with_context(|| format!("Failed to read private key from {}", key_path.display()))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path.display()))?;

    // Build rustls config
    let config = axum_server::tls_rustls::RustlsConfig::from_der(
        certs.into_iter().map(|c| c.to_vec()).collect(),
        key.secret_der().to_vec(),
    )
    .await
    .with_context(|| "Failed to build TLS configuration")?;

    Ok(config)
}

/// Wait for shutdown signal
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}
