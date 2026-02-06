//! Checkpoint scheduler for periodic state snapshots
//!
//! Runs a background task that periodically saves checkpoints to ensure
//! fast recovery and limit log replay time.

use crate::checkpoint::{Checkpoint, CheckpointError};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{interval, Duration};

/// Configuration for the checkpoint scheduler
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Path to checkpoint file
    pub checkpoint_path: PathBuf,

    /// Interval between checkpoints in seconds
    pub interval_secs: u64,

    /// Number of backup checkpoints to retain
    pub backup_count: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            checkpoint_path: PathBuf::from("./data/checkpoint.json"),
            interval_secs: 300, // 5 minutes
            backup_count: 3,
        }
    }
}

/// Trait for providing checkpoint data
///
/// Implemented by the signing service or other components that need
/// to provide state for checkpointing.
pub trait CheckpointProvider: Send + Sync {
    /// Get the current state integrity
    fn integrity(&self) -> nklave_core::state::integrity::StateIntegrity;

    /// Get all validator states
    fn validator_states(&self) -> std::collections::HashMap<[u8; 48], nklave_core::state::validator::ValidatorState>;
}

/// Handle for controlling the checkpoint scheduler
pub struct CheckpointSchedulerHandle {
    /// Sender for shutdown signal
    shutdown_tx: watch::Sender<bool>,

    /// Atomic flag to track if scheduler is running
    running: Arc<AtomicBool>,

    /// Timestamp of last checkpoint (unix seconds)
    last_checkpoint_time: Arc<AtomicU64>,
}

impl CheckpointSchedulerHandle {
    /// Check if the scheduler is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get the time since last checkpoint in seconds
    pub fn checkpoint_age_secs(&self) -> u64 {
        let last = self.last_checkpoint_time.load(Ordering::Relaxed);
        if last == 0 {
            return 0; // No checkpoint yet
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now.saturating_sub(last)
    }

    /// Trigger an immediate shutdown of the scheduler
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Trigger a manual checkpoint (non-blocking)
    ///
    /// Returns the current sequence number that will be checkpointed
    pub fn trigger_checkpoint(&self) -> u64 {
        // This is handled by the scheduler polling or manual save
        // For now just return the last checkpoint time as a proxy
        self.last_checkpoint_time.load(Ordering::Relaxed)
    }
}

/// Checkpoint scheduler that runs periodic backups
pub struct CheckpointScheduler;

impl CheckpointScheduler {
    /// Start the checkpoint scheduler as a background task
    ///
    /// Returns a handle that can be used to control the scheduler.
    pub fn start<P>(
        provider: Arc<P>,
        config: SchedulerConfig,
    ) -> CheckpointSchedulerHandle
    where
        P: CheckpointProvider + 'static,
    {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let running = Arc::new(AtomicBool::new(true));
        let last_checkpoint_time = Arc::new(AtomicU64::new(0));

        let handle = CheckpointSchedulerHandle {
            shutdown_tx,
            running: running.clone(),
            last_checkpoint_time: last_checkpoint_time.clone(),
        };

        // Spawn the background task
        tokio::spawn(Self::run_scheduler(
            provider,
            config,
            shutdown_rx,
            running,
            last_checkpoint_time,
        ));

        handle
    }

    /// Internal scheduler loop
    async fn run_scheduler<P>(
        provider: Arc<P>,
        config: SchedulerConfig,
        mut shutdown_rx: watch::Receiver<bool>,
        running: Arc<AtomicBool>,
        last_checkpoint_time: Arc<AtomicU64>,
    ) where
        P: CheckpointProvider + 'static,
    {
        let mut ticker = interval(Duration::from_secs(config.interval_secs));

        // Skip the first immediate tick
        ticker.tick().await;

        tracing::info!(
            interval_secs = config.interval_secs,
            path = %config.checkpoint_path.display(),
            "Checkpoint scheduler started"
        );

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = Self::save_checkpoint(&provider, &config, &last_checkpoint_time) {
                        tracing::error!(error = %e, "Failed to save scheduled checkpoint");
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Checkpoint scheduler shutting down");

                        // Save a final checkpoint before shutting down
                        if let Err(e) = Self::save_checkpoint(&provider, &config, &last_checkpoint_time) {
                            tracing::error!(error = %e, "Failed to save final checkpoint");
                        }

                        break;
                    }
                }
            }
        }

        running.store(false, Ordering::Relaxed);
        tracing::info!("Checkpoint scheduler stopped");
    }

    /// Save a checkpoint to disk
    fn save_checkpoint<P>(
        provider: &Arc<P>,
        config: &SchedulerConfig,
        last_checkpoint_time: &Arc<AtomicU64>,
    ) -> Result<(), CheckpointError>
    where
        P: CheckpointProvider,
    {
        let integrity = provider.integrity();
        let validators = provider.validator_states();

        let checkpoint = Checkpoint::new(&integrity, validators);

        tracing::debug!(
            sequence = checkpoint.sequence,
            validators = checkpoint.validators.len(),
            "Saving scheduled checkpoint"
        );

        checkpoint.save_atomic(&config.checkpoint_path, config.backup_count)?;

        // Update last checkpoint time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        last_checkpoint_time.store(now, Ordering::Relaxed);

        // Update metrics
        nklave_core::metrics::set_checkpoint_age(0);

        tracing::info!(
            sequence = checkpoint.sequence,
            path = %config.checkpoint_path.display(),
            "Scheduled checkpoint saved"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nklave_core::state::integrity::StateIntegrity;
    use nklave_core::state::validator::ValidatorState;
    use std::collections::HashMap;
    use tempfile::TempDir;

    struct MockProvider {
        integrity: StateIntegrity,
        validators: HashMap<[u8; 48], ValidatorState>,
    }

    impl MockProvider {
        fn new() -> Self {
            Self {
                integrity: StateIntegrity::new(),
                validators: HashMap::new(),
            }
        }
    }

    impl CheckpointProvider for MockProvider {
        fn integrity(&self) -> StateIntegrity {
            self.integrity.clone()
        }

        fn validator_states(&self) -> HashMap<[u8; 48], ValidatorState> {
            self.validators.clone()
        }
    }

    #[tokio::test]
    async fn test_scheduler_starts_and_stops() {
        let dir = TempDir::new().unwrap();
        let provider = Arc::new(MockProvider::new());

        let config = SchedulerConfig {
            checkpoint_path: dir.path().join("checkpoint.json"),
            interval_secs: 1, // Short interval for testing
            backup_count: 2,
        };

        let handle = CheckpointScheduler::start(provider, config);

        assert!(handle.is_running());

        // Wait a bit and then shutdown
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.shutdown();

        // Give the scheduler time to stop
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!handle.is_running());
    }

    #[tokio::test]
    async fn test_scheduler_creates_checkpoint() {
        let dir = TempDir::new().unwrap();
        let checkpoint_path = dir.path().join("checkpoint.json");
        let provider = Arc::new(MockProvider::new());

        let config = SchedulerConfig {
            checkpoint_path: checkpoint_path.clone(),
            interval_secs: 1,
            backup_count: 2,
        };

        let handle = CheckpointScheduler::start(provider, config);

        // Wait for at least one checkpoint cycle
        tokio::time::sleep(Duration::from_secs(2)).await;

        handle.shutdown();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify checkpoint was created
        assert!(checkpoint_path.exists());
    }
}
