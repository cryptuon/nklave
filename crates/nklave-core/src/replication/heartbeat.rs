//! Heartbeat monitoring for failover detection
//!
//! Tracks heartbeats from the primary node and triggers failover
//! when timeout is detected.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Configuration for heartbeat monitoring
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Heartbeat interval in milliseconds
    pub interval_ms: u64,

    /// Timeout before considering primary dead (milliseconds)
    pub timeout_ms: u64,

    /// Number of missed heartbeats before triggering failover
    pub missed_threshold: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_ms: 1000,      // 1 second
            timeout_ms: 30000,      // 30 seconds
            missed_threshold: 3,    // 3 missed heartbeats
        }
    }
}

/// Heartbeat state tracked by the monitor
#[derive(Debug, Clone)]
pub struct HeartbeatState {
    /// Last received heartbeat timestamp (unix ms)
    pub last_heartbeat_ms: u64,

    /// Sequence number from last heartbeat
    pub last_sequence: u64,

    /// State hash from last heartbeat
    pub last_state_hash: [u8; 32],

    /// Number of consecutive missed heartbeats
    pub missed_count: u32,

    /// Whether the primary is considered alive
    pub primary_alive: bool,
}

impl Default for HeartbeatState {
    fn default() -> Self {
        Self {
            last_heartbeat_ms: 0,
            last_sequence: 0,
            last_state_hash: [0u8; 32],
            missed_count: 0,
            primary_alive: false,
        }
    }
}

/// Heartbeat monitor for tracking primary liveness
pub struct HeartbeatMonitor {
    config: HeartbeatConfig,

    /// Last heartbeat timestamp (atomic for lock-free access)
    last_heartbeat_ms: AtomicU64,

    /// Last sequence number
    last_sequence: AtomicU64,

    /// Number of missed heartbeats
    missed_count: AtomicU64,

    /// Whether primary is alive
    primary_alive: AtomicBool,

    /// Channel for failover notifications
    failover_tx: watch::Sender<bool>,

    /// Receiver for failover notifications
    failover_rx: watch::Receiver<bool>,

    /// Shutdown flag
    shutdown: AtomicBool,
}

impl HeartbeatMonitor {
    /// Create a new heartbeat monitor
    pub fn new(config: HeartbeatConfig) -> Self {
        let (failover_tx, failover_rx) = watch::channel(false);

        Self {
            config,
            last_heartbeat_ms: AtomicU64::new(0),
            last_sequence: AtomicU64::new(0),
            missed_count: AtomicU64::new(0),
            primary_alive: AtomicBool::new(false),
            failover_tx,
            failover_rx,
            shutdown: AtomicBool::new(false),
        }
    }

    /// Record a received heartbeat
    pub fn record_heartbeat(&self, sequence: u64, state_hash: [u8; 32]) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.last_heartbeat_ms.store(now_ms, Ordering::Release);
        self.last_sequence.store(sequence, Ordering::Release);
        self.missed_count.store(0, Ordering::Release);

        if !self.primary_alive.load(Ordering::Acquire) {
            info!(sequence = sequence, "Primary connection established");
            self.primary_alive.store(true, Ordering::Release);
        }

        debug!(
            sequence = sequence,
            state_hash = hex::encode(state_hash),
            "Heartbeat received"
        );
    }

    /// Check if heartbeat has timed out
    pub fn check_timeout(&self) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let last_hb = self.last_heartbeat_ms.load(Ordering::Acquire);

        // If we've never received a heartbeat, don't trigger timeout
        if last_hb == 0 {
            return false;
        }

        let elapsed = now_ms.saturating_sub(last_hb);
        elapsed > self.config.timeout_ms
    }

    /// Increment missed heartbeat count and check for failover
    pub fn record_missed(&self) -> bool {
        let missed = self.missed_count.fetch_add(1, Ordering::AcqRel) + 1;

        warn!(
            missed = missed,
            threshold = self.config.missed_threshold,
            "Missed heartbeat"
        );

        if missed >= self.config.missed_threshold as u64 {
            self.primary_alive.store(false, Ordering::Release);
            let _ = self.failover_tx.send(true);
            return true;
        }

        false
    }

    /// Get the current state
    pub fn state(&self) -> HeartbeatState {
        HeartbeatState {
            last_heartbeat_ms: self.last_heartbeat_ms.load(Ordering::Acquire),
            last_sequence: self.last_sequence.load(Ordering::Acquire),
            last_state_hash: [0u8; 32], // Would need Arc<RwLock> for this
            missed_count: self.missed_count.load(Ordering::Acquire) as u32,
            primary_alive: self.primary_alive.load(Ordering::Acquire),
        }
    }

    /// Check if primary is alive
    pub fn is_primary_alive(&self) -> bool {
        self.primary_alive.load(Ordering::Acquire)
    }

    /// Get the last known sequence number
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence.load(Ordering::Acquire)
    }

    /// Subscribe to failover notifications
    pub fn subscribe_failover(&self) -> watch::Receiver<bool> {
        self.failover_rx.clone()
    }

    /// Get milliseconds since last heartbeat
    pub fn ms_since_heartbeat(&self) -> u64 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let last_hb = self.last_heartbeat_ms.load(Ordering::Acquire);
        if last_hb == 0 {
            return u64::MAX;
        }

        now_ms.saturating_sub(last_hb)
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Check if shutdown was signaled
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

/// Handle for the heartbeat check task
pub struct HeartbeatCheckHandle {
    shutdown_tx: watch::Sender<bool>,
}

impl HeartbeatCheckHandle {
    /// Signal the heartbeat checker to stop
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Start periodic heartbeat checking
pub fn start_heartbeat_checker(
    monitor: Arc<HeartbeatMonitor>,
    config: HeartbeatConfig,
) -> HeartbeatCheckHandle {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let check_interval = Duration::from_millis(config.interval_ms);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(check_interval) => {
                    if monitor.check_timeout() {
                        if monitor.record_missed() {
                            warn!("Heartbeat timeout - triggering failover");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Heartbeat checker shutting down");
                        break;
                    }
                }
            }
        }
    });

    HeartbeatCheckHandle { shutdown_tx }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_monitor_creation() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());
        assert!(!monitor.is_primary_alive());
        assert_eq!(monitor.last_sequence(), 0);
    }

    #[test]
    fn test_record_heartbeat() {
        let monitor = HeartbeatMonitor::new(HeartbeatConfig::default());

        monitor.record_heartbeat(100, [1u8; 32]);

        assert!(monitor.is_primary_alive());
        assert_eq!(monitor.last_sequence(), 100);
        assert!(monitor.ms_since_heartbeat() < 1000);
    }

    #[test]
    fn test_missed_heartbeat_threshold() {
        let config = HeartbeatConfig {
            missed_threshold: 3,
            ..Default::default()
        };
        let monitor = HeartbeatMonitor::new(config);

        // First heartbeat to establish connection
        monitor.record_heartbeat(1, [0u8; 32]);
        assert!(monitor.is_primary_alive());

        // Miss heartbeats
        assert!(!monitor.record_missed()); // 1
        assert!(!monitor.record_missed()); // 2
        assert!(monitor.record_missed());  // 3 - triggers failover

        assert!(!monitor.is_primary_alive());
    }

    #[test]
    fn test_heartbeat_resets_missed_count() {
        let config = HeartbeatConfig {
            missed_threshold: 3,
            ..Default::default()
        };
        let monitor = HeartbeatMonitor::new(config);

        monitor.record_heartbeat(1, [0u8; 32]);
        monitor.record_missed();
        monitor.record_missed();

        // Heartbeat should reset the count
        monitor.record_heartbeat(2, [0u8; 32]);

        let state = monitor.state();
        assert_eq!(state.missed_count, 0);
    }
}
