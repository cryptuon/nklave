//! Failover coordination and promotion logic
//!
//! Handles the transition from passive to primary role when failover is detected.

use super::passive::PassiveHandle;
use super::primary::ReplicatorConfig;
use super::protocol::FencingToken;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::watch;
use tracing::{error, info};

/// Node role in the replication cluster
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    /// Primary node - handles signing and replicates to passives
    Primary,

    /// Passive node - receives replicated state, ready for failover
    Passive,

    /// Promoting - in the process of becoming primary
    Promoting,

    /// Standalone - not participating in replication
    Standalone,
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeRole::Primary => write!(f, "primary"),
            NodeRole::Passive => write!(f, "passive"),
            NodeRole::Promoting => write!(f, "promoting"),
            NodeRole::Standalone => write!(f, "standalone"),
        }
    }
}

/// Failover state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverState {
    /// Normal operation
    Normal,

    /// Failover in progress
    InProgress,

    /// Failover completed
    Completed,

    /// Failover failed
    Failed,
}

/// Configuration for failover coordination
#[derive(Debug, Clone)]
pub struct FailoverConfig {
    /// Node identifier
    pub node_id: String,

    /// Initial role
    pub initial_role: NodeRole,

    /// Whether to auto-promote on failover detection
    pub auto_promote: bool,

    /// Minimum time to wait after primary failure before promoting (ms)
    pub promotion_delay_ms: u64,

    /// Replicator configuration (for primary/after promotion)
    pub replicator_config: Option<ReplicatorConfig>,
}

impl Default for FailoverConfig {
    fn default() -> Self {
        Self {
            node_id: "node".to_string(),
            initial_role: NodeRole::Standalone,
            auto_promote: true,
            promotion_delay_ms: 5000,
            replicator_config: None,
        }
    }
}

/// Failover coordinator manages role transitions
pub struct FailoverCoordinator {
    config: FailoverConfig,

    /// Current role
    role: Arc<RwLock<NodeRole>>,

    /// Current failover state
    failover_state: Arc<RwLock<FailoverState>>,

    /// Current fencing token
    fencing_token: AtomicU64,

    /// Role change notifications
    role_tx: watch::Sender<NodeRole>,

    /// Role change receiver
    role_rx: watch::Receiver<NodeRole>,
}

impl FailoverCoordinator {
    /// Create a new failover coordinator
    pub fn new(config: FailoverConfig) -> Self {
        let (role_tx, role_rx) = watch::channel(config.initial_role);

        Self {
            role: Arc::new(RwLock::new(config.initial_role)),
            failover_state: Arc::new(RwLock::new(FailoverState::Normal)),
            fencing_token: AtomicU64::new(0),
            role_tx,
            role_rx,
            config,
        }
    }

    /// Get current role
    pub fn role(&self) -> NodeRole {
        self.role.read().map(|r| *r).unwrap_or(NodeRole::Standalone)
    }

    /// Get current failover state
    pub fn failover_state(&self) -> FailoverState {
        self.failover_state.read().map(|s| *s).unwrap_or(FailoverState::Normal)
    }

    /// Get current fencing token
    pub fn fencing_token(&self) -> u64 {
        self.fencing_token.load(Ordering::Acquire)
    }

    /// Subscribe to role changes
    pub fn subscribe_role_changes(&self) -> watch::Receiver<NodeRole> {
        self.role_rx.clone()
    }

    /// Attempt to promote this node to primary
    ///
    /// Returns Ok(new_fencing_token) on success
    pub async fn promote(&self, passive_handle: &PassiveHandle) -> Result<u64, FailoverError> {
        // Check current role
        let current_role = self.role();
        if current_role != NodeRole::Passive {
            return Err(FailoverError::InvalidRoleTransition {
                from: current_role,
                to: NodeRole::Primary,
            });
        }

        // Set state to promoting
        {
            let mut state = self.failover_state.write()
                .map_err(|_| FailoverError::LockPoisoned)?;
            *state = FailoverState::InProgress;
        }

        info!("Starting promotion to primary");

        // Wait for promotion delay (allows time for other nodes to detect failure)
        tokio::time::sleep(std::time::Duration::from_millis(self.config.promotion_delay_ms)).await;

        // Generate new fencing token
        let new_token = self.fencing_token.fetch_add(1, Ordering::AcqRel) + 1;

        // Get current state from passive
        let integrity = passive_handle.integrity();
        let validators = passive_handle.validator_states();

        info!(
            sequence = integrity.sequence_number,
            validators = validators.len(),
            fencing_token = new_token,
            "Promotion state captured"
        );

        // Update role
        {
            let mut role = self.role.write()
                .map_err(|_| FailoverError::LockPoisoned)?;
            *role = NodeRole::Primary;
        }

        // Notify role change
        let _ = self.role_tx.send(NodeRole::Primary);

        // Update failover state
        {
            let mut state = self.failover_state.write()
                .map_err(|_| FailoverError::LockPoisoned)?;
            *state = FailoverState::Completed;
        }

        info!(
            fencing_token = new_token,
            "Successfully promoted to primary"
        );

        // Update metrics
        crate::metrics::set_node_role("primary");

        Ok(new_token)
    }

    /// Demote this node back to passive (e.g., when original primary recovers)
    pub fn demote(&self) -> Result<(), FailoverError> {
        let current_role = self.role();
        if current_role != NodeRole::Primary {
            return Err(FailoverError::InvalidRoleTransition {
                from: current_role,
                to: NodeRole::Passive,
            });
        }

        info!("Demoting to passive");

        {
            let mut role = self.role.write()
                .map_err(|_| FailoverError::LockPoisoned)?;
            *role = NodeRole::Passive;
        }

        let _ = self.role_tx.send(NodeRole::Passive);

        // Update metrics
        crate::metrics::set_node_role("passive");

        Ok(())
    }

    /// Set role directly (for initialization)
    pub fn set_role(&self, new_role: NodeRole) -> Result<(), FailoverError> {
        {
            let mut role = self.role.write()
                .map_err(|_| FailoverError::LockPoisoned)?;
            *role = new_role;
        }

        let _ = self.role_tx.send(new_role);

        // Update metrics
        crate::metrics::set_node_role(&new_role.to_string());

        Ok(())
    }

    /// Check if this is the primary node
    pub fn is_primary(&self) -> bool {
        self.role() == NodeRole::Primary
    }

    /// Check if this is a passive node
    pub fn is_passive(&self) -> bool {
        self.role() == NodeRole::Passive
    }

    /// Validate a fencing token (reject if stale)
    pub fn validate_fencing_token(&self, token: &FencingToken) -> bool {
        let our_token = self.fencing_token.load(Ordering::Acquire);
        token.token >= our_token
    }
}

/// Errors from failover operations
#[derive(Debug, thiserror::Error)]
pub enum FailoverError {
    #[error("Invalid role transition from {from} to {to}")]
    InvalidRoleTransition { from: NodeRole, to: NodeRole },

    #[error("Lock poisoned")]
    LockPoisoned,

    #[error("Fencing token rejected")]
    FencingTokenRejected,

    #[error("Promotion failed: {0}")]
    PromotionFailed(String),
}

/// Start automatic failover monitoring
///
/// This spawns a task that monitors for failover events and promotes
/// the passive node when appropriate.
pub fn start_auto_failover(
    coordinator: Arc<FailoverCoordinator>,
    passive_handle: PassiveHandle,
) -> watch::Receiver<bool> {
    let (done_tx, done_rx) = watch::channel(false);

    let mut failover_rx = passive_handle.subscribe_failover();

    tokio::spawn(async move {
        loop {
            // Wait for failover signal
            if failover_rx.changed().await.is_err() {
                break;
            }

            if *failover_rx.borrow() {
                info!("Failover detected, attempting promotion");

                match coordinator.promote(&passive_handle).await {
                    Ok(token) => {
                        info!(fencing_token = token, "Promotion successful");
                        let _ = done_tx.send(true);
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "Promotion failed");
                    }
                }
            }
        }
    });

    done_rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_creation() {
        let config = FailoverConfig {
            node_id: "test-node".to_string(),
            initial_role: NodeRole::Passive,
            ..Default::default()
        };

        let coordinator = FailoverCoordinator::new(config);
        assert_eq!(coordinator.role(), NodeRole::Passive);
        assert_eq!(coordinator.failover_state(), FailoverState::Normal);
    }

    #[test]
    fn test_role_change() {
        let config = FailoverConfig {
            initial_role: NodeRole::Standalone,
            ..Default::default()
        };

        let coordinator = FailoverCoordinator::new(config);
        assert_eq!(coordinator.role(), NodeRole::Standalone);

        coordinator.set_role(NodeRole::Primary).unwrap();
        assert_eq!(coordinator.role(), NodeRole::Primary);
        assert!(coordinator.is_primary());
    }

    #[test]
    fn test_fencing_token_validation() {
        let config = FailoverConfig::default();
        let coordinator = FailoverCoordinator::new(config);

        let token = FencingToken::new(1, "node-a");
        assert!(coordinator.validate_fencing_token(&token));

        // Increment our token
        coordinator.fencing_token.store(5, Ordering::Release);

        // Old token should be rejected
        assert!(!coordinator.validate_fencing_token(&token));

        // Current or newer should be accepted
        let newer_token = FencingToken::new(5, "node-b");
        assert!(coordinator.validate_fencing_token(&newer_token));
    }
}
