//! Passive node state receiver
//!
//! The PassiveReceiver connects to the primary, receives decision records,
//! verifies the hash chain, and maintains shadow state ready for failover.

use super::heartbeat::{HeartbeatConfig, HeartbeatMonitor};
use super::protocol::{AckMessage, HelloMessage, ReplicationMessage, PROTOCOL_VERSION};
use super::tls::{ReplicationTlsConfig, ReplicationTlsStream};
use crate::state::integrity::{DecisionRecord, IntegrityError, StateIntegrity};
use crate::state::validator::ValidatorState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

/// Configuration for the passive receiver
#[derive(Debug, Clone)]
pub struct PassiveConfig {
    /// Address of the primary node
    pub primary_addr: String,

    /// Node identifier
    pub node_id: String,

    /// Reconnect delay on connection failure (milliseconds)
    pub reconnect_delay_ms: u64,

    /// Heartbeat configuration
    pub heartbeat_config: HeartbeatConfig,

    /// Optional TLS configuration for mTLS
    pub tls_config: Option<ReplicationTlsConfig>,

    /// Server name for TLS verification (e.g., "primary.nklave.local")
    pub tls_server_name: Option<String>,
}

impl Default for PassiveConfig {
    fn default() -> Self {
        Self {
            primary_addr: "127.0.0.1:26660".to_string(),
            node_id: "passive".to_string(),
            reconnect_delay_ms: 5000,
            heartbeat_config: HeartbeatConfig::default(),
            tls_config: None,
            tls_server_name: None,
        }
    }
}

/// Passive receiver that maintains shadow state
pub struct PassiveReceiver {
    config: PassiveConfig,

    /// Shadow copy of state integrity
    integrity: Arc<RwLock<StateIntegrity>>,

    /// Shadow copy of validator states
    _validator_states: Arc<RwLock<HashMap<[u8; 48], ValidatorState>>>,

    /// Heartbeat monitor
    heartbeat_monitor: Arc<HeartbeatMonitor>,

    /// Current fencing token from primary
    fencing_token: AtomicU64,

    /// Replication lag (sequences behind primary)
    replication_lag: AtomicU64,

    /// Whether we're connected to primary
    connected: AtomicBool,

    /// Shutdown flag
    _shutdown: AtomicBool,

    /// Optional TLS connector for secure connections
    tls_connector: Option<TlsConnector>,

    /// Server name for TLS verification
    tls_server_name: Option<String>,
}

/// Handle for controlling the passive receiver
pub struct PassiveHandle {
    /// Shutdown signal
    shutdown_tx: watch::Sender<bool>,

    /// Reference to integrity for promotion
    integrity: Arc<RwLock<StateIntegrity>>,

    /// Reference to validator states for promotion
    validator_states: Arc<RwLock<HashMap<[u8; 48], ValidatorState>>>,

    /// Heartbeat monitor for failover detection
    heartbeat_monitor: Arc<HeartbeatMonitor>,
}

impl PassiveHandle {
    /// Get the current state integrity (for promotion)
    pub fn integrity(&self) -> StateIntegrity {
        self.integrity.read().map(|i| i.clone()).unwrap_or_default()
    }

    /// Get the current validator states (for promotion)
    pub fn validator_states(&self) -> HashMap<[u8; 48], ValidatorState> {
        self.validator_states.read().map(|v| v.clone()).unwrap_or_default()
    }

    /// Subscribe to failover notifications
    pub fn subscribe_failover(&self) -> watch::Receiver<bool> {
        self.heartbeat_monitor.subscribe_failover()
    }

    /// Check if we should trigger failover
    pub fn should_failover(&self) -> bool {
        !self.heartbeat_monitor.is_primary_alive()
    }

    /// Get replication lag
    pub fn replication_lag(&self) -> u64 {
        // This would need to be tracked
        0
    }

    /// Signal shutdown
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Errors from passive receiver
#[derive(Debug, thiserror::Error)]
pub enum PassiveError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Hash chain verification failed: {0}")]
    HashChainError(#[from] IntegrityError),

    #[error("Genesis root mismatch")]
    GenesisRootMismatch,
}

impl PassiveReceiver {
    /// Create a new passive receiver
    pub fn new(
        config: PassiveConfig,
        initial_integrity: StateIntegrity,
        initial_validators: HashMap<[u8; 48], ValidatorState>,
    ) -> (Self, PassiveHandle) {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        let integrity = Arc::new(RwLock::new(initial_integrity));
        let validator_states = Arc::new(RwLock::new(initial_validators));
        let heartbeat_monitor = Arc::new(HeartbeatMonitor::new(config.heartbeat_config.clone()));

        // Build TLS connector if configured
        let tls_connector = if let Some(ref tls_config) = config.tls_config {
            match tls_config.build_connector() {
                Ok(connector) => {
                    info!("TLS connector configured for passive receiver");
                    Some(connector)
                }
                Err(e) => {
                    error!(error = %e, "Failed to build TLS connector, falling back to plaintext");
                    None
                }
            }
        } else {
            None
        };

        let tls_server_name = config.tls_server_name.clone();

        let receiver = Self {
            config: config.clone(),
            integrity: integrity.clone(),
            _validator_states: validator_states.clone(),
            heartbeat_monitor: heartbeat_monitor.clone(),
            fencing_token: AtomicU64::new(0),
            replication_lag: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            _shutdown: AtomicBool::new(false),
            tls_connector,
            tls_server_name,
        };

        let handle = PassiveHandle {
            shutdown_tx,
            integrity,
            validator_states,
            heartbeat_monitor,
        };

        (receiver, handle)
    }

    /// Run the passive receiver (connects and stays connected to primary)
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), PassiveError> {
        loop {
            // Check for shutdown
            if *shutdown_rx.borrow() {
                info!("Passive receiver shutting down");
                break;
            }

            // Try to connect
            match self.connect_and_receive(&mut shutdown_rx).await {
                Ok(()) => {
                    info!("Connection to primary closed normally");
                }
                Err(e) => {
                    warn!(error = %e, "Connection to primary failed");
                    self.connected.store(false, Ordering::Release);
                }
            }

            // Wait before reconnecting
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(self.config.reconnect_delay_ms)) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Connect to primary and receive messages
    async fn connect_and_receive(
        &self,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<(), PassiveError> {
        let tcp_stream = TcpStream::connect(&self.config.primary_addr).await?;
        info!(addr = %self.config.primary_addr, "TCP connected to primary");

        // Wrap with TLS if configured
        if let Some(ref connector) = self.tls_connector {
            let server_name = self
                .tls_server_name
                .as_deref()
                .unwrap_or("primary.nklave.local");

            match ReplicationTlsStream::connect(connector, server_name, tcp_stream).await {
                Ok(tls_stream) => {
                    info!("TLS handshake successful with primary");
                    self.connected.store(true, Ordering::Release);
                    self.receive_loop_generic(tls_stream, shutdown_rx).await
                }
                Err(e) => {
                    warn!(error = %e, "TLS handshake failed with primary");
                    Err(PassiveError::ConnectionFailed(format!(
                        "TLS handshake failed: {}",
                        e
                    )))
                }
            }
        } else {
            info!(addr = %self.config.primary_addr, "Connected to primary (plaintext - NOT RECOMMENDED FOR PRODUCTION)");
            self.connected.store(true, Ordering::Release);
            self.receive_loop_generic(ReplicationTlsStream::plain(tcp_stream), shutdown_rx)
                .await
        }
    }

    /// Main receive loop with generic stream type
    async fn receive_loop_generic<S>(
        &self,
        mut stream: S,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> Result<(), PassiveError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Receive hello from primary
        let primary_hello = match read_message_generic(&mut stream).await? {
            Some(ReplicationMessage::Hello(h)) => h,
            Some(other) => {
                return Err(PassiveError::Protocol(format!(
                    "Expected Hello, got {:?}",
                    std::mem::discriminant(&other)
                )));
            }
            None => {
                return Err(PassiveError::Protocol(
                    "Connection closed during handshake".to_string(),
                ));
            }
        };

        // Version check
        if primary_hello.version != PROTOCOL_VERSION {
            return Err(PassiveError::Protocol(format!(
                "Version mismatch: expected {}, got {}",
                PROTOCOL_VERSION, primary_hello.version
            )));
        }

        // Send our hello
        let (our_sequence, our_hash, our_genesis) = {
            let guard = self
                .integrity
                .read()
                .map_err(|_| PassiveError::Protocol("Lock poisoned".to_string()))?;
            (
                guard.sequence_number,
                guard.current_hash,
                guard.genesis_validators_root,
            )
        };

        let our_hello = HelloMessage {
            version: PROTOCOL_VERSION,
            node_id: self.config.node_id.clone(),
            role: "Passive".to_string(),
            sequence: our_sequence,
            state_hash: our_hash,
            genesis_root: our_genesis,
        };

        send_message_generic(&mut stream, &ReplicationMessage::Hello(our_hello)).await?;

        info!(
            primary_id = %primary_hello.node_id,
            primary_sequence = primary_hello.sequence,
            our_sequence = our_sequence,
            "Handshake complete with primary"
        );

        // Record initial heartbeat
        self.heartbeat_monitor
            .record_heartbeat(primary_hello.sequence, primary_hello.state_hash);

        // Check genesis root compatibility
        if let (Some(primary_genesis), Some(our_genesis)) =
            (primary_hello.genesis_root, our_genesis)
        {
            if primary_genesis != our_genesis {
                return Err(PassiveError::GenesisRootMismatch);
            }
        }

        // Main receive loop
        loop {
            tokio::select! {
                msg_result = read_message_generic(&mut stream) => {
                    match msg_result {
                        Ok(Some(msg)) => {
                            self.handle_message_generic(msg, &mut stream).await?;
                        }
                        Ok(None) => {
                            info!("Primary disconnected");
                            break;
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }

                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a received message (legacy version for TcpStream)
    #[allow(dead_code)]
    async fn handle_message(
        &self,
        msg: ReplicationMessage,
        stream: &mut TcpStream,
    ) -> Result<(), PassiveError> {
        self.handle_message_generic(msg, stream).await
    }

    /// Handle a received message (generic version)
    async fn handle_message_generic<S>(
        &self,
        msg: ReplicationMessage,
        stream: &mut S,
    ) -> Result<(), PassiveError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match msg {
            ReplicationMessage::Heartbeat(hb) => {
                self.heartbeat_monitor
                    .record_heartbeat(hb.sequence, hb.state_hash);
                self.fencing_token.store(hb.fencing_token, Ordering::Release);

                // Calculate replication lag
                let our_seq = self
                    .integrity
                    .read()
                    .map(|i| i.sequence_number)
                    .unwrap_or(0);
                let lag = hb.sequence.saturating_sub(our_seq);
                self.replication_lag.store(lag, Ordering::Release);

                debug!(
                    primary_sequence = hb.sequence,
                    our_sequence = our_seq,
                    lag = lag,
                    "Heartbeat received"
                );
            }

            ReplicationMessage::Decision(record) => {
                self.apply_decision_record_generic(record, stream).await?;
            }

            ReplicationMessage::SyncResponse(response) => {
                info!(
                    record_count = response.records.len(),
                    has_more = response.has_more,
                    "Received sync response"
                );

                for record in response.records {
                    self.apply_decision_record_generic(record, stream).await?;
                }
            }

            ReplicationMessage::Error(err) => {
                error!(
                    code = ?err.code,
                    description = %err.description,
                    "Received error from primary"
                );
                return Err(PassiveError::Protocol(err.description));
            }

            _ => {
                debug!("Ignoring unexpected message type");
            }
        }

        Ok(())
    }

    /// Apply a decision record to our shadow state (legacy version for TcpStream)
    #[allow(dead_code)]
    async fn apply_decision_record(
        &self,
        record: DecisionRecord,
        stream: &mut TcpStream,
    ) -> Result<(), PassiveError> {
        self.apply_decision_record_generic(record, stream).await
    }

    /// Apply a decision record to our shadow state (generic version)
    async fn apply_decision_record_generic<S>(
        &self,
        record: DecisionRecord,
        stream: &mut S,
    ) -> Result<(), PassiveError>
    where
        S: AsyncWrite + Unpin,
    {
        let new_hash = {
            let mut integrity = self
                .integrity
                .write()
                .map_err(|_| PassiveError::Protocol("Lock poisoned".to_string()))?;

            // Verify and apply the record
            let new_hash = integrity.record_decision(&record)?;

            debug!(
                sequence = record.sequence,
                new_hash = hex::encode(new_hash),
                "Applied decision record"
            );

            new_hash
        };

        // Send acknowledgment
        let ack = AckMessage {
            sequence: record.sequence,
            state_hash: new_hash,
        };
        send_message_generic(stream, &ReplicationMessage::Ack(ack)).await?;

        // Update metrics
        crate::metrics::set_state_sequence(record.sequence);

        Ok(())
    }

    /// Get current replication lag
    pub fn replication_lag(&self) -> u64 {
        self.replication_lag.load(Ordering::Acquire)
    }

    /// Check if connected to primary
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }
}

/// Send a message with length prefix (legacy version for TcpStream)
#[allow(dead_code)]
async fn send_message(
    stream: &mut TcpStream,
    msg: &ReplicationMessage,
) -> Result<(), PassiveError> {
    send_message_generic(stream, msg).await
}

/// Send a message with length prefix (generic version)
async fn send_message_generic<S>(stream: &mut S, msg: &ReplicationMessage) -> Result<(), PassiveError>
where
    S: AsyncWrite + Unpin,
{
    let bytes =
        serde_json::to_vec(msg).map_err(|e| PassiveError::Serialization(e.to_string()))?;

    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;

    Ok(())
}

/// Read a message with length prefix (legacy version for TcpStream)
#[allow(dead_code)]
async fn read_message(
    stream: &mut TcpStream,
) -> Result<Option<ReplicationMessage>, PassiveError> {
    read_message_generic(stream).await
}

/// Read a message with length prefix (generic version)
async fn read_message_generic<S>(stream: &mut S) -> Result<Option<ReplicationMessage>, PassiveError>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > super::protocol::MAX_MESSAGE_SIZE {
        return Err(PassiveError::Protocol(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let msg = serde_json::from_slice(&buf)
        .map_err(|e| PassiveError::Serialization(e.to_string()))?;

    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_receiver_creation() {
        let config = PassiveConfig::default();
        let integrity = StateIntegrity::new();
        let validators = HashMap::new();

        let (receiver, _handle) = PassiveReceiver::new(config, integrity, validators);

        assert!(!receiver.is_connected());
        assert_eq!(receiver.replication_lag(), 0);
    }
}
