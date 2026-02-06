//! Primary node state replication
//!
//! The StateReplicator streams decision records to passive nodes
//! and sends periodic heartbeats.

use super::protocol::{
    ErrorCode, ErrorMessage, Heartbeat, HelloMessage, ReplicationMessage, SyncResponse,
    PROTOCOL_VERSION,
};
use super::tls::{ReplicationTlsConfig, ReplicationTlsStream};
use crate::state::integrity::{DecisionRecord, StateIntegrity};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Configuration for the state replicator
#[derive(Debug, Clone)]
pub struct ReplicatorConfig {
    /// Address to listen for passive node connections
    pub listen_addr: String,

    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,

    /// Maximum number of records to buffer for slow passives
    pub max_buffer_size: usize,

    /// Node identifier
    pub node_id: String,

    /// Optional TLS configuration for mTLS
    pub tls_config: Option<ReplicationTlsConfig>,
}

impl Default for ReplicatorConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:26660".to_string(),
            heartbeat_interval_ms: 1000,
            max_buffer_size: 10000,
            node_id: "primary".to_string(),
            tls_config: None,
        }
    }
}

/// State replicator for the primary node
pub struct StateReplicator {
    config: ReplicatorConfig,

    /// Current fencing token
    fencing_token: AtomicU64,

    /// Channel to receive new decision records
    decision_rx: mpsc::Receiver<DecisionRecord>,

    /// Broadcast channel for sending to passives
    broadcast_tx: broadcast::Sender<ReplicationMessage>,

    /// Record buffer for catch-up sync
    record_buffer: Arc<RwLock<VecDeque<DecisionRecord>>>,

    /// Current state integrity (for heartbeats)
    integrity: Arc<RwLock<StateIntegrity>>,

    /// Shutdown flag
    _shutdown: AtomicBool,
}

/// Handle for controlling the replicator
pub struct ReplicatorHandle {
    /// Sender for new decision records
    decision_tx: mpsc::Sender<DecisionRecord>,

    /// Shutdown signal
    shutdown_tx: watch::Sender<bool>,

    /// Reference to update integrity
    integrity: Arc<RwLock<StateIntegrity>>,
}

impl ReplicatorHandle {
    /// Send a new decision record to be replicated
    pub async fn replicate(&self, record: DecisionRecord) -> Result<(), ReplicationError> {
        self.decision_tx
            .send(record)
            .await
            .map_err(|_| ReplicationError::ChannelClosed)
    }

    /// Update the current state integrity (call after each signing)
    pub fn update_integrity(&self, integrity: StateIntegrity) {
        if let Ok(mut guard) = self.integrity.write() {
            *guard = integrity;
        }
    }

    /// Signal the replicator to shutdown
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Errors from replication
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    #[error("Channel closed")]
    ChannelClosed,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Fencing token rejected")]
    FencingRejected,
}

impl StateReplicator {
    /// Create a new state replicator
    pub fn new(
        config: ReplicatorConfig,
        initial_integrity: StateIntegrity,
    ) -> (Self, ReplicatorHandle) {
        let (decision_tx, decision_rx) = mpsc::channel(1000);
        let (broadcast_tx, _) = broadcast::channel(1000);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        let integrity = Arc::new(RwLock::new(initial_integrity));

        let replicator = Self {
            config: config.clone(),
            fencing_token: AtomicU64::new(1),
            decision_rx,
            broadcast_tx,
            record_buffer: Arc::new(RwLock::new(VecDeque::with_capacity(config.max_buffer_size))),
            integrity: integrity.clone(),
            _shutdown: AtomicBool::new(false),
        };

        let handle = ReplicatorHandle {
            decision_tx,
            shutdown_tx,
            integrity,
        };

        (replicator, handle)
    }

    /// Start the replicator (runs until shutdown)
    pub async fn run(mut self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), ReplicationError> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;

        // Build TLS acceptor if configured
        let tls_acceptor: Option<TlsAcceptor> = if let Some(ref tls_config) = self.config.tls_config {
            match tls_config.build_acceptor() {
                Ok(acceptor) => {
                    info!(addr = %self.config.listen_addr, "State replicator listening with mTLS");
                    Some(acceptor)
                }
                Err(e) => {
                    error!(error = %e, "Failed to build TLS acceptor");
                    return Err(ReplicationError::Protocol(format!("TLS setup failed: {}", e)));
                }
            }
        } else {
            info!(addr = %self.config.listen_addr, "State replicator listening (plaintext - NOT RECOMMENDED FOR PRODUCTION)");
            None
        };

        let heartbeat_interval = Duration::from_millis(self.config.heartbeat_interval_ms);
        let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);

        loop {
            tokio::select! {
                // Accept new passive connections
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            info!(addr = %addr, "Passive node connected");
                            let broadcast_rx = self.broadcast_tx.subscribe();
                            let buffer = self.record_buffer.clone();
                            let integrity = self.integrity.clone();
                            let node_id = self.config.node_id.clone();
                            let _fencing_token = self.fencing_token.load(Ordering::Acquire);
                            let tls_acceptor_clone = tls_acceptor.clone();

                            tokio::spawn(async move {
                                // Wrap with TLS if configured
                                let result = if let Some(acceptor) = tls_acceptor_clone {
                                    match ReplicationTlsStream::accept(&acceptor, stream).await {
                                        Ok(tls_stream) => {
                                            info!(addr = %addr, "TLS handshake successful");
                                            handle_passive_connection_generic(
                                                tls_stream,
                                                broadcast_rx,
                                                buffer,
                                                integrity,
                                                node_id,
                                                _fencing_token,
                                            ).await
                                        }
                                        Err(e) => {
                                            warn!(addr = %addr, error = %e, "TLS handshake failed");
                                            return;
                                        }
                                    }
                                } else {
                                    handle_passive_connection_generic(
                                        ReplicationTlsStream::plain(stream),
                                        broadcast_rx,
                                        buffer,
                                        integrity,
                                        node_id,
                                        _fencing_token,
                                    ).await
                                };

                                if let Err(e) = result {
                                    warn!(error = %e, "Passive connection error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Accept error");
                        }
                    }
                }

                // Receive new decision records to replicate
                Some(record) = self.decision_rx.recv() => {
                    self.buffer_record(record.clone());

                    let msg = ReplicationMessage::Decision(record);
                    let _ = self.broadcast_tx.send(msg);
                }

                // Send periodic heartbeats
                _ = heartbeat_timer.tick() => {
                    if let Ok(integrity) = self.integrity.read() {
                        let heartbeat = Heartbeat::new(
                            integrity.sequence_number,
                            integrity.current_hash,
                            self.fencing_token.load(Ordering::Acquire),
                        );
                        let msg = ReplicationMessage::Heartbeat(heartbeat);
                        let _ = self.broadcast_tx.send(msg);
                    }
                }

                // Check for shutdown
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("State replicator shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Buffer a record for catch-up sync
    fn buffer_record(&self, record: DecisionRecord) {
        if let Ok(mut buffer) = self.record_buffer.write() {
            if buffer.len() >= self.config.max_buffer_size {
                buffer.pop_front();
            }
            buffer.push_back(record);
        }
    }

    /// Increment and return the fencing token
    pub fn next_fencing_token(&self) -> u64 {
        self.fencing_token.fetch_add(1, Ordering::AcqRel) + 1
    }
}

/// Handle a connected passive node (legacy function for TcpStream)
#[allow(dead_code)]
async fn handle_passive_connection(
    stream: TcpStream,
    broadcast_rx: broadcast::Receiver<ReplicationMessage>,
    record_buffer: Arc<RwLock<VecDeque<DecisionRecord>>>,
    integrity: Arc<RwLock<StateIntegrity>>,
    node_id: String,
    fencing_token: u64,
) -> Result<(), ReplicationError> {
    handle_passive_connection_generic(
        ReplicationTlsStream::plain(stream),
        broadcast_rx,
        record_buffer,
        integrity,
        node_id,
        fencing_token,
    )
    .await
}

/// Handle a connected passive node (generic version for any stream type)
async fn handle_passive_connection_generic<S>(
    mut stream: S,
    mut broadcast_rx: broadcast::Receiver<ReplicationMessage>,
    record_buffer: Arc<RwLock<VecDeque<DecisionRecord>>>,
    integrity: Arc<RwLock<StateIntegrity>>,
    node_id: String,
    _fencing_token: u64,
) -> Result<(), ReplicationError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Send hello message
    let (sequence, state_hash, genesis_root) = {
        let guard = integrity
            .read()
            .map_err(|_| ReplicationError::Protocol("Lock poisoned".to_string()))?;
        (
            guard.sequence_number,
            guard.current_hash,
            guard.genesis_validators_root,
        )
    };

    let hello = HelloMessage {
        version: PROTOCOL_VERSION,
        node_id: node_id.clone(),
        role: "Primary".to_string(),
        sequence,
        state_hash,
        genesis_root,
    };

    send_message_generic(&mut stream, &ReplicationMessage::Hello(hello)).await?;

    // Read hello response from passive
    let passive_hello = match read_message_generic(&mut stream).await? {
        Some(ReplicationMessage::Hello(h)) => h,
        Some(other) => {
            return Err(ReplicationError::Protocol(format!(
                "Expected Hello, got {:?}",
                std::mem::discriminant(&other)
            )));
        }
        None => {
            return Err(ReplicationError::Protocol(
                "Connection closed during handshake".to_string(),
            ));
        }
    };

    // Version check
    if passive_hello.version != PROTOCOL_VERSION {
        send_message_generic(
            &mut stream,
            &ReplicationMessage::Error(ErrorMessage {
                code: ErrorCode::VersionMismatch,
                description: format!(
                    "Expected version {}, got {}",
                    PROTOCOL_VERSION, passive_hello.version
                ),
                sequence: None,
            }),
        )
        .await?;
        return Err(ReplicationError::Protocol("Version mismatch".to_string()));
    }

    info!(
        passive_id = %passive_hello.node_id,
        passive_sequence = passive_hello.sequence,
        "Passive node handshake complete"
    );

    // Handle sync if passive is behind
    if passive_hello.sequence < sequence {
        handle_sync_generic(&mut stream, &record_buffer, passive_hello.sequence, sequence).await?;
    }

    // Forward messages from broadcast channel
    loop {
        tokio::select! {
            msg_result = broadcast_rx.recv() => {
                match msg_result {
                    Ok(msg) => {
                        if let Err(e) = send_message_generic(&mut stream, &msg).await {
                            warn!(error = %e, "Failed to send to passive");
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(lagged = n, "Passive fell behind, may need resync");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }

            // Read acknowledgments or sync requests from passive
            read_result = read_message_generic(&mut stream) => {
                match read_result {
                    Ok(Some(ReplicationMessage::Ack(ack))) => {
                        debug!(sequence = ack.sequence, "Received ACK from passive");
                    }
                    Ok(Some(ReplicationMessage::SyncRequest(req))) => {
                        let current_seq = integrity.read()
                            .map(|i| i.sequence_number)
                            .unwrap_or(0);
                        handle_sync_generic(&mut stream, &record_buffer, req.from_sequence, current_seq).await?;
                    }
                    Ok(Some(_)) => {
                        // Ignore other messages
                    }
                    Ok(None) => {
                        info!("Passive disconnected");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading from passive");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle sync request from passive (legacy version for TcpStream)
#[allow(dead_code)]
async fn handle_sync(
    stream: &mut TcpStream,
    record_buffer: &Arc<RwLock<VecDeque<DecisionRecord>>>,
    from_sequence: u64,
    current_sequence: u64,
) -> Result<(), ReplicationError> {
    handle_sync_generic(stream, record_buffer, from_sequence, current_sequence).await
}

/// Handle sync request from passive (generic version)
async fn handle_sync_generic<S>(
    stream: &mut S,
    record_buffer: &Arc<RwLock<VecDeque<DecisionRecord>>>,
    from_sequence: u64,
    current_sequence: u64,
) -> Result<(), ReplicationError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let records = {
        let buffer = record_buffer
            .read()
            .map_err(|_| ReplicationError::Protocol("Lock poisoned".to_string()))?;

        buffer
            .iter()
            .filter(|r| r.sequence > from_sequence && r.sequence <= current_sequence)
            .cloned()
            .collect::<Vec<_>>()
    };

    let response = SyncResponse {
        records,
        has_more: false,
        current_sequence,
    };

    send_message_generic(stream, &ReplicationMessage::SyncResponse(response)).await
}

/// Send a message with length prefix (legacy version for TcpStream)
#[allow(dead_code)]
async fn send_message(
    stream: &mut TcpStream,
    msg: &ReplicationMessage,
) -> Result<(), ReplicationError> {
    send_message_generic(stream, msg).await
}

/// Send a message with length prefix (generic version)
async fn send_message_generic<S>(
    stream: &mut S,
    msg: &ReplicationMessage,
) -> Result<(), ReplicationError>
where
    S: AsyncWrite + Unpin,
{
    let bytes =
        serde_json::to_vec(msg).map_err(|e| ReplicationError::Serialization(e.to_string()))?;

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
) -> Result<Option<ReplicationMessage>, ReplicationError> {
    read_message_generic(stream).await
}

/// Read a message with length prefix (generic version)
async fn read_message_generic<S>(
    stream: &mut S,
) -> Result<Option<ReplicationMessage>, ReplicationError>
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
        return Err(ReplicationError::Protocol(format!(
            "Message too large: {} bytes",
            len
        )));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let msg = serde_json::from_slice(&buf)
        .map_err(|e| ReplicationError::Serialization(e.to_string()))?;

    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replicator_creation() {
        let integrity = StateIntegrity::new();
        let config = ReplicatorConfig::default();
        let (replicator, _handle) = StateReplicator::new(config, integrity);

        assert_eq!(replicator.fencing_token.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_fencing_token_increment() {
        let integrity = StateIntegrity::new();
        let config = ReplicatorConfig::default();
        let (replicator, _handle) = StateReplicator::new(config, integrity);

        assert_eq!(replicator.next_fencing_token(), 2);
        assert_eq!(replicator.next_fencing_token(), 3);
    }
}
