//! TCP/Unix socket server implementing the Tendermint PrivValidator protocol
//!
//! This module provides a socket server that implements the Tendermint
//! PrivValidator protocol, allowing Cosmos validators to use Nklave
//! as a remote signer.
//!
//! The protocol uses length-prefixed protobuf messages wrapped in a
//! `Message` oneof type.

use crate::error::{CosmosError, RemoteSignerCode};
use crate::service::CosmosSigningService;
use prost::Message as ProstMessage;
use std::sync::Arc;
use tendermint_proto::privval::{
    message::Sum, Message, PingResponse, PubKeyResponse, RemoteSignerError, SignedProposalResponse,
    SignedVoteResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// Configuration for the Cosmos protocol server
#[derive(Debug, Clone)]
pub struct CosmosServerConfig {
    /// TCP address to listen on (e.g., "127.0.0.1:26659")
    /// Set to None to disable TCP listener
    pub tcp_addr: Option<String>,

    /// Unix socket path to listen on
    /// Set to None to disable Unix socket listener
    pub unix_socket: Option<String>,
}

impl Default for CosmosServerConfig {
    fn default() -> Self {
        Self {
            tcp_addr: Some("127.0.0.1:26659".to_string()),
            unix_socket: None,
        }
    }
}

/// Handle for controlling the running server
pub struct CosmosServerHandle {
    shutdown_tx: oneshot::Sender<()>,
}

impl CosmosServerHandle {
    /// Signal the server to shut down gracefully
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Cosmos protocol server
pub struct CosmosServer {
    service: Arc<CosmosSigningService>,
    config: CosmosServerConfig,
}

impl CosmosServer {
    /// Create a new Cosmos server
    pub fn new(service: Arc<CosmosSigningService>, config: CosmosServerConfig) -> Self {
        Self { service, config }
    }

    /// Start the server and return a handle for shutdown
    pub async fn serve(self) -> Result<CosmosServerHandle, CosmosError> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // Start TCP listener if configured
        if let Some(ref addr) = self.config.tcp_addr {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| CosmosError::BindError(format!("TCP bind failed: {}", e)))?;

            info!(addr = %addr, "Cosmos TCP server listening");

            let service = self.service.clone();
            tokio::spawn(async move {
                Self::tcp_accept_loop(listener, service).await;
            });
        }

        // Start Unix socket listener if configured
        if let Some(ref path) = self.config.unix_socket {
            // Remove existing socket file if present
            let _ = std::fs::remove_file(path);

            let listener = UnixListener::bind(path)
                .map_err(|e| CosmosError::BindError(format!("Unix socket bind failed: {}", e)))?;

            info!(path = %path, "Cosmos Unix socket server listening");

            let service = self.service.clone();
            tokio::spawn(async move {
                Self::unix_accept_loop(listener, service).await;
            });
        }

        // Wait for shutdown signal in a separate task
        tokio::spawn(async move {
            let _ = shutdown_rx.await;
            info!("Cosmos server shutdown requested");
        });

        Ok(CosmosServerHandle { shutdown_tx })
    }

    async fn tcp_accept_loop(listener: TcpListener, service: Arc<CosmosSigningService>) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!(addr = %addr, "Accepted TCP connection");
                    let service = service.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_tcp_connection(stream, service).await {
                            error!(error = %e, "TCP connection handler error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "TCP accept error");
                }
            }
        }
    }

    async fn unix_accept_loop(listener: UnixListener, service: Arc<CosmosSigningService>) {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    info!("Accepted Unix socket connection");
                    let service = service.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_unix_connection(stream, service).await {
                            error!(error = %e, "Unix socket connection handler error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Unix socket accept error");
                }
            }
        }
    }

    async fn handle_tcp_connection(
        mut stream: TcpStream,
        service: Arc<CosmosSigningService>,
    ) -> Result<(), CosmosError> {
        loop {
            // Read message
            let request = match read_message(&mut stream).await {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    debug!("TCP connection closed by peer");
                    return Ok(());
                }
                Err(e) => {
                    warn!(error = %e, "Error reading from TCP stream");
                    return Err(e);
                }
            };

            // Process and send response
            let response = process_message(request, &service);
            write_message(&mut stream, &response).await?;
        }
    }

    async fn handle_unix_connection(
        mut stream: UnixStream,
        service: Arc<CosmosSigningService>,
    ) -> Result<(), CosmosError> {
        loop {
            // Read message
            let request = match read_message(&mut stream).await {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    debug!("Unix socket connection closed by peer");
                    return Ok(());
                }
                Err(e) => {
                    warn!(error = %e, "Error reading from Unix socket");
                    return Err(e);
                }
            };

            // Process and send response
            let response = process_message(request, &service);
            write_message(&mut stream, &response).await?;
        }
    }
}

/// Read a length-prefixed protobuf message from a stream
async fn read_message<R>(reader: &mut R) -> Result<Option<Message>, CosmosError>
where
    R: AsyncReadExt + Unpin,
{
    // Read length prefix (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None); // Connection closed
        }
        Err(e) => {
            return Err(CosmosError::Internal(format!("Read error: {}", e)));
        }
    }

    let msg_len = u32::from_be_bytes(len_buf) as usize;
    if msg_len > 10 * 1024 * 1024 {
        // 10MB limit
        return Err(CosmosError::Internal(format!(
            "Message too large: {} bytes",
            msg_len
        )));
    }

    // Read message body
    let mut msg_buf = vec![0u8; msg_len];
    reader
        .read_exact(&mut msg_buf)
        .await
        .map_err(|e| CosmosError::Internal(format!("Read error: {}", e)))?;

    // Decode protobuf
    let message = Message::decode(&msg_buf[..])
        .map_err(|e| CosmosError::Internal(format!("Decode error: {}", e)))?;

    Ok(Some(message))
}

/// Write a length-prefixed protobuf message to a stream
async fn write_message<W>(writer: &mut W, message: &Message) -> Result<(), CosmosError>
where
    W: AsyncWriteExt + Unpin,
{
    // Encode message
    let mut msg_buf = Vec::new();
    message
        .encode(&mut msg_buf)
        .map_err(|e| CosmosError::Internal(format!("Encode error: {}", e)))?;

    // Write length prefix (4 bytes, big-endian)
    let len_buf = (msg_buf.len() as u32).to_be_bytes();
    writer
        .write_all(&len_buf)
        .await
        .map_err(|e| CosmosError::Internal(format!("Write error: {}", e)))?;

    // Write message body
    writer
        .write_all(&msg_buf)
        .await
        .map_err(|e| CosmosError::Internal(format!("Write error: {}", e)))?;

    writer
        .flush()
        .await
        .map_err(|e| CosmosError::Internal(format!("Flush error: {}", e)))?;

    Ok(())
}

/// Process a privval protocol message and return the response
fn process_message(request: Message, service: &CosmosSigningService) -> Message {
    let response_sum = match request.sum {
        Some(Sum::PubKeyRequest(req)) => {
            debug!(chain_id = %req.chain_id, "Handling PubKeyRequest");
            handle_pub_key_request(req.chain_id, service)
        }
        Some(Sum::SignVoteRequest(req)) => {
            debug!(chain_id = %req.chain_id, "Handling SignVoteRequest");
            handle_sign_vote_request(req, service)
        }
        Some(Sum::SignProposalRequest(req)) => {
            debug!(chain_id = %req.chain_id, "Handling SignProposalRequest");
            handle_sign_proposal_request(req, service)
        }
        Some(Sum::PingRequest(_)) => {
            debug!("Handling PingRequest");
            Sum::PingResponse(PingResponse {})
        }
        Some(other) => {
            warn!("Received unexpected message type: {:?}", std::mem::discriminant(&other));
            // Return an error response
            Sum::PubKeyResponse(PubKeyResponse {
                pub_key: None,
                error: Some(RemoteSignerError {
                    code: RemoteSignerCode::Unknown as i32,
                    description: "Unexpected message type".to_string(),
                }),
            })
        }
        None => {
            warn!("Received empty message");
            Sum::PubKeyResponse(PubKeyResponse {
                pub_key: None,
                error: Some(RemoteSignerError {
                    code: RemoteSignerCode::Unknown as i32,
                    description: "Empty message".to_string(),
                }),
            })
        }
    };

    Message {
        sum: Some(response_sum),
    }
}

fn handle_pub_key_request(chain_id: String, service: &CosmosSigningService) -> Sum {
    // Verify chain ID
    if let Err(e) = service.verify_chain_id(&chain_id) {
        warn!(error = %e, "Chain ID verification failed");
        return Sum::PubKeyResponse(PubKeyResponse {
            pub_key: None,
            error: Some(RemoteSignerError {
                code: RemoteSignerCode::Unknown as i32,
                description: e.to_string(),
            }),
        });
    }

    // Get the public key
    match service.get_first_public_key() {
        Some(pubkey) => {
            info!(pubkey = hex::encode(pubkey), "Returning public key");
            Sum::PubKeyResponse(PubKeyResponse {
                pub_key: Some(tendermint_proto::crypto::PublicKey {
                    sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                        pubkey.to_vec(),
                    )),
                }),
                error: None,
            })
        }
        None => {
            warn!("No validator registered");
            Sum::PubKeyResponse(PubKeyResponse {
                pub_key: None,
                error: Some(RemoteSignerError {
                    code: RemoteSignerCode::NotFound as i32,
                    description: "No validator registered".to_string(),
                }),
            })
        }
    }
}

fn handle_sign_vote_request(
    req: tendermint_proto::privval::SignVoteRequest,
    service: &CosmosSigningService,
) -> Sum {
    let mut vote = match req.vote {
        Some(v) => v,
        None => {
            warn!("SignVoteRequest missing vote");
            return Sum::SignedVoteResponse(SignedVoteResponse {
                vote: None,
                error: Some(RemoteSignerError {
                    code: RemoteSignerCode::Unknown as i32,
                    description: "Missing vote in request".to_string(),
                }),
            });
        }
    };

    match service.sign_vote(&req.chain_id, &mut vote) {
        Ok(_signature) => {
            info!(
                height = vote.height,
                round = vote.round,
                vote_type = vote.r#type,
                "Vote signed successfully"
            );
            Sum::SignedVoteResponse(SignedVoteResponse {
                vote: Some(vote),
                error: None,
            })
        }
        Err((err, code)) => {
            let error_code = code
                .map(|c| c as i32)
                .unwrap_or(RemoteSignerCode::Unknown as i32);
            warn!(error = %err, code = error_code, "Vote signing failed");
            Sum::SignedVoteResponse(SignedVoteResponse {
                vote: None,
                error: Some(RemoteSignerError {
                    code: error_code,
                    description: err.to_string(),
                }),
            })
        }
    }
}

fn handle_sign_proposal_request(
    req: tendermint_proto::privval::SignProposalRequest,
    service: &CosmosSigningService,
) -> Sum {
    let mut proposal = match req.proposal {
        Some(p) => p,
        None => {
            warn!("SignProposalRequest missing proposal");
            return Sum::SignedProposalResponse(SignedProposalResponse {
                proposal: None,
                error: Some(RemoteSignerError {
                    code: RemoteSignerCode::Unknown as i32,
                    description: "Missing proposal in request".to_string(),
                }),
            });
        }
    };

    match service.sign_proposal(&req.chain_id, &mut proposal) {
        Ok(_signature) => {
            info!(
                height = proposal.height,
                round = proposal.round,
                "Proposal signed successfully"
            );
            Sum::SignedProposalResponse(SignedProposalResponse {
                proposal: Some(proposal),
                error: None,
            })
        }
        Err((err, code)) => {
            let error_code = code
                .map(|c| c as i32)
                .unwrap_or(RemoteSignerCode::Unknown as i32);
            warn!(error = %err, code = error_code, "Proposal signing failed");
            Sum::SignedProposalResponse(SignedProposalResponse {
                proposal: None,
                error: Some(RemoteSignerError {
                    code: error_code,
                    description: err.to_string(),
                }),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CosmosSigningService;
    use nklave_core::Ed25519Keypair;
    use tendermint_proto::privval::{message::Sum, Message, PingRequest};
    use tendermint_proto::types::{BlockId, PartSetHeader, Vote};

    fn create_test_service() -> Arc<CosmosSigningService> {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        service.register_keypair(keypair);
        Arc::new(service)
    }

    #[test]
    fn test_handle_pub_key_request() {
        let service = create_test_service();

        let response = handle_pub_key_request("test-chain".to_string(), &service);

        if let Sum::PubKeyResponse(resp) = response {
            assert!(resp.pub_key.is_some());
            assert!(resp.error.is_none());
        } else {
            panic!("Expected PubKeyResponse");
        }
    }

    #[test]
    fn test_handle_pub_key_request_wrong_chain() {
        let service = create_test_service();

        let response = handle_pub_key_request("wrong-chain".to_string(), &service);

        if let Sum::PubKeyResponse(resp) = response {
            assert!(resp.error.is_some());
        } else {
            panic!("Expected PubKeyResponse");
        }
    }

    #[test]
    fn test_process_ping_request() {
        let service = create_test_service();

        let request = Message {
            sum: Some(Sum::PingRequest(PingRequest {})),
        };

        let response = process_message(request, &service);

        assert!(matches!(response.sum, Some(Sum::PingResponse(_))));
    }

    #[test]
    fn test_handle_sign_vote_request() {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        let validator_address = keypair.tendermint_address().to_vec();
        service.register_keypair(keypair);
        let service = Arc::new(service);

        let req = tendermint_proto::privval::SignVoteRequest {
            vote: Some(Vote {
                r#type: 1, // Prevote
                height: 100,
                round: 0,
                block_id: Some(BlockId {
                    hash: vec![1; 32],
                    part_set_header: Some(PartSetHeader {
                        total: 1,
                        hash: vec![2; 32],
                    }),
                }),
                timestamp: None,
                validator_address,
                validator_index: 0,
                signature: vec![],
                extension: vec![],
                extension_signature: vec![],
            }),
            chain_id: "test-chain".to_string(),
        };

        let response = handle_sign_vote_request(req, &service);

        if let Sum::SignedVoteResponse(resp) = response {
            assert!(resp.vote.is_some());
            assert!(resp.error.is_none());
            assert!(!resp.vote.unwrap().signature.is_empty());
        } else {
            panic!("Expected SignedVoteResponse");
        }
    }

    #[test]
    fn test_handle_sign_vote_request_missing_vote() {
        let service = create_test_service();

        let req = tendermint_proto::privval::SignVoteRequest {
            vote: None,
            chain_id: "test-chain".to_string(),
        };

        let response = handle_sign_vote_request(req, &service);

        if let Sum::SignedVoteResponse(resp) = response {
            assert!(resp.vote.is_none());
            assert!(resp.error.is_some());
        } else {
            panic!("Expected SignedVoteResponse");
        }
    }

    #[tokio::test]
    async fn test_message_roundtrip() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(1024);

        let request = Message {
            sum: Some(Sum::PingRequest(PingRequest {})),
        };

        // Write from client side
        write_message(&mut client, &request).await.unwrap();

        // Read from server side
        let received = read_message(&mut server).await.unwrap().unwrap();

        assert!(matches!(received.sum, Some(Sum::PingRequest(_))));
    }
}
