//! Replication protocol messages
//!
//! Defines the wire format for primary-passive communication.

use crate::state::integrity::DecisionRecord;
use serde::{Deserialize, Serialize};

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum message size (10MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Replication protocol messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplicationMessage {
    /// Handshake to establish connection
    Hello(HelloMessage),

    /// Periodic heartbeat from primary
    Heartbeat(Heartbeat),

    /// Decision record streamed after signing
    Decision(DecisionRecord),

    /// Request to sync from a sequence number
    SyncRequest(SyncRequest),

    /// Response with batch of decision records
    SyncResponse(SyncResponse),

    /// Acknowledgment of received messages
    Ack(AckMessage),

    /// Error message
    Error(ErrorMessage),

    /// Fencing token for split-brain prevention
    FencingToken(FencingToken),
}

/// Initial handshake message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    /// Protocol version
    pub version: u32,

    /// Node identifier
    pub node_id: String,

    /// Current role (Primary or Passive)
    pub role: String,

    /// Current sequence number
    pub sequence: u64,

    /// Current state hash
    #[serde(with = "hex_bytes")]
    pub state_hash: [u8; 32],

    /// Genesis validators root (if set)
    #[serde(with = "option_hex_bytes")]
    pub genesis_root: Option<[u8; 32]>,
}

/// Heartbeat message sent periodically by primary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Current sequence number on primary
    pub sequence: u64,

    /// Current state hash on primary
    #[serde(with = "hex_bytes")]
    pub state_hash: [u8; 32],

    /// Unix timestamp (milliseconds)
    pub timestamp_ms: u64,

    /// Current fencing token
    pub fencing_token: u64,
}

impl Heartbeat {
    /// Create a new heartbeat
    pub fn new(sequence: u64, state_hash: [u8; 32], fencing_token: u64) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            sequence,
            state_hash,
            timestamp_ms,
            fencing_token,
        }
    }
}

/// Request to sync decision records from a specific sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    /// Start sequence number (exclusive)
    pub from_sequence: u64,

    /// Maximum number of records to return
    pub max_records: u32,

    /// Expected state hash at from_sequence
    #[serde(with = "hex_bytes")]
    pub expected_hash: [u8; 32],
}

/// Response containing batched decision records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Records in sequence order
    pub records: Vec<DecisionRecord>,

    /// Whether there are more records available
    pub has_more: bool,

    /// Current sequence on primary
    pub current_sequence: u64,
}

/// Acknowledgment message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckMessage {
    /// Sequence number being acknowledged
    pub sequence: u64,

    /// State hash after applying up to this sequence
    #[serde(with = "hex_bytes")]
    pub state_hash: [u8; 32],
}

/// Error message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// Error code
    pub code: ErrorCode,

    /// Human-readable description
    pub description: String,

    /// Sequence number where error occurred (if applicable)
    pub sequence: Option<u64>,
}

/// Error codes for replication protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Protocol version mismatch
    VersionMismatch,

    /// State hash mismatch (divergence detected)
    HashMismatch,

    /// Sequence gap detected
    SequenceGap,

    /// Invalid fencing token
    InvalidFencingToken,

    /// Genesis root mismatch
    GenesisRootMismatch,

    /// Not authorized (wrong role)
    NotAuthorized,

    /// Internal error
    Internal,
}

/// Fencing token for split-brain prevention
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FencingToken {
    /// Token value (monotonically increasing)
    pub token: u64,

    /// Node ID that generated this token
    pub issued_by: String,

    /// Unix timestamp when issued
    pub issued_at: u64,

    /// Signature over (token, issued_by, issued_at) - optional for now
    pub signature: Option<Vec<u8>>,
}

impl FencingToken {
    /// Create a new fencing token
    pub fn new(token: u64, node_id: &str) -> Self {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            token,
            issued_by: node_id.to_string(),
            issued_at,
            signature: None,
        }
    }

    /// Check if this token supersedes another
    pub fn supersedes(&self, other: &FencingToken) -> bool {
        self.token > other.token
    }
}

/// Serialize/deserialize helper for [u8; 32]
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Serialize/deserialize helper for Option<[u8; 32]>
mod option_hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Deserialize::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_creation() {
        let hb = Heartbeat::new(100, [1u8; 32], 5);
        assert_eq!(hb.sequence, 100);
        assert_eq!(hb.fencing_token, 5);
        assert!(hb.timestamp_ms > 0);
    }

    #[test]
    fn test_fencing_token_supersedes() {
        let token1 = FencingToken::new(1, "node-a");
        let token2 = FencingToken::new(2, "node-b");

        assert!(token2.supersedes(&token1));
        assert!(!token1.supersedes(&token2));
    }

    #[test]
    fn test_message_serialization() {
        let msg = ReplicationMessage::Heartbeat(Heartbeat::new(100, [0u8; 32], 1));
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ReplicationMessage = serde_json::from_str(&json).unwrap();

        if let ReplicationMessage::Heartbeat(hb) = parsed {
            assert_eq!(hb.sequence, 100);
        } else {
            panic!("Expected Heartbeat message");
        }
    }
}
