//! Type wrappers and conversions for Tendermint protocol types

use crate::error::CosmosError;
use sha2::{Digest, Sha256};
use tendermint_proto::types::{BlockId, Vote, Proposal};

/// Vote type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedMsgType {
    /// Unknown vote type (should not occur)
    Unknown,
    /// Prevote in consensus round
    Prevote,
    /// Precommit in consensus round
    Precommit,
    /// Block proposal
    Proposal,
}

impl SignedMsgType {
    /// Convert from protobuf vote type integer
    pub fn from_i32(value: i32) -> Result<Self, CosmosError> {
        match value {
            0 => Ok(SignedMsgType::Unknown),
            1 => Ok(SignedMsgType::Prevote),
            2 => Ok(SignedMsgType::Precommit),
            32 => Ok(SignedMsgType::Proposal),
            _ => Err(CosmosError::InvalidVoteType(value)),
        }
    }

    /// Convert to nklave-core's CosmosSignedMsgType
    pub fn to_core_type(self) -> Option<nklave_core::state::validator::CosmosSignedMsgType> {
        match self {
            SignedMsgType::Prevote => Some(nklave_core::state::validator::CosmosSignedMsgType::Prevote),
            SignedMsgType::Precommit => Some(nklave_core::state::validator::CosmosSignedMsgType::Precommit),
            SignedMsgType::Proposal => Some(nklave_core::state::validator::CosmosSignedMsgType::Proposal),
            SignedMsgType::Unknown => None,
        }
    }
}

impl From<SignedMsgType> for i32 {
    fn from(msg_type: SignedMsgType) -> Self {
        match msg_type {
            SignedMsgType::Unknown => 0,
            SignedMsgType::Prevote => 1,
            SignedMsgType::Precommit => 2,
            SignedMsgType::Proposal => 32,
        }
    }
}

/// Extracted vote information for policy checking
#[derive(Debug, Clone)]
pub struct VoteInfo {
    /// Vote type
    pub msg_type: SignedMsgType,
    /// Block height
    pub height: i64,
    /// Consensus round
    pub round: i32,
    /// Block hash being voted for (None for nil vote)
    pub block_hash: Option<[u8; 32]>,
    /// Validator address
    pub validator_address: Vec<u8>,
}

impl VoteInfo {
    /// Extract vote info from a protobuf Vote message
    pub fn from_vote(vote: &Vote) -> Result<Self, CosmosError> {
        let msg_type = SignedMsgType::from_i32(vote.r#type)?;
        let block_hash = extract_block_hash(vote.block_id.as_ref());

        Ok(Self {
            msg_type,
            height: vote.height,
            round: vote.round,
            block_hash,
            validator_address: vote.validator_address.clone(),
        })
    }
}

/// Extracted proposal information for policy checking
#[derive(Debug, Clone)]
pub struct ProposalInfo {
    /// Block height
    pub height: i64,
    /// Consensus round
    pub round: i32,
    /// POL round (-1 if not set)
    pub pol_round: i32,
    /// Block hash being proposed
    pub block_hash: [u8; 32],
}

impl ProposalInfo {
    /// Extract proposal info from a protobuf Proposal message
    pub fn from_proposal(proposal: &Proposal) -> Result<Self, CosmosError> {
        let block_id = proposal
            .block_id
            .as_ref()
            .ok_or(CosmosError::MissingField("block_id"))?;

        let block_hash = hash_block_id(block_id);

        Ok(Self {
            height: proposal.height,
            round: proposal.round,
            pol_round: proposal.pol_round,
            block_hash,
        })
    }
}

/// Extract block hash from a BlockID
/// Returns None for nil votes (empty or missing block_id)
pub fn extract_block_hash(block_id: Option<&BlockId>) -> Option<[u8; 32]> {
    block_id.and_then(|bid| {
        if bid.hash.is_empty() {
            None
        } else {
            Some(hash_block_id(bid))
        }
    })
}

/// Compute a canonical hash of a BlockID for comparison
pub fn hash_block_id(block_id: &BlockId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&block_id.hash);
    if let Some(ref part_set) = block_id.part_set_header {
        hasher.update(part_set.total.to_le_bytes());
        hasher.update(&part_set.hash);
    }
    hasher.finalize().into()
}

/// Create a canonical sign bytes for a vote
/// This is what gets signed by the validator
pub fn canonical_vote_sign_bytes(
    chain_id: &str,
    vote: &Vote,
) -> Vec<u8> {
    use prost::Message;
    use tendermint_proto::types::CanonicalVote;

    let canonical = CanonicalVote {
        r#type: vote.r#type,
        height: vote.height,
        round: vote.round as i64,
        block_id: vote.block_id.clone().map(|bid| {
            tendermint_proto::types::CanonicalBlockId {
                hash: bid.hash,
                part_set_header: bid.part_set_header.map(|psh| {
                    tendermint_proto::types::CanonicalPartSetHeader {
                        total: psh.total,
                        hash: psh.hash,
                    }
                }),
            }
        }),
        timestamp: vote.timestamp.clone(),
        chain_id: chain_id.to_string(),
    };

    let mut buf = Vec::new();
    canonical.encode_length_delimited(&mut buf).expect("encoding should not fail");
    buf
}

/// Create a canonical sign bytes for a proposal
pub fn canonical_proposal_sign_bytes(
    chain_id: &str,
    proposal: &Proposal,
) -> Vec<u8> {
    use prost::Message;
    use tendermint_proto::types::CanonicalProposal;

    let canonical = CanonicalProposal {
        r#type: proposal.r#type,
        height: proposal.height,
        round: proposal.round as i64,
        pol_round: proposal.pol_round as i64,
        block_id: proposal.block_id.clone().map(|bid| {
            tendermint_proto::types::CanonicalBlockId {
                hash: bid.hash,
                part_set_header: bid.part_set_header.map(|psh| {
                    tendermint_proto::types::CanonicalPartSetHeader {
                        total: psh.total,
                        hash: psh.hash,
                    }
                }),
            }
        }),
        timestamp: proposal.timestamp.clone(),
        chain_id: chain_id.to_string(),
    };

    let mut buf = Vec::new();
    canonical.encode_length_delimited(&mut buf).expect("encoding should not fail");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint_proto::types::PartSetHeader;

    #[test]
    fn test_signed_msg_type_conversion() {
        assert_eq!(SignedMsgType::from_i32(0).unwrap(), SignedMsgType::Unknown);
        assert_eq!(SignedMsgType::from_i32(1).unwrap(), SignedMsgType::Prevote);
        assert_eq!(SignedMsgType::from_i32(2).unwrap(), SignedMsgType::Precommit);
        assert_eq!(SignedMsgType::from_i32(32).unwrap(), SignedMsgType::Proposal);
        assert!(SignedMsgType::from_i32(99).is_err());
    }

    #[test]
    fn test_extract_block_hash_nil() {
        // Nil vote has no block_id
        assert!(extract_block_hash(None).is_none());

        // Empty hash is also nil
        let empty_bid = BlockId {
            hash: vec![],
            part_set_header: None,
        };
        assert!(extract_block_hash(Some(&empty_bid)).is_none());
    }

    #[test]
    fn test_extract_block_hash_valid() {
        let bid = BlockId {
            hash: vec![1, 2, 3, 4],
            part_set_header: Some(PartSetHeader {
                total: 1,
                hash: vec![5, 6, 7, 8],
            }),
        };
        let hash = extract_block_hash(Some(&bid));
        assert!(hash.is_some());
        assert_eq!(hash.unwrap().len(), 32);
    }

    #[test]
    fn test_hash_block_id_deterministic() {
        let bid = BlockId {
            hash: vec![1, 2, 3, 4],
            part_set_header: Some(PartSetHeader {
                total: 1,
                hash: vec![5, 6, 7, 8],
            }),
        };
        let hash1 = hash_block_id(&bid);
        let hash2 = hash_block_id(&bid);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_vote_info_extraction() {
        let vote = Vote {
            r#type: 1, // Prevote
            height: 100,
            round: 0,
            block_id: Some(BlockId {
                hash: vec![1; 32],
                part_set_header: None,
            }),
            timestamp: None,
            validator_address: vec![0; 20],
            validator_index: 0,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        };

        let info = VoteInfo::from_vote(&vote).unwrap();
        assert_eq!(info.msg_type, SignedMsgType::Prevote);
        assert_eq!(info.height, 100);
        assert_eq!(info.round, 0);
        assert!(info.block_hash.is_some());
    }

    #[test]
    fn test_canonical_vote_sign_bytes() {
        let vote = Vote {
            r#type: 1,
            height: 100,
            round: 0,
            block_id: Some(BlockId {
                hash: vec![1; 32],
                part_set_header: None,
            }),
            timestamp: None,
            validator_address: vec![],
            validator_index: 0,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        };

        let bytes = canonical_vote_sign_bytes("test-chain", &vote);
        assert!(!bytes.is_empty());

        // Same vote should produce same bytes
        let bytes2 = canonical_vote_sign_bytes("test-chain", &vote);
        assert_eq!(bytes, bytes2);
    }
}
