//! Cosmos signing service wrapper
//!
//! Wraps the core SigningService to provide Cosmos-specific signing operations

use crate::error::{CosmosError, RemoteSignerCode};
use crate::types::{canonical_proposal_sign_bytes, canonical_vote_sign_bytes, ProposalInfo, SignedMsgType, VoteInfo};
use nklave_core::policy::cosmos::CosmosPolicy;
use nklave_core::policy::types::PolicyDecision;
use nklave_core::state::validator::{ChainState, CosmosSignedMsgType, ValidatorState};
use nklave_core::{Ed25519Keypair, SigningService};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tendermint_proto::types::{Proposal, Vote};
use tracing::{debug, info, warn};

/// Cosmos signing service that wraps the core SigningService
pub struct CosmosSigningService {
    /// Ed25519 keypairs indexed by public key (32 bytes)
    keypairs: Arc<RwLock<HashMap<[u8; 32], Ed25519Keypair>>>,

    /// Validator states indexed by public key (padded to 48 bytes for compatibility)
    validator_states: Arc<RwLock<HashMap<[u8; 48], ValidatorState>>>,

    /// The Cosmos slashing policy
    policy: CosmosPolicy,

    /// Expected chain ID
    chain_id: String,
}

impl CosmosSigningService {
    /// Create a new Cosmos signing service
    pub fn new(chain_id: String) -> Self {
        Self {
            keypairs: Arc::new(RwLock::new(HashMap::new())),
            validator_states: Arc::new(RwLock::new(HashMap::new())),
            policy: CosmosPolicy,
            chain_id,
        }
    }

    /// Create from an existing core SigningService (for integration)
    pub fn from_signing_service(signing_service: &SigningService, chain_id: String) -> Self {
        let service = Self::new(chain_id);
        // Copy validator states that are Cosmos type
        let states = signing_service.validator_states();
        for (pubkey, state) in states {
            if matches!(state.chain_state, Some(ChainState::Cosmos(_))) {
                service.validator_states.write().unwrap().insert(pubkey, state);
            }
        }
        service
    }

    /// Register a keypair with the service
    pub fn register_keypair(&self, keypair: Ed25519Keypair) {
        let pubkey_32 = keypair.public_key_bytes();
        let pubkey_48 = keypair.public_key_bytes_padded();

        // Initialize validator state if not exists
        {
            let mut states = self.validator_states.write().unwrap();
            states.entry(pubkey_48).or_insert_with(|| {
                ValidatorState::new_cosmos(pubkey_32)
            });
        }

        // Store keypair
        self.keypairs.write().unwrap().insert(pubkey_32, keypair);

        info!(
            pubkey = hex::encode(pubkey_32),
            "Registered Cosmos validator keypair"
        );
    }

    /// Get the public key for a registered validator
    pub fn get_public_key(&self, pubkey_32: &[u8; 32]) -> Option<[u8; 32]> {
        self.keypairs.read().unwrap().get(pubkey_32).map(|kp| kp.public_key_bytes())
    }

    /// Get the first registered public key (for single-validator setups)
    pub fn get_first_public_key(&self) -> Option<[u8; 32]> {
        self.keypairs.read().unwrap().keys().next().copied()
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Verify chain ID matches
    pub fn verify_chain_id(&self, chain_id: &str) -> Result<(), CosmosError> {
        if chain_id != self.chain_id {
            return Err(CosmosError::ChainIdMismatch {
                expected: self.chain_id.clone(),
                actual: chain_id.to_string(),
            });
        }
        Ok(())
    }

    /// Sign a vote (prevote or precommit)
    pub fn sign_vote(
        &self,
        chain_id: &str,
        vote: &mut Vote,
    ) -> Result<Vec<u8>, (CosmosError, Option<RemoteSignerCode>)> {
        // Verify chain ID
        self.verify_chain_id(chain_id)
            .map_err(|e| (e, None))?;

        // Extract vote info
        let vote_info = VoteInfo::from_vote(vote)
            .map_err(|e| (e, None))?;

        // Find the keypair for this validator
        let keypairs = self.keypairs.read().unwrap();
        let keypair = self.find_keypair_by_address(&vote_info.validator_address, &keypairs)
            .ok_or_else(|| {
                let err = CosmosError::ValidatorNotFound {
                    pubkey_hex: hex::encode(&vote_info.validator_address),
                };
                (err, Some(RemoteSignerCode::NotFound))
            })?;

        let pubkey_48 = keypair.public_key_bytes_padded();

        // Check slashing policy
        let decision = {
            let states = self.validator_states.read().unwrap();
            let state = states.get(&pubkey_48).ok_or_else(|| {
                (CosmosError::ValidatorNotFound {
                    pubkey_hex: hex::encode(pubkey_48),
                }, Some(RemoteSignerCode::NotFound))
            })?;

            let cosmos_state = match &state.chain_state {
                Some(ChainState::Cosmos(cs)) => cs,
                _ => {
                    return Err((CosmosError::Internal("Validator is not Cosmos type".to_string()), None));
                }
            };

            match vote_info.msg_type {
                SignedMsgType::Prevote => {
                    self.policy.check_prevote(cosmos_state, vote_info.height, vote_info.round, vote_info.block_hash)
                }
                SignedMsgType::Precommit => {
                    self.policy.check_precommit(cosmos_state, vote_info.height, vote_info.round, vote_info.block_hash)
                }
                _ => {
                    return Err((CosmosError::InvalidVoteType(vote.r#type), None));
                }
            }
        };

        match decision {
            PolicyDecision::Allow => {
                debug!(
                    height = vote_info.height,
                    round = vote_info.round,
                    msg_type = ?vote_info.msg_type,
                    "Vote allowed by policy"
                );
            }
            PolicyDecision::Refuse(code) => {
                warn!(
                    height = vote_info.height,
                    round = vote_info.round,
                    msg_type = ?vote_info.msg_type,
                    refusal_code = ?code,
                    "Vote REFUSED by policy - double signing attempt"
                );
                return Err((
                    CosmosError::DoubleSigning {
                        height: vote_info.height,
                        round: vote_info.round,
                    },
                    Some(RemoteSignerCode::DoubleSign),
                ));
            }
        }

        // Create canonical sign bytes and sign
        let sign_bytes = canonical_vote_sign_bytes(chain_id, vote);
        let signature = keypair.sign(&sign_bytes);

        // Update state after successful signing
        {
            let mut states = self.validator_states.write().unwrap();
            if let Some(state) = states.get_mut(&pubkey_48) {
                if let Some(ChainState::Cosmos(ref mut cosmos_state)) = state.chain_state {
                    let msg_type = vote_info.msg_type.to_core_type()
                        .ok_or_else(|| (CosmosError::InvalidVoteType(vote.r#type), None))?;

                    cosmos_state.record_vote(
                        vote_info.height,
                        vote_info.round,
                        msg_type,
                        vote_info.block_hash,
                    );
                }
            }
        }

        let sig_bytes = signature.to_bytes().to_vec();
        vote.signature = sig_bytes.clone();

        info!(
            height = vote_info.height,
            round = vote_info.round,
            msg_type = ?vote_info.msg_type,
            "Vote signed successfully"
        );

        Ok(sig_bytes)
    }

    /// Sign a proposal
    pub fn sign_proposal(
        &self,
        chain_id: &str,
        proposal: &mut Proposal,
    ) -> Result<Vec<u8>, (CosmosError, Option<RemoteSignerCode>)> {
        // Verify chain ID
        self.verify_chain_id(chain_id)
            .map_err(|e| (e, None))?;

        // Extract proposal info
        let proposal_info = ProposalInfo::from_proposal(proposal)
            .map_err(|e| (e, None))?;

        // For proposals, we need to find the keypair differently
        // In a single-validator setup, use the first available keypair
        let keypairs = self.keypairs.read().unwrap();
        let keypair = keypairs.values().next()
            .ok_or_else(|| {
                (CosmosError::ValidatorNotFound {
                    pubkey_hex: "no validators registered".to_string(),
                }, Some(RemoteSignerCode::NotFound))
            })?;

        let pubkey_48 = keypair.public_key_bytes_padded();

        // Check slashing policy
        let decision = {
            let states = self.validator_states.read().unwrap();
            let state = states.get(&pubkey_48).ok_or_else(|| {
                (CosmosError::ValidatorNotFound {
                    pubkey_hex: hex::encode(pubkey_48),
                }, Some(RemoteSignerCode::NotFound))
            })?;

            let cosmos_state = match &state.chain_state {
                Some(ChainState::Cosmos(cs)) => cs,
                _ => {
                    return Err((CosmosError::Internal("Validator is not Cosmos type".to_string()), None));
                }
            };

            self.policy.check_proposal(cosmos_state, proposal_info.height, proposal_info.round, proposal_info.block_hash)
        };

        match decision {
            PolicyDecision::Allow => {
                debug!(
                    height = proposal_info.height,
                    round = proposal_info.round,
                    "Proposal allowed by policy"
                );
            }
            PolicyDecision::Refuse(code) => {
                warn!(
                    height = proposal_info.height,
                    round = proposal_info.round,
                    refusal_code = ?code,
                    "Proposal REFUSED by policy - double signing attempt"
                );
                return Err((
                    CosmosError::DoubleSigning {
                        height: proposal_info.height,
                        round: proposal_info.round,
                    },
                    Some(RemoteSignerCode::DoubleSign),
                ));
            }
        }

        // Create canonical sign bytes and sign
        let sign_bytes = canonical_proposal_sign_bytes(chain_id, proposal);
        let signature = keypair.sign(&sign_bytes);

        // Update state after successful signing
        {
            let mut states = self.validator_states.write().unwrap();
            if let Some(state) = states.get_mut(&pubkey_48) {
                if let Some(ChainState::Cosmos(ref mut cosmos_state)) = state.chain_state {
                    cosmos_state.record_vote(
                        proposal_info.height,
                        proposal_info.round,
                        CosmosSignedMsgType::Proposal,
                        Some(proposal_info.block_hash),
                    );
                }
            }
        }

        let sig_bytes = signature.to_bytes().to_vec();
        proposal.signature = sig_bytes.clone();

        info!(
            height = proposal_info.height,
            round = proposal_info.round,
            "Proposal signed successfully"
        );

        Ok(sig_bytes)
    }

    /// Find a keypair by validator address (first 20 bytes of SHA256 of public key)
    fn find_keypair_by_address<'a>(
        &self,
        address: &[u8],
        keypairs: &'a HashMap<[u8; 32], Ed25519Keypair>,
    ) -> Option<&'a Ed25519Keypair> {
        for keypair in keypairs.values() {
            let tendermint_addr = keypair.tendermint_address();
            if address.len() >= 20 && &tendermint_addr[..] == &address[..20] {
                return Some(keypair);
            }
        }
        None
    }

    /// Get all registered validator public keys
    pub fn registered_validators(&self) -> Vec<[u8; 32]> {
        self.keypairs.read().unwrap().keys().copied().collect()
    }

    /// Export validator states for checkpointing
    pub fn validator_states(&self) -> HashMap<[u8; 48], ValidatorState> {
        self.validator_states.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tendermint_proto::types::{BlockId, PartSetHeader};

    fn create_test_service() -> CosmosSigningService {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        service.register_keypair(keypair);
        service
    }

    #[test]
    fn test_service_creation() {
        let service = CosmosSigningService::new("test-chain".to_string());
        assert_eq!(service.chain_id(), "test-chain");
    }

    #[test]
    fn test_keypair_registration() {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        let pubkey = keypair.public_key_bytes();

        service.register_keypair(keypair);

        assert!(service.get_public_key(&pubkey).is_some());
        assert_eq!(service.registered_validators().len(), 1);
    }

    #[test]
    fn test_chain_id_verification() {
        let service = create_test_service();

        assert!(service.verify_chain_id("test-chain").is_ok());
        assert!(service.verify_chain_id("wrong-chain").is_err());
    }

    #[test]
    fn test_sign_vote_success() {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        let validator_address = keypair.tendermint_address().to_vec();
        service.register_keypair(keypair);

        let mut vote = Vote {
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
        };

        let result = service.sign_vote("test-chain", &mut vote);
        assert!(result.is_ok());
        assert!(!vote.signature.is_empty());
    }

    #[test]
    fn test_sign_vote_double_signing_refused() {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        let validator_address = keypair.tendermint_address().to_vec();
        service.register_keypair(keypair);

        // First vote
        let mut vote1 = Vote {
            r#type: 1,
            height: 100,
            round: 0,
            block_id: Some(BlockId {
                hash: vec![1; 32],
                part_set_header: None,
            }),
            timestamp: None,
            validator_address: validator_address.clone(),
            validator_index: 0,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        };
        assert!(service.sign_vote("test-chain", &mut vote1).is_ok());

        // Second vote at same height/round with DIFFERENT block - should be refused
        let mut vote2 = Vote {
            r#type: 1,
            height: 100,
            round: 0,
            block_id: Some(BlockId {
                hash: vec![2; 32], // Different block!
                part_set_header: None,
            }),
            timestamp: None,
            validator_address,
            validator_index: 0,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        };
        let result = service.sign_vote("test-chain", &mut vote2);
        assert!(result.is_err());

        if let Err((_, Some(code))) = result {
            assert_eq!(code, RemoteSignerCode::DoubleSign);
        } else {
            panic!("Expected DoubleSign error code");
        }
    }

    #[test]
    fn test_sign_vote_idempotent() {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        let validator_address = keypair.tendermint_address().to_vec();
        service.register_keypair(keypair);

        // Sign same vote twice - should succeed (idempotent)
        for _ in 0..2 {
            let mut vote = Vote {
                r#type: 1,
                height: 100,
                round: 0,
                block_id: Some(BlockId {
                    hash: vec![1; 32],
                    part_set_header: None,
                }),
                timestamp: None,
                validator_address: validator_address.clone(),
                validator_index: 0,
                signature: vec![],
                extension: vec![],
                extension_signature: vec![],
            };
            assert!(service.sign_vote("test-chain", &mut vote).is_ok());
        }
    }

    #[test]
    fn test_sign_proposal_success() {
        let service = CosmosSigningService::new("test-chain".to_string());
        let keypair = Ed25519Keypair::random();
        service.register_keypair(keypair);

        let mut proposal = Proposal {
            r#type: 32, // Proposal type
            height: 100,
            round: 0,
            pol_round: -1,
            block_id: Some(BlockId {
                hash: vec![1; 32],
                part_set_header: Some(PartSetHeader {
                    total: 1,
                    hash: vec![2; 32],
                }),
            }),
            timestamp: None,
            signature: vec![],
        };

        let result = service.sign_proposal("test-chain", &mut proposal);
        assert!(result.is_ok());
        assert!(!proposal.signature.is_empty());
    }

    #[test]
    fn test_wrong_chain_id_refused() {
        let service = create_test_service();

        let mut vote = Vote {
            r#type: 1,
            height: 100,
            round: 0,
            block_id: None,
            timestamp: None,
            validator_address: vec![0; 20],
            validator_index: 0,
            signature: vec![],
            extension: vec![],
            extension_signature: vec![],
        };

        let result = service.sign_vote("wrong-chain", &mut vote);
        assert!(result.is_err());
    }
}
