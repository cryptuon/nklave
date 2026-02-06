//! Cosmos/CometBFT slashing protection policy enforcement
//!
//! Implements the Cosmos double-signing rule:
//! Never sign two different messages at the same (height, round, type).
//!
//! Unlike Ethereum, Cosmos does not have surround vote detection.
//! The only slashable condition is signing two different blocks/votes
//! at the same height and round.

use crate::policy::types::{PolicyDecision, RefusalCode};
use crate::state::validator::{CosmosSignedMsgType, CosmosState};

/// Cosmos/CometBFT slashing protection policy
pub struct CosmosPolicy;

impl CosmosPolicy {
    /// Create a new Cosmos policy instance
    pub fn new() -> Self {
        Self
    }

    /// Check if a prevote is safe to sign
    ///
    /// Returns `Allow` if:
    /// - No prevote has been signed for this (height, round), OR
    /// - A prevote with the same block_hash was already signed
    ///
    /// Returns `Refuse(CosmosDoubleSigning)` if:
    /// - A prevote for a different block was already signed at this (height, round)
    pub fn check_prevote(
        &self,
        state: &CosmosState,
        height: i64,
        round: i32,
        block_hash: Option<[u8; 32]>,
    ) -> PolicyDecision {
        self.check_vote(state, height, round, CosmosSignedMsgType::Prevote, block_hash)
    }

    /// Check if a precommit is safe to sign
    ///
    /// Returns `Allow` if:
    /// - No precommit has been signed for this (height, round), OR
    /// - A precommit with the same block_hash was already signed
    ///
    /// Returns `Refuse(CosmosDoubleSigning)` if:
    /// - A precommit for a different block was already signed at this (height, round)
    pub fn check_precommit(
        &self,
        state: &CosmosState,
        height: i64,
        round: i32,
        block_hash: Option<[u8; 32]>,
    ) -> PolicyDecision {
        self.check_vote(state, height, round, CosmosSignedMsgType::Precommit, block_hash)
    }

    /// Check if a proposal is safe to sign
    ///
    /// Returns `Allow` if:
    /// - No proposal has been signed for this (height, round), OR
    /// - A proposal with the same block_hash was already signed
    ///
    /// Returns `Refuse(CosmosDoubleSigning)` if:
    /// - A proposal for a different block was already signed at this (height, round)
    pub fn check_proposal(
        &self,
        state: &CosmosState,
        height: i64,
        round: i32,
        block_hash: [u8; 32],
    ) -> PolicyDecision {
        self.check_vote(
            state,
            height,
            round,
            CosmosSignedMsgType::Proposal,
            Some(block_hash),
        )
    }

    /// Generic vote checking logic
    ///
    /// The core slashing rule for Cosmos: never sign two different messages
    /// at the same (height, round, type).
    fn check_vote(
        &self,
        state: &CosmosState,
        height: i64,
        round: i32,
        msg_type: CosmosSignedMsgType,
        block_hash: Option<[u8; 32]>,
    ) -> PolicyDecision {
        // Check if we've already signed at this (height, round, type)
        if let Some(existing) = state.get_signed_vote(height, round, msg_type) {
            if existing.block_hash == block_hash {
                // Same block (or both nil), safe to re-sign (idempotent)
                PolicyDecision::Allow
            } else {
                // Different block at same (height, round, type) = double signing
                tracing::warn!(
                    height = height,
                    round = round,
                    msg_type = ?msg_type,
                    "Cosmos double signing detected: different block for same height/round"
                );
                PolicyDecision::Refuse(RefusalCode::CosmosDoubleSigning)
            }
        } else {
            // No vote signed for this (height, round, type) yet
            PolicyDecision::Allow
        }
    }

    /// Validate that the height and round are reasonable
    ///
    /// Returns true if the request is valid, false otherwise.
    pub fn validate_request(&self, height: i64, round: i32) -> bool {
        // Height must be positive
        if height <= 0 {
            return false;
        }
        // Round must be non-negative
        if round < 0 {
            return false;
        }
        true
    }
}

impl Default for CosmosPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(val: u8) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = val;
        hash
    }

    #[test]
    fn test_prevote_first_sign() {
        let policy = CosmosPolicy::new();
        let state = CosmosState::new();
        let hash = make_hash(1);

        let decision = policy.check_prevote(&state, 100, 0, Some(hash));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_prevote_nil_first_sign() {
        let policy = CosmosPolicy::new();
        let state = CosmosState::new();

        // Nil vote (no block hash)
        let decision = policy.check_prevote(&state, 100, 0, None);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_prevote_same_block_allowed() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash = make_hash(1);

        // Record the first signing
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, Some(hash));

        // Same block should be allowed (idempotent)
        let decision = policy.check_prevote(&state, 100, 0, Some(hash));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_prevote_double_sign_rejected() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        // Record the first signing
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, Some(hash1));

        // Different block for same height/round should be refused
        let decision = policy.check_prevote(&state, 100, 0, Some(hash2));
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::CosmosDoubleSigning));
    }

    #[test]
    fn test_prevote_nil_then_block_rejected() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash = make_hash(1);

        // Record a nil vote
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, None);

        // Trying to vote for a block after nil vote should be refused
        let decision = policy.check_prevote(&state, 100, 0, Some(hash));
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::CosmosDoubleSigning));
    }

    #[test]
    fn test_prevote_block_then_nil_rejected() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash = make_hash(1);

        // Record a vote for a block
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, Some(hash));

        // Trying to vote nil after voting for a block should be refused
        let decision = policy.check_prevote(&state, 100, 0, None);
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::CosmosDoubleSigning));
    }

    #[test]
    fn test_different_round_allowed() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        // Record vote in round 0
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, Some(hash1));

        // Different block in round 1 should be allowed
        let decision = policy.check_prevote(&state, 100, 1, Some(hash2));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_different_height_allowed() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        // Record vote at height 100
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, Some(hash1));

        // Different block at height 101 should be allowed
        let decision = policy.check_prevote(&state, 101, 0, Some(hash2));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_height_regression_allowed() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        // Record vote at height 100
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, Some(hash1));

        // Voting at height 50 (regression) should be allowed
        // This happens during catch-up after restart
        let decision = policy.check_prevote(&state, 50, 0, Some(hash2));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_precommit_independent_of_prevote() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        // Record prevote for hash1
        state.record_vote(100, 0, CosmosSignedMsgType::Prevote, Some(hash1));

        // Precommit for hash2 should be allowed (different message type)
        let decision = policy.check_precommit(&state, 100, 0, Some(hash2));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_proposal_double_sign_rejected() {
        let policy = CosmosPolicy::new();
        let mut state = CosmosState::new();
        let hash1 = make_hash(1);
        let hash2 = make_hash(2);

        // Record proposal for hash1
        state.record_vote(100, 0, CosmosSignedMsgType::Proposal, Some(hash1));

        // Proposal for hash2 should be refused
        let decision = policy.check_proposal(&state, 100, 0, hash2);
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::CosmosDoubleSigning));
    }

    #[test]
    fn test_validate_request() {
        let policy = CosmosPolicy::new();

        // Valid requests
        assert!(policy.validate_request(1, 0));
        assert!(policy.validate_request(100, 5));

        // Invalid requests
        assert!(!policy.validate_request(0, 0));  // Height 0 invalid
        assert!(!policy.validate_request(-1, 0)); // Negative height invalid
        assert!(!policy.validate_request(1, -1)); // Negative round invalid
    }
}
