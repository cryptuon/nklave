//! Ethereum slashing protection policy enforcement
//!
//! Implements the three slashing conditions:
//! 1. Double proposal: signing two different blocks for the same slot
//! 2. Double vote: signing two different attestations for the same target epoch
//! 3. Surround vote: signing an attestation that surrounds or is surrounded by another

use crate::policy::types::{PolicyDecision, RefusalCode};
use crate::state::validator::ValidatorState;

/// Ethereum slashing protection policy
pub struct EthereumPolicy;

impl EthereumPolicy {
    /// Create a new Ethereum policy instance
    pub fn new() -> Self {
        Self
    }

    /// Check if a block proposal is safe to sign
    ///
    /// Returns `Allow` if:
    /// - No block has been signed for this slot, OR
    /// - A block with the same signing_root was already signed for this slot
    ///
    /// Returns `Refuse(DoubleProposal)` if:
    /// - A different block was already signed for this slot
    pub fn check_block_proposal(
        &self,
        state: &ValidatorState,
        slot: u64,
        signing_root: &[u8; 32],
    ) -> PolicyDecision {
        // Check if we've already signed a block for this slot
        if let Some(existing_root) = state.get_block_signing_root(slot) {
            if existing_root == signing_root {
                // Same block, safe to re-sign (idempotent)
                PolicyDecision::Allow
            } else {
                // Different block for same slot = double proposal
                tracing::warn!(
                    slot = slot,
                    "Double proposal detected: different block for same slot"
                );
                PolicyDecision::Refuse(RefusalCode::DoubleProposal)
            }
        } else {
            // No block signed for this slot yet
            PolicyDecision::Allow
        }
    }

    /// Check if an attestation is safe to sign
    ///
    /// Returns `Allow` if the attestation passes all checks:
    /// - No double vote (different attestation for same target epoch)
    /// - No surround vote (attestation surrounds or is surrounded by previous)
    ///
    /// Returns appropriate refusal code otherwise
    pub fn check_attestation(
        &self,
        state: &ValidatorState,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: &[u8; 32],
    ) -> PolicyDecision {
        // Check for exact match (same source, target, signing_root) - idempotent re-signing
        if let Some(existing_root) = state.get_attestation_signing_root(source_epoch, target_epoch)
        {
            if existing_root == signing_root {
                // Same attestation, safe to re-sign (idempotent)
                return PolicyDecision::Allow;
            } else {
                // Different signing root for same source+target = double vote
                tracing::warn!(
                    source_epoch = source_epoch,
                    target_epoch = target_epoch,
                    "Double vote detected: different signing root for same source and target epoch"
                );
                return PolicyDecision::Refuse(RefusalCode::DoubleVote);
            }
        }

        // Check for double vote: any existing attestation with same target epoch but different source
        // This covers the case where we signed (source_a, target) and now try to sign (source_b, target)
        if self.has_attestation_for_target(state, target_epoch) {
            tracing::warn!(
                target_epoch = target_epoch,
                "Double vote detected: attestation already exists for target epoch"
            );
            return PolicyDecision::Refuse(RefusalCode::DoubleVote);
        }

        // Check for surround vote using min/max span
        if self.is_surround_vote(state, source_epoch, target_epoch) {
            tracing::warn!(
                source_epoch = source_epoch,
                target_epoch = target_epoch,
                "Surround vote detected"
            );
            return PolicyDecision::Refuse(RefusalCode::SurroundVote);
        }

        PolicyDecision::Allow
    }

    /// Check if any attestation exists for the given target epoch
    fn has_attestation_for_target(&self, state: &ValidatorState, target_epoch: u64) -> bool {
        state
            .attestation_history
            .iter()
            .any(|((_, target), _)| target == target_epoch)
    }

    /// Check if the attestation would create a surround vote condition
    ///
    /// A surround vote occurs when:
    /// - New attestation surrounds an existing one: s_new < s_old < t_old < t_new
    /// - New attestation is surrounded by existing: s_old < s_new < t_new < t_old
    fn is_surround_vote(&self, state: &ValidatorState, source_epoch: u64, target_epoch: u64) -> bool {
        // Check if new attestation surrounds any existing attestation
        // For each existing attestation with source > new_source and target < new_target
        if let Some(min_target) = state.attestation_history.get_min_target_for_source_gt(source_epoch)
        {
            if min_target < target_epoch {
                // Found an existing attestation that would be surrounded
                return true;
            }
        }

        // Check if new attestation is surrounded by any existing attestation
        // For each existing attestation with source < new_source, check if target > new_target
        if let Some(max_target) = state.attestation_history.get_max_target_for_source_lt(source_epoch)
        {
            if max_target > target_epoch {
                // Found an existing attestation that surrounds the new one
                return true;
            }
        }

        false
    }
}

impl Default for EthereumPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_root(val: u8) -> [u8; 32] {
        let mut root = [0u8; 32];
        root[0] = val;
        root
    }

    #[test]
    fn test_block_proposal_first_sign() {
        let policy = EthereumPolicy::new();
        let state = ValidatorState::new([0u8; 48]);
        let root = make_root(1);

        let decision = policy.check_block_proposal(&state, 100, &root);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_block_proposal_same_block() {
        let policy = EthereumPolicy::new();
        let mut state = ValidatorState::new([0u8; 48]);
        let root = make_root(1);

        // Record the first signing
        state.record_block_signing(100, root);

        // Same block should be allowed (idempotent)
        let decision = policy.check_block_proposal(&state, 100, &root);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_block_proposal_double_proposal() {
        let policy = EthereumPolicy::new();
        let mut state = ValidatorState::new([0u8; 48]);
        let root1 = make_root(1);
        let root2 = make_root(2);

        // Record the first signing
        state.record_block_signing(100, root1);

        // Different block for same slot should be refused
        let decision = policy.check_block_proposal(&state, 100, &root2);
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::DoubleProposal));
    }

    #[test]
    fn test_attestation_first_sign() {
        let policy = EthereumPolicy::new();
        let state = ValidatorState::new([0u8; 48]);
        let root = make_root(1);

        let decision = policy.check_attestation(&state, 10, 11, &root);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_attestation_double_vote() {
        let policy = EthereumPolicy::new();
        let mut state = ValidatorState::new([0u8; 48]);
        let root1 = make_root(1);
        let root2 = make_root(2);

        // Record the first attestation
        state.record_attestation_signing(10, 11, root1);

        // Different attestation for same target should be refused
        let decision = policy.check_attestation(&state, 10, 11, &root2);
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::DoubleVote));
    }

    #[test]
    fn test_attestation_surround_vote_new_surrounds_old() {
        let policy = EthereumPolicy::new();
        let mut state = ValidatorState::new([0u8; 48]);
        let root1 = make_root(1);
        let root2 = make_root(2);

        // Record attestation with (source=5, target=10)
        state.record_attestation_signing(5, 10, root1);

        // New attestation (source=3, target=12) surrounds the old one
        // 3 < 5 < 10 < 12
        let decision = policy.check_attestation(&state, 3, 12, &root2);
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::SurroundVote));
    }

    #[test]
    fn test_attestation_surround_vote_old_surrounds_new() {
        let policy = EthereumPolicy::new();
        let mut state = ValidatorState::new([0u8; 48]);
        let root1 = make_root(1);
        let root2 = make_root(2);

        // Record attestation with (source=3, target=12)
        state.record_attestation_signing(3, 12, root1);

        // New attestation (source=5, target=10) is surrounded by the old one
        // 3 < 5 < 10 < 12
        let decision = policy.check_attestation(&state, 5, 10, &root2);
        assert_eq!(decision, PolicyDecision::Refuse(RefusalCode::SurroundVote));
    }
}
