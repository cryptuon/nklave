//! Common types for slashing policy enforcement

use serde::{Deserialize, Serialize};

/// Result of a policy check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Request is safe to sign
    Allow,
    /// Request would violate slashing rules
    Refuse(RefusalCode),
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    pub fn is_refused(&self) -> bool {
        matches!(self, PolicyDecision::Refuse(_))
    }
}

/// Reason codes for refusing to sign
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalCode {
    /// Block already signed for this slot (Ethereum)
    DoubleProposal,
    /// Attestation already signed for this target epoch (Ethereum)
    DoubleVote,
    /// Attestation would create surround vote condition (Ethereum)
    SurroundVote,
    /// Safety state continuity violated
    StateRollback,
    /// Request is malformed or missing required fields
    InvalidRequest,
    /// Validator public key not managed by this enclave
    UnknownValidator,
    /// Signing domain not enabled
    UnsupportedDomain,
    /// Internal error during processing
    InternalError,
}

impl std::fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl RefusalCode {
    /// HTTP status code for this refusal
    pub fn http_status(&self) -> u16 {
        match self {
            RefusalCode::DoubleProposal
            | RefusalCode::DoubleVote
            | RefusalCode::SurroundVote
            | RefusalCode::StateRollback => 412, // Precondition Failed
            RefusalCode::InvalidRequest | RefusalCode::UnsupportedDomain => 400, // Bad Request
            RefusalCode::UnknownValidator => 404, // Not Found
            RefusalCode::InternalError => 500,    // Internal Server Error
        }
    }

    /// Human-readable error message
    pub fn message(&self) -> &'static str {
        match self {
            RefusalCode::DoubleProposal => "Slashing protection: block already signed for slot",
            RefusalCode::DoubleVote => {
                "Slashing protection: attestation already signed for target epoch"
            }
            RefusalCode::SurroundVote => "Slashing protection: attestation would create surround vote",
            RefusalCode::StateRollback => "State integrity: safety state continuity violated",
            RefusalCode::InvalidRequest => "Invalid signing request",
            RefusalCode::UnknownValidator => "Validator public key not found",
            RefusalCode::UnsupportedDomain => "Signing domain not supported",
            RefusalCode::InternalError => "Internal error during signing",
        }
    }
}

/// Types of signing requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningType {
    // Ethereum types
    BlockProposal,
    Attestation,
    AggregateAndProof,
    AggregationSlot,
    RandaoReveal,
    VoluntaryExit,
    SyncCommitteeMessage,
    SyncCommitteeSelectionProof,
    SyncCommitteeContributionAndProof,
    ValidatorRegistration,
}

impl SigningType {
    /// Whether this signing type requires slashing protection
    pub fn requires_slashing_protection(&self) -> bool {
        matches!(
            self,
            SigningType::BlockProposal | SigningType::Attestation | SigningType::AggregateAndProof
        )
    }

    /// Get the string name for this signing type (for metrics)
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningType::BlockProposal => "block_proposal",
            SigningType::Attestation => "attestation",
            SigningType::AggregateAndProof => "aggregate_and_proof",
            SigningType::AggregationSlot => "aggregation_slot",
            SigningType::RandaoReveal => "randao_reveal",
            SigningType::VoluntaryExit => "voluntary_exit",
            SigningType::SyncCommitteeMessage => "sync_committee_message",
            SigningType::SyncCommitteeSelectionProof => "sync_committee_selection_proof",
            SigningType::SyncCommitteeContributionAndProof => "sync_committee_contribution_and_proof",
            SigningType::ValidatorRegistration => "validator_registration",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_decision() {
        let allow = PolicyDecision::Allow;
        assert!(allow.is_allowed());
        assert!(!allow.is_refused());

        let refuse = PolicyDecision::Refuse(RefusalCode::DoubleProposal);
        assert!(!refuse.is_allowed());
        assert!(refuse.is_refused());
    }

    #[test]
    fn test_refusal_http_status() {
        assert_eq!(RefusalCode::DoubleProposal.http_status(), 412);
        assert_eq!(RefusalCode::InvalidRequest.http_status(), 400);
        assert_eq!(RefusalCode::UnknownValidator.http_status(), 404);
        assert_eq!(RefusalCode::InternalError.http_status(), 500);
    }
}
