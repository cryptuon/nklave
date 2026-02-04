//! Web3Signer API request and response types
//!
//! These types match the Web3Signer specification used by Lighthouse

use serde::{Deserialize, Serialize};

/// Health check response
#[derive(Debug, Serialize)]
pub struct UpcheckResponse {
    pub status: String,
}

impl Default for UpcheckResponse {
    fn default() -> Self {
        Self {
            status: "OK".to_string(),
        }
    }
}

/// Signature response
#[derive(Debug, Serialize)]
pub struct SignatureResponse {
    pub signature: String,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Fork information included in signing requests
#[derive(Debug, Deserialize)]
pub struct ForkInfo {
    pub fork: Fork,
    pub genesis_validators_root: String,
}

/// Fork data
#[derive(Debug, Deserialize)]
pub struct Fork {
    pub previous_version: String,
    pub current_version: String,
    pub epoch: String,
}

/// Checkpoint (used in attestations)
#[derive(Debug, Deserialize)]
pub struct Checkpoint {
    pub epoch: String,
    pub root: String,
}

/// Attestation data
#[derive(Debug, Deserialize)]
pub struct AttestationData {
    pub slot: String,
    pub index: String,
    pub beacon_block_root: String,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

/// Beacon block header (used in BLOCK_V2)
#[derive(Debug, Deserialize)]
pub struct BeaconBlockHeader {
    pub slot: String,
    pub proposer_index: String,
    pub parent_root: String,
    pub state_root: String,
    pub body_root: String,
}

/// Beacon block (BLOCK_V2 format)
#[derive(Debug, Deserialize)]
pub struct BeaconBlockV2 {
    pub version: String,
    pub block_header: BeaconBlockHeader,
}

/// RANDAO reveal data
#[derive(Debug, Deserialize)]
pub struct RandaoRevealData {
    pub epoch: String,
}

/// Aggregation slot data
#[derive(Debug, Deserialize)]
pub struct AggregationSlotData {
    pub slot: String,
}

/// Attestation with signature
#[derive(Debug, Deserialize)]
pub struct Attestation {
    pub aggregation_bits: String,
    pub data: AttestationData,
    pub signature: String,
}

/// Aggregate and proof data
#[derive(Debug, Deserialize)]
pub struct AggregateAndProofData {
    pub aggregator_index: String,
    pub aggregate: Attestation,
    pub selection_proof: String,
}

/// Voluntary exit data
#[derive(Debug, Deserialize)]
pub struct VoluntaryExitData {
    pub epoch: String,
    pub validator_index: String,
}

/// Sync committee message data
#[derive(Debug, Deserialize)]
pub struct SyncCommitteeMessageData {
    pub beacon_block_root: String,
    pub slot: String,
}

/// Sync aggregator selection data
#[derive(Debug, Deserialize)]
pub struct SyncAggregatorSelectionData {
    pub slot: String,
    pub subcommittee_index: String,
}

/// Sync committee contribution
#[derive(Debug, Deserialize)]
pub struct SyncCommitteeContribution {
    pub slot: String,
    pub beacon_block_root: String,
    pub subcommittee_index: String,
    pub aggregation_bits: String,
    pub signature: String,
}

/// Contribution and proof data
#[derive(Debug, Deserialize)]
pub struct ContributionAndProofData {
    pub aggregator_index: String,
    pub selection_proof: String,
    pub contribution: SyncCommitteeContribution,
}

/// Validator registration data (MEV/Builder API)
#[derive(Debug, Deserialize)]
pub struct ValidatorRegistrationData {
    pub fee_recipient: String,
    pub gas_limit: String,
    pub timestamp: String,
    pub pubkey: String,
}

/// All possible signing request types
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum SigningRequest {
    #[serde(rename = "ATTESTATION")]
    Attestation {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        attestation: AttestationData,
    },

    #[serde(rename = "BLOCK_V2")]
    BlockV2 {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        beacon_block: BeaconBlockV2,
    },

    #[serde(rename = "RANDAO_REVEAL")]
    RandaoReveal {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        randao_reveal: RandaoRevealData,
    },

    #[serde(rename = "AGGREGATION_SLOT")]
    AggregationSlot {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        aggregation_slot: AggregationSlotData,
    },

    #[serde(rename = "AGGREGATE_AND_PROOF")]
    AggregateAndProof {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        aggregate_and_proof: AggregateAndProofData,
    },

    #[serde(rename = "VOLUNTARY_EXIT")]
    VoluntaryExit {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        voluntary_exit: VoluntaryExitData,
    },

    #[serde(rename = "SYNC_COMMITTEE_MESSAGE")]
    SyncCommitteeMessage {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        sync_committee_message: SyncCommitteeMessageData,
    },

    #[serde(rename = "SYNC_COMMITTEE_SELECTION_PROOF")]
    SyncCommitteeSelectionProof {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        sync_aggregator_selection_data: SyncAggregatorSelectionData,
    },

    #[serde(rename = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF")]
    SyncCommitteeContributionAndProof {
        fork_info: ForkInfo,
        #[serde(rename = "signingRoot")]
        signing_root: String,
        contribution_and_proof: ContributionAndProofData,
    },

    #[serde(rename = "VALIDATOR_REGISTRATION")]
    ValidatorRegistration {
        #[serde(rename = "signingRoot")]
        signing_root: String,
        validator_registration: ValidatorRegistrationData,
    },
}

impl SigningRequest {
    /// Get the signing root from the request
    pub fn signing_root(&self) -> &str {
        match self {
            SigningRequest::Attestation { signing_root, .. } => signing_root,
            SigningRequest::BlockV2 { signing_root, .. } => signing_root,
            SigningRequest::RandaoReveal { signing_root, .. } => signing_root,
            SigningRequest::AggregationSlot { signing_root, .. } => signing_root,
            SigningRequest::AggregateAndProof { signing_root, .. } => signing_root,
            SigningRequest::VoluntaryExit { signing_root, .. } => signing_root,
            SigningRequest::SyncCommitteeMessage { signing_root, .. } => signing_root,
            SigningRequest::SyncCommitteeSelectionProof { signing_root, .. } => signing_root,
            SigningRequest::SyncCommitteeContributionAndProof { signing_root, .. } => signing_root,
            SigningRequest::ValidatorRegistration { signing_root, .. } => signing_root,
        }
    }

    /// Get the fork info from the request (if present)
    pub fn fork_info(&self) -> Option<&ForkInfo> {
        match self {
            SigningRequest::Attestation { fork_info, .. } => Some(fork_info),
            SigningRequest::BlockV2 { fork_info, .. } => Some(fork_info),
            SigningRequest::RandaoReveal { fork_info, .. } => Some(fork_info),
            SigningRequest::AggregationSlot { fork_info, .. } => Some(fork_info),
            SigningRequest::AggregateAndProof { fork_info, .. } => Some(fork_info),
            SigningRequest::VoluntaryExit { fork_info, .. } => Some(fork_info),
            SigningRequest::SyncCommitteeMessage { fork_info, .. } => Some(fork_info),
            SigningRequest::SyncCommitteeSelectionProof { fork_info, .. } => Some(fork_info),
            SigningRequest::SyncCommitteeContributionAndProof { fork_info, .. } => Some(fork_info),
            SigningRequest::ValidatorRegistration { .. } => None,
        }
    }

    /// Get the request type as a string for logging
    pub fn request_type(&self) -> &'static str {
        match self {
            SigningRequest::Attestation { .. } => "ATTESTATION",
            SigningRequest::BlockV2 { .. } => "BLOCK_V2",
            SigningRequest::RandaoReveal { .. } => "RANDAO_REVEAL",
            SigningRequest::AggregationSlot { .. } => "AGGREGATION_SLOT",
            SigningRequest::AggregateAndProof { .. } => "AGGREGATE_AND_PROOF",
            SigningRequest::VoluntaryExit { .. } => "VOLUNTARY_EXIT",
            SigningRequest::SyncCommitteeMessage { .. } => "SYNC_COMMITTEE_MESSAGE",
            SigningRequest::SyncCommitteeSelectionProof { .. } => "SYNC_COMMITTEE_SELECTION_PROOF",
            SigningRequest::SyncCommitteeContributionAndProof { .. } => "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
            SigningRequest::ValidatorRegistration { .. } => "VALIDATOR_REGISTRATION",
        }
    }
}
