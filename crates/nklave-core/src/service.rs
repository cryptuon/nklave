//! Signing service that orchestrates the complete signing flow
//!
//! This service ties together key management, slashing protection, and state integrity

use crate::keys::bls::{BlsKeypair, BlsSignature};
use crate::metrics;
use crate::policy::ethereum::EthereumPolicy;
use crate::policy::types::{PolicyDecision, RefusalCode, SigningType};
use crate::state::integrity::{DecisionRecord, IntegrityError, StateIntegrity};
use crate::state::validator::ValidatorState;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use thiserror::Error;

/// The signing service that coordinates all signing operations
pub struct SigningService {
    /// Loaded validator keypairs indexed by public key (RwLock for dynamic reloading)
    keypairs: RwLock<HashMap<[u8; 48], BlsKeypair>>,

    /// Per-validator safety state
    validators: RwLock<HashMap<[u8; 48], ValidatorState>>,

    /// State integrity tracker
    integrity: RwLock<StateIntegrity>,

    /// Ethereum slashing policy
    policy: EthereumPolicy,

    /// Genesis validators root (set on first request)
    genesis_validators_root: RwLock<Option<[u8; 32]>>,
}

impl SigningService {
    /// Create a new signing service with the given keypairs
    pub fn new(keypairs: Vec<BlsKeypair>) -> Self {
        let keypair_map: HashMap<[u8; 48], BlsKeypair> = keypairs
            .into_iter()
            .map(|kp| {
                let pubkey = kp.public_key_bytes();
                (pubkey, kp)
            })
            .collect();

        Self {
            keypairs: RwLock::new(keypair_map),
            validators: RwLock::new(HashMap::new()),
            integrity: RwLock::new(StateIntegrity::new()),
            policy: EthereumPolicy::new(),
            genesis_validators_root: RwLock::new(None),
        }
    }

    /// Create a signing service with existing state (for recovery)
    pub fn with_state(
        keypairs: Vec<BlsKeypair>,
        validators: HashMap<[u8; 48], ValidatorState>,
        integrity: StateIntegrity,
    ) -> Self {
        let keypair_map: HashMap<[u8; 48], BlsKeypair> = keypairs
            .into_iter()
            .map(|kp| {
                let pubkey = kp.public_key_bytes();
                (pubkey, kp)
            })
            .collect();

        let genesis_root = integrity.genesis_validators_root;

        Self {
            keypairs: RwLock::new(keypair_map),
            validators: RwLock::new(validators),
            integrity: RwLock::new(integrity),
            policy: EthereumPolicy::new(),
            genesis_validators_root: RwLock::new(genesis_root),
        }
    }

    /// Get all public keys managed by this service
    pub fn public_keys(&self) -> Vec<[u8; 48]> {
        self.keypairs.read().unwrap().keys().copied().collect()
    }

    /// Get public keys as hex strings with 0x prefix
    pub fn public_keys_hex(&self) -> Vec<String> {
        self.keypairs
            .read()
            .unwrap()
            .keys()
            .map(|pk| format!("0x{}", hex::encode(pk)))
            .collect()
    }

    /// Check if a validator is managed by this service
    pub fn has_validator(&self, pubkey: &[u8; 48]) -> bool {
        self.keypairs.read().unwrap().contains_key(pubkey)
    }

    /// Add new keypairs to the service (for dynamic key reloading)
    ///
    /// Returns the number of new keys added (excludes duplicates)
    pub fn add_keys(&self, keypairs: Vec<BlsKeypair>) -> usize {
        let mut keypair_map = self.keypairs.write().unwrap();
        let initial_count = keypair_map.len();

        for kp in keypairs {
            let pubkey = kp.public_key_bytes();
            keypair_map.entry(pubkey).or_insert(kp);
        }

        keypair_map.len() - initial_count
    }

    /// Get the total number of validators managed by this service
    pub fn validator_count(&self) -> usize {
        self.keypairs.read().unwrap().len()
    }

    /// Set or verify the genesis validators root
    pub fn set_genesis_validators_root(
        &self,
        root: [u8; 32],
    ) -> Result<(), SigningServiceError> {
        let mut genesis_root = self.genesis_validators_root.write().unwrap();

        match *genesis_root {
            Some(existing) if existing != root => {
                Err(SigningServiceError::GenesisRootMismatch {
                    expected: existing,
                    actual: root,
                })
            }
            Some(_) => Ok(()), // Already set to same value
            None => {
                *genesis_root = Some(root);
                // Also update integrity tracker
                let mut integrity = self.integrity.write().unwrap();
                integrity
                    .set_genesis_validators_root(root)
                    .map_err(SigningServiceError::Integrity)?;
                Ok(())
            }
        }
    }

    /// Sign a block proposal
    ///
    /// Returns the BLS signature if allowed, or an error if refused
    pub fn sign_block_proposal(
        &self,
        pubkey: &[u8; 48],
        slot: u64,
        signing_root: [u8; 32],
    ) -> Result<SigningResult, SigningServiceError> {
        let start = Instant::now();
        let validator_hex = format!("0x{}...{}", &hex::encode(&pubkey[..4]), &hex::encode(&pubkey[44..]));

        // Get the keypair
        let keypairs = self.keypairs.read().unwrap();
        let keypair = keypairs
            .get(pubkey)
            .ok_or(SigningServiceError::UnknownValidator(*pubkey))?;

        // Get or create validator state
        let mut validators = self.validators.write().unwrap();
        let state = validators
            .entry(*pubkey)
            .or_insert_with(|| ValidatorState::new(*pubkey));

        // Check slashing protection
        let decision = self.policy.check_block_proposal(state, slot, &signing_root);

        match decision {
            PolicyDecision::Allow => {
                // Sign the message
                let signature = keypair.sign(&signing_root);

                // Record the signing
                state.record_block_signing(slot, signing_root);

                // Record decision in integrity tracker
                let mut integrity = self.integrity.write().unwrap();
                let record = integrity.prepare_record(
                    *pubkey,
                    SigningType::BlockProposal,
                    PolicyDecision::Allow,
                    signing_root,
                );
                integrity
                    .record_decision(&record)
                    .map_err(SigningServiceError::Integrity)?;

                // Record metrics
                let elapsed = start.elapsed().as_secs_f64();
                metrics::record_signing_success("block_proposal", &validator_hex);
                metrics::record_signing_latency("block_proposal", elapsed);
                metrics::record_block_signed(&validator_hex);
                metrics::set_state_sequence(integrity.sequence_number);

                Ok(SigningResult {
                    signature,
                    decision_record: record,
                })
            }
            PolicyDecision::Refuse(code) => {
                // Record the refusal in integrity tracker
                let mut integrity = self.integrity.write().unwrap();
                let record = integrity.prepare_record(
                    *pubkey,
                    SigningType::BlockProposal,
                    PolicyDecision::Refuse(code),
                    signing_root,
                );
                integrity
                    .record_decision(&record)
                    .map_err(SigningServiceError::Integrity)?;

                // Record metrics
                let elapsed = start.elapsed().as_secs_f64();
                metrics::record_signing_refusal("block_proposal", &code.to_string(), &validator_hex);
                metrics::record_signing_latency("block_proposal", elapsed);

                Err(SigningServiceError::SlashingProtection(code))
            }
        }
    }

    /// Sign an attestation
    ///
    /// Returns the BLS signature if allowed, or an error if refused
    pub fn sign_attestation(
        &self,
        pubkey: &[u8; 48],
        source_epoch: u64,
        target_epoch: u64,
        signing_root: [u8; 32],
    ) -> Result<SigningResult, SigningServiceError> {
        let start = Instant::now();
        let validator_hex = format!("0x{}...{}", &hex::encode(&pubkey[..4]), &hex::encode(&pubkey[44..]));

        // Get the keypair
        let keypairs = self.keypairs.read().unwrap();
        let keypair = keypairs
            .get(pubkey)
            .ok_or(SigningServiceError::UnknownValidator(*pubkey))?;

        // Get or create validator state
        let mut validators = self.validators.write().unwrap();
        let state = validators
            .entry(*pubkey)
            .or_insert_with(|| ValidatorState::new(*pubkey));

        // Check slashing protection
        let decision = self
            .policy
            .check_attestation(state, source_epoch, target_epoch, &signing_root);

        match decision {
            PolicyDecision::Allow => {
                // Sign the message
                let signature = keypair.sign(&signing_root);

                // Record the signing
                state.record_attestation_signing(source_epoch, target_epoch, signing_root);

                // Record decision in integrity tracker
                let mut integrity = self.integrity.write().unwrap();
                let record = integrity.prepare_record(
                    *pubkey,
                    SigningType::Attestation,
                    PolicyDecision::Allow,
                    signing_root,
                );
                integrity
                    .record_decision(&record)
                    .map_err(SigningServiceError::Integrity)?;

                // Record metrics
                let elapsed = start.elapsed().as_secs_f64();
                metrics::record_signing_success("attestation", &validator_hex);
                metrics::record_signing_latency("attestation", elapsed);
                metrics::record_attestation_signed(&validator_hex);
                metrics::set_state_sequence(integrity.sequence_number);

                Ok(SigningResult {
                    signature,
                    decision_record: record,
                })
            }
            PolicyDecision::Refuse(code) => {
                // Record the refusal in integrity tracker
                let mut integrity = self.integrity.write().unwrap();
                let record = integrity.prepare_record(
                    *pubkey,
                    SigningType::Attestation,
                    PolicyDecision::Refuse(code),
                    signing_root,
                );
                integrity
                    .record_decision(&record)
                    .map_err(SigningServiceError::Integrity)?;

                // Record metrics
                let elapsed = start.elapsed().as_secs_f64();
                metrics::record_signing_refusal("attestation", &code.to_string(), &validator_hex);
                metrics::record_signing_latency("attestation", elapsed);

                Err(SigningServiceError::SlashingProtection(code))
            }
        }
    }

    /// Sign a generic message (for types without slashing protection)
    ///
    /// Used for: RANDAO reveal, aggregation slot, sync committee messages, etc.
    pub fn sign_generic(
        &self,
        pubkey: &[u8; 48],
        signing_type: SigningType,
        signing_root: [u8; 32],
    ) -> Result<SigningResult, SigningServiceError> {
        let start = Instant::now();
        let validator_hex = format!("0x{}...{}", &hex::encode(&pubkey[..4]), &hex::encode(&pubkey[44..]));
        let type_name = signing_type.as_str();

        // Get the keypair
        let keypairs = self.keypairs.read().unwrap();
        let keypair = keypairs
            .get(pubkey)
            .ok_or(SigningServiceError::UnknownValidator(*pubkey))?;

        // Sign the message (no slashing protection needed for these types)
        let signature = keypair.sign(&signing_root);

        // Record decision in integrity tracker
        let mut integrity = self.integrity.write().unwrap();
        let record = integrity.prepare_record(
            *pubkey,
            signing_type,
            PolicyDecision::Allow,
            signing_root,
        );
        integrity
            .record_decision(&record)
            .map_err(SigningServiceError::Integrity)?;

        // Record metrics
        let elapsed = start.elapsed().as_secs_f64();
        metrics::record_signing_success(type_name, &validator_hex);
        metrics::record_signing_latency(type_name, elapsed);
        metrics::set_state_sequence(integrity.sequence_number);

        Ok(SigningResult {
            signature,
            decision_record: record,
        })
    }

    /// Replay decision records (for crash recovery)
    ///
    /// This method is used during startup to replay decisions from the log
    /// that occurred after the last checkpoint.
    pub fn replay_records(&self, records: Vec<DecisionRecord>) -> Result<u64, SigningServiceError> {
        let mut validators = self.validators.write().unwrap();
        let mut integrity = self.integrity.write().unwrap();

        let mut replayed = 0u64;

        for record in records {
            // Skip records we've already processed
            if record.sequence <= integrity.sequence_number {
                continue;
            }

            // Verify and apply the record to integrity
            integrity
                .record_decision(&record)
                .map_err(SigningServiceError::Integrity)?;

            // Update validator state based on the decision
            if record.decision.is_allowed() {
                let state = validators
                    .entry(record.validator_pubkey)
                    .or_insert_with(|| ValidatorState::new(record.validator_pubkey));

                match record.request_type {
                    SigningType::BlockProposal => {
                        // Extract slot from signing root context (simplified - in real impl would need more info)
                        // For replay, we trust the record as valid
                        tracing::debug!(
                            sequence = record.sequence,
                            "Replayed block proposal record"
                        );
                    }
                    SigningType::Attestation => {
                        tracing::debug!(
                            sequence = record.sequence,
                            "Replayed attestation record"
                        );
                    }
                    _ => {
                        tracing::debug!(
                            sequence = record.sequence,
                            request_type = ?record.request_type,
                            "Replayed generic signing record"
                        );
                    }
                }

                // Note: Full replay would need to extract slot/epoch info from the record
                // For now, we just verify the integrity chain
                let _ = state; // Suppress unused warning
            }

            replayed += 1;
        }

        tracing::info!(replayed, "Replayed decision records");
        Ok(replayed)
    }

    /// Get a copy of the current validator states
    pub fn validator_states(&self) -> HashMap<[u8; 48], ValidatorState> {
        self.validators.read().unwrap().clone()
    }

    /// Get the current state integrity
    pub fn integrity(&self) -> StateIntegrity {
        self.integrity.read().unwrap().clone()
    }

    /// Get the last decision sequence number
    pub fn last_sequence(&self) -> u64 {
        self.integrity.read().unwrap().sequence_number
    }
}

/// Result of a successful signing operation
#[derive(Debug, Clone)]
pub struct SigningResult {
    /// The BLS signature
    pub signature: BlsSignature,

    /// The decision record for logging
    pub decision_record: DecisionRecord,
}

impl SigningResult {
    /// Get the signature as a hex string with 0x prefix
    pub fn signature_hex(&self) -> String {
        self.signature.to_hex()
    }

    /// Get the signature as bytes
    pub fn signature_bytes(&self) -> [u8; 96] {
        self.signature.to_bytes()
    }
}

/// Errors that can occur during signing operations
#[derive(Debug, Error)]
pub enum SigningServiceError {
    #[error("Unknown validator: 0x{}", hex::encode(.0))]
    UnknownValidator([u8; 48]),

    #[error("Slashing protection: {0}")]
    SlashingProtection(RefusalCode),

    #[error("Integrity error: {0}")]
    Integrity(#[from] IntegrityError),

    #[error("Genesis validators root mismatch: expected 0x{}, got 0x{}", hex::encode(.expected), hex::encode(.actual))]
    GenesisRootMismatch { expected: [u8; 32], actual: [u8; 32] },

    #[error("Invalid signing root: {0}")]
    InvalidSigningRoot(String),
}

/// Thread-safe wrapper for SigningService
pub type SharedSigningService = Arc<SigningService>;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service() -> SigningService {
        let keypair = BlsKeypair::generate();
        SigningService::new(vec![keypair])
    }

    #[test]
    fn test_sign_block_proposal() {
        let service = make_service();
        let pubkey = service.public_keys()[0];
        let signing_root = [1u8; 32];

        let result = service.sign_block_proposal(&pubkey, 100, signing_root);
        assert!(result.is_ok());

        let signing_result = result.unwrap();
        assert!(!signing_result.signature_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_double_proposal_rejected() {
        let service = make_service();
        let pubkey = service.public_keys()[0];

        // First proposal
        let result1 = service.sign_block_proposal(&pubkey, 100, [1u8; 32]);
        assert!(result1.is_ok());

        // Different block at same slot
        let result2 = service.sign_block_proposal(&pubkey, 100, [2u8; 32]);
        assert!(matches!(
            result2,
            Err(SigningServiceError::SlashingProtection(RefusalCode::DoubleProposal))
        ));
    }

    #[test]
    fn test_sign_attestation() {
        let service = make_service();
        let pubkey = service.public_keys()[0];
        let signing_root = [1u8; 32];

        let result = service.sign_attestation(&pubkey, 10, 11, signing_root);
        assert!(result.is_ok());
    }

    #[test]
    fn test_double_vote_rejected() {
        let service = make_service();
        let pubkey = service.public_keys()[0];

        // First attestation
        let result1 = service.sign_attestation(&pubkey, 10, 11, [1u8; 32]);
        assert!(result1.is_ok());

        // Different attestation for same target
        let result2 = service.sign_attestation(&pubkey, 10, 11, [2u8; 32]);
        assert!(matches!(
            result2,
            Err(SigningServiceError::SlashingProtection(RefusalCode::DoubleVote))
        ));
    }

    #[test]
    fn test_surround_vote_rejected() {
        let service = make_service();
        let pubkey = service.public_keys()[0];

        // First attestation (5, 10)
        let result1 = service.sign_attestation(&pubkey, 5, 10, [1u8; 32]);
        assert!(result1.is_ok());

        // Surrounding attestation (3, 12) - should be rejected
        let result2 = service.sign_attestation(&pubkey, 3, 12, [2u8; 32]);
        assert!(matches!(
            result2,
            Err(SigningServiceError::SlashingProtection(RefusalCode::SurroundVote))
        ));
    }

    #[test]
    fn test_unknown_validator() {
        let service = make_service();
        let unknown_pubkey = [99u8; 48];

        let result = service.sign_block_proposal(&unknown_pubkey, 100, [1u8; 32]);
        assert!(matches!(
            result,
            Err(SigningServiceError::UnknownValidator(_))
        ));
    }

    #[test]
    fn test_sign_generic() {
        let service = make_service();
        let pubkey = service.public_keys()[0];

        let result = service.sign_generic(&pubkey, SigningType::RandaoReveal, [1u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_genesis_root() {
        let service = make_service();
        let root1 = [1u8; 32];
        let root2 = [2u8; 32];

        // First set should succeed
        assert!(service.set_genesis_validators_root(root1).is_ok());

        // Same root should succeed
        assert!(service.set_genesis_validators_root(root1).is_ok());

        // Different root should fail
        assert!(matches!(
            service.set_genesis_validators_root(root2),
            Err(SigningServiceError::GenesisRootMismatch { .. })
        ));
    }
}
