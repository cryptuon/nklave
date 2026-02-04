//! Per-validator safety state management
//!
//! Tracks signing history to prevent slashable signatures

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

/// Serialize a fixed-size byte array as hex
fn serialize_bytes<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserialize a fixed-size byte array from hex
fn deserialize_bytes<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
    if bytes.len() != N {
        return Err(serde::de::Error::custom(format!(
            "expected {} bytes, got {}",
            N,
            bytes.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Safety state for a single validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorState {
    /// Validator's BLS public key
    #[serde(serialize_with = "serialize_bytes", deserialize_with = "deserialize_bytes")]
    pub pubkey: [u8; 48],

    /// Highest slot for which a block was signed
    pub last_signed_block_slot: Option<u64>,

    /// Map of slot -> signing_root for block proposals
    /// Used to allow idempotent re-signing of the same block
    pub block_signing_roots: BTreeMap<u64, [u8; 32]>,

    /// Highest source epoch in any signed attestation
    pub highest_source_epoch: u64,

    /// Highest target epoch in any signed attestation
    pub highest_target_epoch: u64,

    /// Attestation history for surround vote detection
    pub attestation_history: AttestationHistory,
}

impl ValidatorState {
    /// Create a new validator state with the given public key
    pub fn new(pubkey: [u8; 48]) -> Self {
        Self {
            pubkey,
            last_signed_block_slot: None,
            block_signing_roots: BTreeMap::new(),
            highest_source_epoch: 0,
            highest_target_epoch: 0,
            attestation_history: AttestationHistory::new(),
        }
    }

    /// Get the signing root for a block at the given slot, if any
    pub fn get_block_signing_root(&self, slot: u64) -> Option<&[u8; 32]> {
        self.block_signing_roots.get(&slot)
    }

    /// Record that a block was signed for the given slot
    pub fn record_block_signing(&mut self, slot: u64, signing_root: [u8; 32]) {
        self.block_signing_roots.insert(slot, signing_root);
        if self.last_signed_block_slot.is_none_or(|s| slot > s) {
            self.last_signed_block_slot = Some(slot);
        }
    }

    /// Get the signing root for an attestation with the given source/target, if any
    pub fn get_attestation_signing_root(
        &self,
        source_epoch: u64,
        target_epoch: u64,
    ) -> Option<&[u8; 32]> {
        self.attestation_history
            .get_signing_root(source_epoch, target_epoch)
    }

    /// Record that an attestation was signed
    pub fn record_attestation_signing(
        &mut self,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: [u8; 32],
    ) {
        self.attestation_history
            .record(source_epoch, target_epoch, signing_root);

        if source_epoch > self.highest_source_epoch {
            self.highest_source_epoch = source_epoch;
        }
        if target_epoch > self.highest_target_epoch {
            self.highest_target_epoch = target_epoch;
        }
    }

    /// Prune old entries to limit memory usage
    /// Keeps entries within the weak subjectivity period
    pub fn prune(&mut self, min_slot: u64, min_epoch: u64) {
        // Prune block signing roots older than min_slot
        self.block_signing_roots = self
            .block_signing_roots
            .split_off(&min_slot);

        // Prune attestation history
        self.attestation_history.prune(min_epoch);
    }
}

/// History of signed attestations for surround vote detection
///
/// Uses min-span and max-span data structures for efficient detection
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationHistory {
    /// Map of (source_epoch, target_epoch) -> signing_root
    /// Used for double vote detection and idempotent re-signing
    signed_attestations: BTreeMap<(u64, u64), [u8; 32]>,

    /// For each source epoch, track the minimum target epoch seen
    /// Used to detect if a new attestation surrounds an existing one
    min_target_by_source: BTreeMap<u64, u64>,

    /// For each source epoch, track the maximum target epoch seen
    /// Used to detect if a new attestation is surrounded by an existing one
    max_target_by_source: BTreeMap<u64, u64>,
}

impl AttestationHistory {
    /// Create a new empty attestation history
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the signing root for an attestation, if it exists
    pub fn get_signing_root(&self, source_epoch: u64, target_epoch: u64) -> Option<&[u8; 32]> {
        self.signed_attestations.get(&(source_epoch, target_epoch))
    }

    /// Iterate over all signed attestations
    pub fn iter(&self) -> impl Iterator<Item = ((u64, u64), &[u8; 32])> {
        self.signed_attestations.iter().map(|(&k, v)| (k, v))
    }

    /// Record a new signed attestation
    pub fn record(&mut self, source_epoch: u64, target_epoch: u64, signing_root: [u8; 32]) {
        self.signed_attestations
            .insert((source_epoch, target_epoch), signing_root);

        // Update min target for this source
        self.min_target_by_source
            .entry(source_epoch)
            .and_modify(|t| {
                if target_epoch < *t {
                    *t = target_epoch;
                }
            })
            .or_insert(target_epoch);

        // Update max target for this source
        self.max_target_by_source
            .entry(source_epoch)
            .and_modify(|t| {
                if target_epoch > *t {
                    *t = target_epoch;
                }
            })
            .or_insert(target_epoch);
    }

    /// Get the minimum target epoch for any attestation with source > given source
    /// Used to detect surrounding votes
    pub fn get_min_target_for_source_gt(&self, source_epoch: u64) -> Option<u64> {
        // Find all sources greater than the given source
        // and return the minimum target among them
        self.min_target_by_source
            .range((source_epoch + 1)..)
            .map(|(_, &target)| target)
            .min()
    }

    /// Get the maximum target epoch for any attestation with source < given source
    /// Used to detect surrounded votes
    pub fn get_max_target_for_source_lt(&self, source_epoch: u64) -> Option<u64> {
        // Find all sources less than the given source
        // and return the maximum target among them
        self.max_target_by_source
            .range(..source_epoch)
            .map(|(_, &target)| target)
            .max()
    }

    /// Prune entries older than the given epoch
    pub fn prune(&mut self, min_epoch: u64) {
        self.signed_attestations
            .retain(|(source, _), _| *source >= min_epoch);
        self.min_target_by_source
            .retain(|source, _| *source >= min_epoch);
        self.max_target_by_source
            .retain(|source, _| *source >= min_epoch);
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
    fn test_validator_state_new() {
        let pubkey = [1u8; 48];
        let state = ValidatorState::new(pubkey);

        assert_eq!(state.pubkey, pubkey);
        assert_eq!(state.last_signed_block_slot, None);
        assert!(state.block_signing_roots.is_empty());
        assert_eq!(state.highest_source_epoch, 0);
        assert_eq!(state.highest_target_epoch, 0);
    }

    #[test]
    fn test_block_signing() {
        let mut state = ValidatorState::new([0u8; 48]);
        let root = make_root(1);

        assert!(state.get_block_signing_root(100).is_none());

        state.record_block_signing(100, root);

        assert_eq!(state.get_block_signing_root(100), Some(&root));
        assert_eq!(state.last_signed_block_slot, Some(100));
    }

    #[test]
    fn test_attestation_signing() {
        let mut state = ValidatorState::new([0u8; 48]);
        let root = make_root(1);

        assert!(state.get_attestation_signing_root(10, 11).is_none());

        state.record_attestation_signing(10, 11, root);

        assert_eq!(state.get_attestation_signing_root(10, 11), Some(&root));
        assert_eq!(state.highest_source_epoch, 10);
        assert_eq!(state.highest_target_epoch, 11);
    }

    #[test]
    fn test_surround_detection_spans() {
        let mut history = AttestationHistory::new();

        // Record attestation (5, 10)
        history.record(5, 10, make_root(1));

        // Check spans
        // For source > 5, min target should be 10
        assert_eq!(history.get_min_target_for_source_gt(4), Some(10));
        assert_eq!(history.get_min_target_for_source_gt(5), None);

        // For source < 5, max target should be None (nothing recorded)
        assert_eq!(history.get_max_target_for_source_lt(5), None);

        // Record another attestation (3, 12)
        history.record(3, 12, make_root(2));

        // Now for source < 5, max target should be 12
        assert_eq!(history.get_max_target_for_source_lt(5), Some(12));
    }
}
