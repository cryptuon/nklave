//! EIP-3076 Slashing Protection Interchange Format
//!
//! Supports import/export of slashing protection data for validator migration

use nklave_core::state::validator::ValidatorState;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use thiserror::Error;

/// EIP-3076 interchange format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3076Interchange {
    pub metadata: Eip3076Metadata,
    pub data: Vec<Eip3076ValidatorData>,
}

/// Metadata for the interchange format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3076Metadata {
    pub interchange_format_version: String,
    pub genesis_validators_root: String,
}

/// Per-validator slashing protection data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3076ValidatorData {
    pub pubkey: String,
    pub signed_blocks: Vec<Eip3076SignedBlock>,
    pub signed_attestations: Vec<Eip3076SignedAttestation>,
}

/// Signed block record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3076SignedBlock {
    pub slot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

/// Signed attestation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip3076SignedAttestation {
    pub source_epoch: String,
    pub target_epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

impl Eip3076Interchange {
    /// Current interchange format version
    pub const VERSION: &'static str = "5";

    /// Create a new interchange file from validator states
    pub fn from_validators(
        genesis_validators_root: [u8; 32],
        validators: &[&ValidatorState],
    ) -> Self {
        let data = validators
            .iter()
            .map(|v| {
                let pubkey = format!("0x{}", hex::encode(v.pubkey));

                let signed_blocks: Vec<_> = v
                    .block_signing_roots
                    .iter()
                    .map(|(slot, root)| Eip3076SignedBlock {
                        slot: slot.to_string(),
                        signing_root: Some(format!("0x{}", hex::encode(root))),
                    })
                    .collect();

                let signed_attestations: Vec<_> = v
                    .attestation_history
                    .iter()
                    .map(|((source, target), root)| Eip3076SignedAttestation {
                        source_epoch: source.to_string(),
                        target_epoch: target.to_string(),
                        signing_root: Some(format!("0x{}", hex::encode(root))),
                    })
                    .collect();

                Eip3076ValidatorData {
                    pubkey,
                    signed_blocks,
                    signed_attestations,
                }
            })
            .collect();

        Self {
            metadata: Eip3076Metadata {
                interchange_format_version: Self::VERSION.to_string(),
                genesis_validators_root: format!("0x{}", hex::encode(genesis_validators_root)),
            },
            data,
        }
    }

    /// Import from a file
    pub fn import(path: impl AsRef<Path>) -> Result<Self, Eip3076Error> {
        let file = File::open(path).map_err(|e| Eip3076Error::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        serde_json::from_reader(reader).map_err(|e| Eip3076Error::Parse(e.to_string()))
    }

    /// Export to a file
    pub fn export(&self, path: impl AsRef<Path>) -> Result<(), Eip3076Error> {
        let file = File::create(path).map_err(|e| Eip3076Error::Io(e.to_string()))?;
        let writer = BufWriter::new(file);

        serde_json::to_writer_pretty(writer, self)
            .map_err(|e| Eip3076Error::Serialize(e.to_string()))
    }

    /// Parse the genesis validators root
    pub fn genesis_validators_root(&self) -> Result<[u8; 32], Eip3076Error> {
        parse_hex_bytes(&self.metadata.genesis_validators_root)
    }

    /// Apply this interchange data to validator states
    pub fn apply_to_validators(
        &self,
        validators: &mut std::collections::HashMap<[u8; 48], ValidatorState>,
    ) -> Result<(), Eip3076Error> {
        for validator_data in &self.data {
            let pubkey: [u8; 48] = parse_hex_bytes(&validator_data.pubkey)?;

            let state = validators
                .entry(pubkey)
                .or_insert_with(|| ValidatorState::new(pubkey));

            // Apply signed blocks
            for block in &validator_data.signed_blocks {
                let slot: u64 = block
                    .slot
                    .parse()
                    .map_err(|_| Eip3076Error::Parse("Invalid slot".to_string()))?;

                let signing_root: [u8; 32] = if let Some(ref root) = block.signing_root {
                    parse_hex_bytes(root)?
                } else {
                    [0u8; 32]
                };

                state.record_block_signing(slot, signing_root);
            }

            // Apply signed attestations
            for attestation in &validator_data.signed_attestations {
                let source_epoch: u64 = attestation
                    .source_epoch
                    .parse()
                    .map_err(|_| Eip3076Error::Parse("Invalid source_epoch".to_string()))?;

                let target_epoch: u64 = attestation
                    .target_epoch
                    .parse()
                    .map_err(|_| Eip3076Error::Parse("Invalid target_epoch".to_string()))?;

                let signing_root: [u8; 32] = if let Some(ref root) = attestation.signing_root {
                    parse_hex_bytes(root)?
                } else {
                    [0u8; 32]
                };

                state.record_attestation_signing(source_epoch, target_epoch, signing_root);
            }
        }

        Ok(())
    }
}

/// Parse a hex string into a fixed-size byte array
fn parse_hex_bytes<const N: usize>(s: &str) -> Result<[u8; N], Eip3076Error> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| Eip3076Error::Parse(e.to_string()))?;

    if bytes.len() != N {
        return Err(Eip3076Error::Parse(format!(
            "Expected {} bytes, got {}",
            N,
            bytes.len()
        )));
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Errors related to EIP-3076
#[derive(Debug, Error)]
pub enum Eip3076Error {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Serialization error: {0}")]
    Serialize(String),

    #[error("Genesis validators root mismatch")]
    GenesisRootMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn test_eip3076_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("slashing_protection.json");

        let mut state = ValidatorState::new([1u8; 48]);
        state.record_block_signing(100, [2u8; 32]);
        state.record_attestation_signing(10, 11, [3u8; 32]);

        let interchange =
            Eip3076Interchange::from_validators([0u8; 32], &[&state]);

        interchange.export(&path).unwrap();

        let loaded = Eip3076Interchange::import(&path).unwrap();
        assert_eq!(loaded.data.len(), 1);
        assert_eq!(loaded.data[0].signed_blocks.len(), 1);
        assert_eq!(loaded.data[0].signed_attestations.len(), 1);
    }

    #[test]
    fn test_apply_to_validators() {
        let mut state = ValidatorState::new([1u8; 48]);
        state.record_block_signing(100, [2u8; 32]);

        let interchange =
            Eip3076Interchange::from_validators([0u8; 32], &[&state]);

        let mut validators = HashMap::new();
        interchange.apply_to_validators(&mut validators).unwrap();

        assert!(validators.contains_key(&[1u8; 48]));
        let loaded_state = validators.get(&[1u8; 48]).unwrap();
        assert!(loaded_state.get_block_signing_root(100).is_some());
    }
}
