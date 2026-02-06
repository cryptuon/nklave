//! Slashing policy enforcement modules
//!
//! Provides chain-specific slashing protection:
//! - Ethereum: Double proposal, double vote, surround vote detection
//! - Cosmos: Double signing at same height/round

pub mod cosmos;
pub mod ethereum;
pub mod types;
