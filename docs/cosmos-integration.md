# Cosmos/CometBFT Integration Specification

## Overview

This document specifies how Nklave integrates with Cosmos/CometBFT validator nodes as a remote signer, providing double-signing prevention for Tendermint consensus.

## Protocol Options

### 1. Tendermint Privval Protocol (Recommended)

The Tendermint private validator protocol is the native interface used by tmkms and other remote signers. It supports:

- **Raw Protocol (TCP/Unix Socket)**: Legacy protocol where Tendermint acts as server
- **gRPC Protocol**: Modern approach where Tendermint acts as client (recommended)

**Recommendation**: Start with gRPC protocol for new implementations as it's:
- The recommended approach by Tendermint/CometBFT
- Better supported and documented
- Supports TLS natively

### 2. tmkms Compatibility

[tmkms](https://github.com/iqlusioninc/tmkms) is the most widely deployed remote signer for Cosmos validators. Our implementation will use the same protobuf messages to ensure compatibility with existing validator client configurations.

## Message Types

Based on the [tendermint-proto](https://docs.rs/tendermint-proto/latest/tendermint_proto/privval/index.html) crate:

### Request Messages

```protobuf
// Request for the validator's public key
message PubKeyRequest {
    string chain_id = 1;
}

// Request to sign a vote (prevote or precommit)
message SignVoteRequest {
    tendermint.types.Vote vote = 1;
    string chain_id = 2;
}

// Request to sign a proposal
message SignProposalRequest {
    tendermint.types.Proposal proposal = 1;
    string chain_id = 2;
}

// Keepalive request
message PingRequest {}
```

### Response Messages

```protobuf
message PubKeyResponse {
    tendermint.crypto.PublicKey pub_key = 1;
    RemoteSignerError error = 2;
}

message SignedVoteResponse {
    tendermint.types.Vote vote = 1;
    RemoteSignerError error = 2;
}

message SignedProposalResponse {
    tendermint.types.Proposal proposal = 1;
    RemoteSignerError error = 2;
}

message PingResponse {}

message RemoteSignerError {
    int32 code = 1;
    string description = 2;
}
```

### Core Types

```protobuf
message Vote {
    SignedMsgType type = 1;
    int64 height = 2;
    int32 round = 3;
    BlockID block_id = 4;
    google.protobuf.Timestamp timestamp = 5;
    bytes validator_address = 6;
    int32 validator_index = 7;
    bytes signature = 8;
}

message Proposal {
    SignedMsgType type = 1;
    int64 height = 2;
    int32 round = 3;
    int32 pol_round = 4;
    BlockID block_id = 5;
    google.protobuf.Timestamp timestamp = 6;
    bytes signature = 7;
}

message BlockID {
    bytes hash = 1;
    PartSetHeader part_set_header = 2;
}

enum SignedMsgType {
    SIGNED_MSG_TYPE_UNKNOWN = 0;
    SIGNED_MSG_TYPE_PREVOTE = 1;
    SIGNED_MSG_TYPE_PRECOMMIT = 2;
    SIGNED_MSG_TYPE_PROPOSAL = 32;
}
```

## Slashing Rules

Cosmos slashing is simpler than Ethereum. The core rule is:

> **Never sign two different messages at the same `(height, round, type)`**

### Specific Rules

1. **Prevote Double Sign**: Cannot sign two prevotes for different blocks at the same (height, round)
2. **Precommit Double Sign**: Cannot sign two precommits for different blocks at the same (height, round)
3. **Proposal Double Sign**: Cannot sign two proposals for different blocks at the same (height, round)

### Key Differences from Ethereum

| Aspect | Ethereum | Cosmos |
|--------|----------|--------|
| Slashing Condition | Double proposal, double vote, surround vote | Double signing (same height+round) |
| Epoch vs Height | Uses epochs | Uses height + round |
| Surround Detection | Required (complex) | Not applicable |
| Key Type | BLS12-381 | Ed25519 |

### What Cosmos Does NOT Check

- **Height regression**: A validator can sign at height 100, then height 50 (catch-up after restart)
- **Round regression**: Can sign round 5 then round 3 at same height (Byzantine tolerance)
- **NIL votes**: Signing for BlockID = nil is allowed at any point

## State Model for Cosmos

```rust
/// Cosmos-specific validator state
pub struct CosmosState {
    /// Mapping of (height, round, type) -> (block_hash, timestamp)
    /// Only stores the most recent signature for each combination
    pub signed_votes: HashMap<(i64, i32, SignedMsgType), SignedVoteInfo>,
}

pub struct SignedVoteInfo {
    /// Hash of the block that was signed
    pub block_hash: Option<[u8; 32]>,  // None = nil vote
    /// When the signing occurred
    pub signed_at: u64,
}
```

### State Compaction

Unlike Ethereum (which must track epochs for surround detection), Cosmos state can be compacted more aggressively:

- Old height entries can be pruned once finalized
- Only need to track last N heights for safety
- Recommended: Keep entries for heights > (current_height - 1000)

## Slashing Policy Implementation

```rust
pub struct CosmosPolicy;

impl CosmosPolicy {
    /// Check if a vote is safe to sign
    pub fn check_vote(
        &self,
        state: &CosmosState,
        height: i64,
        round: i32,
        vote_type: SignedMsgType,
        block_id: Option<&BlockID>,
    ) -> PolicyDecision {
        let key = (height, round, vote_type);

        match state.signed_votes.get(&key) {
            None => {
                // First vote at this (height, round, type) - safe
                PolicyDecision::Allow
            }
            Some(prev) => {
                // Already signed at this (height, round, type)
                let current_hash = block_id.map(|b| hash_block_id(b));

                if current_hash == prev.block_hash {
                    // Same block - idempotent, safe
                    PolicyDecision::Allow
                } else {
                    // Different block - DOUBLE SIGN ATTEMPT
                    PolicyDecision::Refuse(RefusalCode::CosmosDoubleSigning)
                }
            }
        }
    }

    /// Check if a proposal is safe to sign
    pub fn check_proposal(
        &self,
        state: &CosmosState,
        height: i64,
        round: i32,
        block_id: &BlockID,
    ) -> PolicyDecision {
        // Same logic as vote but for proposal type
        self.check_vote(state, height, round, SignedMsgType::Proposal, Some(block_id))
    }
}
```

## Communication Protocol

### gRPC Service (Recommended)

```protobuf
service PrivValidatorAPI {
    rpc GetPubKey(PubKeyRequest) returns (PubKeyResponse);
    rpc SignVote(SignVoteRequest) returns (SignedVoteResponse);
    rpc SignProposal(SignProposalRequest) returns (SignedProposalResponse);
}
```

### Connection Flow

```
Validator (Client)              Nklave (Server)
       |                              |
       |--- PubKeyRequest ----------->|
       |<-- PubKeyResponse -----------|
       |                              |
       |--- SignVoteRequest --------->|
       |    (prevote, height=100,     |
       |     round=0, block=0xabc...) |
       |                              |
       |    [Check slashing policy]   |
       |    [Sign with Ed25519]       |
       |                              |
       |<-- SignedVoteResponse -------|
       |    (signed vote)             |
       |                              |
```

### Security

1. **TLS Required**: All production deployments should use TLS
2. **Mutual TLS**: Both client and server should authenticate
3. **Chain ID Verification**: Ensure requests are for the expected chain
4. **Network Isolation**: Use VPC or private networking

## Key Management

### Ed25519 Keys

Cosmos validators use Ed25519 (not BLS like Ethereum). Key format:

```rust
pub struct CosmosValidatorKey {
    /// 32-byte Ed25519 private key
    pub private_key: [u8; 32],
    /// 32-byte Ed25519 public key
    pub public_key: [u8; 32],
}
```

### Key Storage Format

tmkms uses a specific key format. For compatibility, support:

1. **priv_validator_key.json**: Standard Tendermint format
2. **tmkms encrypted**: YubiHSM, Fortanix DSM wrapped keys

## Multi-Chain Considerations

For validators running on multiple Cosmos chains:

1. **Chain ID Binding**: Each key is bound to a specific chain_id
2. **Separate State**: Maintain separate slashing state per chain
3. **Key Isolation**: Use different keys for different chains

## Implementation Phases

### Phase 1: Core Policy
- [ ] Implement `CosmosState` structure
- [ ] Implement `CosmosPolicy` with double-sign detection
- [ ] Add `SigningContext::Cosmos` for replay recovery
- [ ] Add Ed25519 key support

### Phase 2: Protocol Handler
- [ ] Implement protobuf message parsing (use tendermint-proto crate)
- [ ] Create gRPC server for PrivValidatorAPI
- [ ] Handle PubKeyRequest, SignVoteRequest, SignProposalRequest
- [ ] Add ping/pong keepalive

### Phase 3: Integration
- [ ] Test with Gaia testnet
- [ ] Test with other Cosmos chains (Osmosis, etc.)
- [ ] Performance benchmarking
- [ ] Failover testing

## Dependencies

```toml
[dependencies]
# Tendermint protobuf types
tendermint-proto = "0.38"
tendermint = "0.38"

# Ed25519 signing
ed25519-dalek = "2.0"

# gRPC
tonic = "0.11"
prost = "0.12"
```

## References

- [Tendermint Validator Signing Spec](https://docs.tendermint.com/master/spec/consensus/signing.html)
- [CometBFT Signing Spec v0.37](https://docs.cometbft.com/v0.37/spec/consensus/signing)
- [tmkms Repository](https://github.com/iqlusioninc/tmkms)
- [tendermint-proto Rust Crate](https://docs.rs/tendermint-proto/latest/tendermint_proto/privval/index.html)
- [Tendermint Remote Signer Docs](https://docs.tendermint.com/master/nodes/remote-signer.html)
