# State Integrity

The signing enclave must prevent rollback of safety state. Rollback allows a compromised host to present an older state to the enclave and force unsafe signatures.

## Goals

- Detect any truncation or reordering of safety state.
- Fail closed if continuity is violated.
- Provide external auditability of state evolution.

## Software-only approach (v1)

1. The enclave maintains an internal state hash.
2. Every decision updates the hash using a one-way function:

   `state_hash_next = H(state_hash_prev || decision_record)`

3. The host stores decision records in an append-only log.
4. On startup, the enclave replays the log and verifies the hash chain.
5. If continuity is broken, the enclave refuses to sign.

## Safety State Contents

The enclave maintains per-validator safety state. Contents vary by chain. See `slashing-policy.md` for enforcement rules using this state.

### Ethereum Validators

| Field | Type | Purpose |
|-------|------|---------|
| `last_signed_block_slot` | uint64 | Highest slot for which a block was signed |
| `highest_source_epoch` | uint64 | Highest source epoch in any signed attestation |
| `highest_target_epoch` | uint64 | Highest target epoch in any signed attestation |
| `recent_attestations` | [(source, target)] | Compressed record of recent pairs for surround vote detection |

### Cosmos/CometBFT Validators

| Field | Type | Purpose |
|-------|------|---------|
| `last_signed_height` | int64 | Highest block height signed |
| `last_signed_round` | int32 | Round within that height |
| `last_signed_hash` | bytes | Block hash at that height/round |

### Polkadot Validators

**BABE State:**
| Field | Type | Purpose |
|-------|------|---------|
| `last_babe_slot` | uint64 | Highest slot for which a BABE block was produced |
| `last_babe_hash` | bytes | Block hash at that slot |

**GRANDPA State:**
| Field | Type | Purpose |
|-------|------|---------|
| `last_grandpa_round` | uint64 | Highest GRANDPA round participated in |
| `last_prevote_target` | bytes | Target block of last prevote |
| `last_precommit_target` | bytes | Target block of last precommit |

### Tezos Validators

| Field | Type | Purpose |
|-------|------|---------|
| `last_baked_level` | int32 | Highest level at which a block was baked |
| `last_baked_hash` | bytes | Block hash at that level |
| `last_endorsed_level` | int32 | Highest level at which an endorsement was signed |
| `last_endorsed_hash` | bytes | Endorsed block hash at that level |

## Checkpoints

To reduce replay cost, the enclave can emit periodic checkpoints:

- A checkpoint includes the current `state_hash` and a sequence number.
- Checkpoints are signed by the enclave and stored by the host.
- On restart, the enclave verifies the latest checkpoint and replays only the tail of the log.

## Failure modes

- **Truncated log**: detected by missing sequence numbers or hash mismatch.
- **Reordered log**: detected by hash mismatch.
- **State corruption**: detected by invalid decision record format or checksum.

In all cases, the enclave must refuse signing and emit a `REFUSE_STATE_ROLLBACK` response.

## Optional hardware binding (future)

If required, checkpoints can be bound to hardware monotonic counters or measured boot states. This is an optional hardening step and not required for v1 deployment.
