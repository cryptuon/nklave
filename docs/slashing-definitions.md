# Slashing Definitions

This document provides comprehensive definitions of slashable signing conditions across supported blockchain protocols. It serves as the authoritative reference for understanding what constitutes a slashable offense on each chain.

## What is Slashable Signing

Slashable signing occurs when a validator signs messages that violate the consensus protocol's safety rules. These violations can lead to:

- **Economic penalties**: Loss of staked assets (slashing)
- **Forced exit**: Removal from the validator set
- **Permanent ban**: Some chains "tombstone" validators, preventing re-entry

Nklave prevents slashable signing by enforcing protocol safety rules inside an isolated signing boundary. The enclave refuses to produce signatures that would violate these rules, even if requested by compromised software.

---

## Ethereum

Ethereum uses Casper FFG (Friendly Finality Gadget) for finality, with specific rules for block proposals and attestations.

### Slashable Offenses

| Offense | Description | Severity |
|---------|-------------|----------|
| **Double Proposal** | Proposing two different blocks for the same slot | High |
| **Double Vote** | Signing two different attestations with the same target epoch | High |
| **Surround Vote** | Casting an attestation that surrounds or is surrounded by a previous attestation | High |

### Double Proposal

A validator must not sign two different block proposals for the same slot.

**Detection**: Compare `slot` values. If `slot_new == slot_previous` and `signing_root_new != signing_root_previous`, refuse.

### Double Vote (FFG Double Vote)

A validator must not sign two different attestations with the same target epoch.

**Detection**: Compare `target_epoch` values. If `target_epoch_new == target_epoch_previous` and `signing_root_new != signing_root_previous`, refuse.

### Surround Vote

A validator must not sign an attestation whose (source, target) range surrounds or is surrounded by a previously signed attestation.

**Surrounding**: `source_new < source_previous < target_previous < target_new`
**Surrounded**: `source_previous < source_new < target_new < target_previous`

**Detection**: Requires maintaining historical (source, target) pairs and checking for overlapping ranges.

### Penalties

- **Initial penalty**: ~1/32 of validator's effective balance (~1 ETH)
- **Correlation penalty**: Additional penalty based on how many other validators were slashed within ~18 days (up to 100% of stake if 1/3 of validators slashed)
- **Forced exit**: 36 days removal from active validator set

### State Required

Per validator, the enclave must track:

| Field | Purpose |
|-------|---------|
| `last_signed_block_slot` | Prevent double proposals |
| `highest_source_epoch` | High watermark for attestation sources |
| `highest_target_epoch` | High watermark for attestation targets |
| `recent_attestations` | Compressed (source, target) pairs for surround vote detection |

### EIP-3076 Compatibility

Ethereum has standardized slashing protection via EIP-3076, which defines a JSON interchange format for transferring signing history between clients. Nklave should support import/export in this format for validator migration.

---

## Cosmos / CometBFT

Cosmos-based chains use CometBFT (formerly Tendermint) consensus with a simpler height/round model.

### Slashable Offenses

| Offense | Penalty | Jail Duration | Recovery |
|---------|---------|---------------|----------|
| **Double Signing** | 5% of stake | Permanent (tombstoned) | Cannot un-jail |
| **Downtime** | 0.01% of stake | 10 minutes | Can un-jail |

### Double Signing (Equivocation)

A validator must not sign two different blocks at the same height and round.

**Detection**: Compare `(height, round)` tuples. If `height_new == height_previous` AND `round_new == round_previous` AND `block_hash_new != block_hash_previous`, refuse.

### Downtime

Missing more than 95% of blocks in a 10,000 block window results in a small slash and temporary jail. This is not prevented by signing protection (it's an availability issue, not a signing issue).

### Tombstoning

Unlike Ethereum, Cosmos permanently removes ("tombstones") validators who double-sign. There is no recovery path. This makes prevention even more critical.

### State Required

Per validator, the enclave must track:

| Field | Purpose |
|-------|---------|
| `last_signed_height` | Highest block height signed |
| `last_signed_round` | Round within that height |
| `last_signed_hash` | Block hash at that height/round |

### Note on Rounds

CometBFT consensus may go through multiple rounds within a single height before achieving consensus. The enclave must allow signing different blocks in different rounds at the same height, but never two different blocks in the same round.

---

## Polkadot / Substrate

Polkadot uses a hybrid consensus model with separate mechanisms for block production (BABE) and finality (GRANDPA).

### Slashable Offenses

| Offense | Description | Penalty Level |
|---------|-------------|---------------|
| **BABE Equivocation** | Producing 2+ blocks in same time slot | Level 2-4 |
| **GRANDPA Equivocation** | Signing 2+ votes in same round on different chains | Level 2-4 |
| **BEEFY Equivocation** | Similar to GRANDPA for the BEEFY protocol | Level 2-4 |
| **Invalid Finality Vote** | Voting to revert finalized blocks | Level 4 (100%) |

### Penalty Levels

- **Level 2**: Up to 1% slash
- **Level 3**: Up to 10% slash (signs of coordination)
- **Level 4**: Up to 100% slash (severe security risk)

Penalties scale with the number of offenders. A single validator's offense results in minimal slash; coordinated attacks result in exponentially higher penalties.

### BABE Equivocation

A validator must not produce two different blocks for the same slot.

**Detection**: Compare `slot` values. If `slot_new == slot_previous` and `block_hash_new != block_hash_previous`, refuse.

### GRANDPA Equivocation

A validator must not sign two different prevotes or precommits in the same GRANDPA round.

**Detection**: Compare `(round, vote_type)` tuples. If `round_new == round_previous` AND `vote_type_new == vote_type_previous` AND `target_new != target_previous`, refuse.

### State Required

The enclave must track separate state for each consensus layer:

**BABE State** (per validator):
| Field | Purpose |
|-------|---------|
| `last_babe_slot` | Highest slot for which a block was produced |
| `last_babe_hash` | Block hash at that slot |

**GRANDPA State** (per validator):
| Field | Purpose |
|-------|---------|
| `last_grandpa_round` | Highest GRANDPA round participated in |
| `last_prevote_target` | Target block of last prevote |
| `last_precommit_target` | Target block of last precommit |

---

## Tezos

Tezos uses a variant of BFT consensus with baking (block production) and endorsement (attestation).

### Slashable Offenses

| Offense | Penalty | Notes |
|---------|---------|-------|
| **Double Baking** | 640 XTZ or full deposit | Permanent for stakers |
| **Double Endorsement** | 50% of frozen deposit | More severe than baking |
| **Double Attestation** | Adaptive (Paris upgrade) | Scales with severity |

### Double Baking

A baker must not produce two different blocks at the same level.

**Detection**: Compare `level` values. If `level_new == level_previous` and `block_hash_new != block_hash_previous`, refuse.

### Double Endorsement / Attestation

A validator must not endorse two different blocks at the same level.

**Detection**: Compare `level` values. If `level_new == level_previous` and `endorsed_block_new != endorsed_block_previous`, refuse.

### Adaptive Slashing (Paris Upgrade)

Since the Paris protocol upgrade, Tezos uses adaptive slashing where penalties scale with the fraction of stake that committed the same offense. This is similar to Ethereum's correlation penalty.

### State Required

Per validator, the enclave must track:

| Field | Purpose |
|-------|---------|
| `last_baked_level` | Highest level at which a block was baked |
| `last_baked_hash` | Block hash at that level |
| `last_endorsed_level` | Highest level at which an endorsement was signed |
| `last_endorsed_hash` | Endorsed block hash at that level |

---

## Chains Without Slashing

Several major PoS chains do not implement slashing, using only reward-based incentives.

### Avalanche

- No slashing implemented
- Validators lose rewards for incorrect information
- Requires 80% uptime for full rewards
- Lower risk for operators

### Cardano (Ouroboros)

- No slashing implemented
- Security based on Nash equilibrium game theory
- Malicious actors simply don't receive rewards
- ADA remains liquid during staking

### NEAR Protocol

- No slashing currently implemented
- Penalties are reward-based only
- 12-hour epochs with per-epoch reward distribution

### Aptos

- No slashing currently implemented
- Slashing capability exists in protocol but not activated
- Future slashing subject to on-chain governance

### Solana (Proposed)

- No slashing implemented as of early 2026
- SIMD-0204 and SIMD-0212 propose slashing infrastructure
- Expected to add duplicate block production detection
- Parabolic slashing curve proposed (5% offense = 1% slash, 33% offense = 100% slash)

### Why Protection Still Matters

Even on chains without economic slashing:
- Double-signing degrades network health
- Future protocol upgrades may add slashing
- Operators may face reputational damage
- Some chains may add slashing via governance

Nklave can provide signing protection for these chains as a preventive measure.

---

## Implementation Pattern Groupings

Chains can be grouped by similar slashing models for implementation efficiency.

### Group 1: BFT Height/Round Model

**Chains**: Cosmos/CometBFT, Tezos

**Characteristics**:
- Track (height, round) or (level)
- Single signature check per height
- Simpler detection logic

**Shared Implementation Pattern**:
```
IF height_new <= height_previous:
    IF height_new == height_previous AND hash_new != hash_previous:
        REFUSE (double sign)
    ELSE:
        REFUSE (height regression)
```

### Group 2: Casper FFG Model

**Chains**: Ethereum

**Characteristics**:
- Track source/target epochs for attestations
- Complex surround vote detection required
- Requires historical data for weak subjectivity period

**Unique Requirements**:
- Min-span and max-span tracking algorithms
- EIP-3076 compatibility for migration

### Group 3: Hybrid Multi-Protocol Model

**Chains**: Polkadot/Substrate

**Characteristics**:
- Multiple consensus layers with separate state
- Block production and finality tracked independently
- Coordination detection increases penalties

**Unique Requirements**:
- Separate state machines for BABE and GRANDPA
- Round tracking for finality votes

### Group 4: No-Slashing Chains

**Chains**: Avalanche, Cardano, NEAR, Aptos, (current) Solana

**Characteristics**:
- No economic penalty for misbehavior
- Optional protection for network health
- May add slashing in future

---

## State Requirements Summary

| Chain | Height/Slot | Round | Source Epoch | Target Epoch | Block Hash | Surround Detection |
|-------|-------------|-------|--------------|--------------|------------|-------------------|
| **Ethereum** | Yes | No | Yes | Yes | Yes | Yes |
| **Cosmos** | Yes | Yes | No | No | Yes | No |
| **Polkadot** | Yes | Yes | No | No | Yes | No |
| **Tezos** | Yes | No | No | No | Yes | No |
| **Solana** (proposed) | Yes | No | No | No | Yes | No |

---

## References

- Ethereum: [EIP-3076](https://eips.ethereum.org/EIPS/eip-3076), [Casper FFG Paper](https://arxiv.org/abs/1710.09437)
- Cosmos: [CometBFT Documentation](https://docs.cometbft.com/)
- Polkadot: [Polkadot Wiki - Slashing](https://wiki.polkadot.network/docs/learn-offenses)
- Tezos: [Adaptive Slashing Documentation](https://octez.tezos.com/docs/active/adaptive_slashing.html)
