# Slashing Policy

This document specifies the slashing-prevention rules enforced by the signing enclave. For comprehensive definitions of slashable offenses across all supported chains, see `slashing-definitions.md`.

## Principles

- The enclave must be the final authority on whether a signature is produced.
- Rules are deterministic and enforce protocol safety.
- Safety state is minimal and append-only.
- Each chain has specific rules; the enclave applies the appropriate policy based on `chain_id`.

---

## Ethereum Policy

### Block Proposals

**Rule: No double proposal.**

If a block has already been signed for a given slot, the enclave must refuse any other proposal for that same slot.

State required:
- `last_signed_block_slot`
- Optionally a recent map of `slot -> signing_root` for audit.

### Attestations

**Rule: No double vote.**

Do not sign two attestations for the same target epoch.

**Rule: No surround vote.**

Do not sign an attestation whose (source, target) surrounds or is surrounded by a previously signed attestation.

State required (per validator):
- Highest signed source epoch.
- Highest signed target epoch.
- A compressed record of recent (source, target) pairs sufficient to detect surround votes.

---

## Cosmos / CometBFT Policy

### Block Signing

**Rule: No double signing at same height and round.**

If a block has already been signed for a given (height, round) pair, the enclave must refuse any other block for that same pair.

**Rule: Monotonic height progression.**

The enclave should refuse to sign blocks at heights lower than previously signed, except for different rounds at the same height.

State required (per validator):
- `last_signed_height`
- `last_signed_round`
- `last_signed_hash`

---

## Polkadot Policy

### BABE Block Production

**Rule: No BABE equivocation.**

Do not produce two different blocks for the same slot.

State required:
- `last_babe_slot`
- `last_babe_hash`

### GRANDPA Finality Votes

**Rule: No GRANDPA equivocation.**

Do not sign two different prevotes or precommits for the same round.

State required:
- `last_grandpa_round`
- `last_prevote_target`
- `last_precommit_target`

---

## Tezos Policy

### Baking

**Rule: No double baking.**

Do not bake (produce) two different blocks at the same level.

State required:
- `last_baked_level`
- `last_baked_hash`

### Endorsement

**Rule: No double endorsement.**

Do not endorse two different blocks at the same level.

State required:
- `last_endorsed_level`
- `last_endorsed_hash`

---

## Optional Extensions

Future phases may add enforcement for:

- Voluntary exits (Ethereum).
- Sync committee messages (Ethereum).
- Builder/proposer separation constraints.
- BEEFY protocol (Polkadot).
- IBC-related signing (Cosmos).

---

## Reason Codes

Each refusal must map to a deterministic reason code and human-readable message for auditability. See `protocol.md` for the authoritative list of decision codes.
