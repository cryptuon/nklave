# Signing Protocol

This document defines the logical interface between the host proxy and the signing enclave. The protocol is intentionally minimal and versioned.

## Goals

- Narrow, explicit message surface.
- Deterministic responses and error codes.
- Forward-compatible evolution.
- Chain-agnostic design with chain-specific extensions.

## Versioning

Every request includes a `protocol_version`. The enclave must reject unknown major versions.

## Request schema (logical)

All requests include:

- `protocol_version`
- `request_id`
- `chain_id` (identifies the blockchain protocol: `ethereum`, `cosmos`, `polkadot`, `tezos`)
- `validator_pubkey`
- `signing_domain`
- `timestamp`

Signing data (exactly one required):

- `signing_root` (precomputed), or
- `signing_object` (full object for enclave to hash)

### Ethereum Context Fields

- `slot` (required for proposals and attestations)
- `source_epoch` (required for attestations)
- `target_epoch` (required for attestations)

### Cosmos/CometBFT Context Fields

- `height` (required for all signing operations)
- `round` (required for all signing operations)
- `block_hash` (required for all signing operations)

### Polkadot Context Fields

- `slot` (required for BABE block production)
- `round` (required for GRANDPA votes)
- `vote_type` (required for GRANDPA: `prevote` or `precommit`)

### Tezos Context Fields

- `level` (required for all signing operations)

### Optional fields (all chains)

- `genesis_validators_root`
- `fork_version`
- `client_metadata`

The host proxy may send either a precomputed `signing_root` or a full `signing_object`. If a full object is provided, the enclave computes the root internally.

## Field Requirements by Signing Domain

### Ethereum

| Field | Block Proposal | Attestation | Voluntary Exit | Sync Committee |
|-------|---------------|-------------|----------------|----------------|
| `slot` | Required | Required | - | Required |
| `source_epoch` | - | Required | - | - |
| `target_epoch` | - | Required | - | - |
| `genesis_validators_root` | Recommended | Recommended | Required | Recommended |
| `fork_version` | Recommended | Recommended | Required | Recommended |
| `client_metadata` | Optional | Optional | Optional | Optional |

### Cosmos/CometBFT

| Field | Block Vote | Prevote | Precommit |
|-------|-----------|---------|-----------|
| `height` | Required | Required | Required |
| `round` | Required | Required | Required |
| `block_hash` | Required | Required | Required |

### Polkadot

| Field | BABE Block | GRANDPA Prevote | GRANDPA Precommit |
|-------|-----------|-----------------|-------------------|
| `slot` | Required | - | - |
| `round` | - | Required | Required |
| `vote_type` | - | Required | Required |
| `target_block` | - | Required | Required |

### Tezos

| Field | Baking | Endorsement |
|-------|--------|-------------|
| `level` | Required | Required |
| `block_hash` | Required | Required |

## Response schema (logical)

All responses include:

- `request_id`
- `decision_code`
- `decision_hash`
- `state_commitment`

On success:

- `signature`

On refusal:

- `refusal_reason`

## Decision Codes

The following codes are the authoritative list. All other documents reference this section.

### Success

| Code | Description |
|------|-------------|
| `SIGN_OK` | Request validated and signature produced |

### Slashing Prevention Refusals

| Code | Chain | Description |
|------|-------|-------------|
| `REFUSE_DOUBLE_PROPOSAL` | Ethereum, Polkadot | Block already signed for this slot |
| `REFUSE_DOUBLE_VOTE` | Ethereum | Attestation already signed for this target epoch |
| `REFUSE_SURROUND_VOTE` | Ethereum | Attestation would create surround vote condition |
| `REFUSE_HEIGHT_REUSE` | Cosmos, Tezos | Block already signed for this height/level |
| `REFUSE_GRANDPA_EQUIVOCATION` | Polkadot | GRANDPA vote already signed for this round |
| `REFUSE_BABE_EQUIVOCATION` | Polkadot | BABE block already produced for this slot |

### State Integrity Refusals

| Code | Description |
|------|-------------|
| `REFUSE_STATE_ROLLBACK` | Safety state continuity violated |

### Request Errors

| Code | Description |
|------|-------------|
| `REFUSE_INVALID_REQUEST` | Malformed request or missing required fields |
| `REFUSE_UNKNOWN_VALIDATOR` | Validator pubkey not managed by this enclave |
| `REFUSE_UNSUPPORTED_DOMAIN` | Signing domain not enabled |
| `REFUSE_UNSUPPORTED_CHAIN` | Chain ID not supported by this enclave |

### Internal Errors

| Code | Description |
|------|-------------|
| `REFUSE_INTERNAL_ERROR` | Enclave encountered unexpected error |

## State commitment

Each response includes a commitment to the enclave's safety state. The commitment is used to detect rollback and to provide external auditability.

## Serialization

The wire format should be compact and deterministic (e.g., a binary schema with fixed ordering). The exact codec is an implementation choice but must be strictly versioned and fully specified.
