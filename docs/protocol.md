# Signing Protocol

This document defines the logical interface between the host proxy and the signing enclave. The protocol is intentionally minimal and versioned.

## Goals

- Narrow, explicit message surface.
- Deterministic responses and error codes.
- Forward-compatible evolution.

## Versioning

Every request includes a `protocol_version`. The enclave must reject unknown major versions.

## Request schema (logical)

All requests include:

- `protocol_version`
- `request_id`
- `validator_pubkey`
- `signing_domain`
- `timestamp`

Signing data (exactly one required):

- `signing_root` (precomputed), or
- `signing_object` (full object for enclave to hash)

Context fields (required based on signing domain):

- `slot` (required for proposals and attestations)
- `source_epoch` (required for attestations)
- `target_epoch` (required for attestations)

Optional fields:

- `genesis_validators_root`
- `fork_version`
- `client_metadata`

The host proxy may send either a precomputed `signing_root` or a full `signing_object`. If a full object is provided, the enclave computes the root internally.

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

## Decision codes

Recommended codes:

- `SIGN_OK`
- `REFUSE_DOUBLE_PROPOSAL`
- `REFUSE_DOUBLE_VOTE`
- `REFUSE_SURROUND_VOTE`
- `REFUSE_STATE_ROLLBACK`
- `REFUSE_INVALID_REQUEST`
- `REFUSE_INTERNAL_ERROR`

## State commitment

Each response includes a commitment to the enclave's safety state. The commitment is used to detect rollback and to provide external auditability.

## Serialization

The wire format should be compact and deterministic (e.g., a binary schema with fixed ordering). The exact codec is an implementation choice but must be strictly versioned and fully specified.
