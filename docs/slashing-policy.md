# Slashing Policy

This document specifies the slashing-prevention rules enforced by the signing enclave.

## Principles

- The enclave must be the final authority on whether a signature is produced.
- Rules are deterministic and enforce protocol safety.
- Safety state is minimal and append-only.

## Block proposals

**Rule: No double proposal.**

- If a block has already been signed for a given slot, the enclave must refuse any other proposal for that same slot.

State required:

- `last_signed_block_slot`
- Optionally a recent map of `slot -> signing_root` for audit.

## Attestations

**Rule: No double vote.**

- Do not sign two attestations for the same target epoch.

**Rule: No surround vote.**

- Do not sign an attestation whose (source, target) surrounds or is surrounded by a previously signed attestation.

State required (per validator):

- Highest signed source epoch.
- Highest signed target epoch.
- A compressed record of recent (source, target) pairs sufficient to detect surround votes.

## Optional extensions

Future phases may add enforcement for:

- Voluntary exits.
- Sync committee messages.
- Builder/proposer separation constraints.

## Reason codes

Each refusal must map to a deterministic reason code and human-readable message for auditability.
