# Deployment Guide

This guide describes typical deployment patterns and operational considerations for Nklave.

## Prerequisites

- Validator client with remote signer support (Ethereum, Cosmos, Polkadot, or Tezos).
- Dedicated host (VM or bare metal) for validator + Nklave proxy.
- Completed key ceremony (see below).

## Key Ceremony

Before deployment, validator keys must be securely loaded into the enclave.

### Key Generation

- Generate validator keys in an air-gapped environment.
- Use cryptographically secure entropy sources.
- Record key identifiers (public keys) for audit trail.
- For Ethereum, follow EIP-2335 keystore format.

### Loading Keys into Enclave

- Transfer keys via encrypted channel or secure physical media.
- Verify key integrity using checksums or signatures.
- Initialize safety state for each validator:
  - Set all watermarks to 0 (or import from previous slashing protection database).
  - For Ethereum, support EIP-3076 import format.
- Delete key material from transfer media after loading.

### Verification

- Confirm enclave holds expected public keys (query enclave for managed keys).
- Verify initial state commitment is recorded in the audit log.
- Optionally test signing with a non-slashable test request on a testnet.

## Deployment patterns

### Single-node deployment

- Validator client, host proxy, and enclave on the same host.
- Suitable for small operators or early pilots.

### Active/passive failover

- Primary node handles signing.
- Passive node mirrors state via continuous log replication.
- State synchronization mechanism:
  - Primary streams append-only log entries to passive in real-time.
  - Passive verifies hash chain on receipt of each entry.
  - Passive maintains its own state checkpoint for fast recovery.
- Failover procedure:
  1. Detect primary failure (heartbeat timeout or explicit signal).
  2. Verify passive state is ahead of or equal to last known primary state.
  3. Passive assumes signing authority.
  4. Never allow failback without verifying monotonicity.
- See `state-integrity.md` for hash chain verification details.

### Fleet deployment

- One enclave instance manages multiple validators.
- Single Host Proxy serves all validators:
  - Proxy routes requests to enclave based on `validator_pubkey`.
  - Each validator has isolated safety state within the enclave.
  - No cross-validator state leakage.
- Useful for large operators with centralized signing infrastructure.
- Consider load balancing at the validator client layer, not the proxy layer.

## Integration with validator clients

Nklave targets the remote signer interface used by major validator clients across supported chains. The host proxy exposes a compatible API endpoint. Specific client adapter documentation will be added as integrations are completed.

## Configuration

Typical configuration includes:

- Validator public keys managed by the enclave.
- Allowed signing domains and fork context.
- Logging and metrics endpoints.
- State log storage location and retention policy.

## Upgrade and rollback strategy

- Enclave upgrades must preserve state continuity.
- Host upgrades should be staged in a passive node first.
- Any failure to verify state continuity must result in signing refusal.

## Security hygiene

- Restrict administrative access to the host.
- Use read-only filesystems where possible.
- Monitor refusal codes and anomaly metrics for early warning.
