# Deployment Guide

This guide describes typical deployment patterns and operational considerations for Nklave.

## Prerequisites

- Ethereum validator client with remote signer support.
- Dedicated host (VM or bare metal) for validator + Nklave proxy.
- Secure key ceremony process for loading validator keys into the enclave.

## Deployment patterns

### Single-node deployment

- Validator client, host proxy, and enclave on the same host.
- Suitable for small operators or early pilots.

### Active/passive failover

- Primary node handles signing.
- Passive node mirrors state and can take over if the primary fails.
- Requires strict state integrity to avoid rollback.

### Fleet deployment

- One enclave instance manages multiple validators.
- Each validator has isolated safety state.
- Useful for large operators with centralized signing.

## Integration with validator clients

Nklave targets the remote signer interface used by major Ethereum clients. The host proxy exposes a compatible API endpoint. Specific client adapters are documented in the integrations guide when available.

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
