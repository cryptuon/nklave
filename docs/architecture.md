# Architecture

This document describes the major components and data flow of Nklave.

## Components

1. **Signing Enclave**
   - Owns validator key material.
   - Implements slashing-prevention policy.
   - Maintains minimal safety state.
   - Produces signatures or refusal codes.

2. **Host Proxy (Signer Interface)**
   - Runs on the validator host.
   - Exposes a remote signer interface compatible with validator clients.
   - Normalizes requests and forwards them to the enclave.
   - Manages retries, metrics, and local configuration.

3. **State Integrity Layer**
   - Ensures that signing state cannot be rolled back.
   - Uses append-only logs and cryptographic chaining.
   - Supports optional hardware binding later.

4. **Audit and Metrics**
   - Records every signing decision with reason codes.
   - Exports metrics for latency, health, and refusal rates.
   - Designed for SIEM or log aggregation integration.

## Data flow

1. Validator client requests a signature through the standard remote signer interface.
2. Host proxy validates the request format and forwards it to the enclave.
3. Enclave checks slashing-prevention rules against its safety state.
4. Enclave returns one of:
   - `SIGN_OK` with signature and state commitment.
   - `REFUSE_*` with reason code and state commitment.
5. Host proxy returns the response to the validator client and logs the decision.

## Isolation boundary

The signing enclave is designed as a minimal trusted computing base. The host proxy and validator client are treated as untrusted. Compromise of the host should not enable unsafe signing.

## Multi-Chain Architecture

Nklave supports multiple blockchain protocols through a modular design:

### Chain-Specific Policy Modules

Each supported chain has a dedicated policy module within the enclave:

- **Ethereum module**: Implements Casper FFG rules (double proposal, double vote, surround vote).
- **Cosmos module**: Implements CometBFT rules (height/round double signing).
- **Polkadot module**: Implements BABE and GRANDPA equivocation rules.
- **Tezos module**: Implements baking and endorsement rules.

### Shared Infrastructure

All chains share:
- State integrity layer (append-only logs, hash chaining).
- Audit and metrics subsystem.
- Key management and storage.
- Host proxy communication protocol.

### Per-Chain State Isolation

Each validator's safety state is isolated by `(chain_id, validator_pubkey)`. A single enclave instance can manage validators across multiple chains without cross-contamination of state.

## Integration strategy

Nklave targets the remote signer interface exposed by major validator clients across supported chains. The host proxy presents a compatible interface and translates requests to the enclave protocol. See `deployment.md` for client-specific integration details.

## Deployment models

- **Single node**: validator client + proxy + enclave on one host.
- **Active/passive failover**: primary node runs signing; passive node mirrors state and can assume signing authority without rollback.
- **Fleet operations**: multiple validators behind one enclave instance, each with isolated safety state.
