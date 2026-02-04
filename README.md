# Nklave

Nklave is a signing security layer for proof-of-stake validators across multiple blockchain networks. It sits between a validator client and its signing keys, enforcing slashing-prevention rules inside a small, isolated signing component. The goal is simple: make slashable signing impossible by construction, even if the host or validator process is compromised.

**Supported chains**: Ethereum (primary), Cosmos/CometBFT, Polkadot, Tezos. See `docs/slashing-definitions.md` for chain-specific slashing conditions.

This repository contains product, architecture, and operational documentation. It is intentionally independent of any prior notes or drafts.

## What Nklave does

- Holds validator keys inside an isolated signing component.
- Accepts sign requests via a narrow API compatible with common validator clients.
- Verifies each request against slashing-prevention rules before signing.
- Emits deterministic refusal codes and audit trails for every decision.
- Preserves compatibility with existing custody, MPC, DVT, and uptime tooling.

## What Nklave does not do (v1)

- It does not replace validator clients.
- It does not replace custody/MPC systems.
- It does not guarantee physical attack resistance.
- It does not claim side-channel immunity.
- It does not provide global anti-slash across multiple independent enclaves without explicit coordination.

## Why this is different

Most stacks focus on who can sign. Nklave focuses on what should never be signed. It adds a policy-enforcing trust boundary that makes slashable signing logically impossible, not just operationally unlikely.

## High-level architecture

1. **Signing Enclave**
   - Owns validator keys.
   - Enforces slashing-prevention invariants.
   - Maintains minimal safety state.

2. **Host Proxy (Signer Interface)**
   - Runs next to the validator client.
   - Exposes a standard remote-signer interface.
   - Translates requests to the enclave protocol.

3. **State Integrity Layer**
   - Prevents rollback of signing state.
   - Uses append-only logs with cryptographic chaining.
   - Supports optional hardware binding later.

4. **Audit and Metrics**
   - Decision logs with reason codes.
   - Metrics for latency, refusal rates, and health.

## Documentation

- Product overview: `docs/product-overview.md`
- Architecture: `docs/architecture.md`
- Threat model: `docs/threat-model.md`
- Signing protocol: `docs/protocol.md`
- Slashing definitions: `docs/slashing-definitions.md`
- Slashing policy: `docs/slashing-policy.md`
- State integrity: `docs/state-integrity.md`
- Deployment guide: `docs/deployment.md`
- Operations and audit: `docs/operations.md`
- Roadmap: `docs/roadmap.md`

## Status

This repository is documentation-first. Implementation details are captured in the docs and are intended to guide engineering milestones and customer-facing guarantees.

## Contact

Open an issue or start a discussion to propose changes to the architecture or roadmap.
