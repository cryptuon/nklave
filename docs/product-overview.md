# Product Overview

## Problem

Proof-of-stake validators across multiple blockchain networks face two distinct categories of risk:

1. **Key security risk**: preventing unauthorized access to signing keys.
2. **Slashing risk**: preventing the validator from signing messages that violate protocol rules.

Most existing systems focus on the first category. They control who can sign (custody, MPC, HSMs) but do not reliably prevent the validator from signing slashable messages if the software requests it.

This problem exists across all major PoS chains:
- **Ethereum**: Double proposals, double votes, and surround votes can result in loss of 1 ETH or more.
- **Cosmos**: Double signing results in 5% stake loss and permanent "tombstoning."
- **Polkadot**: BABE and GRANDPA equivocation can result in up to 100% slash.
- **Tezos**: Double baking and endorsement incur significant penalties.

See `slashing-definitions.md` for comprehensive details on each chain's slashing conditions.

## Product

Nklave is a signing security layer that enforces slashing-prevention rules inside a minimal, isolated signing component. It interposes on every signing request and either produces a signature or rejects the request with a deterministic reason code.

This provides a new capability: **provable prevention of slashable signing**, even when the host OS, validator client, or surrounding infrastructure is compromised.

## Supported Chains

Nklave is designed to support multiple blockchain protocols:

| Chain | Status | Slashing Model |
|-------|--------|----------------|
| **Ethereum** | Primary target | Casper FFG (slot/epoch based) |
| **Cosmos/CometBFT** | Planned | BFT (height/round based) |
| **Polkadot** | Planned | Hybrid (BABE + GRANDPA) |
| **Tezos** | Planned | BFT (level based) |

The architecture is chain-agnostic, with chain-specific policy modules. See `roadmap.md` for rollout schedule.

## Value

- **Safety by construction**: the signing boundary refuses unsafe requests according to each chain's protocol rules.
- **Multi-chain support**: single architecture supports Ethereum, Cosmos, Polkadot, Tezos, and future chains.
- **Compatibility**: integrates with existing custody/MPC, DVT, and validator clients across all supported chains.
- **Operational simplicity**: software-only deployment on standard servers.
- **Auditability**: deterministic decisions and append-only audit trails with chain-specific reason codes.

## Target users

- Institutional staking providers.
- Exchanges and custodians running validators.
- Large validator operators with compliance obligations.

## What stays the same

- Operators continue to use their preferred validator clients.
- Custody/MPC and approval flows remain upstream.
- Monitoring and uptime tooling remain in place.
- DVT networks continue to improve availability.

Nklave adds a trust boundary that enforces protocol safety without replacing any of these systems.
