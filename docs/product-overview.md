# Product Overview

## Problem

Ethereum validators face two distinct categories of risk:

1. **Key security risk**: preventing unauthorized access to signing keys.
2. **Slashing risk**: preventing the validator from signing messages that violate protocol rules.

Most existing systems focus on the first category. They control who can sign (custody, MPC, HSMs) but do not reliably prevent the validator from signing slashable messages if the software requests it.

## Product

Nklave is a signing security layer that enforces slashing-prevention rules inside a minimal, isolated signing component. It interposes on every signing request and either produces a signature or rejects the request with a deterministic reason code.

This provides a new capability: **provable prevention of slashable signing**, even when the host OS, validator client, or surrounding infrastructure is compromised.

## Value

- **Safety by construction**: the signing boundary refuses unsafe requests.
- **Compatibility**: integrates with existing custody/MPC, DVT, and validator clients.
- **Operational simplicity**: software-only deployment on standard servers.
- **Auditability**: deterministic decisions and append-only audit trails.

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
