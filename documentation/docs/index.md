# nklave

**Policy-enforcing trust boundary for PoS validators.**

Nklave is a signing security layer that makes slashable signing impossible by construction. It sits between validator clients (Lighthouse, Teku, Prysm, Lodestar) and signing keys, enforcing slashing-prevention rules before any signature is produced — backed by an append-only signed-message log with cryptographic checkpoints.

## What problem does nklave solve?

Stake-slashing incidents on Ethereum, Cosmos, and Solana have repeatedly cost validators six- and seven-figure penalties. Most of them weren't malicious — they were operational mistakes: double-signing during a key rotation, accidental restarts loading old EthDB state, two clients pointing at the same key. Nklave makes the entire class of mistakes impossible: even if your validator client tries to double-sign, the request is refused at the trust boundary.

## Architecture at a glance

```
Validator client ─┐                                       ┌─ Signing key
                  │   ┌──────────────────────────────┐    │
                  ├──▶│  Nklave policy engine        │───▶│
                  │   │  ┌────────────────────────┐  │    │
                  │   │  │ Slashing protection DB │  │    │
                  │   │  └────────────────────────┘  │    │
                  │   └──────────────────────────────┘    │
                  └─────────────────  Sign / refuse  ─────┘
                                  │
                                  ▼
                       ┌──────────────────────┐
                       │  Append-only log     │
                       │  + Merkle checkpoints│
                       └──────────────────────┘
```

## Why nklave

- **Slashing-proof by construction.** The policy engine refuses any signature that would trigger a slashing condition (double-vote, surround-vote, double-block-proposal), evaluated in <500µs.
- **Supports every major signing scheme.** BLS12-381 for Ethereum 2, Ed25519 for Cosmos/Solana, secp256k1 for legacy validators. One trust boundary, all networks.
- **Drop-in for existing clients.** Speaks Web3Signer's HTTP signing protocol. Lighthouse, Teku, Prysm, and Lodestar all work out of the box.
- **Append-only auditable log.** Every signature request and outcome lands in a tamper-evident log with cryptographic checkpoints — investigate after the fact.
- **Hardware-key ready.** Plug HSMs (Ledger, YubiHSM, AWS CloudHSM) for the key custody layer; nklave still enforces policy in front.

## Start here

- [Getting started](./getting-started.md) — install nklave and route your first validator through it
- [Policy engine](./topics/policy-engine.md) — how policies are evaluated
- [Slashing protection](./topics/slashing-protection.md) — the database design
- [Deployment](./topics/deployment.md) — running nklave in production
