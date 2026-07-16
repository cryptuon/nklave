[![CI](https://github.com/cryptuon/nklave/actions/workflows/ci.yml/badge.svg)](https://github.com/cryptuon/nklave/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docs](https://img.shields.io/badge/docs-cryptuon.com-blue)](https://docs.cryptuon.com/nklave)
[![Crates.io](https://img.shields.io/crates/v/nklave-core.svg)](https://crates.io/crates/nklave-core)

# nklave

**[🌐 Site](https://nklave.cryptuon.com/) · [📚 Docs](https://docs.cryptuon.com/nklave/) · [📦 crates.io package](https://crates.io/crates/nklave-core) · [🔬 Cryptuon Research](https://github.com/cryptuon)**

**Policy-enforcing trust boundary for PoS validators — the slashing firewall in front of your signing keys.**

Nklave is a signing security layer that makes slashable signing impossible by construction. It sits between validator clients and signing keys, enforcing EIP-3076 slashing-prevention rules and configurable policies before any signature is produced — so a compromised or buggy validator client cannot produce a slashable signature, even when the host is fully compromised.

## Why this matters in 2026: restaking multiplies your slashing surface

For most of proof-of-stake's history, a validator key faced exactly one slashing surface: the consensus layer of the chain it validated. Restaking changed that. As **EigenLayer-style restaking and Actively Validated Services (AVS)** go mainstream, the *same* staked capital and — increasingly — the *same* keys are opted into multiple independent slashing regimes at once. Each AVS defines its own slashing conditions. Each one is a new way to lose stake, governed by code you did not write.

That shift makes the boundary between "what asked for a signature" and "what actually gets signed" the single most valuable control point a staking operation has. A policy firewall that sits in front of the signing keys — refusing anything that violates a rule *before* the key is touched, and logging every decision — stops being a nice-to-have and becomes critical infrastructure.

nklave is that firewall. Today it enforces the consensus-layer slashing rules that account for the overwhelming majority of real-world slashing incidents (double proposals, double votes, surround votes on Ethereum; height/round double-signing on CometBFT), with EIP-3076 interchange import/export for migration. Its policy layer evaluates every request to an explicit allow-or-refuse decision *before* the key is reached — exactly the shape you need as restaking pushes more, and more heterogeneous, signing constraints down onto the same keys.

> **Honest scope:** nklave enforces *protocol-level* slashing prevention (EIP-3076 and equivalents). AVS-specific slashing conditions are defined per-service and are not built in — but the policy engine is designed so operators can express additional guardrails as first-class policies. See [ROADMAP.md](ROADMAP.md) for where restaking-aware policy work is headed.

```
┌─────────────────┐         ┌─────────────────────────────────┐         ┌─────────────────┐
│ Validator Client│         │            Nklave               │         │  Signing Keys   │
│                 │  Sign   │  ┌───────────────────────────┐  │         │                 │
│  - Lighthouse   │ ──────▶ │  │     Policy Engine         │  │ ──────▶ │  - BLS (ETH2)   │
│  - Teku         │         │  │  ┌─────────────────────┐  │  │         │  - Ed25519      │
│  - Prysm        │ ◀────── │  │  │ Slashing Protection │  │  │ ◀────── │    (Cosmos)     │
│  - Lodestar     │  Sig/   │  │  └─────────────────────┘  │  │  Sign   │                 │
│                 │  Refuse │  └───────────────────────────┘  │         │                 │
└─────────────────┘         └─────────────────────────────────┘         └─────────────────┘
                                         │
                                         ▼
                            ┌───────────────────────┐
                            │   Append-Only Log     │
                            │   + Checkpoints       │
                            └───────────────────────┘
```

## Quick Start

### Docker

```bash
docker run -p 9000:9000 ghcr.io/cryptuon/nklave
```

### From Source

```bash
cargo install nklave-server
nklave --keys-dir ./keys --data-dir ./data
```

### With Docker Compose

```bash
git clone https://github.com/cryptuon/nklave
cd nklave
docker compose -f docker/docker-compose.yml up
```

## Features

- **Enforce before the key is touched** - The policy chain evaluates every request first; a refused request never reaches the keystore or HSM. Slashable signing is impossible by construction, even if the host is compromised.
- **Web3Signer Compatible** - Drop-in replacement for existing validator setups
- **Slashing Protection** - Enforces EIP-3076 and custom rules at the signing layer
- **First-class policy engine** - Slashing rules live in a dedicated policy module (`nklave-core::policy`) that returns an explicit `Allow`/`Refuse(code)` decision per request — a real enforcement layer, not a config afterthought, and the extension point that matters as restaking pushes more signing constraints onto the same keys
- **Multi-Chain** - Ethereum (BLS), Cosmos/CometBFT (Ed25519), extensible to others
- **Audit Trail** - Append-only decision logs with cryptographic chaining
- **State Integrity** - Rollback-resistant checkpoints prevent state manipulation
- **Embedded UI** - Vue.js dashboard for monitoring and operations
- **High Availability** - Primary/passive replication with automatic failover

## Crates

| Crate | Description |
|-------|-------------|
| [`nklave-core`](crates/nklave-core) | Core signing logic, BLS/Ed25519 keys, slashing protection rules |
| [`nklave-api`](crates/nklave-api) | Web3Signer-compatible HTTP API with embedded UI |
| [`nklave-storage`](crates/nklave-storage) | Append-only logs, checkpoints, EIP-3076 interchange |
| [`nklave-server`](crates/nklave-server) | Main server binary with TLS, metrics, configuration |
| [`nklave-cosmos`](crates/nklave-cosmos) | Cosmos/CometBFT remote signer protocol |
| [`nklave-cli`](crates/nklave-cli) | CLI tools for key management and operations |

## API Endpoints

```bash
# Health checks
GET  /livez                          # Liveness probe
GET  /readyz                         # Readiness probe
GET  /health                         # Detailed health status

# Web3Signer API
GET  /api/v1/eth2/publicKeys         # List validator public keys
POST /api/v1/eth2/sign/:pubkey       # Sign a message

# Admin
POST /reload                         # Reload keys from disk
GET  /status                         # Server status
POST /admin/checkpoint               # Force checkpoint
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NKLAVE_LISTEN_ADDR` | `127.0.0.1:9000` | Server listen address |
| `NKLAVE_KEYS_DIR` | `./keys` | Validator keystores directory |
| `NKLAVE_DATA_DIR` | `./data` | State and logs directory |
| `NKLAVE_KEYSTORE_PASSWORD` | - | Password for encrypted keystores |
| `NKLAVE_API_TOKENS` | - | Comma-separated bearer tokens |
| `NKLAVE_METRICS_ADDR` | - | Prometheus metrics endpoint |
| `RUST_LOG` | `nklave=info` | Log level |

## Documentation

Full documentation at [docs.cryptuon.com/nklave](https://docs.cryptuon.com/nklave):

- [Architecture](https://docs.cryptuon.com/nklave/architecture)
- [Deployment Guide](https://docs.cryptuon.com/nklave/deployment)
- [Threat Model](https://docs.cryptuon.com/nklave/threat-model)
- [Slashing Policy](https://docs.cryptuon.com/nklave/slashing-policy)
- [API Reference](https://docs.cryptuon.com/nklave/api)

See [ROADMAP.md](ROADMAP.md) for the project vision, milestones, and the cheapest path to a production deployment.

## Contributing

Contributions are welcome. Please open an issue to discuss significant changes before submitting a PR.

```bash
# Run tests
cargo test --all

# Run with coverage
cargo llvm-cov --all-features

# Run benchmarks
cargo bench -p nklave-core
```

## License

MIT License - [Cryptuon Research](https://www.cryptuon.com) · [contact@cryptuon.com](mailto:contact@cryptuon.com)

---

## Part of Cryptuon Research

`nklave` is one of [20 open-source blockchain-infrastructure projects](https://www.cryptuon.com/projects) from **[Cryptuon Research](https://www.cryptuon.com)** — blockchain theory, shipped as protocols.

**Related projects:** [Tesseract](https://tesseract.cryptuon.com/) · [Switchboard](https://switchboard.cryptuon.com/) · [StreamSync](https://streamsync.cryptuon.com/)

Docs: [docs.cryptuon.com/nklave](https://docs.cryptuon.com/nklave/) · Contact: [contact@cryptuon.com](mailto:contact@cryptuon.com)
