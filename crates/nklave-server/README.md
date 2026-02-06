# nklave-server

[![Crates.io](https://img.shields.io/crates/v/nklave-server.svg)](https://crates.io/crates/nklave-server)

Main server binary for [Nklave](https://github.com/cryptuon/nklave) with TLS, metrics, and configuration.

## Installation

```bash
cargo install nklave-server
```

## Usage

```bash
# Start with default configuration
nklave --keys-dir ./keys --data-dir ./data

# With environment variables
NKLAVE_LISTEN_ADDR=0.0.0.0:9000 \
NKLAVE_KEYSTORE_PASSWORD=secret \
nklave
```

## Binaries

- `nklave` - Main server binary
- `generate-test-keys` - Generate test validator keystores
- `slashing-protection` - EIP-3076 import/export utility

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NKLAVE_LISTEN_ADDR` | `127.0.0.1:9000` | Server listen address |
| `NKLAVE_KEYS_DIR` | `./keys` | Validator keystores directory |
| `NKLAVE_DATA_DIR` | `./data` | State and logs directory |
| `NKLAVE_KEYSTORE_PASSWORD` | - | Keystore decryption password |
| `NKLAVE_API_TOKENS` | - | Comma-separated bearer tokens |
| `NKLAVE_METRICS_ADDR` | - | Prometheus metrics endpoint |
| `NKLAVE_CHECKPOINT_INTERVAL` | `300` | Checkpoint interval in seconds |

## License

MIT License - [Cryptuon](https://cryptuon.com)
