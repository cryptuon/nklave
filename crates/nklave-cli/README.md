# nklave-cli

[![Crates.io](https://img.shields.io/crates/v/nklave-cli.svg)](https://crates.io/crates/nklave-cli)

Command-line tools for [Nklave](https://github.com/cryptuon/nklave) key management and operations.

## Installation

```bash
cargo install nklave-cli
```

## Commands

```bash
# Check server status
nklave status --server http://localhost:9000

# List validators
nklave validators list

# Import slashing protection data
nklave slashing import --file interchange.json

# Export slashing protection data
nklave slashing export --output interchange.json

# Generate a new keystore
nklave keys generate --output ./keys/validator.json
```

## Usage

```bash
# Connect to a remote server
nklave --server https://nklave.example.com status

# Use with authentication
nklave --token YOUR_API_TOKEN validators list
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NKLAVE_SERVER` | Server URL (default: `http://localhost:9000`) |
| `NKLAVE_TOKEN` | API bearer token |

## License

MIT License - [Cryptuon](https://cryptuon.com)
