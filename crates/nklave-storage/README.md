# nklave-storage

[![Crates.io](https://img.shields.io/crates/v/nklave-storage.svg)](https://crates.io/crates/nklave-storage)
[![Docs.rs](https://docs.rs/nklave-storage/badge.svg)](https://docs.rs/nklave-storage)

Persistence layer for [Nklave](https://github.com/cryptuon/nklave): append-only decision logs, checkpoints, and EIP-3076 interchange.

## Features

- **Decision Logs** - Append-only audit trail with cryptographic chaining
- **Checkpoints** - Periodic state snapshots for fast recovery
- **EIP-3076** - Slashing protection interchange format support
- **Log Rotation** - Automatic rotation with configurable limits
- **Encrypted Storage** - Optional AES-256-CTR encryption for sensitive data

## Usage

```rust
use nklave_storage::{DecisionLog, Checkpoint};

// Open or create a decision log
let log = DecisionLog::open("./data/decisions.log")?;

// Append a decision record
log.append(&decision_record)?;

// Create a checkpoint
let checkpoint = Checkpoint::new(&integrity, validators);
checkpoint.save("./data/checkpoint.json")?;
```

## License

MIT License - [Cryptuon](https://cryptuon.com)
