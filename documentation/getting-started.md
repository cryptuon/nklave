# Getting started

This guide gets you from zero to a validator client signing through nklave in about five minutes.

## Requirements

- A running validator client (Lighthouse, Teku, Prysm, or Lodestar)
- An existing signing key (keystore JSON, mnemonic, or HSM endpoint)
- One of: Docker, or a Linux/macOS host with Rust 1.75+

## Install

=== "Docker (recommended)"

    ```bash
    docker run -d --name nklave \
      -p 9000:9000 \
      -v nklave-data:/var/lib/nklave \
      -v $(pwd)/keystores:/keystores:ro \
      ghcr.io/cryptuon/nklave:latest \
      --keystore-dir /keystores \
      --data-dir /var/lib/nklave
    ```

=== "From source"

    ```bash
    git clone https://github.com/cryptuon/nklave.git
    cd nklave
    cargo build --release
    ./target/release/nklave --keystore-dir ./keystores --data-dir ./var/nklave
    ```

=== "Cargo install"

    ```bash
    cargo install nklave-core
    nklave --keystore-dir ~/keystores --data-dir ~/.nklave
    ```

## Point your validator at nklave

Nklave speaks the Web3Signer HTTP signing protocol. Update your validator client's signer URL to `http://localhost:9000`:

=== "Lighthouse"

    ```bash
    lighthouse vc \
      --beacon-nodes http://localhost:5052 \
      --validators-dir /opt/lighthouse/validators \
      --use-remote-signer http://localhost:9000
    ```

=== "Teku"

    ```yaml
    # teku-config.yaml
    validators-external-signer-url: http://localhost:9000
    validators-external-signer-public-keys: <pubkey-list>
    ```

=== "Prysm"

    ```bash
    validator --web3signer-url=http://localhost:9000
    ```

## Verify it's working

Send a test signing request:

```bash
curl -X POST http://localhost:9000/api/v1/eth2/sign/<pubkey> \
  -H "Content-Type: application/json" \
  -d '{
    "type": "ATTESTATION",
    "fork_info": {...},
    "signingRoot": "0x...",
    "attestation": {...}
  }'
```

Successful signatures land in the append-only log at `<data-dir>/log/`. Refusals are logged with the policy rule that blocked them.

## Next steps

- [Policy engine](./topics/policy-engine.md) — what rules nklave enforces and how to extend them
- [Slashing protection](./topics/slashing-protection.md) — DB design and migration from existing slashing protection databases
- [Deployment](./topics/deployment.md) — production hardening, key custody, HA
- [Monitoring](./topics/monitoring.md) — Prometheus metrics, alerts, audit log review
