# Deployment

This page covers production deployment patterns for nklave: single-host, HA, and key-custody integration.

## Single-host

The simplest deployment: nklave runs on the same box as the validator client, listening on `127.0.0.1:9000`.

```bash
# /etc/systemd/system/nklave.service
[Unit]
Description=nklave signing security layer
After=network.target

[Service]
Type=simple
User=nklave
ExecStart=/usr/local/bin/nklave \
    --keystore-dir /etc/nklave/keystores \
    --data-dir /var/lib/nklave \
    --listen 127.0.0.1:9000 \
    --config /etc/nklave/nklave.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Pros: zero network latency between validator and signer. Cons: shared blast radius — if the host is compromised, both validator client and signing keys are exposed.

## HA: leader/follower

For high-uptime requirements, run two nklave instances against a shared Postgres slashing-protection DB:

```
Validator client ──▶ HAProxy ──▶ nklave-1 ──▶ Postgres ◀── nklave-2 ◀── (standby)
```

HAProxy round-robins or always-prefers-leader. Postgres serializes slashing-protection updates with `SELECT … FOR UPDATE`, so the same attestation can never be signed twice across the cluster.

```toml
# /etc/nklave/nklave.toml on both hosts
[slashing-protection]
backend = "postgres"
url = "postgres://nklave:***@db.cluster.internal/nklave?sslmode=verify-full"
```

## Key custody

In production, signing keys should live in dedicated hardware. Nklave offloads key operations to:

=== "YubiHSM 2"

    ```toml
    [signing-keys]
    backend = "yubihsm"
    connector_url = "http://localhost:12345"
    auth_key_id = 1
    auth_key_password_file = "/etc/nklave/yubihsm.passwd"
    ```

=== "AWS CloudHSM"

    ```toml
    [signing-keys]
    backend = "aws-cloudhsm"
    cluster_id = "cluster-abc"
    iam_role = "arn:aws:iam::123:role/nklave"
    ```

=== "Local keystore (dev)"

    ```toml
    [signing-keys]
    backend = "local-keystore"
    keystore_dir = "/etc/nklave/keystores"
    password_file = "/etc/nklave/keystore-passwd"
    ```

The policy engine evaluates the request before the HSM is consulted. Refused requests never reach the HSM at all.

## Network exposure

`nklave` listens on plain HTTP by default — terminate TLS at HAProxy / nginx in front, mTLS-authenticated to the validator client. Never expose port 9000 to the public internet.
