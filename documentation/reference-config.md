# Configuration reference

`nklave.toml` is the full configuration file. Defaults are conservative — most installations only need to set `signing-keys.backend` and the policy parameters.

## Top-level keys

```toml
listen = "127.0.0.1:9000"
data_dir = "/var/lib/nklave"
log_format = "json"           # json | text
log_level = "info"            # trace | debug | info | warn | error
```

## `[slashing-protection]`

```toml
[slashing-protection]
backend = "rocksdb"           # rocksdb | postgres
path = "/var/lib/nklave/slashing"   # if backend = rocksdb
url = "postgres://..."         # if backend = postgres
```

## `[signing-keys]`

```toml
[signing-keys]
backend = "local-keystore"   # local-keystore | yubihsm | aws-cloudhsm | gcp-kms

# local-keystore
keystore_dir = "/etc/nklave/keystores"
password_file = "/etc/nklave/keystore-passwd"

# yubihsm
connector_url = "http://localhost:12345"
auth_key_id = 1
auth_key_password_file = "/etc/nklave/yubihsm.passwd"

# aws-cloudhsm
cluster_id = "cluster-abc"
iam_role = "arn:aws:iam::123:role/nklave"
```

## `[log]`

```toml
[log]
checkpoint_interval_seconds = 60
operator_key_path = "/etc/nklave/operator.key"
retention_days = 365
max_file_size_mb = 1024
```

## `[policies.*]`

Each policy has its own subtable:

```toml
[policies.slashing-protection-attestation]
enabled = true

[policies.slashing-protection-block]
enabled = true

[policies.fork-allowlist]
enabled = true
allowed_forks = ["0x05000000", "0x06000000"]

[policies.rate-limit]
enabled = true
max_signs_per_hour = 240
```

Custom policies (Rust) are registered programmatically and don't appear here.

## `[metrics]`

```toml
[metrics]
listen = "127.0.0.1:9090"
path = "/metrics"
```

## Reload behavior

`SIGHUP` reloads `nklave.toml`. Policy parameters can change live; the slashing-protection backend and the signing-keys backend require a full restart.
