# CLI reference

The `nklave` binary exposes both the signing server and a set of management commands.

## Top-level commands

```
nklave serve              # start the signing server (default)
nklave import             # import EIP-3076 slashing-protection JSON
nklave export             # export slashing-protection DB to EIP-3076
nklave log                # query / verify the append-only log
nklave key                # list / inspect loaded keys
nklave policy             # list active policies and their config
nklave doctor             # check configuration and connectivity
```

## `nklave serve`

```
nklave serve [OPTIONS]

  --config <PATH>        Path to nklave.toml (default ./nklave.toml)
  --listen <ADDR>        Override [listen]
  --data-dir <PATH>      Override [data_dir]
  --keystore-dir <PATH>  Override [signing-keys.keystore_dir]
  --log-level <LEVEL>    Override [log_level]
```

## `nklave import`

```
nklave import --interchange-file <PATH> [OPTIONS]

  --interchange-file <PATH>   EIP-3076 JSON file from your previous slashing-protection DB
  --overwrite                 Replace existing entries (default: refuse if any pubkey already present)
```

## `nklave log`

```
nklave log query [OPTIONS]

  --validator <PUBKEY>        Filter by validator pubkey
  --decision <DECISION>       Filter by allow | refuse
  --policy <NAME>             Filter by refusing policy name
  --since <RFC3339>           Inclusive lower time bound
  --until <RFC3339>           Inclusive upper time bound
  --format <FORMAT>           json (default) | text | csv

nklave log verify [OPTIONS]
  --from <CHECKPOINT>         Start checkpoint (default 0)
  --to <CHECKPOINT>           End checkpoint (default latest)
```

Exit code from `verify` is 0 if the checkpoint chain is intact, non-zero otherwise.

## `nklave doctor`

Runs a battery of preflight checks:

- nklave.toml syntax
- Slashing-protection DB reachable + schema current
- Signing-keys backend reachable + auth correct
- Operator key for checkpoint signing loaded
- Listening port available
- File-system permissions on data_dir

Output is structured for CI:

```
$ nklave doctor
✓ config valid
✓ slashing-protection rocksdb reachable
✗ yubihsm: connector returned 503 (is yubihsm-connector running?)
✓ operator key loaded
✓ port 9000 available

1 problem found
```

Non-zero exit if any check fails.
