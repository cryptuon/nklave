# Slashing protection

Slashing protection is the core reason nklave exists. This page covers the database design, the rules it enforces, and how to migrate from your validator client's built-in slashing protection.

## The three slashable offenses

Ethereum proof-of-stake (and by extension every Tendermint and Solana variant) makes three signing actions slashable:

1. **Double-vote.** Signing two attestations with the same `target_epoch` for the same validator.
2. **Surround-vote.** Signing an attestation whose `source` and `target` epochs surround a previously-signed attestation's source/target pair.
3. **Double-block-proposal.** Signing two beacon-block proposals in the same `slot`.

Nklave's policy engine refuses each of these before the signing key is ever consulted.

## Database design

The slashing-protection DB is a tamper-evident embedded store backed by either:

- **RocksDB** (default) — best for single-host operation
- **Postgres** — for multi-node HA setups behind a leader/follower

Per validator pubkey, nklave tracks:

| Column | Type | Purpose |
|---|---|---|
| `attestation_min_source_epoch` | u64 | The lowest source epoch ever signed |
| `attestation_min_target_epoch` | u64 | The lowest target epoch ever signed |
| `attestation_max_source_epoch` | u64 | The highest source epoch ever signed |
| `attestation_max_target_epoch` | u64 | The highest target epoch ever signed |
| `proposal_min_slot` | u64 | The lowest slot ever proposed |
| `proposal_max_slot` | u64 | The highest slot ever proposed |
| `log_offset` | u64 | Position of the matching entry in the append-only log |

For each signing request, nklave evaluates the proposed signature against these bounds in a single SQL `SELECT` (or RocksDB merge), refuses if the rules would be violated, and otherwise commits an updated row + appends to the log atomically.

## Migration from existing slashing protection

Most validator clients support the [EIP-3076 interchange format](https://eips.ethereum.org/EIPS/eip-3076) for exporting their slashing-protection DB. Nklave imports it directly:

```bash
nklave import \
  --interchange-file ./slashing-protection.json \
  --keystore-dir ./keystores
```

The import sets the four attestation bound columns and the two proposal bound columns per pubkey to whatever your previous client recorded, so nklave will refuse to sign any duplicate from before the switch.

## Rule extensions

The default rules implement the protocol minimums. Policy-engine extensions can layer additional constraints:

- **Time-locked withdrawal authorization** — refuse withdrawal-credential signatures unless a separate 24-hour timer has elapsed since they were last requested.
- **Cap signatures per hour** — refuse signing requests if the validator's rate exceeds N per hour (defense against runaway clients).
- **Allowlisted fork versions** — refuse signing on any fork version not in the allowlist (defense against accidental testnet signing).

See [Policy engine](./policy-engine.md) for how to write your own.
