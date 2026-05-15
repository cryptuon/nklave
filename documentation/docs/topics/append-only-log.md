# Append-only log

Every signing request, evaluation, and outcome lands in nklave's append-only log. The log is tamper-evident: each batch of entries is summarized into a Merkle root and periodically checkpointed.

## Format

The log is a sequence of newline-delimited JSON records:

```json
{"ts": 1742054400, "validator": "0xabc...", "type": "ATTESTATION", "decision": "allow", "signing_root": "0xdef..."}
{"ts": 1742054401, "validator": "0xabc...", "type": "ATTESTATION", "decision": "refuse", "policy": "slashing-protection-attestation", "reason": "double vote at target_epoch=12345"}
```

## Checkpoints

Every `checkpoint_interval_seconds` (default 60) nklave seals the in-memory log entries into a checkpoint:

- Computes the Merkle root over all entries since the last checkpoint
- Signs the root with the operator key
- Writes `{ts, prev_root, root, signature, entry_count}` as a marker into the log

To verify the log hasn't been tampered with, walk the checkpoint chain forwards and recompute each Merkle root from the entries it covers. Mismatches indicate the log was edited after the fact.

## Operator key

The checkpoint signing key is distinct from any validator signing key. It can be:

- A Ed25519 keypair stored in a separate keystore
- A YubiHSM slot
- An AWS KMS key

The operator key never leaves its custody; nklave only requests signatures over checkpoint roots.

## Querying the log

```bash
# All entries for a validator
nklave log query --validator 0xabc...

# All refused signatures in a time window
nklave log query --decision refuse --since 2026-04-01 --until 2026-04-08

# Verify checkpoint chain
nklave log verify --from 0 --to latest
```

The `verify` command walks the entire checkpoint chain, recomputes each Merkle root, and confirms each checkpoint signature against the registered operator pubkey. A non-zero exit code means the log has been tampered with.

## Retention

Logs rotate by size (default 1GB per file) and by age (default 365 days). Older logs are sealed (no further appends) and can be moved to cold storage; the checkpoint chain remains verifiable across the boundary.
