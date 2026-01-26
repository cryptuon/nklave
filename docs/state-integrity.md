# State Integrity

The signing enclave must prevent rollback of safety state. Rollback allows a compromised host to present an older state to the enclave and force unsafe signatures.

## Goals

- Detect any truncation or reordering of safety state.
- Fail closed if continuity is violated.
- Provide external auditability of state evolution.

## Software-only approach (v1)

1. The enclave maintains an internal state hash.
2. Every decision updates the hash using a one-way function:

   `state_hash_next = H(state_hash_prev || decision_record)`

3. The host stores decision records in an append-only log.
4. On startup, the enclave replays the log and verifies the hash chain.
5. If continuity is broken, the enclave refuses to sign.

## Checkpoints

To reduce replay cost, the enclave can emit periodic checkpoints:

- A checkpoint includes the current `state_hash` and a sequence number.
- Checkpoints are signed by the enclave and stored by the host.
- On restart, the enclave verifies the latest checkpoint and replays only the tail of the log.

## Failure modes

- **Truncated log**: detected by missing sequence numbers or hash mismatch.
- **Reordered log**: detected by hash mismatch.
- **State corruption**: detected by invalid decision record format or checksum.

In all cases, the enclave must refuse signing and emit a `REFUSE_STATE_ROLLBACK` response.

## Optional hardware binding (future)

If required, checkpoints can be bound to hardware monotonic counters or measured boot states. This is an optional hardening step and not required for v1 deployment.
