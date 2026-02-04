# Operations and Audit

This document covers observability, auditing, and operational controls.

## Metrics

Recommended metrics include:

- Signing request rate and latency (p50/p95).
- Refusal count by reason code (see `protocol.md` for authoritative code list).
- Last signed slot/height/level per validator (chain-dependent).
- Enclave health and restart count.
- State log size and checkpoint age.

## Logs

Each signing decision should be logged with:

- `request_id`
- `validator_pubkey`
- decision code
- decision hash
- state commitment

Logs must be append-only and retained for audit and forensic analysis.

## Alerts

Suggested alerts:

- Sudden spike in refusal rates.
- Repeated `REFUSE_STATE_ROLLBACK` events.
- Missing heartbeats from the enclave.
- Unexpected gaps in signing activity.

## Audit trails

The decision hash and state commitment enable external verification that the enclave followed its policy without rollback. These records can be exported to SIEM or compliance tooling.

## Incident Response

### State Integrity Failures

If the enclave refuses signing due to state integrity issues, identify the failure mode (see `state-integrity.md` for definitions):

**Truncated log** (missing sequence numbers):
1. Freeze signing immediately.
2. Identify gap in sequence numbers from log analysis.
3. Attempt recovery from backup logs or replicated passive node.
4. If recovery fails, restore from last checkpoint preserving monotonicity.

**Reordered log** (hash mismatch):
1. Freeze signing immediately.
2. Compare log hashes against expected chain.
3. Identify point of divergence.
4. Do NOT proceed if reordering could mask unsafe signatures.

**State corruption** (invalid record format):
1. Freeze signing immediately.
2. Validate checkpoint integrity.
3. Rebuild state from last valid checkpoint.
4. Audit all signing activity since corruption window.

### General Response Procedure

In all state integrity failure cases:
- The enclave will emit `REFUSE_STATE_ROLLBACK` for any signing requests.
- Do not attempt to bypass or override the refusal.
- Escalate to root-cause analysis before resuming.
- Document findings for compliance audit.
- Consider whether the incident indicates host compromise.
