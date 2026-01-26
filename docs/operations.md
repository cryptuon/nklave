# Operations and Audit

This document covers observability, auditing, and operational controls.

## Metrics

Recommended metrics include:

- Signing request rate and latency (p50/p95).
- Refusal count by reason code.
- Last signed slot and epoch per validator.
- Enclave health and restart count.

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

## Incident response

If the enclave refuses signing due to state integrity issues:

1. Freeze signing to avoid unsafe behavior.
2. Verify log continuity and checkpoint validity.
3. Restore from the last known-good checkpoint only if it preserves monotonicity.
4. Escalate to a root-cause analysis before resuming.
