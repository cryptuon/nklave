# Monitoring

Nklave exposes Prometheus metrics, a structured JSON log, and an audit-log query API.

## Metrics endpoint

```bash
curl http://localhost:9000/metrics
```

Key counters and histograms:

| Metric | Type | Meaning |
|---|---|---|
| `nklave_signing_requests_total{type, decision}` | Counter | Total signing requests by message type and outcome. |
| `nklave_policy_refusals_total{policy}` | Counter | Refusals by policy name — high values mean misconfigured validator. |
| `nklave_signing_latency_seconds` | Histogram | End-to-end signing-request latency. |
| `nklave_policy_evaluation_seconds{policy}` | Histogram | Per-policy evaluation time. |
| `nklave_slashing_db_size_bytes` | Gauge | Current size of the slashing-protection DB. |
| `nklave_log_checkpoint_age_seconds` | Gauge | Seconds since the last log checkpoint. |
| `nklave_keystore_count` | Gauge | Number of loaded signing keys. |

## Alerts

Suggested alerting rules (Prometheus syntax):

```yaml
groups:
- name: nklave
  rules:
  - alert: NklavePolicyRefusalsSurging
    expr: rate(nklave_policy_refusals_total[5m]) > 0.5
    for: 2m
    annotations:
      summary: "nklave is refusing >30 requests/min — validator misconfigured?"

  - alert: NklaveCheckpointStale
    expr: nklave_log_checkpoint_age_seconds > 600
    for: 1m
    annotations:
      summary: "nklave hasn't checkpointed the log in >10 min"

  - alert: NklaveSigningLatencyHigh
    expr: histogram_quantile(0.99, rate(nklave_signing_latency_seconds_bucket[5m])) > 0.1
    for: 5m
    annotations:
      summary: "p99 signing latency >100ms — HSM saturated?"
```

## Structured log

Nklave writes its own operational log (separate from the append-only audit log) to stdout as newline-delimited JSON, suitable for ingestion by Loki / Datadog / CloudWatch:

```json
{"ts": "2026-04-15T10:00:00Z", "level": "info", "event": "policy.refuse", "validator": "0xabc", "policy": "slashing-protection-attestation"}
{"ts": "2026-04-15T10:00:05Z", "level": "warn", "event": "hsm.slow", "duration_ms": 87}
```

## Audit-log queries

For after-the-fact incident investigation, the audit log is queryable via the CLI:

```bash
nklave log query --since "2026-04-15 09:55" --until "2026-04-15 10:05" --decision refuse
```

Outputs the matching entries with the full SigningContext, policy that refused, and reason — everything needed to reconstruct what happened.
