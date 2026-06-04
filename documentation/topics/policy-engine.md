# Policy engine

The policy engine is the layer between an incoming signing request and the signing key. It evaluates a sequence of policies; if any refuses, the request is rejected before the key is touched.

## Built-in policies

Nklave ships with four policies enabled by default:

| Policy | Refuses if … |
|---|---|
| `slashing-protection-attestation` | The attestation would violate the double-vote or surround-vote rules. |
| `slashing-protection-block` | The block proposal slot was previously signed. |
| `fork-allowlist` | The signing root targets a fork version not in `allowed_forks`. |
| `rate-limit` | The validator's signing rate exceeds `max_signs_per_hour`. |

Each is configured under `policies:` in `nklave.toml`:

```toml
[policies.rate-limit]
max_signs_per_hour = 240    # ~4/min

[policies.fork-allowlist]
allowed_forks = ["0x05000000", "0x06000000"]   # capella, deneb
```

## Custom policies

A policy is a Rust trait:

```rust
pub trait Policy: Send + Sync {
    fn evaluate(&self, ctx: &SigningContext) -> PolicyDecision;
}

pub enum PolicyDecision {
    Allow,
    Refuse { reason: String },
}
```

`SigningContext` carries the requested validator pubkey, the signing root, the message type, the parsed fork-version, the wall-clock timestamp, and a handle to read (but not mutate) the slashing-protection DB.

To register a custom policy, implement the trait and add it to the policy chain at startup:

```rust
use nklave::policy::{Policy, PolicyDecision, SigningContext};

struct WithdrawalCooldown { hours: u64 }

impl Policy for WithdrawalCooldown {
    fn evaluate(&self, ctx: &SigningContext) -> PolicyDecision {
        if ctx.message_type != "VOLUNTARY_EXIT" { return PolicyDecision::Allow; }
        let last = ctx.db.last_signed("VOLUNTARY_EXIT", ctx.pubkey);
        if last.elapsed_hours() < self.hours {
            return PolicyDecision::Refuse {
                reason: format!("withdrawal cooldown: {}h remaining",
                                self.hours - last.elapsed_hours())
            };
        }
        PolicyDecision::Allow
    }
}

// In main.rs
nklave.add_policy(Box::new(WithdrawalCooldown { hours: 24 }));
```

Policies evaluate in registration order; the first refusal short-circuits the chain.

## Audit trail

Every evaluation is logged to the [append-only log](./append-only-log.md) — both allow and refuse outcomes, with the policy name and reason. After-the-fact investigation of a refused signature is straightforward:

```bash
nklave log search --policy=slashing-protection-attestation --validator=<pubkey>
```
