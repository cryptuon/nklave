# nklave Roadmap

nklave is an open-source, policy-enforcing trust boundary for proof-of-stake validators. It sits between validator clients and signing keys and enforces EIP-3076 slashing-prevention rules — and configurable policy — *before* any signature is produced. This roadmap describes where the project is going and the cheapest realistic path to running it in production.

*Dates are targets and may shift with engineering capacity and operator feedback. See [`docs/roadmap.md`](docs/roadmap.md) for the granular engineering checklist this document summarizes.*

---

## Vision

As proof-of-stake matured, a validator key faced exactly one slashing surface: the consensus layer of the chain it validated. Restaking broke that assumption. EigenLayer-style restaking and Actively Validated Services (AVS) opt the *same* staked capital — and increasingly the same keys — into multiple independent slashing regimes, each with its own conditions defined by code the operator did not write.

That makes the boundary between "what requested a signature" and "what actually got signed" the single most valuable control point a staking operation has. nklave's goal is to be the default, audited, open-source **policy firewall** that lives at that boundary: a small, verifiable layer that refuses any request violating a rule before the key is touched, logs every decision immutably, and integrates with the validator clients and key-management systems operators already run — without replacing them.

Principles that constrain the roadmap:

- **Boundary, not replacement.** nklave integrates with existing validator clients and custody/MPC/HSM systems. It never becomes a full validator client.
- **Impossible-by-construction over best-effort.** A refused request must never reach the key material, even under full host compromise.
- **Small and auditable.** Scope stays narrow so the security-critical code stays reviewable.
- **Honest about scope.** nklave enforces *protocol-level* slashing prevention (EIP-3076 and equivalents). AVS-specific slashing conditions are per-service and are not built in; the policy layer is the place operators express additional guardrails.

## Milestones

### Phase 0 — Documentation & alignment ✅
Product, architecture, and threat-model docs published; MVP scope defined; multi-chain architecture finalized.

### Phase 1 — Ethereum MVP ✅
Signing boundary with Ethereum slashing rules (double proposal, double vote, surround vote); Web3Signer-compatible remote-signer interface; deterministic refusal codes and structured audit logs; append-only hash-chained state; EIP-3076 import/export; health endpoints; atomic checkpoints; Docker + Lighthouse/Teku integration test environments.

### Phase 2 — Pilot-ready + Cosmos (in progress)
Checkpoint-based replay reduction and rollback hardening; active/passive failover; hardened logging, metrics, and alerting; a paid pilot with 1–2 Ethereum operators. Cosmos/CometBFT slashing policy (height/round double-signing) validated against Cosmos Hub and one additional chain.

### Phase 3 — Polkadot + production hardening
BABE and GRANDPA equivocation prevention (Polkadot/Kusama); a second Ethereum validator-client integration; key ceremony and rotation workflows; fleet-management tooling; compliance and audit-report artifacts.

### Phase 4 — Tezos + optional hardware binding
Double-baking / double-endorsement prevention for Tezos; evaluation of hardware-backed checkpoints (TPM / measured boot) and confidential-VM deployment for operators that require it.

### Restaking-aware policy (cross-cutting, exploratory)
As AVS slashing conditions stabilize, extend the policy layer with restaking-aware guardrails operators can express as first-class policies — the natural extension of nklave's existing allow/refuse enforcement model. Tracked here rather than tied to one chain phase.

---

## Cheapest path to production

nklave is **validator middleware** — it has no standalone "product launch." "Production" means a hardened nklave deployment running in front of real signing keys, beside real validators, refusing slashable requests under real load. The cheapest credible path gets you there without spinning up expensive infrastructure or risking mainnet stake before you've earned confidence.

**The path, cheapest-first:**

1. **Harden and validate on the cheapest testnet first.** Run nklave in front of a validator on a free Ethereum testnet — **Hoodi** (current primary testnet) or **Holesky** — where stake has no real value. Drive it with a real validator client (Lighthouse or Teku) against a real beacon node, replay adversarial signing requests, and confirm every slashable request is refused with the correct code. This costs testnet ETH (free) and one small node — near-zero.
2. **Run the EIP-3076 conformance and adversarial test suite.** Import known-slashing interchange files and confirm nklave refuses; import/export round-trip a validator's history to prove migration safety. This is the acceptance gate before any real value is at risk.
3. **Deploy beside existing mainnet validators — no new fleet.** Because nklave sits *between* the client and the key, it drops in alongside validators you already run. There is no separate cluster to provision: the extra infrastructure is one nklave process (plus its passive replica for HA) co-located with existing signing infrastructure. Marginal cost over an existing operation is small.
4. **Turn on production-viability controls before trusting real stake:**
   - **Security audit** of the signing boundary and state-integrity code.
   - **HA / failover** — active/passive replication with automatic failover so signing survives a node loss without producing a slashable signature.
   - **Remote-signer / key-management integration** — wire nklave to your existing keystore, HSM, or KMS rather than holding keys in a new place.
   - **EIP-3076 conformance tests** in CI, run against every release.
   - **Monitoring & alerting** — Prometheus metrics, per-validator watermarks, and alerts on any refusal, replication lag, or checkpoint failure.

**Why this is the cheapest path:** testnet validation is free and catches the failures that matter; deploying as middleware beside existing validators avoids standing up new infrastructure; and staging the production-viability controls (audit, HA, KMS integration, conformance, monitoring) *after* testnet validation means you spend on hardening only what has already proven correct. The expensive mistake — slashed mainnet stake — is exactly what this ordering is designed to avoid.

---

## Non-goals

- Becoming a full validator client or beacon node.
- Replacing custody, MPC, or HSM systems (nklave integrates with them).
- Kernel-level or client-fork enforcement (too invasive, hurts portability).
- Enforcing AVS-specific business logic that belongs in the AVS itself; nklave enforces signing-safety guardrails, not application semantics.

## Success criteria

- Zero slashable signatures across all pilot deployments and supported chains.
- Demonstrable enforcement under host compromise — a refused request never reaches key material.
- Operators integrate without replacing their validator clients or key-management systems.
- A single nklave deployment serves a multi-chain operator across every supported chain.

---

Questions, pilot interest, or want to shape a milestone? Open an issue, or reach [contact@cryptuon.com](mailto:contact@cryptuon.com). See the [site](https://nklave.cryptuon.com/) and [docs](https://docs.cryptuon.com/nklave/).
