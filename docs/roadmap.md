# Roadmap

This roadmap is a planning artifact. Dates are targets and may shift based on customer feedback and engineering capacity.

*Last updated: January 2026*

---

## Phase 0: Documentation and Alignment (by February 2026)

- Publish product, architecture, and threat-model documentation.
- Define MVP scope and acceptance criteria.
- Select the first Ethereum validator client to support (Lighthouse or Teku).
- Finalize multi-chain architecture design.

## Phase 1: Ethereum MVP (March to May 2026)

- Implement the signing enclave with Ethereum slashing rules:
  - Double proposal prevention.
  - Double vote prevention.
  - Surround vote detection.
- Implement a host proxy exposing the chosen client's remote signer interface.
- Add deterministic refusal codes and structured audit logs.
- Add basic state integrity with append-only hash chaining.
- Support EIP-3076 slashing protection database import/export.
- Build a minimal deployment bundle for local testing.

## Phase 2: Pilot-Ready + Cosmos Support (June to August 2026)

**Ethereum Hardening:**
- Add checkpoints to reduce replay time and harden rollback detection.
- Implement active/passive failover procedure.
- Harden logging, metrics, and alerting.
- Deliver a paid pilot with 1-2 early Ethereum operators.

**Cosmos/CometBFT Support:**
- Implement Cosmos slashing policy module (height/round double signing).
- Add support for Cosmos validator clients.
- Validate against Cosmos Hub and one additional Cosmos chain.

## Phase 3: Polkadot Support + Production Hardening (September to November 2026)

**Polkadot/Substrate Support:**
- Implement BABE equivocation prevention.
- Implement GRANDPA equivocation prevention.
- Support Polkadot and Kusama validator clients.

**Production Hardening:**
- Expand to a second Ethereum validator client integration.
- Improve key ceremony and rotation workflows.
- Add operator tooling for fleet management.
- Formalize compliance artifacts and audit report templates.

## Phase 4: Tezos + Optional Hardware Binding (December 2026 and beyond)

**Tezos Support:**
- Implement double baking prevention.
- Implement double endorsement prevention.
- Support Tezos baker clients.

**Optional Hardware Binding:**
- Evaluate hardware-backed checkpoints (TPM or measured boot).
- Add attestation support if required by regulators or enterprise buyers.
- Explore dedicated appliance or confidential VM deployments.

---

## Alternatives Considered

This section documents key architectural decisions and the alternatives that were evaluated.

### Software-Only vs. Hardware-First

**Decision**: Start with software-only state integrity, add hardware binding as optional enhancement.

**Rationale**:
- Software-only allows faster iteration and broader deployment compatibility.
- Most slashing incidents stem from software bugs, not sophisticated attacks.
- Hardware binding adds complexity and limits deployment options.
- Enterprise customers requiring hardware can opt-in later.

**Alternatives rejected**:
- Requiring SGX/SEV from day one (limits deployment targets).
- TPM-only approach (insufficient for full state binding).

### Signing Boundary vs. Full Validator Replacement

**Decision**: Nklave is a signing boundary that integrates with existing validator clients.

**Rationale**:
- Operators have existing validator client investments and preferences.
- Replacing the entire validator stack increases adoption friction.
- Focused scope enables a smaller, more auditable codebase.
- Compatibility with DVT and other availability solutions.

**Alternatives rejected**:
- Building a complete validator client (too broad, competitive market).
- Kernel-level enforcement (too invasive, portability issues).

### Chain Selection Rationale

**Decision**: Ethereum first, then Cosmos, then Polkadot, then Tezos.

**Rationale**:
- **Ethereum first**: Largest staking market, highest penalty risk, most customer demand.
- **Cosmos second**: Simpler slashing model (height/round), large ecosystem of chains, permanent tombstoning makes prevention critical.
- **Polkadot third**: More complex (dual consensus), but growing institutional interest.
- **Tezos fourth**: Similar to Cosmos model, smaller but established market.

**Future chains under consideration**:
- Solana (when slashing is implemented).
- Aptos (when slashing is activated).
- Other chains based on customer demand.

---

## Success Criteria

- Zero slashable signatures in pilot deployments across all supported chains.
- Clear evidence that the signing boundary enforces policy under host compromise.
- Operators can integrate without replacing custody/MPC or validator clients.
- Multi-chain operators can use a single Nklave deployment for all supported chains.
