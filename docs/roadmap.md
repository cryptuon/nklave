# Roadmap

This roadmap is a planning artifact. Dates are targets and may shift based on customer feedback and engineering capacity. The current date is January 26, 2026.

## Phase 0: Documentation and Alignment (by February 2026)

- Publish product, architecture, and threat-model documentation.
- Define MVP scope and acceptance criteria.
- Select the first validator client to support (Lighthouse or Teku).

## Phase 1: MVP Signing Boundary (March to May 2026)

- Implement the signing enclave with core slashing rules.
- Implement a host proxy exposing the chosen client's remote signer API.
- Add deterministic refusal codes and structured audit logs.
- Add basic state integrity with append-only hash chaining.
- Build a minimal deployment bundle for local testing.

## Phase 2: Pilot-Ready Release (June to August 2026)

- Add checkpoints to reduce replay time and harden rollback detection.
- Implement active/passive failover procedure.
- Harden logging, metrics, and alerting.
- Deliver a paid pilot with 1-2 early operators.

## Phase 3: Production Hardening (September to November 2026)

- Expand to a second validator client integration.
- Improve key ceremony and rotation workflows.
- Add operator tooling for fleet management.
- Formalize compliance artifacts and audit report templates.

## Phase 4: Optional Hardware Binding (December 2026 and beyond)

- Evaluate hardware-backed checkpoints (TPM or measured boot).
- Add attestation support if required by regulators or enterprise buyers.
- Explore dedicated appliance or confidential VM deployments.

## Success criteria

- Zero slashable signatures in pilot deployments.
- Clear evidence that the signing boundary enforces policy under host compromise.
- Operators can integrate without replacing custody/MPC or validator clients.
