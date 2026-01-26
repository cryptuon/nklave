# Threat Model

This threat model defines the security boundaries and claims for Nklave v1.

## Attacker capabilities (assumed)

The attacker can:

- Gain root on the validator host OS.
- Tamper with or replace the validator client binary.
- Modify host filesystems, configs, and logs.
- Intercept or modify network traffic on the host.
- Cause the validator client to request arbitrary signatures.

## Out of scope (v1)

Nklave does not claim protection against:

- Physical access attacks (cold boot, DMA, evil maid).
- Advanced side-channel attacks on enclave execution.
- Compromise of the enclave implementation itself.
- Global anti-slash across multiple independent enclaves without explicit coordination.

## Security goals

Nklave v1 guarantees:

1. **Key non-exfiltration**: signing keys are not readable by the host.
2. **Non-slashable signing**: slashable requests are refused, even if requested by compromised software.
3. **Monotonic safety state**: signing state cannot be rolled back by host tampering.
4. **Auditability**: every decision is logged with deterministic reason codes.

## Trust assumptions

- The enclave implementation is correct and minimal.
- The enclave boundary is enforced by the chosen isolation technology.
- Operators secure physical access to validator hosts.

## Residual risks

- Denial of service: the host can prevent signing by blocking requests.
- Liveness tradeoffs: strict enforcement may reduce availability if state is corrupted.
- Supply chain: vulnerabilities in the enclave build pipeline could compromise safety.
