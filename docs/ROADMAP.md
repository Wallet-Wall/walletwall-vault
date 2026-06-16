# Roadmap

> Research roadmap, not a production commitment. Dates and exact quantum-risk timelines
> are intentionally not claimed here.

WalletWall Vault is a staged research prototype for evaluating a migration path from
classical Ethereum authorization toward stronger post-quantum verifier options. Each
stage must preserve the repository's current boundary: no production-readiness claims,
no real-fund custody claims, and no exact "Q-day" claims.

## Current Stage: Prototype Boundary

Implemented:

- EIP-712 withdrawal authorization.
- Per-owner nonces and deadlines for replay protection.
- `EcdsaOnly`, `PqOnly`, and `Hybrid` vault modes.
- `PqOnly` blocked while the mock verifier is active.
- `IPQCVerifier` trust-boundary interface.
- Mock ML-DSA-shaped verifier for local/testnet demos.
- Trusted-attestation verifier that enforces an authorized EVM attestor signature.
- Off-chain attestor CLI that verifies ML-DSA-65 with `@noble/post-quantum` before
  signing in real verify mode.
- Timelocked owner-controlled PQ verifier updates.
- Prototype docs and tests.

Not implemented:

- On-chain ML-DSA verification.
- ZK proof verification of ML-DSA.
- Threshold attestor committee.
- Hardened attestor service operations.
- Production deployment process.
- Third-party audit.
- Production custody controls.

## Near-Term Work

- Keep security assumptions and app-boundary docs current with contract behavior.
- Expand negative tests for verifier payload binding, replay edges, and governance
  transitions as the prototype changes.
- Add known-answer vectors where practical and distinguish official vectors from
  library-generated fixtures.
- Improve attestor tooling ergonomics without weakening fail-closed behavior.
- Document deployment observations for local/testnet networks only.

## Verifier Research Path

The verifier path should progress only when each step is implemented and reviewed:

1. Mock verifier for local/testnet wiring.
2. Trusted-attestation verifier for evaluating off-chain ML-DSA verification plus
   on-chain attestor enforcement.
3. Threshold or committee-based attestation research, if operationally justified.
4. ZK proof verifier research for proving ML-DSA verification off-chain and checking a
   succinct proof on-chain.
5. Chain-native verifier or precompile integration if an L1/L2 provides reviewed
   support.

The current repository is at steps 1 and 2. Later steps remain research directions, not
completed security properties.

## Governance Work

Before any non-local deployment could be considered, the governance model would need:

- Reviewed owner multisig or timelock-controller setup.
- Monitoring for verifier proposal, cancellation, and application events.
- Clear runbooks for canceling bad verifier proposals.
- Key-management controls for owner and attestor keys.
- Independent review of the configured verifier bytecode and deployment process.

These items are not complete in this repository.

## App Integration Work

The private WalletWall app may use this repository as a research/prototype reference,
but app-facing copy should stay within the boundaries in
[`WALLETWALL_APP_BOUNDARY.md`](WALLETWALL_APP_BOUNDARY.md).

Any future product integration would need a separate product threat model, deployment
plan, user warnings, support model, and legal/compliance review. This repository does
not provide those artifacts.

## Criteria Before Stronger Claims

Do not make stronger claims until all relevant criteria are met:

- The claimed verifier path is implemented.
- The implementation has tests for success and fail-closed behavior.
- Independent review or audit has been completed.
- Deployment governance and monitoring are defined and tested.
- App-facing documentation matches the actual deployed verifier and governance.
- The wording avoids real-fund, production-readiness, quantum-proof, and exact-timeline
  claims unless those claims have separate evidence.
