# Threat Model

> Research prototype. Not audited. Not production custody. Do not use real funds.

This document describes the trust assumptions and threat boundaries for the
WalletWall Vault research prototype. It is written to prevent overclaiming: the
repository demonstrates a migration path and contract-level controls, but it does not
claim production readiness or real-fund safety.

## System Scope

In scope:

- `WalletWallVault`, including deposits, withdrawals, per-owner accounting, replay
  protection, pause controls, and verifier governance.
- `IPQCVerifier` implementations included in this repository.
- The off-chain ML-DSA attestor CLI and fixture tooling included in this repository.
- Local and testnet evaluation of hybrid authorization flows.

Out of scope:

- The private WalletWall application repository.
- Production WalletWall app behavior; production app surfaces remain read-only
  intelligence/status/readiness surfaces unless a future reviewed integration says otherwise.
- Production custody operations, deployment monitoring, key management, incident
  response, and user support.
- Claims about an exact quantum-computer timeline, including any exact "Q-day" date.
- Production-grade post-quantum security.

## Assets and Security Properties

The prototype is intended to explore these properties:

- Withdrawal authorization through signed EIP-712 messages.
- Per-owner replay protection through nonces and deadlines.
- Tamper resistance for withdrawal fields included in the signed message.
- A verifier trust boundary that can be swapped through owner-controlled governance.
- Clear separation between mock verification, trusted attestation, and future verifier
  paths.

It does not claim:

- Safe custody of real assets.
- An audited implementation.
- Production-grade quantum resistance.
- Complete operational controls.
- Independence from trusted administrators or trusted attestors.

## Primary Trust Assumptions

### Vault Owner Credentials

Each vault owner is responsible for their configured ECDSA signer and PQ public key.
The contract cannot recover from stolen keys, unsafe key storage, compromised signing
devices, or a user signing an unintended withdrawal.

### Configured PQ Verifier

`WalletWallVault` delegates PQ signature validity to the configured `IPQCVerifier`.
The vault does not execute ML-DSA verification itself. The active verifier is therefore
the main PQ trust boundary.

`MockMLDSAVerifier` is test/demo-only. It checks shape, not cryptographic validity. It
must not be treated as a real PQ authorization layer.

`AttestationPQCVerifier` verifies an authorized EVM attestor signature over a statement
about the withdrawal digest and PQ input hashes. It does not verify ML-DSA on-chain.
Its security depends on the attestor correctly verifying ML-DSA off-chain before
signing.

### Attestor

For the trusted-attestation path, the attestor key and service are trusted components.
A compromised attestor key, modified service, bypassed verifier, or malicious operator
can approve invalid PQ inputs. The prototype CLI reduces accidental mis-signing in the
demonstrated flow, but it is not a hardened attestation service.

### Owner Governance

The contract owner can pause the vault and can change the PQ verifier through a delayed
proposal/apply flow. The delay gives observers time to review a pending verifier change,
but it does not remove owner trust. A compromised owner can propose a weak verifier and
apply it after the delay.

The owner can be a multisig through `Ownable2Step`, but this repository does not deploy,
audit, or operate that multisig.

## Replay and Domain Separation

Withdrawals use an EIP-712 typed message that includes:

- `vaultOwner`
- `recipient`
- `amount`
- `nonce`
- `deadline`
- `vaultMode`

The EIP-712 domain binds signatures to the vault contract address, chain ID, and
domain name/version. A valid signature for one contract, chain, nonce, amount,
recipient, deadline, or mode should not authorize a different withdrawal.

Replay protection is provided by a strictly increasing per-owner nonce plus a signed
deadline. The contract does not maintain a global signature registry.

The trusted-attestation verifier also binds its attestation to the withdrawal digest,
public-key hash, PQ-signature hash, algorithm identifier, verifier address, chain ID,
and deadline. It has no independent nonce; it relies on the vault withdrawal digest for
replay protection.

## Threats Considered

| Threat | Current posture |
| --- | --- |
| Reusing a withdrawal signature | Mitigated by per-owner nonce and deadline. |
| Altering withdrawal amount, recipient, owner, mode, nonce, or deadline | Mitigated because those fields are signed. |
| Cross-chain or cross-contract replay | Mitigated by EIP-712 domain separation. |
| Reentrancy during ETH withdrawal | Mitigated with `ReentrancyGuard` and checks-effects-interactions. |
| Mock verifier accepted as real PQ security | Documented limitation; `PqOnly` is blocked while the mock verifier is active. |
| Malicious or compromised attestor | Not solved. This is a core trust assumption of the attestation path. |
| Malicious or compromised contract owner | Not solved. Timelocked verifier governance creates review time, not trustlessness. |
| Immediate attestor rotation inside a configured verifier | Documented; `updateAttestor` is instant and not covered by the vault's two-day verifier timelock. Near-term hardening: immutable-attestor verifier (see [Attestation_Governance_Hardening.md](Attestation_Governance_Hardening.md)). |
| Force-sent ETH | Accounted balances are unaffected; force-sent ETH is not credited to a vault. |
| Production deployment mistakes | Out of scope; this repository is not a deployment system. |

## Known Gaps

- No on-chain ML-DSA verification.
- No ZK proof verifier.
- No threshold attestor committee.
- Attestor rotation inside `AttestationPQCVerifier` is immediate and is not covered by the
  vault's verifier timelock. The hardening plan (recommended near-term: an
  immutable-attestor verifier) is documented in
  [Attestation_Governance_Hardening.md](Attestation_Governance_Hardening.md).
- No hardened attestor service, key isolation, monitoring, transparency log, or
  incident process.
- No audited multisig or timelock-controller deployment.
- No formal verification or third-party audit.
- ETH-only prototype; no ERC-20 or NFT custody model.
- No claim about when quantum-capable key recovery may become practical.

## Safe Interpretation

WalletWall Vault may be described as a research prototype that demonstrates how a
classical ECDSA authorization path could be combined with a PQ verifier interface and a
trusted attestation migration step.

It should not be described as production-ready, audited, quantum-proof, safe for real
funds, a custody product, a production deposit or withdrawal service, a real-yield
product, or a mainnet production write path. Local and Sepolia simulator paths are
developer/testnet rehearsal exceptions only.
