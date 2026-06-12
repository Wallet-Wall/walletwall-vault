# Trusted Attestation Verifier

> Research prototype. Not audited. Local and testnet use only. Do not use real funds.

## What it is

`AttestationPQCVerifier` is a non-mock implementation of `IPQCVerifier`. It checks an
authorized EVM attestor's EIP-712 signature over a statement that binds a withdrawal
digest to hashes of a PQ public key and PQ signature.

It is stronger than `MockMLDSAVerifier` only because it enforces a signature from the
configured attestor. The contract assumes that the attestor verified the ML-DSA-65
signature correctly off-chain before signing the attestation.

## What it is not

- It does not implement or execute ML-DSA verification on-chain.
- It does not remove trust in the attestor or the attestor's operating environment.
- It is not audited or suitable for production custody.
- It does not make this repository suitable for real funds.
- It is not a ZK verifier or a native chain verifier.

## Architecture flow

1. A withdrawal request is hashed into the vault's EIP-712 withdrawal digest.
2. An off-chain service receives the withdrawal digest, PQ public key, and PQ signature.
3. The service verifies the ML-DSA-65 signature with a real FIPS 204-compatible
   implementation.
4. If verification succeeds, the configured EVM attestor signs the `PQCAttestation`
   EIP-712 message.
5. The caller encodes the attestor signature and attestation metadata as the verifier
   payload.
6. `WalletWallVault` calls `AttestationPQCVerifier.verify`.
7. The verifier checks the payload shape, deadline, public-key hash, EIP-712 signature,
   and configured attestor.

The attestor CLI at [`scripts/attestor-cli.ts`](../scripts/attestor-cli.ts) implements
steps 3 through 5 with `@noble/post-quantum` ML-DSA-65 verification. It refuses to sign
in real verify mode unless verification succeeds and the signed message exactly matches
the withdrawal digest.

The older [`scripts/sign-attestation.ts`](../scripts/sign-attestation.ts) remains a
payload-construction example only. It does not verify ML-DSA and must not be used as an
attestor service.

## Attestor CLI

`npm run attestor:demo` uses deterministic library-generated ML-DSA-65 material. It
verifies the signature before signing the attestation and prints:

> DEMO ONLY — do not use generated/demo PQ material for real funds.

`npm run attestor:verify -- ...` requires:

- `--withdrawal-digest`: the 32-byte vault withdrawal digest.
- `--message` or `--message-file`: the bytes signed by ML-DSA; these must equal the
  withdrawal digest.
- `--public-key` or `--public-key-file`: ML-DSA-65 public key bytes.
- `--pq-signature` or `--pq-signature-file`: ML-DSA-65 signature bytes.
- `--verifier`: deployed `AttestationPQCVerifier` address.
- `--chain-id`: intended chain ID.
- `--deadline`: attestation expiry timestamp.
- `ATTESTOR_PRIVATE_KEY` or `--attestor-private-key`: EVM attestor key.

Hex files may contain a `0x`-prefixed value. Other files are treated as raw bytes. Real
verify mode rejects malformed inputs, failed ML-DSA verification, message/digest
mismatches, and the known deterministic demo material.

Deterministic library-generated fixtures live under
[`test/fixtures/mldsa/library-generated/`](../test/fixtures/mldsa/library-generated/).
They are not official NIST vectors and are not deployment credentials.

## Trust model

The configured `attestor` is the authorization authority for this verifier. A valid
attestation proves that the attestor signed the bound statement, not that the EVM
independently executed ML-DSA.

Security therefore depends on:

- correct off-chain ML-DSA verification,
- protection of the EVM attestor key,
- correct binding of the verified inputs into the attestation,
- availability and operational integrity of the attestation service, and
- secure owner control over `updateAttestor`.

The contract owner can rotate the attestor. A compromised owner or attestor can
authorize invalid PQ inputs.

The CLI prevents accidental signing after a local verification failure. It cannot
protect against a compromised host, modified service code, stolen attestor key, or an
operator intentionally bypassing the CLI.

This is a **trusted attestation model, not trustless PQ verification.** The vault
cannot detect or prevent abuse at the attestor layer.

## Attestor rotation delay asymmetry

`WalletWallVault` protects against verifier replacement through a timelocked
`proposePQVerifier` / `applyPQVerifierUpdate` governance flow (two-day delay). This
delay allows users to observe a pending verifier change and react before it takes
effect.

`AttestationPQCVerifier.updateAttestor` has **no equivalent delay.** The attestor owner
can rotate to a new attestor immediately in a single transaction. This means:

- The vault's two-day governance delay does **not** protect users from immediate
  attestor rotation inside an already-configured `AttestationPQCVerifier`.
- A compromised attestor owner can silently replace a legitimate attestor with a
  malicious one, causing the verifier to accept fraudulent PQ attestations from the
  next block onward.
- Users and integrators relying on this verifier must monitor the `AttestorUpdated(address indexed oldAttestor, address indexed newAttestor)` event to detect unexpected rotations.

This asymmetry is a deliberate design trade-off of the Phase 1 attestation path. It can
only be eliminated by replacing the attestation path with a ZK or chain-native verifier
that does not rely on a trusted off-chain authority. See
[Verifier_Roadmap.md](Verifier_Roadmap.md).

## EIP-712 attestation

Domain:

```text
name: AttestationPQCVerifier
version: 1
chainId: current chain ID
verifyingContract: deployed verifier address
```

Typed message:

```text
PQCAttestation(
  bytes32 withdrawalDigest,
  bytes32 publicKeyHash,
  bytes32 pqSignatureHash,
  bytes32 algorithmId,
  address verifier,
  uint256 chainId,
  uint256 deadline
)
```

Field meanings:

- `withdrawalDigest`: the exact digest passed by `WalletWallVault`.
- `publicKeyHash`: `keccak256(pqPublicKeyBytes)`.
- `pqSignatureHash`: `keccak256(pqSignatureBytes)` computed off-chain.
- `algorithmId`: `keccak256("ATTESTED-ML-DSA-65")`.
- `verifier`: the deployed `AttestationPQCVerifier` address.
- `chainId`: the chain on which verification is intended.
- `deadline`: the final timestamp at which the attestation is accepted.

## Verifier payload

The `signature` argument passed through `IPQCVerifier.verify` must be:

```solidity
abi.encode(
    bytes attestationSignature,
    uint256 deadline,
    bytes32 publicKeyHash,
    bytes32 pqSignatureHash
)
```

The raw PQ signature is verified off-chain and is represented on-chain by
`pqSignatureHash`. The PQ public key remains the `publicKey` argument to `verify`; the
contract checks that its hash matches `publicKeyHash`.

## Replay and domain separation

The attestation binds the withdrawal digest, both PQ input hashes, algorithm identifier,
verifier address, chain ID, and deadline. The EIP-712 domain also binds the verifier
address and chain ID. These checks prevent an attestation from being reused for altered
inputs, another verifier deployment, or another chain.

The verifier does not maintain its own nonce or consumed-attestation registry. Vault
withdrawal replay protection remains the responsibility of the withdrawal digest,
which includes the vault nonce and withdrawal deadline. Integrations outside
`WalletWallVault` must provide equivalent replay protection.

## Known limitations

- The EVM trusts an ECDSA attestor instead of verifying ML-DSA itself.
- A compromised attestor key can authorize invalid PQ signatures.
- An incorrect, modified, or bypassed off-chain verifier can produce invalid
  attestations.
- **Attestor rotation is owner-controlled and immediate within this verifier.** The
  vault's two-day verifier governance delay does not cover `updateAttestor`. See
  [Attestor rotation delay asymmetry](#attestor-rotation-delay-asymmetry) above.
- There is no threshold attestor committee, slashing, transparency log, or availability
  guarantee.
- Demo mode uses deterministic test material and does not provide deployment security.
- The attestor CLI blocks demo material and library-generated fixture material in real
  verify mode. This prevents accidental signing from known generated inputs but does not
  remove trust in the attestor key, host, or service.
- The CLI is a prototype process, not a hardened or highly available attestation
  service.

## Migration path

`WalletWallVault` depends on `IPQCVerifier`, so a future verifier can replace the trusted
attestation path through the vault's delayed verifier-governance process. Stronger
future approaches may verify a ZK proof of ML-DSA verification or call native chain
support. Either path requires independent review, test vectors, operational controls,
and updated security documentation before deployment assumptions can change.
