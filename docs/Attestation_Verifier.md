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

The helper script at [`scripts/sign-attestation.ts`](../scripts/sign-attestation.ts)
demonstrates steps 4 and 5. Its generated fallback PQ bytes are mock data; the script
does not perform step 3.

Run it with `npm run sign:attestation`. The following environment variables override
the generated local sample values:

- `WITHDRAWAL_DIGEST`: 32-byte withdrawal digest.
- `PQ_PUBLIC_KEY`: hex-encoded PQ public key bytes.
- `PQ_SIGNATURE`: hex-encoded PQ signature bytes.
- `ATTESTOR_PRIVATE_KEY`: EVM private key used to sign the attestation.
- `VERIFIER_ADDRESS`: existing verifier address; otherwise the script deploys a local
  sample verifier.
- `CHAIN_ID`: EIP-712 chain ID; defaults to the connected network.
- `ATTESTATION_DEADLINE`: Unix timestamp; defaults to one hour after the latest block.

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
- An incorrect or bypassed off-chain verifier can produce invalid attestations.
- Attestor rotation is owner-controlled and immediate within this verifier.
- There is no threshold attestor committee, slashing, transparency log, or availability
  guarantee.
- The helper script constructs attestations but does not verify ML-DSA.

## Migration path

`WalletWallVault` depends on `IPQCVerifier`, so a future verifier can replace the trusted
attestation path through the vault's delayed verifier-governance process. Stronger
future approaches may verify a ZK proof of ML-DSA verification or call native chain
support. Either path requires independent review, test vectors, operational controls,
and updated security documentation before deployment assumptions can change.
