# Open PQ Verifier

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**
> Trusted attestation is not trustless verification. ZK / native PQ remains a future
> trust-minimization path.

WalletWall's open PQ verifier is a reproducible verification boundary. It lets
WalletWall, auditors, verifier operators, and third parties check the same ML-DSA-65
signature material and arrive at the same structured result. Optional EIP-712
attestations can bridge verified results into testnet contracts, but that attestation
path remains trusted and is **not** a ZK proof or native on-chain PQ verification.

**Running it yourself?** See the [PQ Verifier Operator Guide](PQ_Verifier_Operator_Guide.md)
for step-by-step instructions and [PQ Verifier Reproducibility](PQ_Verifier_Reproducibility.md)
for how operators compare results and how pure verification differs from EIP-712
attestation.

## What it is

The open verifier answers exactly one question:

> Did this ML-DSA-65 signature verify for this message and public key?

It returns a deterministic, structured result (see
[Verifier_Result_Schema.md](Verifier_Result_Schema.md)). For a stable, app-consumable
envelope around that result — with a timestamp, optional provenance, a JSON Schema, and a
validator — see the [PQ Verifier Evidence Artifact](PQ_Verifier_Evidence_Artifact.md).

- **Independently hostable.** The verifier module ([`src/verifier/`](../src/verifier/))
  has no Hardhat dependency and no EVM private key. It can be vendored, re-hosted, or
  reimplemented by a third party to cross-check results.
- **Deterministic.** The same `(message, publicKey, signature)` inputs always produce
  the same result JSON, including the reason code and the input hashes.
- **Standards-anchored.** It checks ML-DSA-65 signature validity per **FIPS 204** using
  `@noble/post-quantum`, exercised against official NIST ACVP vectors (see
  [`test/MLDSAConformance.test.ts`](../test/MLDSAConformance.test.ts) and
  [`test/PQVerifier.test.ts`](../test/PQVerifier.test.ts)).

## What it is not

- It **does not custody funds.**
- It **does not store or require private keys** (no `ATTESTOR_PRIVATE_KEY`).
- It **does not sign attestations** or any other message.
- It **does not verify ML-DSA on-chain**, and it is **not** a ZK proof.
- It does not make this repository production custody, and it is not audited.

The attestation layer is **optional and separate**. Trusted attestation is **not** ZK,
and it is **not** on-chain ML-DSA verification. This repository remains
**research/testnet only**, with **no real funds**.

## Module layout

```text
src/verifier/
  schema.ts      result schema, reason codes, version constants (dependency-free leaf)
  result.ts      builds the structured result; hashes inputs with keccak256
  ml-dsa-65.ts   pure ML-DSA-65 verification → deterministic PQVerificationResult
```

The pure module never imports the attestation layer. The dependency direction is
one-way: the attestation layer consumes the verifier, never the reverse.

```text
src/verifier/ml-dsa-65.ts        (pure verification, no signing, no EVM key)
        ▲
        │ consumes verified result
        │
scripts/lib/attestation.ts       (optional EIP-712 attestation, trusted attestor key)
```

### Reason codes

Exactly one reason is reported per verification:

| Reason                       | Meaning                                               |
| ---------------------------- | ----------------------------------------------------- |
| `ML_DSA_65_VALID`            | Signature verified for the message and public key.    |
| `EMPTY_MESSAGE`              | The message had zero bytes.                            |
| `INVALID_PUBLIC_KEY_LENGTH`  | Public key was not the ML-DSA-65 length (1952 bytes). |
| `INVALID_SIGNATURE_LENGTH`   | Signature was not the ML-DSA-65 length (3309 bytes).  |
| `VERIFY_FAILED`              | Well-formed inputs, but the signature did not verify. |
| `VERIFY_EXCEPTION`           | The underlying verifier threw while checking.         |

Reason precedence is fixed: empty message → public-key length → signature length →
cryptographic verification.

## CLI usage

The standalone CLI requires **no** attestor key and never signs anything:

```bash
# Inline hex
npm run verifier:verify -- \
  --message 0x... \
  --public-key 0x... \
  --pq-signature 0x... \
  --json

# File inputs (hex files may contain 0x...; other files are treated as raw bytes)
npm run verifier:verify -- \
  --message-file ./message.bin \
  --public-key-file ./public-key.bin \
  --pq-signature-file ./signature.bin \
  --json
```

Rules:

- Each input accepts **exactly one** of an inline hex value or a file path.
- Inline values are **`0x`-prefixed, even-length hex only** (no base64). A file is
  read as hex when its contents start with `0x`, otherwise as raw bytes.
- Malformed input — non-hex characters, odd-length hex, an un-prefixed inline
  value, a missing input, or both inline and file forms for the same input —
  **exits non-zero** with a clear error and never produces a result.
- `--json` prints JSON only; without it, a concise human-readable result is printed.
- A **failed verification is still a successful process** (exit `0`) reporting
  `"verified": false`. Only malformed CLI input exits non-zero.

These encoding and failure rules are pinned by `test/PQVerifierCli.test.ts`, and the
verifier's closed reason-code set and one-way (no-signing, no-Hardhat, no-attestor-key)
boundary are pinned by `test/PQVerifier.test.ts` and `test/PQVerifierBoundary.test.ts`.

Example (valid library-generated fixture triple):

```bash
npm run verifier:verify -- \
  --message-file test/fixtures/mldsa/library-generated/message.hex \
  --public-key-file test/fixtures/mldsa/library-generated/public-key.hex \
  --pq-signature-file test/fixtures/mldsa/library-generated/signature.hex \
  --json
```

## Programmatic usage

```ts
import { verifyMLDSA65Detailed } from "./src/verifier/ml-dsa-65";

const result = verifyMLDSA65Detailed(publicKeyBytes, messageBytes, signatureBytes);
if (result.result.verified) {
  // result.result.reason === "ML_DSA_65_VALID"
}
```

A boolean convenience wrapper, `verifyMLDSA65(publicKey, message, signature)`, preserves
the historical helper signature used by the conformance tests and the attestation layer.

## Relationship to the attestation layer

[`scripts/lib/attestation.ts`](../scripts/lib/attestation.ts) now **consumes** this
module's result instead of owning the verification logic. After verification succeeds,
and only then, the attestor may sign an EIP-712 `PQCAttestation`
(see [Attestation_Verifier.md](Attestation_Verifier.md)). Real verify mode still refuses
demo and library-generated fixture material. The attestation path is a **trusted**
bridge into testnet contracts — it is not a substitute for native on-chain PQ
verification.

## Security posture

```text
Research prototype.
Testnet/local only.
Not audited.
Do not use real funds.
Trusted attestation is not trustless verification.
ZK/native PQ remains a future trust-minimization path.
```

See [Security_Assumptions.md](Security_Assumptions.md) and
[Verifier_Roadmap.md](Verifier_Roadmap.md).
