# PQ Verifier Operator Guide

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**
> Trusted attestation is not trustless verification. ZK / native PQ verification
> remains future trust-minimization work.

WalletWall's open PQ verifier is independently hostable and reproducible. It checks
ML-DSA-65 / FIPS 204 signature validity for provided message, public key, and signature
bytes. It does **not** custody funds, store private keys, sign attestations, verify
on-chain, or make WalletWall production-ready.

This guide shows an independent operator how to run the verifier themselves and how to
publish a result others can reproduce. For the verifier's scope see
[Open_PQ_Verifier.md](Open_PQ_Verifier.md); for the result fields see
[Verifier_Result_Schema.md](Verifier_Result_Schema.md); for reproducibility and how pure
verification differs from EIP-712 attestation see
[PQ_Verifier_Reproducibility.md](PQ_Verifier_Reproducibility.md).

## Who this guide is for

- **Independent verifier operators** who want to run the check on their own machine.
- **Auditors** cross-checking a claimed verification result.
- **Protocols** evaluating the verifier boundary before relying on it.
- **WalletWall contributors** reproducing results during review.
- **Developers** exercising the testnet vault rehearsal path.

You do not need to trust WalletWall's machine: you run the same open code on the same
input bytes and compare the structured result.

## Prerequisites

- **Node.js v18+ and npm** (the repository's stated baseline; CI and the optional
  Docker image use Node 20). The verifier CLI runs under CommonJS, so no `--esm` flag
  or Node-version gymnastics are required.
- `npm install` once in the repository root.
- **No wallet or EVM private key.** The verifier CLI never reads `ATTESTOR_PRIVATE_KEY`.
- **No RPC key.** It performs no on-chain calls.
- **No Dune key.** It performs no data queries.

```bash
git clone https://github.com/Wallet-Wall/walletwall-vault.git
cd walletwall-vault
npm install
```

> **Do not run this as a production custody service. This repository is research/testnet
> only, not audited, and not suitable for real funds.**

## Running the verifier

The command is `npm run verifier:verify -- <flags>`. Each of the three inputs accepts
**exactly one** of an inline hex value or a file path:

| Input         | Inline flag      | File flag             |
| ------------- | ---------------- | --------------------- |
| Message       | `--message`      | `--message-file`      |
| Public key    | `--public-key`   | `--public-key-file`   |
| PQ signature  | `--pq-signature` | `--pq-signature-file` |

Add `--json` for machine-readable output (JSON only). Omit it for a concise
human-readable summary.

- Hex files may contain a `0x`-prefixed value. Other files are treated as **raw bytes**.
- A **failed verification is still a successful process** (exit `0`) reporting
  `"verified": false`. Only malformed CLI input (e.g. both inline and file forms for one
  input, a missing input, or an unknown command) exits non-zero.

### Inline hex (JSON mode)

```bash
npm run verifier:verify -- \
  --message 0x... \
  --public-key 0x... \
  --pq-signature 0x... \
  --json
```

### File inputs (JSON mode)

```bash
npm run verifier:verify -- \
  --message-file ./message.bin \
  --public-key-file ./public-key.bin \
  --pq-signature-file ./signature.bin \
  --json
```

### Human-readable mode

Drop `--json`:

```bash
npm run verifier:verify -- \
  --message-file ./message.hex \
  --public-key-file ./public-key.hex \
  --pq-signature-file ./signature.hex
```

### Optional: run inside the existing Docker image

The repository already ships a Node 20 Docker image (see **Docker Support** in
[README.md](../README.md)). Because the verifier CLI is CommonJS, you can run it inside
that image by overriding the default command — no Docker changes are required:

```bash
docker run --rm walletwall-vault \
  npm run --silent verifier:verify -- \
  --message-file test/fixtures/mldsa/library-generated/message.hex \
  --public-key-file test/fixtures/mldsa/library-generated/public-key.hex \
  --pq-signature-file test/fixtures/mldsa/library-generated/signature.hex \
  --json
```

## Using the bundled fixtures

The repository ships test material you can verify directly. **These are test vectors,
not credentials.**

### Library-generated fixture (directly runnable)

`test/fixtures/mldsa/library-generated/` contains a deterministic, valid
`(message, publicKey, signature)` triple as `0x`-prefixed hex files:

```bash
npm run verifier:verify -- \
  --message-file test/fixtures/mldsa/library-generated/message.hex \
  --public-key-file test/fixtures/mldsa/library-generated/public-key.hex \
  --pq-signature-file test/fixtures/mldsa/library-generated/signature.hex \
  --json
```

Expected result (this is deterministic — every operator should see exactly this):

```json
{
  "schemaVersion": "walletwall.pq-verifier.v1",
  "verifier": { "name": "walletwall-vault-pq-verifier", "version": "0.1.0" },
  "algorithm": "ML-DSA-65",
  "fips": "FIPS-204",
  "mode": "pure",
  "input": {
    "messageHash": "0x736040b98747745e98dbbeb459df3c6f5dc3d89fd305bccade65d2807cb0530c",
    "publicKeyHash": "0x3ae18e10835136b3f369b331045bd230caefed3e5c32a3bd0be523a5ccda12f0",
    "signatureHash": "0x3ad471f5c1048bfc22a707479e3f827bd032da80870c98fbdef2b964ad50caed"
  },
  "result": { "verified": true, "reason": "ML_DSA_65_VALID" }
}
```

This fixture is library-generated, not an official NIST known-answer vector. See
[`test/fixtures/mldsa/library-generated/README.md`](../test/fixtures/mldsa/library-generated/README.md).

### Official NIST ACVP vectors (conformance anchor)

`test/fixtures/mldsa/nist-cavp/ml-dsa-65-sigver-acvp.json` holds a 6-vector subset (3
valid + 3 invalid) of the official NIST ACVP ML-DSA-65 sigVer vectors (FIPS 204, external
interface, pure mode). They are exercised in
[`test/MLDSAConformance.test.ts`](../test/MLDSAConformance.test.ts). Their hex fields are
stored **without** a `0x` prefix; prepend `0x` if you pass one inline to the CLI. See
[`test/fixtures/mldsa/nist-cavp/README.md`](../test/fixtures/mldsa/nist-cavp/README.md).

## Interpreting the output

The full field reference lives in
[Verifier_Result_Schema.md](Verifier_Result_Schema.md). In short:

- **`result.verified: true`** — the ML-DSA-65 signature verified for the supplied message
  and public key (`result.reason` is `ML_DSA_65_VALID`).
- **`result.verified: false`** — verification did not succeed; `result.reason` explains
  why.
- **`input.messageHash` / `publicKeyHash` / `signatureHash`** — `0x`-prefixed keccak256
  hashes of the supplied bytes. The raw bytes are never printed by default.

### Reason codes

| Reason                      | `verified` | Meaning                                               |
| --------------------------- | ---------- | ----------------------------------------------------- |
| `ML_DSA_65_VALID`           | `true`     | Signature verified for the message and public key.    |
| `EMPTY_MESSAGE`             | `false`    | The message had zero bytes.                            |
| `INVALID_PUBLIC_KEY_LENGTH` | `false`    | Public key was not the ML-DSA-65 length (1952 bytes). |
| `INVALID_SIGNATURE_LENGTH`  | `false`    | Signature was not the ML-DSA-65 length (3309 bytes).  |
| `VERIFY_FAILED`             | `false`    | Well-formed inputs, but the signature did not verify. |
| `VERIFY_EXCEPTION`          | `false`    | The underlying verifier threw while checking.         |

## Comparing outputs across operators

Two operators running the same input bytes must get the same result JSON. To compare:

1. Run the verifier with the same `--message*`, `--public-key*`, and `--pq-signature*`
   inputs and `--json`.
2. Compare `input.messageHash`, `input.publicKeyHash`, `input.signatureHash`,
   `result.verified`, and `result.reason`.
3. Do **not** compare logs, ordering of unrelated runs, or timestamps — the result schema
   has no timestamp, and matching the fields above is sufficient.

If the hashes match but `verified`/`reason` differ, the operators are not running the
same verifier code (check the commit SHA and verifier version). See
[PQ_Verifier_Reproducibility.md](PQ_Verifier_Reproducibility.md).

## What to publish when operating independently

To let others reproduce your claim, publish:

- the verifier **repository commit SHA** you ran,
- the **package version** and **verifier version** (`verifier.version` in the result,
  currently `0.1.0`),
- the exact **command** you ran,
- the **result JSON**,
- references to the **fixture or the input hashes** (`messageHash`, `publicKeyHash`,
  `signatureHash`) so others can confirm they verified the same bytes.

### What NOT to publish

- raw **private keys** of any kind,
- **seed phrases**,
- **PQ private keys**,
- unnecessary raw **signature or public key bytes** — unless you are intentionally
  disclosing a public test vector. (Public keys and signatures are not secret, but the
  default hash-only output keeps disclosures deliberate.)

## Operational boundary

The verifier CLI:

- does **not** attest,
- does **not** sign anything,
- does **not** submit transactions,
- does **not** custody assets,
- does **not** read `ATTESTOR_PRIVATE_KEY` or any private key.

It answers one question and returns a structured result. Bridging a verified result into
a testnet contract is a **separate, optional, trusted** step handled by the attestation
layer — see [Attestation_Verifier.md](Attestation_Verifier.md) and
[PQ_Verifier_Reproducibility.md](PQ_Verifier_Reproducibility.md). That path is not a ZK
proof and not on-chain ML-DSA verification.

## Security posture

```text
Research prototype.
Testnet/local only.
Not audited.
Do not use real funds.
No custody. No private keys.
Trusted attestation is not trustless verification.
ZK/native PQ remains a future trust-minimization path.
```

See [Security_Assumptions.md](Security_Assumptions.md) and
[Verifier_Roadmap.md](Verifier_Roadmap.md).
