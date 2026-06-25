# ML-DSA Evidence Manifest

> **Research prototype. Not audited. Testnet/local only. No real funds.**
> This document describes read-only evidence. It is not a signature, not an
> attestation, not a ZK proof, and not on-chain ML-DSA verification.

The **ML-DSA evidence manifest** is a single, deterministic, machine-checkable
file that records the current ML-DSA / post-quantum **evidence boundary** of this
repository in one place the private WalletWall app (or any third party) can
reference read-only.

- **Manifest:** [`evidence/ml-dsa/manifest.json`](../evidence/ml-dsa/manifest.json)
- **Schema:** [`evidence/ml-dsa/schema/ml-dsa-evidence-manifest.v1.schema.json`](../evidence/ml-dsa/schema/ml-dsa-evidence-manifest.v1.schema.json)
- **Builder + validator:** [`scripts/lib/ml-dsa-evidence-manifest.ts`](../scripts/lib/ml-dsa-evidence-manifest.ts)
- **Generator:** [`scripts/generate-mldsa-evidence-manifest.ts`](../scripts/generate-mldsa-evidence-manifest.ts)

## What it is

The manifest is an **index** over the repository's already-committed,
drift-checked ML-DSA evidence artifacts:

- the two [`walletwall.pq-verifier-evidence.v1`](PQ_Verifier_Evidence_Artifact.md)
  examples (one accepted, one rejected), and
- the deterministic library-generated ML-DSA-65 fixture that the SP1 proof-input
  path draws from.

For each indexed artifact it records:

| Field | Meaning |
| --- | --- |
| `id`, `kind`, `sourceType`, `reference` | The fixture identity and provenance (NIST ACVP / library-generated). |
| `parameterSet`, `verifierMode` | `ML-DSA-65` (FIPS 204), verified by the open `pure` off-chain verifier. |
| `messageHash`, `publicKeyHash`, `signatureHash` | keccak256 of the message, public key, and signature — **never the raw bytes**. |
| `result` | The off-chain verification outcome: `accepted` + a closed `reason` code. |
| `artifactPath`, `artifactHash` | A repo-relative pointer to the referenced file and the keccak256 integrity hash of its bytes. |

On top of the per-entry index it records the overall `boundary` and an explicit
`limitations` list.

## The boundary it records

```jsonc
"boundary": {
  "verificationMode": "off-chain",          // ML-DSA is verified off-chain, not on-chain
  "attestation": "trusted-attestor",        // the non-mock on-chain path trusts an EIP-712 attestor
  "onChainMLDSAVerification": false,         // no native/ZK on-chain ML-DSA verification exists
  "onChainVerifierIsMock": true,            // the active testnet on-chain verifier is a mock
  "custody": false                          // this repository does not custody funds
}
```

## Limitations

The manifest carries these limitations, and the validator enforces that each
topic is disclosed:

- **Off-chain post-quantum verification only** — ML-DSA-65 signatures are
  verified off-chain, not on-chain.
- **Trusted-attestor boundary** — the non-mock `AttestationPQCVerifier` trusts an
  authorized EIP-712 attestor and does not execute ML-DSA on-chain.
- **Mock verifier limitations** — the active testnet on-chain verifier is a mock
  that performs no real ML-DSA verification.
- **Research prototype — not audited.**
- **Testnet / reference path only** — no mainnet deployment and no production
  custody.
- **No real funds.**

Mainnet remains gated by audit, funding, and operational controls. The manifest
makes no production-custody, mainnet-ready, or "quantum-proof" claim.

## Validating locally

```bash
npm run validate:evidence    # validate the committed manifest (shape, sources, no drift)
npm run evidence:manifest    # regenerate the manifest from its committed sources
```

`validate:evidence` checks the committed manifest in three independent ways:

1. **Shape** — the authoritative TypeScript validator
   (`scripts/lib/ml-dsa-evidence-manifest.ts`) rejects unknown keys at every
   level, malformed hashes/timestamps, an under-marked boundary, missing
   limitation topics, an inconsistent `accepted`/`reason` pairing, overclaim
   language on asserted fields, and any embedded raw key/signature material.
2. **Source integrity** — every entry's `artifactHash` must equal the keccak256
   of the file it points at, and each `pq-verifier-evidence` entry must mirror the
   input hashes carried by the referenced evidence artifact.
3. **No drift** — the committed manifest must equal a freshly built one.

## How the app references it

The manifest is **read-only evidence**. The private WalletWall app may fetch and
display the boundary facts, per-entry results, and limitations. It must not treat
the manifest as authorization to perform vault writes, and it must surface the
limitations alongside any displayed result. See
[WalletWall app boundary](WALLETWALL_APP_BOUNDARY.md).

## Relationship to the SP1 proof path

The manifest is the **input contract** for a future Rust/SP1 proof-input
scaffold: the `library-generated` ML-DSA-65 entry is the same deterministic
fixture the SP1 journal/public-values path
([SP1 smoke lane](SP1_Smoke_Lane.md), [PQ proof artifact](PQ_Proof_Artifact.md))
consumes. A proof-input fixture can mirror the manifest's hashes and parameter
set without claiming production ZK verification or on-chain readiness.
