# ZK Verifier Adapter Boundary

> **Research prototype. Not audited. Testnet/local only. No real funds.**
> This is a read-only boundary descriptor and an alignment check — not a proof,
> not production ZK verification, and not on-chain ML-DSA verification.

The **ZK verifier adapter boundary** is a single, deterministic, read-only object
that ties together the four ML-DSA-65 pieces this repository already ships and
shows — fully cross-checked — how they relate:

| Piece | Source |
| --- | --- |
| SP1 **proof input** | [`zkvm/fixtures/mldsa65-withdrawal.inputs.json`](../zkvm/fixtures/mldsa65-withdrawal.inputs.json) (`walletwall.sp1-proof-input.v1`) |
| SP1 guest **journal** | the 160-byte public values the guest commits and `ZKMLDSAVerifier` decodes |
| gated **proof** slot | no real Groth16 bytes in CI; `status: "gated"` |
| read-only **evidence** | [`evidence/ml-dsa/manifest.json`](../evidence/ml-dsa/manifest.json) (`walletwall.ml-dsa-evidence-manifest.v1`) |

- **Adapter:** [`evidence/zk/zk-verifier-adapter.json`](../evidence/zk/zk-verifier-adapter.json)
- **Schema:** [`evidence/zk/schema/zk-verifier-adapter.v1.schema.json`](../evidence/zk/schema/zk-verifier-adapter.v1.schema.json)
- **Builder + validator:** [`scripts/lib/zk-verifier-adapter.ts`](../scripts/lib/zk-verifier-adapter.ts)
- **Generator:** [`scripts/generate-zk-verifier-adapter.ts`](../scripts/generate-zk-verifier-adapter.ts)

## The on-chain verifier role it records

The [`ZKMLDSAVerifier`](../contracts/verifiers/ZKMLDSAVerifier.sol) (`IPQCVerifier`)
contract is the trustless target: `verify(digest, publicKey, proof)` decodes the
160-byte journal, cross-checks the digest / public-key hash / chain id / verifier
address, and calls the SP1 verifier. But:

```jsonc
"onChainVerifier": {
  "interface": "IPQCVerifier",
  "contract": "ZKMLDSAVerifier",
  "algorithmId": "ZK-ML-DSA-65",
  "sp1Verifier": "mock",            // the active testnet SP1 verifier is a mock
  "onChainVerification": false,     // no live/production on-chain ML-DSA verification
  "custody": false
}
```

## The binding the validator enforces

The core check is that the embedded **journal decodes to exactly the hashes the
proof input declares**, which proves the whole object describes one ML-DSA-65
material set and carries hashes only:

- `keccak256(journal.withdrawalDigest) == proofInput.messageHash`
- decoded `publicKeyHash == proofInput.publicKeyHash`
- decoded `signatureHash == proofInput.signatureHash`
- decoded `chainId` / `verifierAddress` match the journal fields
- `journal.publicValuesHash == keccak256(journal.publicValues)` and the journal is
  exactly 160 bytes.

The generator additionally cross-checks, on disk, that these hashes match the
ML-DSA evidence manifest's source entry and that the referenced SP1 input file is
intact.

```bash
npm run validate:zk-adapter   # validate the committed adapter (shape + binding + sources + no drift)
npm run zk:adapter            # regenerate it deterministically
```

## What it is NOT

- It does **not** prove anything. No Groth16 proof bytes are present; heavy SP1
  proving stays gated behind `RUN_SP1_E2E=1` and an external prover (see
  [ZK Prover Runbook](ZK_Prover_Runbook.md)).
- It does **not** perform on-chain ML-DSA verification. The active testnet on-chain
  verifier is a **mock**; the non-mock production path today is the trusted EIP-712
  attestor, not a ZK proof.
- It does **not** prove production custody security and is **not** audited.
- Mainnet remains gated by audit, funding, and operational controls.

## How the app references it

The adapter is **read-only evidence**. The private WalletWall app may display the
boundary, the proof-input/journal/evidence linkage, the gated proof status, and
the limitations. It must not treat the adapter as authorization for any vault
write, and it must surface the limitations alongside any displayed status. See
[WalletWall app boundary](WALLETWALL_APP_BOUNDARY.md).

## Follow-up

A natural next step is a **hosted ZK adapter evidence endpoint** spec, or
extending the adapter to carry a real (gated) Groth16 proof + program vKey once an
external prover produces one — still without claiming production ZK verification
or on-chain readiness.
