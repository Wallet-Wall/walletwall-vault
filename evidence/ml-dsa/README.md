# ML-DSA evidence

Read-only, app-consumable ML-DSA (FIPS 204) evidence for this **research
prototype**. Not audited. Testnet/local only. No real funds.

- [`manifest.json`](manifest.json) — the deterministic ML-DSA evidence manifest:
  an index over the repository's committed ML-DSA evidence artifacts, recording
  keccak256 input hashes, off-chain verification results, artifact integrity
  hashes, the evidence boundary, and an explicit limitations list. **Hashes only
  — never raw key, signature, or message bytes.**
- [`schema/ml-dsa-evidence-manifest.v1.schema.json`](schema/ml-dsa-evidence-manifest.v1.schema.json)
  — the JSON Schema for the manifest.

This is evidence only: **not** a signature, **not** an attestation, **not** a ZK
proof, and **not** on-chain ML-DSA verification. The active testnet on-chain
verifier is a mock; the non-mock path trusts an EIP-712 attestor and verifies
ML-DSA off-chain. Mainnet is gated by audit, funding, and operational controls.

Validate and regenerate locally:

```bash
npm run validate:evidence    # validate the committed manifest
npm run evidence:manifest    # regenerate it from its committed sources
```

See [docs/ML_DSA_Evidence_Manifest.md](../../docs/ML_DSA_Evidence_Manifest.md)
for the full description.
