# ZK Adapter Evidence Endpoint (spike)

> **Research prototype. Not audited. Testnet/local only. No real funds.**
> A non-production SPIKE: no server, no network listener, read-only. It serves
> evidence — not a proof, not production ZK verification, not on-chain ML-DSA
> verification.

This spike defines the **response-shape contract** for a hosted, **read-only**
endpoint that serves the
[ZK verifier adapter boundary](ZK_Verifier_Adapter_Boundary.md)
(`walletwall.zk-verifier-adapter.v1`) to the private WalletWall app, with caching.

- **Example response:** [`evidence/zk/zk-adapter-evidence-response.example.json`](../evidence/zk/zk-adapter-evidence-response.example.json)
- **Schema:** [`evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json`](../evidence/zk/schema/zk-adapter-evidence-response.v1.schema.json)
- **Handler + serializer + validator:** [`scripts/lib/zk-adapter-endpoint.ts`](../scripts/lib/zk-adapter-endpoint.ts)
- **Generator:** [`scripts/generate-zk-adapter-evidence-response.ts`](../scripts/generate-zk-adapter-evidence-response.ts)

Like [`scripts/lib/hosted-verifier-demo.ts`](../scripts/lib/hosted-verifier-demo.ts),
this is a **pure, transport-agnostic** request→response function. It ships **no
server, no listener, and no deployed-service requirement** — it exists to evaluate
the shape and caching contract of a future hosted endpoint, not to run one.

## Success response (200)

The `walletwall.zk-adapter-evidence-response.v1` success response wraps the
committed adapter with a served-at timestamp and a strong content-hash ETag:

```jsonc
{
  "schema": "walletwall.zk-adapter-evidence-response.v1",
  "service": "walletwall-zk-adapter-evidence-demo",
  "mode": "spike-non-production",
  "status": 200,
  "ok": true,
  "contentType": "application/json",
  "servedAt": "<ISO-8601 UTC>",
  "etag": "0x<keccak256 of the canonical adapter JSON>",
  "adapter": { /* the full walletwall.zk-verifier-adapter.v1 boundary */ },
  "limitations": [ /* spike / read-only / gated / not-audited / testnet / no-real-funds */ ],
  "regeneration": { "command": "npm run zk:adapter:response", "deterministic": true }
}
```

The validator (`validateAdapterEvidenceResponse`) reuses `validateAdapter` for the
embedded adapter and additionally requires that `etag == keccak256(adapter)`, so
the served evidence and its cache key can never disagree.

## Conditional GET (caching contract)

`handleAdapterEvidenceRequest(request, adapter)` is read-only and answers:

| Request | Response |
| --- | --- |
| `GET` (or no method) | `200` with the adapter + `etag` |
| `GET` with `ifNoneMatch === etag` | `304 Not Modified` (no body) |
| `GET` with a stale `ifNoneMatch` | `200` with the adapter |
| non-`GET` method | `405 Method Not Allowed` |
| unknown request field / non-object | `400 Bad Request` |

The app fetches once, stores the `etag`, and sends `ifNoneMatch` on re-fetch; a
`304` lets it keep its cached evidence.

## Validate / regenerate locally

```bash
npm run validate:zk-response   # validate the committed example (shape + adapter + etag + 304 + no drift)
npm run zk:adapter:response    # regenerate it from the committed adapter
```

## What it is NOT

- It does **not** run a server, open a network listener, or require any deployed
  service or secret.
- It performs **no** vault write, transaction, deploy, or on-chain call — it serves
  read-only evidence.
- The served adapter is **not** a proof, **not** production ZK verification, and
  **not** on-chain ML-DSA verification. The active on-chain SP1 verifier is a mock
  and heavy proving stays gated behind `RUN_SP1_E2E=1`.
- It is **not** audited. Mainnet remains gated by audit, funding, and operational
  controls.

See [WalletWall app boundary](WALLETWALL_APP_BOUNDARY.md) for how the private app
may reference this read-only evidence.

## Follow-up

Extend the adapter to carry a real (gated) Groth16 proof + program vKey once an
external prover produces one, and add a negative-path response schema (304/4xx)
spec — still without claiming production ZK verification or on-chain readiness.
