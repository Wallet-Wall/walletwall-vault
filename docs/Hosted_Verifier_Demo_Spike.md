# Hosted PQ Verifier — Demo / Spike

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**
> This is a **spike**, not a service. **No** server, network listener, secret,
> deployed endpoint, or production infrastructure is added. It exists only to
> evaluate the boundary and threat model of a _future_ hosted verifier.

## Summary

The open PQ verifier ([`src/verifier/`](../src/verifier/)) is already
independently hostable: it is a pure function with no Hardhat dependency, no EVM
key, and no signing. This spike asks a narrow question:

> If we exposed the open verifier over a request/response transport, what would
> the boundary look like, and what would it have to refuse?

It answers with a **transport-agnostic, in-process handler**
([`scripts/lib/hosted-verifier-demo.ts`](../scripts/lib/hosted-verifier-demo.ts))
plus a runnable demo
([`scripts/hosted-verifier-demo.ts`](../scripts/hosted-verifier-demo.ts),
`npm run hosted:demo`). The handler accepts a JSON-shaped request, strictly
decodes and size-bounds it, runs the pure verifier, and returns the stable
`walletwall.pq-verifier-evidence.v1` envelope (hashes only) with an HTTP-like
status code. **It never opens a socket.** Wrapping it in an actual HTTP server is
deliberately out of scope and gated on the go/no-go criteria below.

```bash
npm run hosted:demo                          # prints valid / tampered / malformed responses
npx hardhat test test/HostedVerifierDemo.test.ts
```

## Threat model

### Inputs accepted

| Field                 | Type                  | Constraint                                                      |
| --------------------- | --------------------- | --------------------------------------------------------------- |
| `message`             | `0x` hex string       | even-length hex, ≤ 4096 bytes                                   |
| `publicKey`           | `0x` hex string       | even-length hex, ≤ 4096 bytes                                   |
| `signature`           | `0x` hex string       | even-length hex, ≤ 8192 bytes                                   |
| `source` _(optional)_ | `{ type, reference }` | `type` in the closed evidence source set; non-empty `reference` |

Unknown fields are rejected. The per-field byte caps are a **DoS guard**: they
bound per-request memory/CPU while still leaving near-miss length errors to the
verifier's reason codes (absurd inputs are rejected before any verification).

### Outputs returned

A deterministic response `{ service, mode, status, ok, evidence? , error? }`:

- `200 OK` — request well-formed; `evidence` is the hashes-only verification
  envelope. **A failed _verification_ is still a 200** (`evidence.result.verified:
false`); only a malformed/oversized _request_ is an error.
- `400 BAD_REQUEST` — malformed request (missing/extra field, bad hex, bad source).
- `413 PAYLOAD_TOO_LARGE` — a field exceeds its byte cap.

The response carries **only keccak256 hashes** of the inputs — never raw key,
signature, or message bytes (pinned by tests).

### What the hosted boundary must NEVER do (and does not)

- **No private keys.** Reads no `ATTESTOR_PRIVATE_KEY` and no environment variable.
- **No signing.** No ML-DSA signing, no EIP-712, no EVM signing.
- **No attestor path.** The trusted attestation layer is never invoked; this is
  pure verification only.
- **No contract writes.** No signer, no `sendTransaction`, no contract instantiation.
- **No custody.** It holds nothing and moves no funds.
- **No raw-material echo.** Inputs are reduced to hashes before anything is returned.

These are enforced both at runtime (the handler only imports
`verifyMLDSA65Detailed` + `buildEvidence`) and by a **static source guard** in
`test/HostedVerifierDemo.test.ts`.

### Rate-limit considerations (for a real deployment — NOT in this spike)

A real hosted endpoint would additionally need, all of which are **out of scope here**:

- per-client rate limiting / quotas (requires per-client state and infra),
- a global concurrency cap and request timeout,
- a maximum request-body size enforced at the transport layer (the handler's
  per-field caps are a second line of defence, not the first),
- structured request logging that records **only hashes**, never raw inputs,
- abuse monitoring and an Attack-Mode / WAF posture.

### Deterministic response schema

Responses are a pure function of the request and an injected clock (`opts.now`);
the only non-deterministic field is the evidence timestamp, which a caller can
pin. This makes the boundary cacheable and reproducible.

## Go / No-Go criteria for building a real hosted verifier

**Go** (proceed to a minimal hosted service) only when all hold:

1. There is a concrete consumer that needs verification over a network boundary
   (vs. vendoring the pure verifier), with a defined SLA.
2. Rate limiting, request size limits, timeouts, and abuse monitoring are
   specified and owned.
3. Logging/observability is designed to record **hashes only** (no raw inputs).
4. The deployment target, ownership, and on-call are agreed; secrets management
   is **not required** (the verifier needs none) and that property is preserved.
5. A security review of the transport wrapper is scheduled.

**No-Go / stop** if any hold:

- The endpoint would need to sign, hold a key, or write to a chain → that is the
  **trusted attestation** boundary, not this one; keep it separate.
- It would need to custody or move funds.
- It would imply on-chain or trustless verification it does not perform.
- It cannot guarantee hashes-only logging.

## Outcome of this spike

A hosted verifier is **feasible and low-risk at the boundary level**: the core is
already a pure, keyless, hashes-only function and this handler shows the request,
response, size-bounding, and refusal surface needed to expose it. **No production
service, server, secret, or custody behavior was added** — only the in-process
handler, a demo runner, and tests. The decision to build a real endpoint remains
**deferred** to the go/no-go criteria above.

## Related

- [Open_PQ_Verifier.md](Open_PQ_Verifier.md) · [PQ_Verifier_Operator_Guide.md](PQ_Verifier_Operator_Guide.md) · [PQ_Verifier_Evidence_Artifact.md](PQ_Verifier_Evidence_Artifact.md)
- [ZK_PQ_Status_Matrix.md](ZK_PQ_Status_Matrix.md) · [THREAT_MODEL.md](THREAT_MODEL.md) · [Security_Assumptions.md](Security_Assumptions.md)
