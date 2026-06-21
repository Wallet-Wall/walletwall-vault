# Verifier Result Schema

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**

This document describes the deterministic result returned by the open PQ verifier
([`src/verifier/`](../src/verifier/)). The schema is defined in
[`src/verifier/schema.ts`](../src/verifier/schema.ts). For the verifier's scope and
guarantees, see [Open_PQ_Verifier.md](Open_PQ_Verifier.md).

The result is **deterministic**: identical `(message, publicKey, signature)` inputs
always produce byte-identical JSON. It contains only keccak256 **hashes** of the inputs
— never the raw public key, signature, or message bytes — so it is safe to log and
serve. The open verifier does not custody funds, does not store private keys, and does
not sign attestations.

## Schema version

`schemaVersion` is the stable identifier `walletwall.pq-verifier.v1`. It is bumped only
on a breaking change to the result shape.

`verifier.version` is the **open verifier module's own version**, deliberately decoupled
from the repository's `package.json` version so that result determinism does not depend
on repo release bumps. The current value is a local constant (`0.1.0`) documented in
`src/verifier/schema.ts`.

## Shape

```ts
export interface PQVerificationResult {
  schemaVersion: "walletwall.pq-verifier.v1";
  verifier: {
    name: "walletwall-vault-pq-verifier";
    version: string;
  };
  algorithm: "ML-DSA-65";
  fips: "FIPS-204";
  mode: "pure";
  input: {
    messageHash: string; // 0x-prefixed keccak256 of the message bytes
    publicKeyHash: string; // 0x-prefixed keccak256 of the public key bytes
    signatureHash: string; // 0x-prefixed keccak256 of the signature bytes
  };
  result: {
    verified: boolean;
    reason: string; // one of the reason codes below
  };
}
```

## Fields

| Field                | Type      | Notes                                                                |
| -------------------- | --------- | -------------------------------------------------------------------- |
| `schemaVersion`      | string    | Always `walletwall.pq-verifier.v1` for this schema.                  |
| `verifier.name`      | string    | Always `walletwall-vault-pq-verifier`.                              |
| `verifier.version`   | string    | Open verifier module version (local constant, not the repo version). |
| `algorithm`          | string    | Always `ML-DSA-65`.                                                  |
| `fips`               | string    | Always `FIPS-204` (FIPS 204, written with a hyphen in this schema).  |
| `mode`               | string    | Always `pure` — verification only, no signing, no custody.          |
| `input.messageHash`  | string    | `keccak256(message)`; raw message bytes are never included.          |
| `input.publicKeyHash`| string    | `keccak256(publicKey)`; raw key bytes are never included.            |
| `input.signatureHash`| string    | `keccak256(signature)`; raw signature bytes are never included.      |
| `result.verified`    | boolean   | `true` only when ML-DSA-65 verification succeeds.                    |
| `result.reason`      | string    | Exactly one reason code (see below).                                |

> Note: `fips` uses the value `FIPS-204` (hyphenated) as the canonical schema string.
> Prose elsewhere in this repository refers to the standard as "FIPS 204".

## Reason codes

| Reason                      | `verified` | Meaning                                               |
| --------------------------- | ---------- | ----------------------------------------------------- |
| `ML_DSA_65_VALID`           | `true`     | Signature verified for the message and public key.    |
| `EMPTY_MESSAGE`             | `false`    | The message had zero bytes.                            |
| `INVALID_PUBLIC_KEY_LENGTH` | `false`    | Public key was not the ML-DSA-65 length (1952 bytes). |
| `INVALID_SIGNATURE_LENGTH`  | `false`    | Signature was not the ML-DSA-65 length (3309 bytes).  |
| `VERIFY_FAILED`             | `false`    | Well-formed inputs, but the signature did not verify. |
| `VERIFY_EXCEPTION`          | `false`    | The underlying verifier threw while checking.         |

Reason precedence is fixed and checked in this order:

1. `EMPTY_MESSAGE`
2. `INVALID_PUBLIC_KEY_LENGTH`
3. `INVALID_SIGNATURE_LENGTH`
4. cryptographic verification → `ML_DSA_65_VALID` / `VERIFY_FAILED` / `VERIFY_EXCEPTION`

## Example

```json
{
  "schemaVersion": "walletwall.pq-verifier.v1",
  "verifier": {
    "name": "walletwall-vault-pq-verifier",
    "version": "0.1.0"
  },
  "algorithm": "ML-DSA-65",
  "fips": "FIPS-204",
  "mode": "pure",
  "input": {
    "messageHash": "0x736040b98747745e98dbbeb459df3c6f5dc3d89fd305bccade65d2807cb0530c",
    "publicKeyHash": "0x3ae18e10835136b3f369b331045bd230caefed3e5c32a3bd0be523a5ccda12f0",
    "signatureHash": "0x3ad471f5c1048bfc22a707479e3f827bd032da80870c98fbdef2b964ad50caed"
  },
  "result": {
    "verified": true,
    "reason": "ML_DSA_65_VALID"
  }
}
```
