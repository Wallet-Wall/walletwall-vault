# PQ Verifier Reproducibility

> ⚠️ **Research prototype. Not audited. Testnet/local only. Do not use real funds.**
> Trusted attestation is not trustless verification. ZK / native PQ verification
> remains future trust-minimization work.

WalletWall's open PQ verifier is independently hostable and reproducible. It checks
ML-DSA-65 / FIPS 204 signature validity for provided message, public key, and signature
bytes. It does **not** custody funds, store private keys, sign attestations, verify
on-chain, or make WalletWall production-ready.

This document explains what "reproducible" means here, how two operators independently
confirm the same PQ material, and how pure verification differs from an optional EIP-712
attestation. For how to run the verifier, see
[PQ_Verifier_Operator_Guide.md](PQ_Verifier_Operator_Guide.md); for the result fields,
see [Verifier_Result_Schema.md](Verifier_Result_Schema.md).

## What "deterministic" means in this repo

Given the same input **bytes** — message, public key, signature — the verifier produces
the same structured result every time and on every machine. Specifically these fields are
deterministic for the same inputs:

- `input.messageHash`
- `input.publicKeyHash`
- `input.signatureHash`
- `result.verified`
- `result.reason`

The result schema intentionally carries **no timestamp, no nonce, and no host
information**, so there is nothing run-specific to differ. Two correct runs of the same
verifier version on the same bytes yield byte-identical result JSON.

`verifier.version` (currently `0.1.0`) is a local constant decoupled from the
repository's package version, so result determinism does not change when the repo bumps
its release. The verification outcome itself is anchored to FIPS 204 via official NIST
ACVP vectors (see [`test/MLDSAConformance.test.ts`](../test/MLDSAConformance.test.ts) and
[`test/PQVerifier.test.ts`](../test/PQVerifier.test.ts)).

## Why raw inputs are not printed by default

`input.*` carries only `0x`-prefixed **keccak256 hashes** of the supplied bytes, never the
raw bytes. This keeps results safe to log and publish while still letting anyone confirm
they verified the *same* inputs: matching `messageHash`, `publicKeyHash`, and
`signatureHash` proves identical input bytes without disclosing them. Public keys and
signatures are not secret, but hash-only output makes any raw disclosure a deliberate
choice rather than a default side effect.

## How two operators independently verify the same PQ material

1. Both operators obtain the same input bytes (e.g. a shared fixture, or hex strings
   exchanged out of band).
2. Each runs:

   ```bash
   npm run verifier:verify -- \
     --message <0x… or --message-file PATH> \
     --public-key <0x… or --public-key-file PATH> \
     --pq-signature <0x… or --pq-signature-file PATH> \
     --json
   ```

3. Each records the verifier **commit SHA**, the **verifier version**, the **command**,
   and the **result JSON**.
4. They compare `input.messageHash`, `input.publicKeyHash`, `input.signatureHash`,
   `result.verified`, and `result.reason`.

If all five match, both operators verified the same bytes and reached the same FIPS 204
conclusion. If the hashes match but `verified`/`reason` differ, they are not running the
same verifier code — reconcile the commit SHA and `verifier.version`.

## How to cite a verification result

In an audit or rehearsal write-up, cite a result by the facts needed to reproduce it:

```text
Verifier: walletwall-vault-pq-verifier@0.1.0
Repo commit: <git SHA>
Command: npm run verifier:verify -- --message-file … --public-key-file … --pq-signature-file … --json
Inputs (keccak256): messageHash=0x…, publicKeyHash=0x…, signatureHash=0x…
Result: verified=true, reason=ML_DSA_65_VALID
```

Anyone with the same input bytes and the cited commit can re-run the command and obtain
the identical result JSON.

## Why this is not a trustless proof

Reproducibility means *anyone running the open code on the same bytes gets the same
answer*. It does **not** mean the result is a cryptographic proof verifiable without
re-running the check. To trust a published result you either:

- re-run the verifier yourself on the same inputs, or
- trust the operator who ran it.

A **trustless** PQ proof — one a third party can verify succinctly without redoing the
ML-DSA work or trusting the runner — would require ZK or native on-chain PQ verification,
which remains future work (see [Verifier_Roadmap.md](Verifier_Roadmap.md)). The open
verifier reduces trust by making the check **open, hostable, and reproducible**; it does
not eliminate it.

## Pure verification vs optional EIP-712 attestation

Pure verification answers: "Does this ML-DSA-65 signature verify for this message and
public key?"

Attestation answers: "Did a configured EVM attestor sign a statement that it observed a
verification result?"

These are related but not equivalent. The current testnet contract consumes attestations.
The open verifier helps make the underlying PQ check reproducible.

| Aspect            | Pure verification (open verifier)        | EIP-712 attestation (optional)                  |
| ----------------- | ---------------------------------------- | ----------------------------------------------- |
| Question answered | Does the ML-DSA-65 signature verify?     | Did the configured attestor sign that it did?   |
| Output            | Deterministic result JSON (hashes only)  | An EVM attestor's EIP-712 signature             |
| Keys required     | None                                     | The trusted attestor's EVM private key          |
| Reproducible by   | Anyone, by re-running the open code      | Only verifiable as the attestor's signature     |
| Trust model       | Trust the runner, or re-run yourself     | Trust the configured attestor and its key/host  |
| On-chain role     | None                                     | Consumed by `AttestationPQCVerifier` on testnet |

The attestation layer (see [Attestation_Verifier.md](Attestation_Verifier.md)) **consumes**
a pure verification result before signing; it refuses demo and library-generated fixture
material in real verify mode. Attestation is a **trusted** bridge into testnet contracts —
it is not a ZK proof and not on-chain ML-DSA verification.

## Security posture

```text
Research prototype.
Testnet/local only.
Not audited.
Do not use real funds.
No custody. No private keys.
Deterministic verification result for the same input bytes.
Optional trusted attestation is separate from pure verification.
ZK/native PQ remains a future trust-minimization path.
```

See [Open_PQ_Verifier.md](Open_PQ_Verifier.md),
[Verifier_Result_Schema.md](Verifier_Result_Schema.md), and
[Security_Assumptions.md](Security_Assumptions.md).
