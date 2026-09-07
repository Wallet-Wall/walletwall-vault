# SD-4 — temporal adjudication (append-only correction to PR #188)

**This document does not amend `c67d1439`.** PR #188's ledger entry, its two
reproduction suites, and its stated conclusion are left exactly as published.
They are valuable *falsified* evidence: the reasoning is legible, the
experiments reproduce, and the conclusion is wrong in a way that is only
visible once a second measurement axis is applied. Rewriting it would destroy
the record of how the error survived three rounds of review.

Everything below is additive. Where it contradicts #188, the contradiction is
stated here and the original text is left standing.

---

## 1. Status

| Claim | Status | Established by |
| --- | --- | --- |
| `SD4_SNAPSHOT_DESIGN_REJECTED` | **CONFIRMED** | #188, unchanged |
| `SD4_GENERAL_IMPOSSIBILITY` | **REFUTED** | round 3 (candidate G′ exists) |
| `CANDIDATE_F`, `F_SCOPED` | KILLED | round 3 — asset-control cut `min(2,k) → 1` |
| `CANDIDATE_G` | KILLED | round 2 — inert on the `pqSignatureLength` axis |
| `CANDIDATE_H1..H4`, `H_PRECISE` | KILLED | round 3 — meter is orderable away; meters a corpse |
| `CANDIDATE_G_PRIME` (atomic) | **KILLED** | **lane T** — T1, T2, T10 |
| `CANDIDATE_G_PRIME_NOTICE` | **KILLED** | **lane T** — T10 |
| `CANDIDATE_G_PRIME_DELAY` | **KILLED** | **lane T** — T7b |
| `CANDIDATE_G_PRIME_RESET` | **KILLED** | **lane T** — T7b |
| `CANDIDATE_G_PRIME_CLAMPED` | **SURVIVES_CURRENT_BATTERY** | lane T — T11a, T11b |
| `CANDIDATE_G_PRIME_FINAL_ADMISSION` | **NOT ESTABLISHED** | — |

Round 3's own headline — "G′ survives" — is **superseded**. Plain G′ is dead.

---

## 2. The error in round 3's method

Round 3 adjudicated every candidate against `AUTHORITY.md` §3, whose rows are
**minimum compromise cuts**, and read *cut unchanged* as the safety verdict.

A cut census answers **who** must be compromised. It is structurally incapable
of answering **when** the values they install become observable. Two designs
with identical cuts on every row can differ completely on that second quantity,
and G′ is exactly such a design. Round 3 did surface the atomic ratify+execute
composition, but recorded it as a *disclosure* rather than pricing it as an
authority dimension — which is the same category of error as #188's, one axis
later.

## 3. Why visibility is load-bearing here

Derived from source, not assumed (lane T, `T0a`–`T0c`):

- `setGuardians` is **quorum-gated** (`DOMAIN_GUARDIAN`, `_requireQuorum`), so
  the credential cannot rotate out a compromised roster.
- `rotateCredential` does **not** defeat a pending recovery — `executeRecovery`
  measures against `r.proposedSigner` / `r.proposedPqKeyHash`, by design.
- therefore **`cancelRecovery` is the credential's only remedy**, and
  `initiateRecovery:1177` carries `challengesUsed: recovery.challengesUsed`
  **forward across episodes**. Only `delete recovery` on a *successful* execute
  resets it.

So the credential holds `CHALLENGE_LIMIT` = **2 cancels for the lifetime of the
vault**, not two per episode (`T0b`). A remedy that scarce is spent on what the
payload *looks like*. The security property is therefore not "seven days
elapse" — it is **the coincidence between the payload a defender inspects and
the payload that executes**, and that is what plain G′ destroys.

The maliciousness predicate is the kernel's own, not a narrative: a payload
naming the honest verifier installs a real two-factor credential; a payload
naming `alwaysTrue` collapses the PQ conjunct so the signer's ECDSA key spends
alone. This matters because **`proposedVerifier` is the only component of a
recovery payload carrying an objective, defender-checkable red flag.** A
compromised quorum's *nominee* is indistinguishable from a legitimate one — the
credential holder cannot tell from the payload who ought to own the vault. A
payload naming `alwaysTrue` is something no legitimate recovery ever contains.

### 3.1 The harm lands in no cell of the cut table

`AUTHORITY.md` §3's **"Silent crypto downgrade"** row reads `unreachable`, and
that verdict is about a **single factor**: its enforcement column closes with
*"The escape from a dead verifier is the GUARDIAN quorum, not one factor."* The
quorum installing a permissive verifier at `k` is the row's explicitly intended
escape, not a violation of it.

So the row does **not** move under G′, and `T9` confirms the reason: G′ never
writes `securityFloor`. This is exactly where design E differs — `AUTHORITY.md:78`
records that E moves the row from `unreachable` to `k` precisely because it
grants a floor write. G′ grants no capability at all; `proposedVerifier` was
already the quorum's parameter.

**And that is the problem.** The guardian escape was tolerable because it is
*loud*: `initiateRecovery` emits `RecoveryInitiated`, and the payload sits in
storage for `RECOVERY_DELAY` under a credential veto. The row's title word
**"silent"** is never examined in its enforcement column, which argues only
about *who*. Plain G′ makes that escape **quiet without moving any number in
the table**. The table has no column in which the change could be recorded —
which is why round 3, having checked every row, concluded the design was safe.

This is the general lesson, and it outlives SD-4: **a minimum-cut census is a
complete answer to "who" and silent on "when". A design can be neutral on every
row and still expand authority.**

## 4. The measured ladder

Guaranteed notice on the payload that *actually executes*, adversary playing
the latest amendment each rung permits (`T10`, `T11b`):

| Rung | Guaranteed notice | Verdict |
| --- | --- | --- |
| `atomic` — amend any time before expiry | **0 s** | killed |
| `notice` — amend only strictly before maturity | **< 60 s** | killed |
| `delay` — amended payload ages `RATIFICATION_DELAY` | 3 d | killed by T7b |
| `reset` — amended payload ages `RECOVERY_DELAY` | 7 d | killed by T7b |
| `clamped` — `delay`, refusing an amendment that could not age and still run | 3 d | **survives** |

`notice` is **my own round-3 proposal**, and it is worthless: "before maturity"
is unbounded below, so maturity-minus-one-second is a legal amendment.
Separating ratification from execution into two transactions is not notice;
only an enforced interval between them is.

`T7b` is a defect **introduced by the remediation**, found by construction and
with no adversary present: on `delay` and `reset`, a late amendment can push
`executableAt` past `expiresAt`, leaving an episode whose execution window is
closed from *both* sides — `TooEarly` before the new maturity, `Expired` after
it. `clamped` refuses such an amendment instead, and `T11a` shows the approved
episode then survives intact on its original schedule.

## 5. What G′-CLAMPED does and does not touch

Asserted, not argued (`T3`–`T9`):

- `securityFloor` is **never written** — `I-FLOOR-SHAPE-IMMUTABLE` intact. This
  is the exact assertion design E failed.
- `proposedSigner` is not a parameter on any rung; no calldata shape can carry
  one (`T8`).
- `challengesUsed` is never written: ratification neither refunds nor consumes
  the credential's veto (`T5`).
- `expiresAt` is never extended by any rung (`T7`).
- a stale attestation does not bind a later episode — and fails
  **`QuorumNotMet`, not `BadRoster`**, because the digest is recomputed from the
  live `executableAt`, so the binding is cryptographic rather than a comparison
  that could be forgotten (`T3`).
- a roster change invalidates a ratified request (`T4`).
- an expired episode cannot be revived by ratifying it (`T6`). The pre-existing
  residue that `active` is never cleared on expiry is unchanged — G′ neither
  causes nor repairs it.

## 6. Oracle repair

`stateful/invariants.ts` set `G-DECLARATION-SUBORDINATE-TO-RECOVERY`'s `source`
to *"setVerifier's `I-DECLARATION-SUBORDINATE-TO-LIVE-RECOVERY` **refuses** the
requirePq false → true edge…"*. No such identifier exists in the Solidity, and
`VaultKernelPrototype.sol:906-918` records that this interlock *"was written,
measured and REMOVED."* The `check` was correct; the provenance claim was
inverted.

The field now declares the property an **open requirement with no establishing
mechanism**, names the source location recording the removal, and warns that a
remediation which repairs the harm still trips the predicate — because the
predicate observes the transition and cannot observe the repair. Without that
warning, a correct G′ scores as SD-4 and the campaign counts the fix as the
defect.

`STATEFUL_AUTHORITY_EVIDENCE.json` embeds `{name, source}` per invariant and is
therefore **stale** with respect to this edit until regenerated.

## 7. Not established

- Whether `RATIFICATION_DELAY` should be 3 d, 7 d, or another value. Lane T
  measures the *guarantee mechanism*; the magnitude is a liveness/notice
  trade-off and is an owner decision. See
  `semantics/WW-VNEXT-RECOVERY-SOVEREIGNTY.yaml`.
- Whether `clamped` survives the stateful composition campaign. It has not been
  run against it, and §6 must land first or the campaign will misjudge it.
- Any production Solidity. Every variant in this lane is compiled in memory;
  `git diff HEAD -- '*.sol'` is empty.

---

*Adjudication worktree `wv-sd4-adversarial`, detached at `c67d1439`
(tree `c2be0fde`), base #186 `b710b250`. Local, unpushed. No branch, tag, PR or
issue metadata created or modified.*
