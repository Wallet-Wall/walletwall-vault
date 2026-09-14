# SD-2 — the containment budget: tumbling accounting measured against the rolling invariant

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**
> Adjudication only. This lane changes **zero bytes** of `VaultKernelPrototype.sol`, of production
> `contracts/`, of the ledger (`stateful/defects.ts`), of every `stateful/` predicate, of every
> receipt and of every document under `docs/`. It adds one tracked reproduction and this record.
> Nothing was pushed, no PR was opened, no version was bumped, nothing was deployed.

**Base:** `origin/main` = `03ce978bb0758b1ac82ea45a1dd749a645dbced6`, tree
`b945dc42a85d705d650f838a4fb38e6bb2eb165e` (the merge commit of PR #199, SD-8).
**Worktree:** `C:\dev\wv-sd2-adjudication`, branch
`security/vnext-sd2-containment-budget-adjudication`, created at exactly that commit with its own
`npm ci`; the shared checkout `C:\dev\walletwall-vault` was never branch-switched.
**Frozen input:** SD-11 (PR #198) closed under its recorded conditions; SD-8 (PR #199) sustained as
`STATE_INCOHERENCE` with opaque PQ-key bytes an owner decision. Neither is touched below.
**Baseline before any edit:** `test/StatefulSustainedDefects.test.ts` (the file that reproduces
SD-2 today) **7 passing / 0 failing** under `--grep SD-2`; the whole ledger suite with the
provenance suites **36 passing / 0 failing** with this lane's file present.
**This lane's evidence:** `test/Sd2ContainmentBudgetAdjudication.test.ts`, sha256
`d74ea639b1ddcaf2b382613e4170039bd9d4aead4f896883d46061fb0d1a4578`, **43 passing / 0 failing**
(mocha's own summary; run twice, before and after formatting, identical). Whole prototype suite
with the file present: **957 passing / 0 failing** (7 min; the base carries 914, this lane adds 43).

## 0. The question, and the five quantities it is made of

Does the containment-budget implementation permit more continuous contained time than the
published invariant intends, because accounting uses fixed (tumbling) epochs rather than a true
rolling horizon? The ledger says 9 contiguous days against a declared 6. That figure was treated as
a hypothesis to reproduce, not as authority.

The lane keeps five quantities apart, because the ledger's "9 days" names only one of them and the
published invariant bounds a different one:

| | Quantity | Where it is measured |
|---|---|---|
| **Q1** | **Total** contained time inside one window of length `W` (the integral; the duty cycle) | `maxInAnyWindow` over mined instants |
| **Q2** | **Continuous** contained time: the longest stretch with no uncontained instant (episodes are `[t, t+MAX)`, so two episodes touching at one instant are contiguous) | `maxContinuous` over mined instants |
| **Q3** | **Activations**: distinct successful `enterContainment` calls | guardian-domain nonce |
| **Q4** | **Accounting-window state**: `containmentWindowStart`, `containmentUsedInWindow` | storage getters |
| **Q5** | **Authorization** to enter containment at all | `_requireQuorum`, AST |

The invariant under test, quoted from `docs/Vault_vNext_Architecture.md` §6 (T0, restated in §22 D5,
in `Vault_vNext_Hazard_Register.md` H-30 and in `KERNEL_ADMISSION.md` K-11):

> **I-CONTAINMENT-BUDGET (T0).** Over any rolling wall-clock window of length `W`, the total time
> spent in CONTAINED … is at most `B`, with `B < W`. The window origin advances **only** by elapsed
> wall clock and can be moved by no principal.

It bounds **Q1** over **every** window. Nothing published bounds Q2 separately; Q2 ≤ Q1 by
definition, so a Q1 bound of `B` implies a Q2 bound of `B`.

## 1. Phase A — the mechanism, from the compiler's AST and the deployed constants (test §A)

Every claim in this section is asserted from the solc standard-JSON AST in the Hardhat build-info,
never from source text and never from memory of the source.

### 1.1 State words and their writers (§A1, §A2)

| Word | Writers (function: count) | Readers (function: count) | `delete` |
|---|---|---|---|
| `safeState` | `initialize` 1 (NORMAL), `enterContainment` 1 (CONTAINED), `bindMigration` 1 (MIGRATION_ONLY), `retire` 1 (RETIRED) | many | none |
| `containedUntil` | `enterContainment` 1 | `_effectiveState` 1 | none |
| `containmentWindowStart` | `enterContainment` 1 | `enterContainment` 1 | none |
| `containmentUsedInWindow` | `enterContainment` 2 (`= 0`, `+= CONTAINMENT_MAX`) | `enterContainment` 2 | none |

`SafeState.NORMAL` is assigned in exactly one place, `initialize`. **No function ever writes the
vault back to NORMAL after genesis.** Exit from CONTAINED is the derived view `_effectiveState`
(`safeState == CONTAINED && block.timestamp >= containedUntil` reads as NORMAL), evaluated at read
time with no principal acting. Exit is therefore **automatic and actor-free**; there is no early
exit, no extension and no other reader of the expiry. Every episode is exactly `CONTAINMENT_MAX`.

### 1.2 The action matrix under CONTAINED (§A3, executable in §C4)

| Gate | External mutators | Under CONTAINED |
|---|---|---|
| `_requireNormal` | `execute`, `rotateCredential`, `setVerifier`, `setPolicy`, `setGuardians` | **withdrawn** (`BadState`) |
| `_requireRecoveryOpen` | `initiateRecovery`, `cancelRecovery`, `cancelRecoveryByQuorum`, `executeRecovery` | **live** |
| own gate | `bindMigration` (refuses RETIRED only), `retire`, `egress`, `initialize`, `enterContainment` | live (bind measured in §C3) |

Containment withdraws spending and every credential/quorum **mutation**, including `setGuardians`:
the containing quorum freezes itself out of roster changes for the duration. It withdraws nothing
from recovery or migration.

### 1.3 Authorization and statement order (§A4, §A6)

`enterContainment` is the **only** path to CONTAINED. Its body, in order: `_effectiveState()` must be
NORMAL → `_digest(ACTION_RECOVER, guardianGeneration, keccak256("CONTAIN"), DOMAIN_GUARDIAN, nonce,
deadline)` → `_requireQuorum` → `_consume(DOMAIN_GUARDIAN, …)` → the accounting → the writes. It
reads `block.timestamp` **once** (`nowTs`), which feeds the rollover test, the origin and the expiry.
No credential authorisation is involved. The kernel has **no emergency-principal trigger**, no state
variable and no function naming one: the architecture's "emergency principal, or guardian quorum"
resolves in this kernel to the quorum alone.

Because the state gate precedes quorum and nonce, and both precede the accounting, **a refused attempt
writes nothing and burns no nonce** (measured in §B3 and §B8). One prose delta, adjacent to SD-2 and
harmless: `I-CONTAINMENT-NO-EXTENSION` says re-entry while contained is a **no-op**; the kernel
**reverts** `BadState`. The effect the rule wants — no extension — holds either way.

### 1.4 Constants (§A5)

| Constant | Value | Consequence |
|---|---|---|
| `CONTAINMENT_MAX` | 3 days | one episode |
| `CONTAINMENT_WINDOW` (`W`) | 30 days | one accounting epoch |
| `CONTAINMENT_BUDGET` (`B`) | 6 days | `B < W`; **`B = 2 × MAX` exactly**, so the budget is two whole activations per epoch |
| `RECOVERY_DELAY` | 7 days | `> B`: one epoch's budget cannot cover one recovery delay |

Genesis leaves all three accounting words at zero, so the first activation of any vault is itself a
rollover (`origin := now`, `used := 0`).

### 1.5 The state machine, as implemented

```
enterContainment at nowTs (quorum k, fresh guardian nonce):
  require effective state == NORMAL                  // else BadState
  if nowTs >= containmentWindowStart + W:            // EPOCH ROLLOVER
      containmentWindowStart := nowTs                //   origin jumps to THIS activation
      containmentUsedInWindow := 0
  require containmentUsedInWindow + MAX <= B         // else ContainmentBudget
  containmentUsedInWindow += MAX
  containedUntil := nowTs + MAX ;  safeState := CONTAINED
exit: none. effective state reads NORMAL at containedUntil with nobody acting.
```

An accounting epoch is `[origin, origin + W)`; a new epoch begins at the **first activation** at or
after `origin + W`, not at `origin + W` itself. Epochs are therefore at least `W` long, each admits at
most `B / MAX = 2` activations, and the counter never slides: it is **tumbling**, keyed to activations.

## 2. Phase B — deterministic reproduction and the mechanical boundary search (test §B)

### 2.1 Mechanical search (§B1, §B1b, §B1c)

The adversary's only freedom is **when** to fire: each activation after the first fires at the earliest
admissible instant plus a chosen delay. A grid of 22 delays (0, 1 s, 1 h, 1–3 d, 6 d, 12 d, 20 d,
23 d, 24 d ± 1 s, 25 d, 26 d, 27 d ± 1 s, 28 d, 30 d ± 1 s, 33 d) over three free activations gives
**10,648 plans**; a coarser grid over four free activations gives **130,321 plans**. Earliest-admissible
instants are found by bracket-and-bisect on the pure model, exact to the second (admissibility for a
fixed state is monotone in time; asserted).

| Model | Plans | max **Q2** (continuous) | max **Q1** (in one 30 d window) |
|---|---|---|---|
| tumbling (kernel as implemented), 4 activations | 10,648 | **9 d** | **9 d** |
| tumbling, 5 activations | 130,321 | 9 d (does not grow) | 9 d |
| rolling (the published invariant, literal) | 10,648 | 6 d | 6 d |

The Q2 argmax set is exactly: **A2 delayed by `d ∈ [24 d, 27 d)`** after its earliest instant
(A1 + 3 d), i.e. **A2 fires at T0 + [27 d, 30 d)** so that its episode ends at or after the epoch
boundary, followed by A3 and A4 **immediately**. 24 d − 1 s is out (a one-second gap), 24 d is in,
26 d is in (A2 straddles the boundary), 27 d − 1 s is in, 27 d is out (A2 becomes the new epoch's
first activation). The **Q1** argmax set is wider: any A2 delay in `[3 d, 27 d)` already places three
episodes inside one 30-day window, contiguous or not. **The ledger's "9 days" is Q2 and is correct;
Q1 = 9 d is reached by far more transcripts and does not require contiguity.**

### 2.2 The maximum on the exact kernel, at exact legal instants (§B2)

`T0 = 1789481324`. Four transactions, four consecutive guardian nonces, every block timestamp pinned
with `setNextBlockTimestamp`:

| Act | Block | Instant | Nonce | State after: `containedUntil` / origin / `used` |
|---|---|---|---|---|
| A1 | 31 | T0 | 0 | T0 + 3 d / T0 / 3 d |
| A2 | 32 | T0 + 27 d | 1 | T0 + 30 d / T0 / **6 d** (epoch 1 budget spent, at its end) |
| A3 | 33 | T0 + 30 d | 2 | T0 + 33 d / **T0 + 30 d** / 3 d (origin jumped, counter restarted) |
| A4 | 34 | T0 + 33 d | 3 | T0 + 36 d / T0 + 30 d / 6 d |

Contained without interruption on `[T0 + 27 d, T0 + 36 d)`: **Q2 = 9 d = B + MAX**, exactly `1.5 × B`.
Q1 inside `[T0 + 27 d, T0 + 57 d)` is also 9 d. Every episode measured exactly `MAX`; nonces 0–3.

### 2.3 Boundary controls (§B3, §B4, §B7, §B8)

| Probe (fresh vault unless noted) | Instant | Verdict | Meaning |
|---|---|---|---|
| re-entry during A4 (repro vault) | T0 + 34 d | `BadState`, nonce unchanged, expiry unchanged | no extension; refused before quorum |
| A2 at +26 d, then re-entry | +29 d − 1 s | `BadState` | still contained one second before expiry |
| same | +29 d | `ContainmentBudget` | at the expiry instant the vault is NORMAL and the **budget** refuses |
| same | +30 d − 1 s | `ContainmentBudget` | **negative control**: one second before the epoch ends |
| same | +30 d | **admitted**, origin := +30 d, used := 3 d | **positive control**: the rollover is `>=`, exact |
| same | +33 d − 1 s | `BadState` | contiguity boundary, second-exact |
| same | +33 d | admitted | zero-gap second activation of epoch 2 |
| within one epoch: A1, A2 at +3 d, A3 at +6 d | +6 d | `ContainmentBudget`, used stays 6 d, nonce stays 2 | the budget really binds inside an epoch |
| after the maximal chain (repro vault) | T0 + 60 d − 1 s | `ContainmentBudget` | **forced uncontained gap of 24 d** |
| same | T0 + 48 d | spend **admitted** | spending live throughout the gap |
| same | T0 + 60 d | admitted | epoch 3 opens exactly at origin + W |

### 2.4 Quorum requirement, pre-signing, unauthorised principals (§B5, §B6, §B11)

Four activations are **four distinct k-of-n quorum attestations** over four consecutive nonces. They
can be **produced in one signing session** and **relayed by an outsider** at the right instants — the
relayer holds nothing and the four relayed acts reproduce the 9 d (§B5). A single seat is refused
`QuorumNotMet`; an outsider with no attestations, the spending credential signing as if it were two
guardians, and a proof over the wrong guardian generation are all refused `QuorumNotMet` and move no
accounting word (§B6). After the maximal chain every authority-bearing field — `ecdsaSigner`,
`pqPublicKeyHash`, `pqVerifier`, `guardianCommitment`, `guardianThreshold`, `guardianGeneration`,
`credentialGeneration`, `policyEngine`, the floor, and the SPEND / CREDENTIAL / MIGRATION nonces — is
**byte-identical**; only the guardian nonce moved, by exactly four (§B11).

### 2.5 Sequencer discretion (§B9)

None is required. The construction works at exact legal timestamps (§2.2), and the rollover test is
`>=`, so no instant has to be "won". With **one second of slack at every step** the same four acts
still yield 9 d of contained time in a 30-day window; strict contiguity is then broken by the 1 s gaps,
and restored at block granularity (gaps ≤ 12 s count as one run). A2 fired at +29 d, whose episode
**straddles** the boundary, yields 9 d strictly contiguous with epoch 2 opening at A3 (+32 d): the
remainder past the boundary is charged to **neither** epoch.

### 2.6 Model ↔ kernel cross-validation (§B10)

On six plans (greedy; A2 +12 d; A2 at the argmax −1 s, exact, +1 s; A2 +26 d) the pure tumbling model
predicted every earliest admissible instant **and the refusal reason one second before it**; the
kernel confirmed all of them. Continuous / in-window: greedy 6 / 6, mid 6 / 9, max−1 s 6 / 9,
max 9 / 9, max+1 s 9 / 9, late 9 / 9 (days).

## 3. Phase C — consequence and authority (test §C)

**What the excess denies.** Spending by the legitimate credential is refused `BadState` at T0 + 33 d + 1 s,
T0 + 34 d and T0 + 36 d − 1 s and admitted at exactly T0 + 36 d (§C1). `setPolicy` (credential, HYBRID)
and `setGuardians` (quorum) are refused `BadState` during the chain (§C4). The denial is **symmetric**:
it is not a capability the quorum gains over the assets; it is a capability nobody has while contained.

**What stays live, measured.** Recovery is initiated **and** the credential's bounded challenge is
exercised under containment; on a second vault a recovery initiated at t0 + 27 d + 1 s (contained)
matures and **executes at t0 + 34 d + 1 s while the vault is still contained**, installing the
guardian-approved credential, and the vault remains contained afterwards (§C2). `bindMigration`
(quorum + credential) succeeds under containment (§C3). Containment never gates the remedy or the escape.

**Who can impose it, and what they already hold.** Only a **guardian quorum at cut `k`** (2 of 3 in the
fixture), acting **four times** (or pre-signing four times and letting anyone relay). That principal
already holds `setGuardians`, `initiateRecovery` (credential replacement at `k`, the accepted D1
residual whose closure AUTHORITY.md §8.2 records as reaching the assets), `cancelRecoveryByQuorum`
and the quorum half of `bindMigration`. The measured authority delta of the maximal construction is
**zero** (§B11). This lane does **not** infer "longer denial is harmless because the quorum could do
worse"; it measures that no field, nonce or gate other than the containment words moved, and that the
accounting runs **after** quorum and nonce, so no accounting choice can change **who** (§A4, §D8).

**Long horizon (§C5, model, 600 d, adversary repeating the maximal chain).** Tumbling: 40 activations,
duty cycle **exactly `B / W` = 20.00 %**, Q2 = 9 d, and after **every** 9-day chain an uncontained gap
of **exactly `W − B` = 24 d**. Rolling, same adversary: 29 activations, 14.5 %, Q2 = 6 d. The excess
does **not** raise the long-run duty cycle and is **not renewable**: two maximal chains are separated
by the full forced gap; the sequence of uncontained intervals stays infinite, as `B < W` promises.

**Measured against the brief's five questions:**

| Does the defect… | Measured |
|---|---|
| increase maximum denial duration? | **Yes.** Q2: 6 d → 9 d; Q1 in any 30 d window: 6 d → 9 d (1.5 ×). |
| make denial renewable indefinitely? | **No.** Duty cycle stays `B / W`; a 24 d forced gap follows every chain. |
| affect recovery / migration? | **No.** All four recovery actions and migration binding measured live under containment. |
| change credential / verifier authority? | **No.** Authority state byte-identical; only guardian nonces move. |
| only violate a declared duration bound? | **Yes, exactly that** — a T0 duration bound, by one `MAX`, at an already-held cut. |

## 4. Phase D — candidate semantics, measured side by side (test §D; reference models only)

All seven semantics ran the same 3-free-delay search (grid of 13 delays, 2,197 plans each) plus a
legitimate back-to-back probe (A1 at T0, A2 at T0 + 3 d). Nothing below is implemented; every row
is a pure model.

| Semantics | Invariant it enforces | max Q2 | max Q1 (30 d) | legit 6 d back-to-back | words | work | reset | cut |
|---|---|---|---|---|---|---|---|---|
| **tumbling (kernel)** | per accounting epoch ≤ B | **9 d** | **9 d** | yes | 2 | constant | origin := now, used := 0 at first act ≥ origin + W | k, unchanged |
| **1. rolling budget (literal)** | any window of W ≤ B | 6 d | 6 d | yes | 2 (ring of B/MAX = 2 starts) | constant | none; episodes age out | k, unchanged |
| **2. token bucket** | long-run rate ≤ B/W, burst ≤ B | 6 d | **9 d** | yes | 2 | constant + one multiply | none; continuous refill | k, unchanged |
| **3. cooldown 12 d** | ≥ 12 d between episodes | 3 d | 6 d | **no** | 0 | constant | none | k, unchanged |
| **4. keep kernel, restate invariant** | = tumbling row | 9 d | 9 d | yes | 2 | — | — | k, unchanged |
| **5. two-start ring** | second-most-recent start ≥ W old | 6 d | 6 d | yes | 2 | constant, no arithmetic | none; older start ages out at start + W | k, unchanged |
| M24/M46 reset every trigger (control) | none | 12 d (4 acts) | 12 d | yes | 2 | — | every act | — |
| tumbling with B = MAX (control) | one act per epoch | 3 d | 3 d | **no** | 2 | — | as kernel | — |

Per-candidate notes the brief asked for:

1. **Rolling budget.** Enforces the published invariant literally. Timestamp dependence: one
   `block.timestamp` read, as today. Worst case: with `B / MAX = 2` at most two live episodes need
   storing, so a ring of two starts — constant work, two words. Reset: none. Cut: unchanged (accounting
   runs after quorum). Permanent denial: impossible — every episode ages out at `start + W`. Legitimate
   containment: preserves the 6 d back-to-back. Recovery/migration: untouched, as today (no gate reads
   the accounting). It **removes** the tumbling straddle, so an honest quorum can no longer cover a
   7-day recovery delay in one stretch by preparing 27 days ahead — a constants observation (§1.4), not
   a semantics one.
2. **Token bucket.** Enforces a long-run rate and a burst cap, **not** the any-window bound: a full
   bucket plus refill puts 9 d inside one 30 d window (§D4). It therefore does not satisfy the published
   invariant either; rejected as a remediation of the stated invariant.
3. **Cooldown.** Satisfies the any-window bound but forbids the second back-to-back activation the
   current design explicitly permits (§D5): over-strict, harms legitimate containment. Rejected.
4. **Keep tumbling, correct the prose.** Zero bytes. The honest statement is: **per accounting epoch
   (origin = the first activation at or after the previous origin + W) contained time ≤ B; hence in
   any rolling window of length W contained time ≤ B + MAX, continuous containment ≤ B + MAX, and the
   long-run duty cycle ≤ B / W.** Also correct "can be moved by no principal": the origin is moved by
   the quorum's own activation, forward only and only after ≥ W has elapsed.
5. **Two-start ring — the simplest mechanism the measured property implies.** Because episodes are
   indivisible `MAX` blocks and `B = 2 × MAX` exactly, "at most B contained in any W" is the same as
   "at most two episode starts in any half-open window of length W", i.e. **the second-most-recent
   start must be at least W old**. §D3 proves it **extensionally identical** to candidate 1 on all
   2,197 plans. It needs exactly the **two uint64 words the kernel already has** (`prevStart`,
   `lastStart` in place of `containmentWindowStart`, `containmentUsedInWindow`), no counter arithmetic
   and no reset. The reduction holds **only while `B / MAX` is an integer**; a constants change to a
   non-integer ratio would require candidate 1's general form.

**None of the seven changes a principal cut** (§D8): accounting decides *when* a quorum may contain,
never *who*; the quorum and nonce checks precede it (§A4).

## 5. Phase E — adversarial discrimination (test §E)

Two fixed transcripts of quorum attempts, fed identically to the kernel, to every reference model and
to every mutant: **CHAIN** = A1 at t0, A2 +27 d, A3 +30 d, A4 +33 d, A5 +36 d (post-chain control),
A6 +60 d (next epoch); **IN-EPOCH** = A1 at t0, A2 +3 d, A3 +6 d (within-epoch control).

Kernel: CHAIN → `OK OK OK OK ContainmentBudget OK`; IN-EPOCH → `OK OK ContainmentBudget`.

| Discriminator | Result |
|---|---|
| E1 tumbling model | equals the kernel on both transcripts, **reason for reason** |
| E2 rolling model | differs at **exactly one step**, CHAIN A4 (kernel admits, rolling refuses): that step **is** the SD-2 observation; identical on IN-EPOCH; the ring model makes the same single distinction |
| E3 permissive model (M24/M46) | differs at the IN-EPOCH control and the CHAIN post-chain control (it admits both) |
| E4 over-strict models (cooldown, B = MAX) | differ at the legitimate back-to-back step (they refuse it) |

**Kernel mutants**, compiled in memory from the real source with one textual change and deployed
through `implOverride` (zero bytes on disk). Each must (i) pass a positive control (contain once), (ii)
agree with the real kernel on every transcript step **before** its kill step, and (iii) flip the named
admission decision, moving Q2 in the predicted direction on that transcript:

| Mutant | Change | Kill (transcript, step) | Q2 mutant vs kernel |
|---|---|---|---|
| `M-SD2-RESET-EVERY-TRIGGER` | rollover test → `nowTs >= containmentWindowStart` | IN-EPOCH A3: `ContainmentBudget` → `OK` | 9 d vs 6 d |
| `M-SD2-NO-CHARGE` | delete `containmentUsedInWindow += CONTAINMENT_MAX` | IN-EPOCH A3: `ContainmentBudget` → `OK` | 9 d vs 6 d |
| `M-SD2-ORIGIN-NEVER-MOVES` | delete `containmentWindowStart = nowTs` | CHAIN A5: `ContainmentBudget` → `OK` | 12 d vs 9 d |
| `M-SD2-ROLLOVER-STRICT` | `>=` → `>` at the rollover | CHAIN A3 (exact instant T0 + 30 d): `OK` → `ContainmentBudget` | 6 d vs 9 d |
| `M-SD2-BUDGET-HALVED` | `CONTAINMENT_BUDGET = 3 days` | IN-EPOCH A2: `OK` → `ContainmentBudget` | 3 d vs 6 d |

**5 / 5 killed**, every kill credited to a containment-admission decision on the shared transcript,
never to a setup revert; the real kernel passes every discriminator the mutants fail (§E7).

## 6. Verdict

**SD-2 is SUSTAINED and REPRODUCED EXACTLY.** The kernel's accounting is tumbling, keyed to
activations; the published `I-CONTAINMENT-BUDGET (T0)` is a rolling any-window bound; the kernel
violates it by exactly one `CONTAINMENT_MAX` in both Q1 and Q2: **9 d against a declared 6 d, 1.5 ×**,
reachable by the declared guardian cut `k` through four ordinary quorum acts at exact legal timestamps.

**What SD-2 is.** A **declared-duration-bound violation with a bounded, non-renewable,
authority-neutral liveness consequence**. It is not accounting incoherence (the stored words are
internally consistent with the tumbling semantics they implement), not a capability gain (authority
delta zero, cut unchanged, recovery and migration live), and not merely documentation **unless the
owner re-declares the invariant** (candidate 4). The ledger's classification `LIVENESS_DENIAL` —
"a principal deprives another beyond a declared bound" — **stands**: the quorum deprives the credential
of spending (and every mutation) for 9 d where a T0 invariant promised at most 6 d in any 30 d.

**Does the ledger wording survive?** The verdict, the classification, the roots (`k = 2`), the
"9 CONTIGUOUS contained days against a declared 6-day budget", the "1.5 ×" and the
`notAnEscalationBecause` field all survive re-derivation. Five corrections are due, none of which
changes the verdict:

1. **Q1 and Q2 are conflated.** "Measured worst case is 9.00 days inside a 30-day rolling window" is
   Q1 and is reached by any A2 fired 3 d–27 d late, with no contiguity; "9 CONTIGUOUS days" is Q2 and
   requires A2 in the last `MAX` of the epoch plus zero-gap A3/A4. Both are 9 d; they are different
   observations with different reachability.
2. **`rootCause` mislocates the cause.** "Resets the origin to NOW rather than sliding it" suggests a
   grid-aligned origin (`origin += W`) would be correct. It would not: a fixed grid is also tumbling
   and yields the same `B + MAX`. The cause is **per-epoch accounting with a whole-budget reset**; the
   jump-to-now detail only makes epochs *longer* than W, which is more restrictive, not less.
3. **`contradicts` cites only the kernel comment.** The authoritative statement is the architecture's
   T0 invariant (`docs/Vault_vNext_Architecture.md` §6 and §22 D5), repeated in the Hazard Register
   (H-30) and `KERNEL_ADMISSION.md` (K-11). All four are contradicted; the kernel comment is the least
   of them.
4. **`minimalFixSketch` over-specifies.** "A small ring of (start, duration) entries" is candidate 1's
   general form; with `B = 2 × MAX` the sound implementation is **two start timestamps in the two
   words already allocated** (candidate 5), with no duration field and no counter.
5. **Adjacent prose deltas, harmless, recorded so they are not rediscovered:** re-entry while
   contained is a **revert**, not the documented no-op; and the origin **is** moved by a principal's
   act (forward, only after ≥ W), contrary to "can be moved by no principal".

One oracle note, not a change in this lane: the stateful campaign's `G-CONTAINMENT-BUDGET-BOUNDED`
checks `containmentUsedInWindow ≤ 6 d` — the kernel's own **counter** — so it inherits the tumbling
accounting and **structurally cannot observe SD-2**; only a wall-clock measurement over mined instants
(this file's `maxInAnyWindow`) can. SD10's model census re-discovered SD-2 for the same reason.

**Stop conditions, evaluated.**

| Condition | Fires? | Because |
|---|---|---|
| historical 9-vs-6 characterization materially wrong | **no** | reproduced exactly; corrections are to attribution and precision, not to the number |
| the rolling invariant not authoritative / current | **no** | T0 in the governing architecture doc (introduced `537a2aa`, 2026-08-31), restated in H-30 and K-11; kernel `79e05a3` same day; ledger `ec5adce` 2026-09-01; nothing since re-declares it |
| same already-authorised quorum and only the prose is wrong | **partly** | the quorum is the same and authority delta is zero, but the violated statement is a T0 invariant with an executable 1.5 × consequence — whether that is "only prose" is precisely the owner's choice between candidates 4 and 5 |
| a proposed fix creates a stronger liveness failure | **no** for 1 / 5 (legit 6 d preserved, no permanent denial); **yes** for 3 (forbids legit back-to-back) — rejected | measured in §D |
| candidate semantics require an owner / product decision | **YES** | see below |

**Implementation is NOT warranted in this lane.** The choice is between two owner decisions with
identical cut and identical storage footprint: **(a)** keep the T0 invariant as written and implement
candidate 5 (two start words, constant work, no reset, no new principal, no permanent denial, preserves
legitimate 6 d back-to-back, removes the straddle); or **(b)** keep the kernel and re-declare the
invariant per candidate 4 (zero bytes; the true bounds become `B + MAX` per window and `B / W`
long-run). Recommendation, stated not decided: **(a)** if the T0 statement is the intended contract,
since it costs no words and no authority; **(b)** only if the owner values the straddle's incidental
ability to cover a 7-day recovery delay — which is really a **D5 constants question** (`B = 6 d <
RECOVERY_DELAY = 7 d`, OPEN in the architecture) and should be decided as one. Either way, the ledger
entry's five corrections above are due, and `docs/` should carry whichever statement is chosen.

## 7. What this lane does NOT establish

- Anything about SD-4, SD-8 or SD-11; none of their edges, files or conditions was touched or read as
  variable.
- That candidate 5 is correct for constants other than the current ones: its reduction requires
  `B / MAX` to be an integer, stated in §D3 so a constants change is known to break it.
- Anything about the numeric values of `MAX`, `B`, `W` (D5, OPEN). The 7-day-versus-6-day observation
  is recorded as an input to that decision, not adjudicated.
- Anything about the production vault's `DailySpendLimitPolicy` rolling ledger beyond the observation
  that the same tumbling-versus-rolling distinction was already fixed there (`docs/Phase_3_Status.md`).
- That the campaign's oracle should change; that is a separate assurance lane.

## 8. Verification

```
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test prototype/vnext-kernel/test/Sd2ContainmentBudgetAdjudication.test.ts
```

- New file: **43 passing / 0 failing** (twice: before and after `prettier --write`, identical results).
  Wall time ≈ 5 s (in-process EDR; each mutant compile ≈ 0.8 s).
- Ledger + provenance suites with the file present (`StatefulSustainedDefects`,
  `EvidenceSubjectProvenance`, `PublicationProvenance`): **36 passing / 0 failing**. The evidence
  subject (`contracts/` + `stateful/` trees) is untouched; a file under `test/` is outside it.
- Whole prototype suite with the file present: **957 passing / 0 failing** (7 min; the base carries 914, this lane adds 43).
- `tsc` with `--strict --noUncheckedIndexedAccess --types node,mocha` over the new file alone reports
  only the `ethers` namespace-type gap that every prototype test shares (`world.ts` reports the same
  class); no other diagnostic in the new file.
- Counts: 43 tests (6 mechanism, 13 reproduction, 5 consequence, 8 candidate, 11 discrimination);
  7 reference semantics; 5 kernel mutants, 5 killed, 0 survivors, 0 inconclusive; 10,648 + 130,321 +
  10,648 + 7 × 2,197 model plans; ≈ 150 mined probes, every one pinned to its instant.

## 9. Production and publication boundary

- `contracts/` (production): **untouched**. `prototype/vnext-kernel/contracts/`: **untouched**.
  `stateful/`, `docs/`, `AUTHORITY.md`, `defects.ts`, every receipt: **untouched**. Working tree before
  commit: exactly two untracked files, this record and the test.
- Nothing pushed: the branch has **no upstream** (`git rev-parse @{u}` fails), `origin/main` is still
  `03ce978b` in the local refs, no PR opened, no deployment, no version bump.
