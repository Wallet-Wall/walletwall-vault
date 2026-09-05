# Stateful adversarial authority campaign

> **EXPERIMENTAL · NOT AUDITED · NOT PRODUCTION · NO DEPLOYMENT.**
> This lane changes **zero bytes of Solidity.**

## The question this lane asks, and the two it does not

| Lane                                    | Question                                                                                        | Shape             |
| --------------------------------------- | ----------------------------------------------------------------------------------------------- | ----------------- |
| `vNext Kernel / Slither`                | Do the **implementation patterns** look unsafe?                                                 | static            |
| `vNext Kernel / Authority Completeness` | Is **every privileged external path** classified and routed to its intended authority mechanism? | per-function      |
| **`vNext Kernel / Stateful Authority`** | Can **individually-valid, individually-correctly-gated transitions be composed over time** into an outcome below its declared cut? | **per-history**   |

It reasons about

```text
STATE + ACTION + AUTHORITY  ->  NEXT STATE
```

and never about

```text
FUNCTION  ->  EXPECTED GATE
```

It does not duplicate, replace, or vouch for either of the other two.

## Why the oracle is not a second copy of the kernel

The failure mode of every model-based test is an oracle that reads the same
storage and re-evaluates the same conditions as the implementation, and so
agrees with it by construction — including when the implementation is wrong.

This model refuses to predict **success** at all. It keeps three things:

1. **What the harness did** — which actor issued each action, and *which
   authority roots that actor holds*. Declared by the campaign, never read back
   from the chain, so the kernel cannot make the oracle agree with it.
2. **Declared cuts** — copied from `AUTHORITY.md` §3. An **input**, not a
   derivation: if the published claim is itself wrong, that is a finding about
   the document.
3. **Observed outcomes** — what actually changed on chain, by **state diff**,
   never by asking which function was called.

The judgement is one asymmetric implication, in the safety direction only:

> If a protected outcome occurred, the roots that **authorised** it must satisfy
> at least one declared authority path **in full**.

It deliberately does **not** assert the converse. Liveness is proven instead by
explicit **positive controls** — fully-honest actions that must succeed — so a
campaign in which everything reverts cannot score as a pass.

There is exactly **one** declared exception to the no-mirroring rule:
`G-RECOVERY-COMMITMENT-BINDS`, which recomputes the recovery possession digest
from the fields the architecture *requires* it to bind. A kernel that binds more
still passes; only one that binds less fails. The reason is in the source
comment.

## Running it

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test \
  prototype/vnext-kernel/test/StatefulAuthorityFuzz.test.ts
```

```bash
npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test \
  prototype/vnext-kernel/test/StatefulMutationAdequacy.test.ts
```

```bash
npx tsx prototype/vnext-kernel/generate-stateful-evidence.ts
```

**Required CI runs a fixed seed set and nothing else.** There is no
clock-derived or environment-derived randomness anywhere in this lane, so every
failure replays from the seed printed beside it, and a red run is never a
coincidence. To explore beyond the fixed set locally, edit `CI_SEEDS` in
`test/StatefulAuthorityFuzz.test.ts` — deliberately a reviewable source change
rather than an environment variable, because a knob that changes what CI proves
should appear in a diff.

## Layout

| File             | Role                                                                             |
| ---------------- | -------------------------------------------------------------------------------- |
| `prng.ts`        | mulberry32. Deterministic, dependency-free. Why not `fast-check` is in the header |
| `world.ts`       | Roots, principals, seats, actors, and the deployed fixture                       |
| `model.ts`       | The abstract oracle: declared cuts, authority paths, recovery evidence           |
| `actions.ts`     | The generated commands, including every adversarial quorum shape                 |
| `invariants.ts`  | Global properties, each tied to a source construct — plus the rejected ones      |
| `profiles.ts`    | Adversary models: who is compromised, and what the generator reaches for         |
| `campaign.ts`    | Generate, execute, judge, shrink, replay                                         |
| `mutants.ts`     | Deliberately weakened kernels, compiled in memory                                |
| `defects.ts`     | The sustained-defect ledger                                                      |

## Three things worth knowing before you trust a green run

**The campaign was silently inert once.** Actors declared the key material they
hold by concrete label, hard-coded to one world's name. Every campaign deploys
its own world under its own label, so in every run but one those labels matched
nothing: each "attacker" held zero roots and signed with decoys. The suite was
green — full action coverage, 728/728 positive controls — while the adversary
did nothing. **Mutation adequacy is what found it**, when thirteen deliberately
weakened kernels survived. Roles are now bound to the world at campaign
construction.

**The oracle repeated the kernel's own assumption once.** Guardian roots were
indexed by roster *seat*, on the reasoning that the kernel's strictly-ascending
roster makes seats and principals 1:1. True of the real kernel, and wrong as a
model: the mutant that relaxes the roster to non-decreasing installs a roster
where one principal holds two seats, and the seat-indexed oracle credited that
principal with two roots and saw nothing. Roots are now counted by **distinct
address**.

**One mutation was unsound and was replaced.** An earlier `M11` moved a state
write in front of the authority check to model "gate after effect". In the EVM a
reverting authorization rolls the whole transaction back, so the effect never
persists and no property could ever observe it. A mutation that cannot fail is
not a test. It was replaced with a **non-reverting** failure — a policy plane
whose refusal is ignored — which is observable.

## What a pass here does not mean

- **Not exhaustive.** A bounded, seeded campaign over a bounded action
  vocabulary. Anything outside the generated distribution is untested.
- **Not formal verification.** Deterministic seeded campaigns are still testing.
  "No violation found" is not "no violation exists".
- **Not an audit.**
- **No cryptographic claim.** The second factor is an independent ECDSA keypair
  standing in for a PQ scheme. Nothing here says anything about ML-DSA.
- **Does not prove guardian independence (H-31).** Distinct on-chain addresses
  may still be one off-chain custodian. This lane counts on-chain principals and
  invents no identity system to pretend otherwise.
- **Mutation score is adequacy, not coverage.** Killing every mutation in a
  hand-written catalogue shows the properties detect *those* classes. It does
  not enumerate the classes that are missing.
- **The generator's distribution is tuned.** Several profiles bias timing and
  parameter choices so a seam is reachable at all — `executeRecovery` never once
  succeeded before that tuning, and R2–R7 were going untested behind a green
  suite. Biasing a distribution is not filtering a sequence, but coverage is
  uneven by construction.

`STATEFUL_AUTHORITY_EVIDENCE.json` carries the same list as a first-class field,
not a footnote.

## Staleness note — generated evidence versus later semantic corrections

> The generated implementation/campaign evidence remains evidence for
> `c67d1439`. It intentionally does not claim the W2 remediation exists.
> Semantic corrections discovered after that receipt are persisted separately.
> The receipt will be regenerated only after W2 implementation and
> re-measurement.

**Artifact identity.** The receipt's own fields are `head =
28adbb8834c39ae2e106e31d3a25f5b39c84c943`, `tree =
849e140b7b02121e9ad4a7f1047539654c45fc9a`, with `solidityChanged.bytes = 299`
read from `MEASUREMENTS.json`. It was generated there and is carried **unchanged**
to `c67d1439` (`git diff` against that head is empty for all four artifacts); it
is evidence for the kernel bytes those measurements were taken from.

**What remains valid.** Every campaign result, every mutation kill, the declared
cuts, and the four sustained-defect entries it carries (`SD-2`, `SD-4`, `SD-5`,
`SD-8`) as they stood at that head. Nothing in it is wrong *about that kernel*.

**What it does not represent** — semantic claims discovered after it was
generated, persisted separately and **deliberately not written into it**:

- the `source` field of `G-DECLARATION-SUBORDINATE-TO-RECOVERY` names an
  interlock the kernel records as removed. Corrected in `invariants.ts` as a
  provenance correction only — the predicate is unchanged, so no campaign
  result changes — and not regenerated into the receipt;
- the SD-4 entry's *"No fifth family is known"*, its A/E dichotomy, and its
  unqualified *"liveness cost is INHERENT"* are superseded
  (`../SD4_*.md`, `../../../docs/Vault_vNext_Recovery_Amendment.md` §4);
- `SD-9` (a–e) and `SD-10`, and K-9's partial conformance
  (`../SD9_RECOVERY_LIFECYCLE_DEFECTS.md`, `../KERNEL_ADMISSION.md`), post-date it
  and are absent from its `sustainedDefects`.

**Why regeneration before W2 would mislead.** The generator embeds the current
`defects.ts` and re-runs the campaign: it would restamp measurements against a
kernel W1 does not change, republish the superseded SD-4 ledger text under a
fresh identity, and still omit SD-9/SD-10 because they are not in `defects.ts`.
The same holds for `AUTHORITY_CENSUS.json`, `MEASUREMENTS.json` and
`SCANNER_EVIDENCE.json`, which measure a kernel these corrections do not touch.

**What authorises regeneration.** The W2 implementation landing and being
re-measured — at which point `defects.ts` carries the remediated entries, the
campaign runs against the changed kernel, and the receipt's `head` moves for a
reason.

### W2 status (Lane W2I — local implementation diff, receipts still NOT regenerated)

The W2 implementation exists on this diff but is uncommitted, so a regenerated
receipt would stamp `head`/`tree` values that cannot truthfully identify the
tree it describes. The canonical `STATEFUL_AUTHORITY_EVIDENCE.json` is therefore
left byte-unchanged and is now stale in countable ways the campaign suite itself
detects (its "receipt describes the matrix" test is RED on this diff by design,
not by accident — it fails on the first comparison, the campaign count):
**18 profiles** where the receipt lists 17 (`recovery-lifecycle` appended), so
**252 planned campaigns** where the receipt says 238 and **13,680 planned
transitions** where it says 12,920; **21 global invariants** where the receipt
lists 20 (`G-CHALLENGE-EPOCH` added); a new judged outcome
`RECOVERY_QUORUM_CANCEL`; and kernel bytes 18,425 / sha256 `17884089…` where the
receipt's `solidityChanged` still names 18,105 / `73be083f…`. The mutation
catalogue (`MUTATIONS`, 22) is unchanged — the fifteen W2 mutants live in
`test/W2RecoveryLifecycleMutations.test.ts`, which is deterministic-history
adequacy rather than campaign adequacy. Regeneration is authorised at the commit
that carries this diff; the regenerator now prefers the `w2RecoveryLifecycle`
block of `MEASUREMENTS.json`. The exact plan is in
`../W2_IMPLEMENTATION_RECORD.md`.
