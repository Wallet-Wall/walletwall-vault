# SD5-I Publication Integrity — Corrections

**ADDITIVE RECORD.** Four defects were found by independent review in material already published on
this branch. Two of them live in commit messages, which are immutable once pushed; correcting them by
rewriting history would destroy the record of the error. They are corrected here instead, and the
source comments that repeated them are corrected in the same commit that carries this file.

No accepted commit is touched. `#194` (`be1789f4`, `87a3f05`), `#186` and `#179` are unchanged.

---

## C-1 — `validation.prototypeTests` overstated its provenance (BLOCKER)

**The claim.** `MEASUREMENTS.json` recorded, at evidence commit `b7a4f17`:

```text
validation._scope          "CURRENT aggregate test and assurance results of measuredAtHead,
                            taken from the CI execution at that head"
validation.measuredAtHead  8ba71c90...
validation.prototypeTests  "738 passing, 0 failing ... at measuredAtHead"
```

**Why it cannot be true.** Commit `8ba71c90`'s own message states that one assertion — the
evidence-currency check — is RED at that commit by design, because the `MEASUREMENTS.json` committed
*there* still declares the previous subject `be1789f4` while the kernel's comments have moved. A
clean checkout of `8ba71c90` therefore cannot produce an all-green suite.

**What actually happened.** The 738/0 run was executed on the working tree at `8ba71c90` *after*
`MEASUREMENTS.json` had been re-declared and the receipt regenerated — that is, on the
evidence-container state, not on the subject tree. There are also no `pull_request` workflow runs at
`8ba71c90`; CI runs at the branch tip, so no CI execution at that head exists to have been quoted.

**This is precisely the class of overstatement this lane exists to eliminate.** The lane corrected a
generator that named the wrong commit, and then published a figure attributed to the wrong tree. The
mechanism was fixed while the same habit reappeared one field away.

**The correction.** The two provenances are separated and never collapsed:

```text
SUBJECT VALIDATION      what executes on a CLEAN CHECKOUT of measuredAtHead
CONTAINER CLOSURE       what executes once MEASUREMENTS declares that subject
                        and the regenerated receipt is committed alongside it
```

`validation.prototypeTests` now reports the first and says so. `validation.publicationIntegrityClosure`
reports the second and says so. No container commit id and no CI run id is recorded in either, because
naming the commit that contains this file would reintroduce exactly the self-reference the lane removes.

**Measured, not assumed.** The clean-checkout result at `8ba71c90` was derived by detaching to that
exact commit (tree verified `ce3dabae...`), rebuilding from clean, and running the full suite:

```text
CLEAN CHECKOUT OF 8ba71c90    737 passing, 1 failing

the single failure, by exact identity:
  vNext Kernel — evidence subject provenance
    / evidence CURRENCY — the subject still describes the code that publishes it
      / the measured inputs are byte-identical between subject and container

  AssertionError: these measured inputs changed between the declared evidence
  subject (be1789f4) and the commit publishing the evidence (8ba71c90) ...
  expected [ contracts, stateful ] to deeply equal []
```

So the published figure was wrong by exactly one assertion, and that assertion is the one the commit
message already said would be red. Both drifted paths are accounted for: commit A edited kernel
comments (`contracts`) and the defect-ledger header (`stateful`).

---

## C-2 — the synthetic PR merge commit was described too strongly

**The claim.** Commit `8ba71c90`'s message, and source comments repeating it, said of
`43426b229238d2dbdd2e4972acea7454b3d2c9a8`:

```text
"exists in no clone"
"can never be checked out"
"cannot be resolved in any clone"
```

**Why it is too strong.** GitHub exposes the ref, and it fetches:

```text
git ls-remote origin 'refs/pull/194/*'
  87a3f056...  refs/pull/194/head
  43426b22...  refs/pull/194/merge

git fetch origin refs/pull/194/merge   ->  FETCH_HEAD = 43426b22...
git cat-file -t 43426b22...            ->  commit
git log --oneline -1 43426b22...       ->  Merge 87a3f05... into 5e8c68d3...
```

The original observation — `git cat-file` failing — was accurate about *that clone at that moment*,
because `refs/pull/*` is not fetched by default. Generalising it to "no clone, ever" was not.

**The accurate defect, which is unchanged in force.** `43426b22...` is a **synthetic GitHub PR merge
commit**: trigger-dependent (it exists for `pull_request` runs and not for `push` runs of the same
commit), transient and non-canonical (GitHub recreates it as the base or head moves, and it is not
reachable from any branch), and **not present in an ordinary clone** without explicitly fetching
`refs/pull/N/merge`. It is therefore **not a durable evidence subject** — which is the whole point.
Provenance that depends on which trigger fired is not provenance.

---

## C-3 — the source digest quoted in a commit message is wrong

**The claim.** Evidence commit `b7a4f17`'s message says:

```text
sourceDigests[kernel]    ede1e2f7... -> 1b5c1e6d...
```

**Adjudication, re-derived rather than copied.** `reproduce.ts` computes each entry as
`sha256(file content)`. Hashing the tracked file at each commit gives:

```text
87a3f05    ede1e2f7de8487cdc561e8a4b11da8a781540c2bbfc7be696bc5c2eb2f8d00df
8ba71c90   402a14a8704853657cfbb2ad5a0bc6a302fd8f346e3af8760d1c16ecd3b7a240
b7a4f17    402a14a8704853657cfbb2ad5a0bc6a302fd8f346e3af8760d1c16ecd3b7a240
```

**The committed `MEASUREMENTS.json` value `402a14a8...` is CORRECT. The commit message is WRONG.**

`1b5c1e6d...` was the digest of an intermediate tree that was never committed: the first measurement
pass ran before commit A was amended to correct a Solidity comment. The amendment's runtime hashes
were carried into the message; its source digest was not. The message therefore names a digest of a
tree that exists nowhere in this branch's history.

Nothing generated is affected — `MEASUREMENTS.json`, the receipt, and every byte measurement were
produced by tooling from the amended tree.

---

## C-4 — the tree self-reference explanation was imprecise

**The claim.** `evidence-subject.ts` and commit `b7a4f17` said:

```text
"a commit's tree hash cannot be known before that commit exists"
```

**Why that is not the rule.** A tree object is built and hashed *before* the commit that references
it; `git write-tree` does exactly that, and the commit is written afterwards naming it. The stated
reason was wrong even though the conclusion it supported is right.

**The precise rule.** The obstruction is **self-reference, not ordering**. An artifact that embeds
the identity of the tree containing it makes its own bytes part of the identity it is trying to
state: change the embedded value and the tree hash changes, which changes the value that should have
been embedded. The same holds for embedding its containing commit id, which additionally depends on
the commit message, author and timestamps. This is why evidence names its SUBJECT — a tree that is
already fixed and outside the artifact — and why the two-commit shape follows from the artifact's
content, not from any fragility about when the tooling runs.

---

## The mechanism itself, verified end-to-end in CI

The corrections above are to WORDING and to PROVENANCE ATTRIBUTION. The mechanism they describe was
independently confirmed working by CI's own artifacts, which is the strongest form of evidence
available for it, because CI is the environment where no operator supplies discipline.

`vNext Kernel / Stateful Authority` regenerates the receipt and uploads it. Comparing what that job
produced before and after the correction, for the same body of evidence:

```text
                    #194 (before)                       #195 (after)
push run            87a3f05...  the CONTAINER           8ba71c90...  the SUBJECT
pull_request run    43426b22...  synthetic merge        8ba71c90...  the SUBJECT
```

Two triggers, two different answers before; two triggers, one answer after — and that answer is the
commit `MEASUREMENTS.json` declares. Trigger-independence is the property the lane set out to obtain,
and it is demonstrated in the real CI environment rather than only on a developer machine.

`git diff --exit-code` against the committed receipt passed in both runs, so the receipt CI produced
is byte-identical to the one the PR publishes.
