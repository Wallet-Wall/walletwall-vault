# SP1 implementation receipt after its merge — the integration binding

> [!CAUTION]
> Research prototype. Not audited. Testnet/local only. Do not use real funds. This is evidence plumbing for the SP1
> implementation lane's receipt after its pull request (#219) merged. It changes no contract, no zkvm source, no ELF,
> no `PROGRAM_VKEY`, no SP1 verifier, no designation (`PROGRAM_IDENTITY` stays `mldsa65-withdrawal-d1`) and no
> authorization; it deploys nothing and downloads nothing.

> **Merge changes provenance location, not the set of bytes that were reviewed.**
> **A historical receipt is never rewritten merely because its reviewed subject moved into main.**

## Three facts, kept apart

The receipt ([`evidence/zk/sp1-impl/implementation-receipt.json`](../evidence/zk/sp1-impl/implementation-receipt.json))
has one `baseCommit`. Before the merge that one field did two jobs: it was where the lane began, and it was what any
later tree was compared with. After the merge those are different commits, and so are four facts:

| Fact | What it is | #219 |
| --- | --- | --- |
| Historical lane base | the main commit the lane began from: the receipt's `baseCommit`, which it states its change set against. Never moved | `4ffd92ca` |
| Reviewed subject | the head the pull request merged: the merge commit's second parent (git shows the merge, not an approval) | `2964b51c`, tree `1d640c7a` |
| Integrated subject | the commit on main's first-parent history that introduced the receipt: a two-parent merge commit carrying the reviewed tree byte for byte | `74bbb0d9`, parents `4ffd92ca` and `2964b51c`, tree `1d640c7a` |
| Descendant drift baseline | what every later tree must carry, byte for byte, committed and on disk: the integrated subject's `contracts/` and the receipt itself | `contracts` tree `439e0cd5`, receipt blob `5cba7595` |

The binding is [`evidence/zk/sp1-impl/receipt-integration.json`](../evidence/zk/sp1-impl/receipt-integration.json). It
is derived from git alone by [`scripts/lib/sp1-impl-receipt-integration.ts`](../scripts/lib/sp1-impl-receipt-integration.ts)
and never typed: `npm run validate:sp1-impl-receipt` derives it again and compares it byte for byte. It pins the
historical receipt's sha256 (`b9f34d45…`) as the merge carries it, so a receipt and binding edited together still fail.

## Why every branch failed after the merge

- **The validator (the re-review's A2).** The check compared what the receipt states against its base with the latest
  main commit in HEAD's history. After the merge that commit is `74bbb0d9`, the merge of the receipt's own subject:
  the lane's two contract changes read as changed since the base and unchanged since main, so every descendant read as
  drift, one empty commit included. Main itself passed that check only because it skipped any HEAD on main's
  first-parent line.
- **The tests.** The receipt suite read its inputs at HEAD, a generating context, and the base rule then saw the merge
  in HEAD's history.
- **Regeneration.** Generating the receipt again on a descendant took the merge as its base, so the lane's own changes
  read as none, and "no contract changed since the base" was read as "a contract outside the wrapper changed":
  `STOP: CROSS_CHAIN_FIX_NEEDS_NEW_MUTABLE_PRINCIPAL, TD2_INVARIANTS_WEAKENED`, with no contract changed. That input is
  now refused at its source: a base that already carries the receipt is no lane base, because a lane's base precedes
  its receipt.

## What is checked now

1. **The binding is what git derives.** Where the receipt first entered main's first-parent history is a two-parent
   merge commit whose tree is its second parent's. Main is read only as `refs/remotes/origin/main` (a tag, a branch or
   a file named `origin/main` would win the short name, and CI fetches tags), and git reads the objects themselves: no
   replace ref and no graft is consulted. The receipt's base is a main commit, an ancestor of the lane commit that
   wrote the receipt, and main's `contracts/` did not move between that base and the merge's first parent (A2, judged
   at the merge: the receipt states its change set against the base, which would otherwise hide main's change).
2. **This tree descends from the integrated subject and carries its protected subject.** HEAD descends from the merge;
   HEAD's `contracts/` tree and receipt blob are the merge's; on disk every file under `contracts/`, and the receipt,
   hash to the merge's objects, read byte for byte (index flags such as assume-unchanged are not consulted, and an
   untracked or removed file is drift).
3. **The receipt re-derives, unchanged.** It is derived again from its historical base, verified at the commit that
   wrote it as of the reviewed head, and compared byte for byte, exactly as before the merge. Every absolute fact it
   states (the hashes of its evidence, the compiled wrapper's AST, the zkvm subject's trees, the probes' outcomes) is
   judged there on every descendant.

Only `contracts/` needed a new baseline: it is what the receipt states against its base (the contract sources changed
since it, the journal the wrapper decoded there). The check is stricter than before on it: the lane's F-1 probe
contract was never hashed, and now any byte under `contracts/` is drift.

## Merge topologies

| Topology | In git | Result |
| --- | --- | --- |
| Merge commit, branch up to date (#219; the ruleset requires up-to-date branches) | two parents; the second is the reviewed head; same tree | bound |
| Merge commit of a branch not up to date | the tree differs from the head's | refused: it carries bytes nobody reviewed |
| A merge whose tree adds anything (an evil merge), protected or not | the tree differs from the head's | refused |
| Squash merge (the ruleset allows it) | one parent | refused: no parent names the reviewed head |
| Rebase merge (the ruleset allows it) | the lane's commits replayed as single-parent main commits | refused |
| Fast-forward (no pull request method; the ruleset refuses direct pushes) | the lane's commits become main's first parents | refused |
| Octopus merge | more than two parents | refused |
| A merge made from the lane's side | main's first parent runs through the lane: a single-parent introduction | refused |
| The receipt removed and restored on main | it enters main again later | still bound to its first merge, which an append-only main never moves; the restored bytes are judged as any descendant's |
| A later pull request's CI checkout (`refs/pull/N/merge`) | a descendant: two parents, main's tip first | judged as a descendant |

A refused topology fails closed. A later lane whose receipt would land by squash or rebase cannot use this binding.

## Why this does not reduce security

- Nothing is skipped: not on branches, not on main, not when main is an ancestor. Being on main only locates the
  merge, and its second parent names the head it merged; the tree comparison shows the merge added no byte to that
  head. A descendant is judged by its bytes, never by where it is.
- The drift baseline is absolute bytes. Any change to `contracts/` or to the receipt after the merge fails, with
  the message that it needs new evidence; nothing tells anyone to regenerate the receipt.
- The historical receipt is untouched: same bytes, same base (`4ffd92ca`), same verdict. The binding is a separate,
  derived record. It is an integration, not a supersession: no new ELF, vkey, verifier, authorization, soundness
  evidence or successor designation.
- A genuine change still derives its STOP: a contract outside the wrapper gives the same pair, from a real change set.
- It fails closed without the full history (a shallow clone), without origin/main, with an origin/main from before the
  merge, with objects git cannot read, and without the binding.

**Residuals.** The validator's own code is the checker, reviewed by pull request, as before. A protected change after
the merge needs evidence no lane defines yet: a later lane must supersede this receipt (as SP1-P1's was superseded),
and until then the change fails closed; that holds for any change under `contracts/`, an unrelated vault fix
included, because the receipt states that no contract outside the wrapper changed.

**Supersession of `PROVING_AVAILABILITY` (SP1-PA2B).** The receipt also binds `PROVING_AVAILABILITY` and the
availability file's digest, read from the working tree, and SP1-PA2B's archive record moves that status to
`ARCHIVED_VERIFIED_UNEXERCISED`. The receipt is never restamped: `npx tsx scripts/generate-sp1-impl-receipt.ts
--supersession --lane <id> --record <the archive record> --reason "<why>"` writes
`evidence/zk/sp1-impl/receipt-supersession.json` once (`walletwall.sp1-impl-receipt-supersession.v1`): the receipt's
bytes pinned by sha256, a first-parent commit of `origin/main` at which the receipt was live (an ancestor of HEAD
carrying the same receipt, with a pre-archive availability), `supersedes: ["PROVING_AVAILABILITY"]` (the only
status superseded this way), and the superseding records (the archive record first: the one the live availability
accepted, each a regular file in the checkout). `validate:sp1-impl-receipt` then derives that one status and that one file's digest at that commit, read from git, and everything else live. The
supersession is refused unless the live availability record validates and names an archived state, so it cannot
hide a live refusal and cannot be filed while nothing moved; an uncommitted supersession file binds nothing, so the
receipt derives live until the file is committed; the historical subject is refused when it is a lane
commit, a merge's second parent, a commit without the receipt, or one whose availability was already archived
(`test/Sp1ImplReceiptSupersession.test.ts`). Main's history is protected by its
ruleset as measured; an administrator can change that. "Reviewed" means merged through a pull request with its
required checks: git shows the merge, not an approval, and the measured ruleset requires no approving review; the
receipt's `OWNER_REVIEW_AND_MERGE` prerequisite stays as published. `contracts/` pins sources: the wrapper's compiled
code is pinned by its build record, but a dependency or compiler change (`package-lock.json`, `hardhat.config.ts`)
reaches the other contracts' compiled code without changing a source, and the receipt never bound that. Someone who
can write to a clone's `.git` (a forged commit-graph, say) defeats any check run in it; CI's fresh clone is the one that
counts. The binding proves which bytes were merged, not that they are sound.

## Adversarial review

An independent review attacked the binding before publication, each attack run against the module on throwaway
repositories. It found no HIGH or CRITICAL finding:

| Finding | Severity | Resolution |
| --- | --- | --- |
| git resolves the short name `origin/main` to a tag, a branch or a file of that name before the remote-tracking ref, and CI fetches tags: a pushed tag could choose "main", and so the merge and head the binding names | MEDIUM | main is read only as `refs/remotes/origin/main`, in the binding, the base rule and the generator; tests show each shadow moving git's answer and none moving the binding's |
| `--no-replace-objects` leaves grafts (`info/grafts`, `GIT_GRAFT_FILE`) honoured | LOW | every git read of the binding and of the base rule points `GIT_GRAFT_FILE` at a file that does not exist; tested with both |
| a receipt removed and restored on main (a rebase merge) made "entered main once" fail forever | LOW, availability | bound to the first merge, which an append-only main never moves; restored bytes are judged as any descendant's |
| "reviewed subject" claims a review git cannot show | LOW | the record states it attests topology and bytes, not who reviewed or merged; `OWNER_REVIEW_AND_MERGE` stays as published |
| `contracts/` pins sources, not compiled code | LOW, as before | stated in the residuals above |
| the base rule's own git reads honoured replace refs; a CRLF clone's drift was named as a protected change | INFO | the base rule reads the objects themselves too (tested); a CRLF-only drift is named so |

The review found none of the following, each tried: laundering unreviewed bytes into a descendant through content
edits, untracked or assume-unchanged files, removals or case-only renames; binding through a squash, rebase,
fast-forward, octopus, swapped-parent or lane-side merge, an evil merge, a replace ref, a shallow clone, or a missing or
stale `origin/main`; a check that passes on a git error.

## Mutation testing

A curated campaign of **66 mutants** on the final bytes covers each check named above:
- reading main and its objects (the full ref, replace refs, grafts, shallow clones, a missing origin/main, unreadable ancestry);
- where the receipt entered main and through which topology;
- the reviewed-head anchor, the receipt digest, the tree identity, and the historical base versus the reviewed subject;
- A2 at the merge;
- the committed record;
- every descendant check, committed and on disk;
- the base-precedes-its-receipt rule, the glue that judges a tree only through the binding, a validator that trusts main or bypasses the binding, the genuine-STOP condition, and the CLI.

Each mutant is one edit, applied alone in a separate detached worktree, run against the two receipt suites, and its bytes restored and re-hashed afterwards. Results: **66 killed, none survived, none invalid, no flaky kill.**

Three mutants were killed only through the receipt suite's before-all hook. Each was checked to fail for its own reason:
- every base read as carrying the receipt;
- the base judged at HEAD, which is the original bug's own message;
- the merge used as the base.

Two earlier rounds shaped the code. The first ran 25 mutants on an earlier commit, all killed, and was stopped when the review's fixes changed the code. The second found one survivor: once the binding named the first introduction, "its first parent lacks the receipt" was implied. That conjunct was designed out rather than called equivalent. The catalog and harness are in the pull request's comments.

## Reproduce / check

```bash
npm run validate:sp1-impl-receipt
npx hardhat test test/Sp1ImplReceipt.test.ts test/Sp1ImplReceiptIntegration.test.ts
npx tsx scripts/generate-sp1-impl-receipt.ts --integration
```

The last writes the binding from git again; an unchanged file is the check.
