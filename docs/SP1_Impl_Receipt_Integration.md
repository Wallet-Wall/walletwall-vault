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
| Reviewed subject | the head the pull request merged: the merge commit's second parent | `2964b51c`, tree `1d640c7a` |
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

1. **The binding is what git derives.** The receipt entered origin/main's first-parent history exactly once, through a
   two-parent merge commit whose tree is its second parent's. The receipt's base is a main commit, an ancestor of the
   lane commit that wrote the receipt, and main's `contracts/` did not move between that base and the merge's first
   parent (A2, judged at the merge: the receipt states its change set against the base, which would otherwise hide
   main's change).
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
| The receipt removed and re-added on main | two introductions | refused |
| A later pull request's CI checkout (`refs/pull/N/merge`) | a descendant: two parents, main's tip first | judged as a descendant |

A refused topology fails closed. A later lane whose receipt would land by squash or rebase cannot use this binding.

## Why this does not reduce security

- Nothing is skipped: not on branches, not on main, not when main is an ancestor. Being on main only locates the
  merge; the merge is trusted because its tree is the reviewed head's, never because it is on main.
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
and until then the change fails closed. Main's history is protected by its ruleset as measured; an administrator can
change that. The binding proves which bytes were merged, not that they are sound.

## Reproduce / check

```bash
npm run validate:sp1-impl-receipt
npx hardhat test test/Sp1ImplReceipt.test.ts test/Sp1ImplReceiptIntegration.test.ts
npx tsx scripts/generate-sp1-impl-receipt.ts --integration
```

The last writes the binding from git again; an unchanged file is the check.
