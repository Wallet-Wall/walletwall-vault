/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * SUSTAINED DEFECTS — the ledger, not a suppression list.
 *
 * Three composition defects were found by the stateful adversarial lane and then
 * REPRODUCED FIRSTHAND against the compiled kernel. That lane deliberately
 * altered ZERO bytes of Solidity and recorded each as a deterministic,
 * permanently-executed reproduction (test/StatefulSustainedDefects.test.ts).
 *
 * SD-1 HAS SINCE BEEN REMEDIATED, and the history of that is preserved rather
 * than rewritten. It moved OUT of `SUSTAINED_DEFECTS` and INTO
 * `REMEDIATED_DEFECTS` below, which carries the head it was SUSTAINED at, the
 * head it was REMEDIATED at, the invariant that closed it, and — because the
 * remediation is scoped rather than total — the residual it leaves behind. That
 * residual is `SD-4`, and it is carried as a first-class sustained defect in its
 * own right, not as a footnote to a closed one.
 *
 * The count is therefore still three, and that is a coincidence of arithmetic,
 * not a target: SD-1 left and SD-4 arrived.
 *
 * WHY A LEDGER RATHER THAN A SUPPRESSION
 * --------------------------------------
 * Each entry below is asserted in BOTH directions:
 *
 *   1. a campaign violation matching a listed defect does NOT fail the run —
 *      otherwise this lane would be permanently red for a defect it is
 *      deliberately not fixing here; and
 *   2. each listed defect MUST STILL BE REPRODUCIBLE. If a fix lands, its
 *      reproduction stops reproducing and the suite FAILS, forcing this ledger
 *      and AUTHORITY.md to be updated together.
 *
 * A defect that can be silently fixed without anyone updating the document that
 * claims it is unreachable is how a stale security table is born. Direction (2)
 * is what prevents that, and it is why this is not a list of ignores.
 *
 * NONE OF THESE IS AN UNAUTHORIZED ASSET OR CONTROL ESCALATION. Every one is a
 * DENIAL / LIVENESS outcome. No declared asset-control, credential-replacement,
 * verifier-replacement, guardian or migration cut is reduced by any of them —
 * that is stated here as a bound on the claim, not as mitigation.
 */

export interface SustainedDefect {
  id: string;
  title: string;
  /** Campaign property whose violation this defect explains, if it surfaces as one. */
  property: string | null;
  /** Roots required. Compared against the declared cut in the same units. */
  rootsRequired: string;
  /** The published claim this falsifies, quoted. */
  contradicts: string;
  /** The exact source construct responsible. */
  rootCause: string;
  classification: "LIVENESS_DENIAL" | "STATE_INCOHERENCE";
  /** Why this is NOT an authority-cut reduction. Stated so the claim cannot be over-read. */
  notAnEscalationBecause: string;
  /** The minimal proposed remediation, NOT applied in this PR. */
  minimalFixSketch: string;
  /**
   * Where the deterministic reproduction lives, when it is NOT the default
   * `test/StatefulSustainedDefects.test.ts`. A ledger that names the wrong file
   * sends a reader looking for evidence that is not there, which is worse than
   * naming none.
   */
  reproducedBy?: string;
}

export const SUSTAINED_DEFECTS: readonly SustainedDefect[] = [
  {
    id: "SD-2-containment-window-is-tumbling",
    title:
      "The containment budget window is TUMBLING, not rolling: containments straddling a rollover yield 9 CONTIGUOUS contained days against a declared 6-day budget",
    property: null,
    rootsRequired: "k = 2 distinct guardian principals — exactly the declared guardian cut, and an accepted trust root (D1).",
    contradicts:
      "VaultKernelPrototype.sol's own comment 'Rolling containment budget window origin' and enterContainment's 'total contained time in any rolling window is capped at CONTAINMENT_BUDGET (I-CONTAINMENT-BUDGET), so denial is a duty cycle, not a state'. Measured worst case is 9.00 days inside a 30-day rolling window against a declared 6.00.",
    rootCause:
      "`if (nowTs >= containmentWindowStart + CONTAINMENT_WINDOW) { containmentWindowStart = nowTs; containmentUsedInWindow = 0; }` resets the origin to NOW rather than sliding it, so the accounting is per-epoch. Containments at W+27d and W+30d land in different epochs while being contiguous in wall-clock time. Each epoch's own accounting stays within budget; the ROLLING guarantee does not hold.",
    classification: "LIVENESS_DENIAL",
    notAnEscalationBecause:
      "Containment withdraws SPENDING and never recovery — `_requireRecoveryOpen` admits CONTAINED — so the remedy path stays open throughout, and the overshoot is 1.5x a declared bound rather than an unbounded state. It reduces no cut: k guardians already hold this capability by design.",
    minimalFixSketch:
      "Either implement a true rolling window (a small ring of (start,duration) entries, as the production vault's rolling spend ledger already does), or restate I-CONTAINMENT-BUDGET as a TUMBLING-epoch bound and publish the real worst case as 2 x CONTAINMENT_MAX contiguous plus one epoch boundary. The second is a documentation change and costs zero bytes.",
  },
  {
    id: "SD-3-setverifier-skips-genesis-satisfiability",
    title:
      "setVerifier may raise requirePq to true while pqPublicKeyHash is zero — the exact configuration initialize refuses as unsatisfiable — permanently bricking spending at cut 1 on an ECDSA-only vault",
    property: "G-PQ-COMMITMENT-SATISFIABLE",
    rootsRequired:
      "1 — the sole ECDSA credential root of a vault born with an ECDSA-only floor, where `_authorise` IS the ECDSA conjunct alone. No guardian, no PQ material.",
    contradicts:
      "AUTHORITY.md section 3, row 'Credential stranding | unreachable | Enforced by: I-INCOMING-CREDENTIAL-POSSESSION on both rotation and recovery'. Stranding here is reached through the FLOOR, not through a credential install, so that mechanism never engages.",
    rootCause:
      "`initialize` contains `if (g.floor.requirePq && g.pqKeyHash == bytes32(0)) revert BadSignature();` with the comment 'A mandatory PQ conjunct with no committed key is unsatisfiable, and would brick spending from birth.' `setVerifier` writes the same struct through `_requireSaneFloor`, which checks only that the two LENGTHS are non-zero — it never re-checks the key commitment. `_authorise` then requires `keccak256(pqKey) == pqPublicKeyHash == 0`, which no preimage satisfies.",
    classification: "STATE_INCOHERENCE",
    notAnEscalationBecause:
      "The single root that can do this is the same root that can already move every asset on an ECDSA-only vault, so it buys an attacker nothing; and a guardian quorum can still recover, because executeRecovery installs a fresh pqKeyHash of the guardians' choosing. It is an unguarded transition into a state genesis validation explicitly forbids, escapable at k.",
    minimalFixSketch:
      "Add the genesis check to the transition: in setVerifier, after _requireSaneFloor, `if (floor.requirePq && pqPublicKeyHash == bytes32(0)) revert BadSignature();`. One comparison. Not applied here.",
  },
  {
    id: "SD-4-ecdsa-only-shape-declaration-is-uncounted",
    title:
      "On a vault born ECDSA-ONLY, the requirePq false -> true edge DECLARES the structural shape for the first time, and a shape that does not match a pending recovery's proposed key invalidates that already-quorum-approved request without consuming a challenge",
    property: null,
    rootsRequired:
      "1 — the sole ECDSA credential root of an ECDSA-only vault, where `_authorise` degenerates to the ECDSA conjunct alone. Strictly cheaper than SD-1 was, and reachable on a strictly narrower set of vaults.",
    contradicts:
      "AUTHORITY.md section 3, row 'Permanent recovery veto | unreachable'. That row is now enforced by I-FLOOR-SHAPE-IMMUTABLE for every vault whose floor already mandates PQ, and this is the declared exception to it: on an ECDSA-only genesis the shape has not been declared yet, so there is nothing for the freeze to hold.",
    rootCause:
      "`_requireNoDowngrade`'s I-FLOOR-SHAPE-IMMUTABLE clause is guarded on `current.requirePq`, because a vault born ECDSA-only must be able to declare a shape at all — freezing 0/0 forever would make the floor permanently unraisable. On that one edge `setVerifier` therefore still chooses both length fields freely, and `_requireIncomingPossession` measures a pending recovery against them. The guard cannot be moved to `next.requirePq` without also forbidding the legitimate declaration.",
    classification: "LIVENESS_DENIAL",
    notAnEscalationBecause:
      "It is ONE-SHOT and self-healing, which is what separates it from the SD-1 veto it is the residue of. `requirePq` is monotone, so the edge exists at most once per vault; the shape is FROZEN immediately afterwards; and `MAX_PQ_LENGTH` bounds it to a shape a block can actually carry, so the quorum simply re-initiates against the now-immovable shape and completes at k. Cost to the defender is one re-initiation (RECOVERY_DELAY), never the remedy. Reproduced end to end, including the escape, in test/Sd1RecoveryFloorBinding.test.ts.",
    minimalFixSketch:
      "Require the caller to EXHIBIT the committed key on the false -> true edge: in _requireNoDowngrade's caller, `if (!current.requirePq && next.requirePq) { if (pqKey.length != next.pqPublicKeyLength || keccak256(pqKey) != pqPublicKeyHash) revert BadSignature(); }`. NOT APPLIED, and the reason is a scope boundary rather than an oversight: that check necessarily also closes SD-3 (a zero pqPublicKeyHash has no exhibitable preimage), so SD-1 and SD-3 are NOT separable at this edge. It also pins the shape to the length of the preimage of the VAULT's incumbent key, which is a different variable from the quorum's r.proposedPqKeyHash, so it narrows the residual without provably eliminating it. Both belong to whichever lane takes SD-3.",
    reproducedBy: "prototype/vnext-kernel/test/Sd1RecoveryFloorBinding.test.ts",
  },
];

/**
 * REMEDIATED DEFECTS — the other half of the ledger, and the reason the file is
 * not simply shorter than it used to be.
 *
 * A defect that is fixed and then DELETED from the ledger leaves a repository in
 * which the fix has no provenance and the reproduction has no explanation. Each
 * entry below therefore records the head the defect was SUSTAINED at, the head
 * it was REMEDIATED at, the invariant that closed it, and the residual it left.
 * The historical evidence receipt at the sustaining head is NOT rewritten.
 */
export interface RemediatedDefect {
  id: string;
  title: string;
  /** The commit at which the defect was reproduced and RECORDED as sustained. */
  sustainedAt: string;
  /** The branch carrying the remediation. The exact head is stamped by the evidence receipt. */
  remediatedOn: string;
  /** The security invariant the remediation establishes. */
  invariant: string;
  /** The exact production-source delta, in words. */
  sourceDelta: string;
  /** Designs evaluated and rejected, with the reason. A fix with no rejected alternatives was not chosen. */
  rejectedAlternatives: string;
  /** Where the ORIGINAL counterexample now lives, inverted. */
  invertedReproduction: string;
  /** What the remediation does NOT close, named by id. */
  residual: string | null;
}

export const REMEDIATED_DEFECTS: readonly RemediatedDefect[] = [
  {
    id: "SD-1-floor-length-poisoning",
    title:
      "setVerifier could change pqPublicKeyLength / pqSignatureLength freely while _requireIncomingPossession read that floor LIVE, so the credential principal held an unbounded, uncounted veto over guardian recovery",
    sustainedAt: "ec5adce91bf6956a655a637513102bd6613c04f8",
    remediatedOn: "security/vnext-sd1-recovery-floor-binding",
    invariant:
      "I-FLOOR-SHAPE-IMMUTABLE — for every accepted setVerifier transition s -> s', s.securityFloor.requirePq implies s'.pqPublicKeyLength == s.pqPublicKeyLength and s'.pqSignatureLength == s.pqSignatureLength. Since initialize and setVerifier are the only writers of securityFloor, the two structural fields are CONSTANTS for the life of any vault whose floor mandates PQ, and no credential-writable state remains in the recovery satisfiability condition.",
    sourceDelta:
      "Two clauses, both inside existing internal helpers, no new state and no changed signature. (1) _requireNoDowngrade gains the shape-freeze comparison, guarded on current.requirePq. (2) _requireSaneFloor gains a MAX_PQ_LENGTH magnitude bound, because I-FLOOR-SHAPE-IMMUTABLE would otherwise make an unsatisfiable uint32 shape PERMANENT.",
    rejectedAlternatives:
      "METERING the veto through challengesUsed was rejected: that counter bounds cancelRecovery only because a cancellation is REVERSIBLE by the defender, and a floor write is not — no guardian path writes securityFloor and executeRecovery never touches it — so a counter bounds only how many times an attacker re-chooses which permanent state to inflict. SNAPSHOTTING the floor into RecoveryRequest was rejected: _authorise reads the same live slot, so a floor poisoned BEFORE the quorum proposes is copied faithfully into the snapshot, and a recovery that did complete would install a credential the live floor could never use. The ledger's own earlier sketch — permitting a length change alongside a pqParamLevel INCREASE — was rejected because pqParamLevel is a bare uint16 with no ceiling, so it converts an unbounded veto into a 65,535-deep one, which over a 21-day episode is not a bound at all.",
    invertedReproduction:
      "test/StatefulSustainedDefects.test.ts still runs the exact SD-1 sequence, now asserting that the poisoning transition is REFUSED and the vetoed recovery EXECUTES. test/Sd1RecoveryFloorBinding.test.ts carries the full R1-R9 regression plus the adversarial permutations.",
    residual: "SD-4-ecdsa-only-shape-declaration-is-uncounted",
  },
];

/** Campaign properties whose violation is EXPLAINED by a listed defect. */
export const KNOWN_DEFECT_PROPERTIES: ReadonlySet<string> = new Set(
  SUSTAINED_DEFECTS.map((d) => d.property).filter((p): p is string => p !== null),
);

export const explains = (property: string): SustainedDefect | undefined =>
  SUSTAINED_DEFECTS.find((d) => d.property === property);
