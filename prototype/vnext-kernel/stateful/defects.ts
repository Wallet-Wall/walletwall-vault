/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * SUSTAINED DEFECTS — the ledger, not a suppression list.
 *
 * Three composition defects were found by this lane and then REPRODUCED
 * FIRSTHAND against the compiled kernel. Per the lane's brief, remediation is a
 * SEPARATE and MINIMAL change: this PR alters ZERO bytes of Solidity. What it
 * does instead is record each defect as a deterministic, permanently-executed
 * reproduction (test/StatefulSustainedDefects.test.ts).
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
 * NONE OF THE THREE IS AN UNAUTHORIZED ASSET OR CONTROL ESCALATION. Every one is
 * a DENIAL / LIVENESS outcome. No declared asset-control, credential-replacement,
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
}

export const SUSTAINED_DEFECTS: readonly SustainedDefect[] = [
  {
    id: "SD-1-floor-length-poisoning",
    title:
      "setVerifier may change pqPublicKeyLength / pqSignatureLength freely, and _requireIncomingPossession reads that floor LIVE — so the credential principal holds an unbounded, uncounted veto over guardian recovery",
    property: null,
    rootsRequired:
      "2 — both credential factors (ECDSA + PQ). Exactly the declared min(2,k) asset-control cut; no guardian is compromised.",
    contradicts:
      "AUTHORITY.md section 3, row 'Permanent recovery veto | unreachable | Enforced by: containment budgeted B < W; challenge capped; no pause exists'. None of the three named mechanisms bounds this channel: challengesUsed stays at 0 throughout.",
    rootCause:
      "VaultKernelPrototype.sol `_requireNoDowngrade` compares ONLY `requirePq` and `pqParamLevel`; the two LENGTH fields of SecurityFloor are unconstrained. `setVerifier` then writes the whole struct. `_requireIncomingPossession` reads `securityFloor` at EXECUTION time and rejects `c.newPqPop.length != floor.pqSignatureLength`, so an already-quorum-approved recovery can be invalidated after the fact. `executeRecovery` writes `pqVerifier` but never `securityFloor`, so no guardian quorum can repair the floor — only `setVerifier` writes it, and that is credential-gated.",
    classification: "LIVENESS_DENIAL",
    notAnEscalationBecause:
      "It requires BOTH credential factors, which is already the declared cut for moving assets — an attacker holding them can spend directly and gains no new reach. What it falsifies is the separate 'permanent recovery veto is unreachable' row, i.e. the REMEDY is deniable, not that the attacker's authority grew.",
    minimalFixSketch:
      "Extend _requireNoDowngrade to refuse a change to pqPublicKeyLength/pqSignatureLength unless it accompanies a pqParamLevel INCREASE, or snapshot the floor shape into RecoveryRequest at initiation and evaluate incoming possession against the SNAPSHOT rather than the live floor. Either is a few bytes; neither is attempted here.",
  },
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
];

/** Campaign properties whose violation is EXPLAINED by a listed defect. */
export const KNOWN_DEFECT_PROPERTIES: ReadonlySet<string> = new Set(
  SUSTAINED_DEFECTS.map((d) => d.property).filter((p): p is string => p !== null),
);

export const explains = (property: string): SustainedDefect | undefined =>
  SUSTAINED_DEFECTS.find((d) => d.property === property);
