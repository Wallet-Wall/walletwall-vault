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
 * TWO HAVE SINCE BEEN REMEDIATED — SD-1 by `I-FLOOR-SHAPE-IMMUTABLE` and SD-3 by
 * `I-DECLARATION-EXHIBITED`. SD-2 and SD-4 stand. The history of each closure is
 * preserved rather than rewritten: every closed entry moved OUT of
 * `SUSTAINED_DEFECTS` and INTO `REMEDIATED_DEFECTS` below, carrying the head it
 * was SUSTAINED at, the invariant that closed it, the designs rejected on the
 * way, and the residual it leaves.
 *
 * SD-4 IS STILL OPEN ON PURPOSE, and its entry is the most useful thing in this
 * file. A fix WAS built, measured and then REMOVED, because refusing a one-shot
 * transition hands the opposing principal a permanent veto over a capability it
 * cannot itself exercise. Recording a rejected fix and why it was rejected is
 * worth more than shipping it, and it is what stops the next lane rebuilding it.
 *
 * A RESIDUAL IS A FIRST-CLASS ENTRY, NOT A FOOTNOTE: SD-1 names SD-5, the
 * permanence its freeze introduced, and SD-3 names SD-4, which its exhibit
 * provably does NOT close. A residual pointing at a closed defect would be stale
 * evidence, and the ledger test refuses it.
 *
 * The count moved from three to four, and that is arithmetic rather than a
 * target: SD-1, SD-3 and SD-4 left; SD-5, SD-6 and SD-7 arrived, all three
 * surfaced by RE-DERIVING the defects the lane before had recorded instead of
 * trusting them. Two recorded claims turned out to be wrong in the process —
 * SD-3's title overstated its severity, and SD-3's own minimal fix sketch would
 * not have closed it — which is the argument for re-deriving rather than
 * implementing what the ledger says.
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
    id: "SD-5-permanent-shape-capture-on-the-declaring-edge",
    title:
      "The requirePq false -> true declaration is one-shot and IRREVERSIBLE, so one root on an ECDSA-only vault may pin a structurally vacuous shape — 1-byte key, 1-byte signature, pqParamLevel 65535 — that no principal, a guardian quorum included, can ever change",
    property: null,
    rootsRequired:
      "1 — the sole ECDSA credential root of a vault born ECDSA-only, where `_authorise` degenerates to the ECDSA conjunct alone. The same cut that already moves every asset on that vault class, so it is no escalation; what is new is that this particular choice outlives the remedy.",
    contradicts:
      "AUTHORITY.md section 3, the 'Silent crypto downgrade' row's unqualified parenthetical 'true of all four fields since I-FLOOR-SHAPE-IMMUTABLE'. That holds only ONCE requirePq already does. On the declaring edge two of the four fields are free, and the choice made there is permanent.",
    rootCause:
      "`_requireSaneFloor` bounds the two lengths only against 0 and MAX_PQ_LENGTH, and `_requireNoDowngrade` admits any pqParamLevel INCREASE, so {1, 1, 65535} is admissible. `I-FLOOR-SHAPE-IMMUTABLE` then freezes both lengths for the life of the vault, and `securityFloor` has exactly two writers — `initialize`, one-shot, and `setVerifier`, which the freeze closes. `executeRecovery` writes `recovery`, `pqVerifier` and the credential and NEVER the floor, so the shape survives the remedy intact. `I-DECLARATION-EXHIBITED` blunts this — a 1-byte shape needs a 1-byte preimage of the committed hash — but does not close it, because the same cut-1 principal can plant that commitment one transaction earlier through SD-6's unattested rotation.",
    classification: "LIVENESS_DENIAL",
    notAnEscalationBecause:
      "It reduces no cut. On an ECDSA-only vault the asset-control cut is ALREADY 1 — `_authorise` returns before the PQ leg — so a permanently vacuous second factor removes nothing the vault ever had. The harm is that the vault can never GAIN one: a real 1,312-byte ML-DSA-44 key is refused forever. A permanent agility loss on one vault class, not an authority gain.",
    minimalFixSketch:
      "Only one family closes it: let a COMPLETED guardian recovery re-declare the shape to that of the material it just proved possession of. NOT APPLIED, and for a hard constraint rather than a preference — it lets a quorum move a field `I-FLOOR-SHAPE-IMMUTABLE` currently freezes against every principal, i.e. it LOOSENS an existing check, and it moves AUTHORITY.md's 'Silent crypto downgrade' row from unreachable to k. Cheaper blunting worth costing first: a MIN_PQ_LENGTH, or removing `pqParamLevel`, which no execution path reads.",
    reproducedBy: "prototype/vnext-kernel/test/Sd34AuthenticationSatisfiability.test.ts",
  },
  {
    id: "SD-6-unattested-commitment-install-on-an-ecdsa-only-floor",
    title:
      "While requirePq is false, rotateCredential installs an arbitrary pqPublicKeyHash with NO possession proof of any kind, because _requireIncomingPossession returns before every PQ check",
    property: null,
    rootsRequired:
      "1 — the ECDSA credential of a vault whose floor does not (yet) mandate PQ. No PQ material, no guardian.",
    contradicts:
      "AUTHORITY.md section 3, row 'Credential stranding | unreachable | Enforced by: I-INCOMING-CREDENTIAL-POSSESSION on both rotation and recovery'. The invariant is named for both paths but is inert on either while requirePq is false.",
    rootCause:
      "`_requireIncomingPossession` reads the live floor and returns at `if (!floor.requirePq) return;` BEFORE the length filter, the `keccak256(c.newPqKey) != expectedPqKeyHash` cross-check and the verifier call. On an ECDSA-only vault only the self-consistency test and the incoming ECDSA proof run, so `_installCredential` writes a commitment attested by nothing.",
    classification: "STATE_INCOHERENCE",
    notAnEscalationBecause:
      "The commitment is DORMANT while requirePq is false — no path reads it — and installing one costs the same single root that already controls the vault outright on this class. It became load-bearing only when `I-DECLARATION-EXHIBITED` made that commitment the thing a declaration is measured against: it is the mechanism by which a determined adversary still chooses the shape, and simultaneously the LIVENESS path by which an honest zero-commitment vault adopts PQ at all.",
    minimalFixSketch:
      "Make `_requireIncomingPossession` demand a preimage whenever `expectedPqKeyHash != 0`, WITHOUT a length comparison — the length is meaningless while no shape is declared, and comparing against the undeclared zero length would permanently brick PQ rotation on ECDSA-only vaults. NOT APPLIED: it changes a helper shared by the rotation and recovery paths, a wider blast radius than this lane's brief admits, and it must be designed together with SD-5.",
    reproducedBy: "prototype/vnext-kernel/test/Sd34AuthenticationSatisfiability.test.ts",
  },
  {
    id: "SD-7-genesis-admits-an-unsatisfiable-floor",
    title:
      "initialize admits a genesis whose committed key cannot satisfy the floor it declares — a vault BORN unable to authorise, with the shape already frozen",
    property: null,
    rootsRequired:
      "0 — no principal is compromised. The configuration is chosen by whoever deploys the vault, and `deployVault` is permissionless, so a bad genesis lands at its own CREATE2 address and harms only that vault.",
    contradicts:
      "`initialize`'s own comment, 'A mandatory PQ conjunct with no committed key is unsatisfiable, and would brick spending from birth'. The check written under it tests only ZERO-ness, so it catches the degenerate case and admits every other unsatisfiable one.",
    rootCause:
      "`initialize` validates the floor with `_requireSaneFloor` (shape bounds only) plus a single zero-ness test on the key commitment. `_requireIncomingPossession` has exactly two call sites, `rotateCredential` and `executeRecovery`, and `initialize` is neither — so there is NO genesis possession proof of any kind. A genesis committing a 48-byte key against a declared 32-byte shape is admitted, and `I-FLOOR-SHAPE-IMMUTABLE` freezes that shape from birth because `requirePq` already holds. Both clauses of the SD-3 / SD-4 remediation live in `setVerifier` and never run here.",
    classification: "STATE_INCOHERENCE",
    notAnEscalationBecause:
      "It is self-inflicted and unreachable by an attacker against someone else's vault: the whole genesis is bound into the CREATE2 salt, so a different configuration is a different address, and `I-COUNTERFACTUAL-IDENTITY-BINDING` means nobody can occupy the identity a user predicted. Spending is dead from birth, but a guardian quorum still recovers — `executeRecovery` installs a fresh commitment of the quorum's choosing at the declared shape — so the vault is escapable at k, exactly as SD-3's spending brick was.",
    minimalFixSketch:
      "Carry the key bytes in `GenesisConfig` and apply the same exhibit at genesis: refuse when `requirePq` holds and the supplied key either has the wrong length or does not hash to the committed value. NOT APPLIED, and the reason is blast radius rather than difficulty: `GenesisConfig` is hashed into `genesisSalt`, so adding a member changes EVERY vault address the factory can produce, and the factory ABI with it. That is a larger change than closing a cut-0 self-inflicted misconfiguration warrants, and it belongs with SD-5 and SD-6 in a lane that can re-derive the whole genesis surface.",
    reproducedBy: "prototype/vnext-kernel/test/Sd34AuthenticationSatisfiability.test.ts",
  },
  {
    id: "SD-4-ecdsa-only-shape-declaration-is-uncounted",
    title:
      "On a vault born ECDSA-only, the requirePq false -> true declaration adds a whole authentication conjunct to an ALREADY-QUORUM-APPROVED recovery, destroying it at cut 1 with no challenge consumed and the request left stranded active",
    property: "G-DECLARATION-SUBORDINATE-TO-RECOVERY",
    rootsRequired:
      "1 — the sole ECDSA credential root of a vault born ECDSA-only, where `_authorise` returns before the PQ leg. No PQ material, no guardian.",
    contradicts:
      "AUTHORITY.md section 3, row 'Permanent recovery veto | unreachable | Enforced by: containment budgeted B < W; challenge capped; no pause exists'. None of the three named mechanisms bounds this channel: `challengesUsed` stays at 0 throughout, and `setVerifier` contains no reference to `recovery` at all.",
    rootCause:
      "The declaring edge is the one transition that still chooses both structural length fields freely, and `_requireIncomingPossession` measures an already-approved recovery against them LIVE. The mechanism is stronger than a length mismatch: before the edge, line `if (!floor.requirePq) return;` returns before EVERY PQ check, so a quorum may approve a request while no PQ material is required of it; after the edge, three checks and an external verifier call appear on that same request. Both forms are reproduced — one dies on the key length, the other on the signature length — so any fix constraining only ONE length closes neither reliably.",
    classification: "LIVENESS_DENIAL",
    notAnEscalationBecause:
      "It reduces no cut. On an ECDSA-only vault the asset-control cut is already 1, so the principal doing this already controls the vault outright. What it falsifies is the separate 'permanent recovery veto is unreachable' row: the REMEDY is deniable for one episode, raising the cut-1 recovery-delay denial from the 14 days `I-VETO-BOUND` implies (2 metered cancellations) to 21 (2 metered plus 1 unmetered). The quorum self-heals by re-proposing against the declared shape.",
    minimalFixSketch:
      "TWO FAMILIES WERE BUILT AND BOTH REJECTED, and recording why is the point of this entry. (1) An INTERLOCK refusing the declaration while a live approved request exists was implemented, measured and REMOVED: the declaration is one-shot and no guardian path can ever write `securityFloor`, so the refusal hands the quorum a renewable, uncounted veto over a capability it cannot itself exercise — `initiateRecovery` has no `!recovery.active` guard while the credential's counter-move is capped — pinning an ECDSA-only vault at cut 1 forever. Trading a bounded one-shot credential harm for an unbounded guardian one is not a remediation. (2) METERING the destruction against `challengesUsed` fails for a subtler reason: a counter has teeth only through its REFUSAL, and refusing a ONE-SHOT transition is permanent deprivation, so metering moves the irreversibility from the attacker to the defender. The only design that closes this soundly RECORDS THE PROPOSED KEY AND SIGNATURE LENGTHS IN `RecoveryRequest` at `initiateRecovery` and measures the recovery against the REQUEST rather than the live floor — which needs new storage, a new `initiateRecovery` signature, a moved selector and a manifest entry, i.e. its own lane.",
    reproducedBy: "prototype/vnext-kernel/test/Sd34AuthenticationSatisfiability.test.ts",
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
    // SD-1 originally declared SD-4 as its residual. SD-4 has since been
    // REMEDIATED in its own right, so the chain is re-pointed at what actually
    // survives from the freeze this entry introduced: SD-5, the permanence of a
    // shape once declared. A residual pointing at a closed defect is stale
    // evidence, and the ledger test refuses it.
    residual: "SD-5-permanent-shape-capture-on-the-declaring-edge",
  },
  {
    id: "SD-3-setverifier-skips-genesis-satisfiability",
    title:
      "setVerifier could raise requirePq without re-checking that the vault's COMMITTED material can satisfy the requirements being declared — the exact configuration initialize refuses at genesis",
    sustainedAt: "ec5adce91bf6956a655a637513102bd6613c04f8",
    remediatedOn: "security/vnext-sd3-sd4-authentication-satisfiability",
    invariant:
      "I-DECLARATION-EXHIBITED — for every accepted setVerifier transition s -> s' with !s.requirePq && s'.requirePq, the call must exhibit a byte string K with |K| == s'.pqPublicKeyLength and keccak256(K) == s.pqPublicKeyHash. Every OTHER floor-touching transition already measures the committed key, so this is what makes that measurement an INDUCTIVE invariant rather than an assumption about genesis.",
    sourceDelta:
      "Two comparisons inside setVerifier, on the false -> true edge only, using the `pqKey` parameter that already exists and that `_authorise` provably ignores on that edge. No new state, no new parameter, no selector change.",
    rejectedAlternatives:
      "The ledger's OWN recorded sketch — `if (floor.requirePq && pqPublicKeyHash == bytes32(0)) revert` — was implemented and measured at +55 B and REJECTED as insufficient: it closes only the zero-commitment form, and a vault with a perfectly good NON-ZERO commitment reaches the identical dead state by declaring a shape no preimage of that commitment has. A SIGNATURE leg was rejected because the declarer supplies arbitrary bytes of any length and `_requireSaneFloor` already bounds them, and because two maximal legs would push the arming call past the txpool transaction cap, breaking the legitimate maximum-shape declaration the boundary suite pins. A VERIFIER call was rejected as self-certification in both bindings: the declarer chooses the incoming verifier in the same transaction, and can swap the incumbent to an always-true one first while the floor is still ECDSA-only.",
    invertedReproduction:
      "test/Sd34AuthenticationSatisfiability.test.ts keeps both forms as executed evidence and asserts the refusal; test/Sd34DeclarationInvariants.test.ts carries the full regression including the two-transaction adoption path the exhibit makes necessary.",
    residual: "SD-4-ecdsa-only-shape-declaration-is-uncounted",
  },
];

/** Campaign properties whose violation is EXPLAINED by a listed defect. */
export const KNOWN_DEFECT_PROPERTIES: ReadonlySet<string> = new Set(
  SUSTAINED_DEFECTS.map((d) => d.property).filter((p): p is string => p !== null),
);

export const explains = (property: string): SustainedDefect | undefined =>
  SUSTAINED_DEFECTS.find((d) => d.property === property);
