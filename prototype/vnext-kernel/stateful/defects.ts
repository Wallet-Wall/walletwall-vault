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
 * FOUR HAVE SINCE BEEN REMEDIATED — SD-1 by `I-FLOOR-SHAPE-IMMUTABLE`, SD-3 by
 * `I-DECLARATION-EXHIBITED`, and SD-6 and SD-7 together by
 * `I-COMMITMENT-EXHIBITED-AT-ADMISSION`. SD-2, SD-4, SD-5 and SD-8 stand, each
 * for a stated reason rather than for want of effort. The history of each closure is
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
 * The count is arithmetic rather than a target. SD-1 and SD-3 left; SD-5, SD-6
 * and SD-7 arrived; SD-6 and SD-7 then left too, and SD-8 arrived as the declared
 * residual of SD-7's fix. Every one of those arrivals came from RE-DERIVING what
 * the previous lane had recorded instead of trusting it, and each round found a
 * wrong claim: SD-3's title overstated its severity; SD-3's own minimal fix
 * sketch would not have closed it; SD-7's deferral rested on a false statement
 * about genesisSalt; and this lane's own first draft claimed vault addresses were
 * unchanged when only the SALT is. That last one was caught by hostile review of
 * the finished work, which is the argument for reviewing a remediation as
 * adversarially as the defect it closes.
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
      "`_requireSaneFloor` bounds the two lengths only against 0 and MAX_PQ_LENGTH, and `_requireNoDowngrade` admits any pqParamLevel INCREASE, so {1, 1, 65535} is admissible. `I-FLOOR-SHAPE-IMMUTABLE` then freezes both lengths for the life of the vault, and `securityFloor` has exactly two writers — `initialize`, one-shot, and `setVerifier`, which the freeze closes. `executeRecovery` writes `recovery`, `pqVerifier` and the credential and NEVER the floor, so the shape survives the remedy intact. `I-DECLARATION-EXHIBITED` blunts this — a 1-byte shape needs a 1-byte preimage of the committed hash — and `I-COMMITMENT-EXHIBITED-AT-ADMISSION` now forces that commitment to have been exhibited when it was installed. NEITHER closes it, and the reason is that an exhibit proves POSSESSION OF A PREIMAGE and nothing about that preimage being a well-formed key: the attacker simply holds the 1-byte string and exhibits it at both points. `pqSignatureLength` is weaker still — no commitment anywhere in this kernel binds it, so the vacuous shape is reachable against an HONEST genesis commitment with no rotation in the sequence at all (test/Sd34AuthenticationSatisfiability.test.ts). SD-5 is a MIN_PQ_LENGTH question, not an admission question.",
    classification: "LIVENESS_DENIAL",
    notAnEscalationBecause:
      "It reduces no cut. On an ECDSA-only vault the asset-control cut is ALREADY 1 — `_authorise` returns before the PQ leg — so a permanently vacuous second factor removes nothing the vault ever had. The harm is that the vault can never GAIN one: a real 1,312-byte ML-DSA-44 key is refused forever. A permanent agility loss on one vault class, not an authority gain.",
    minimalFixSketch:
      "Only one family closes it: let a COMPLETED guardian recovery re-declare the shape to that of the material it just proved possession of. NOT APPLIED, and for a hard constraint rather than a preference — it lets a quorum move a field `I-FLOOR-SHAPE-IMMUTABLE` currently freezes against every principal, i.e. it LOOSENS an existing check, and it moves AUTHORITY.md's 'Silent crypto downgrade' row from unreachable to k. Cheaper blunting worth costing first: a MIN_PQ_LENGTH, or removing `pqParamLevel`, which no execution path reads.",
    reproducedBy: "prototype/vnext-kernel/test/Sd34AuthenticationSatisfiability.test.ts",
  },
  {
    id: "SD-8-genesis-exhibit-cannot-prove-well-formedness",
    title:
      "The genesis exhibit proves knowledge of a PREIMAGE, never that the preimage is a well-formed key of the verifier's scheme, so a deployer can still commit correct-length garbage and produce a vault born unable to authorise",
    property: null,
    rootsRequired:
      "0 — no principal is compromised. This is the DECLARED RESIDUAL of SD-7's remediation: the configuration is chosen by whoever deploys, and `deployVault` is permissionless, so a bad genesis lands at its own CREATE2 address and harms only that vault.",
    contradicts:
      "Nothing published — it is recorded HERE, at the moment of SD-7's remediation, precisely so that closing SD-7 is not read as a stronger claim than it is. That remediation closes the structurally CONTRADICTORY genesis (no preimage, or a preimage of the wrong length); it does not and cannot close the semantically dead one.",
    rootCause:
      "The only party able to judge whether key bytes are well-formed for a scheme is a verifier, and at genesis the deployer CHOOSES `g.verifier` in the same transaction — so a verifier leg there would be self-certification, rejected for the identical reason `I-DECLARATION-EXHIBITED` has no signature leg. keccak256 is scheme-agnostic by construction: it cannot distinguish an ML-DSA public key from 1,312 bytes of noise. The kernel performs no structural validation of key bytes anywhere, deliberately, because doing so would bind it to one PQ scheme.",
    classification: "STATE_INCOHERENCE",
    notAnEscalationBecause:
      "It reduces no cut and is unreachable by an attacker against someone else's vault: the whole genesis is bound into the CREATE2 salt, so a different configuration is a different address (`I-COUNTERFACTUAL-IDENTITY-BINDING`). It is escapable at k — a guardian quorum recovers such a vault and installs material it actually holds, executed rather than argued. The residue over SD-7 is narrow: an ACCIDENTAL misconfiguration is now refused at birth, and only a DELIBERATE one survives, which is indistinguishable from a deployer who commits a real key and then destroys it.",
    minimalFixSketch:
      "No admission-time fix exists, and that is the finding rather than an omission. The candidates are (a) a kernel-held allowlist of trusted verifiers, which introduces a governance principal this kernel does not have and gates deployment on it; (b) scheme-aware structural validation of key bytes, which binds the kernel to one PQ scheme and contradicts the floor/plane separation; (c) a PoP against a verifier fixed OUTSIDE the genesis, which is (a) wearing a different hat. All three trade a cut-0 self-inflicted misconfiguration for a new permanent authority — the trade this repository has now rejected three times.",
    reproducedBy: "prototype/vnext-kernel/test/Sd67CommitmentAdmission.test.ts",
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
    id: "SD-6-unattested-commitment-install-on-an-ecdsa-only-floor",
    title:
      "While requirePq was false, rotateCredential and executeRecovery installed an arbitrary pqPublicKeyHash with NO possession proof of any kind, because _requireIncomingPossession returned before every PQ check",
    sustainedAt: "a70de68db2e3c9d832ef9f4087238c3c6e9826ca",
    remediatedOn: "security/vnext-sd6-sd7-commitment-admission",
    invariant:
      "I-COMMITMENT-EXHIBITED-AT-ADMISSION (dormant half) — every accepted transition that writes a NON-ZERO value to pqPublicKeyHash must exhibit a byte string K with keccak256(K) equal to the value being written. bytes32(0) is the kernel's representation of 'no PQ credential' and stays admissible wherever the floor does not mandate PQ, which is what preserves the ECDSA-only rotation and the clear-then-rotate escape.",
    sourceDelta:
      "ONE flat clause added to _requireIncomingPossession, which both rotateCredential and executeRecovery already route through. No new state, no new parameter, no selector change on either path: CredentialChange already carried newPqKey. The clause deliberately omits any LENGTH comparison — see rejectedAlternatives.",
    rejectedAlternatives:
      "DELETING THE requirePq EARLY RETURN OUTRIGHT (so the full exhibit — length, preimage and verifier PoP — runs on the dormant path) was rejected as DISQUALIFYING. While requirePq is false, _requireSaneFloor returns before every bound, so both dormant length fields are unvalidated and may hold any uint32; MAX_PQ_LENGTH is not applied on that path and _requireNoDowngrade's freeze is guarded on the CURRENT floor. Reading them in the install path lets ONE false -> false setVerifier at cut 1 write pqPublicKeyLength = type(uint32).max, after which every credential install INCLUDING executeRecovery is undeliverable forever, with no guardian-reachable writer of securityFloor to undo it. That is a permanent, uncounted, cut-1 veto over the remedy — a strictly worse form of the harm the SD-4 interlock was rejected for, since it gives the CREDENTIAL a renewable veto over the REPEATABLE capability that exists to remove that credential. A VERIFIER leg was rejected as self-certification: on an ECDSA-only vault the same cut-1 principal also owns setVerifier, so it installs an always-true verifier one transaction earlier. Requiring the exhibit REGARDLESS of the commitment being zero was rejected because no byte string hashes to bytes32(0), which would make the entire ECDSA-only class unrotatable and I-DECLARATION-EXHIBITED dead code.",
    invertedReproduction:
      "test/Sd34AuthenticationSatisfiability.test.ts runs the original unattested-install sequence and now asserts the REFUSAL, with a positive control proving a 7-byte exhibit still installs (the invariant is about attestation, not shape). test/Sd67CommitmentAdmission.test.ts carries the full firsthand reproduction with its verdict moved, and test/Sd67AdmissionInvariants.test.ts carries the regression matrix including the recovery twin.",
    residual: "SD-5-permanent-shape-capture-on-the-declaring-edge",
  },
  {
    id: "SD-7-genesis-admits-an-unsatisfiable-floor",
    title:
      "initialize admitted a genesis whose committed key could not satisfy the floor it declared — a vault BORN unable to authorise, with the shape already frozen",
    sustainedAt: "a70de68db2e3c9d832ef9f4087238c3c6e9826ca",
    remediatedOn: "security/vnext-sd6-sd7-commitment-admission",
    invariant:
      "I-COMMITMENT-EXHIBITED-AT-ADMISSION (base case) — initialize must exhibit a preimage of any non-zero g.pqKeyHash, and where g.floor.requirePq holds that preimage must carry the declared g.floor.pqPublicKeyLength. This is what makes the chain of key measurements an INDUCTIVE invariant with an authenticated base rather than an assumption about genesis.",
    sourceDelta:
      "Two comparisons in initialize plus a new `bytes calldata pqKey` WITNESS parameter, forwarded by the factory. The witness is a PARAMETER and deliberately NOT a GenesisConfig member: genesisSalt binds the genesis AUTHORITY and a preimage proof confers none. Consequence, asserted against a constant captured from the parent build: the CONFIGURATION -> SALT function is unchanged and predictVault keeps its exact signature. That constant pins the SALT and cannot pin an address — a clone's address is CREATE2(factory, salt, keccak256(initcode)) and the ERC-1167 initcode embeds the implementation address, so every deployed address moves whenever the kernel bytecode moves, as it does in every remediation in this stack. Selectors move on initialize (09bbae89 -> 9d288286) and deployVault (f1cfaa80 -> 1d0c155d); both manifest entries are updated with the reason.",
    rejectedAlternatives:
      "THE LEDGER'S OWN RECORDED SKETCH — 'carry the key bytes in GenesisConfig' — was rejected, and its stated REASON was found to be FALSE. That reason was 'GenesisConfig is hashed into genesisSalt, so adding a member changes EVERY vault address the factory can produce'. genesisSalt (VaultKernelPrototype.sol) hashes an ENUMERATED FIELD LIST, not the struct as a unit, so a new member alone moves no SALT. That false mechanism was the recorded justification for deferring the only fix that closes SD-7. (Addresses do move — the clone initcode embeds the implementation address — but that is true of every change to this kernel and so never distinguished this fix from any other.) The member form is still rejected, on the correct and smaller ground that it would change predictVault's ABI as well as deployVault's, and would invite a later editor to add the witness to the salt enumeration, which WOULD change the configuration -> salt map. A VERIFIER call at genesis was rejected as self-certification: the deployer chooses g.verifier in the same transaction. REFUSING requirePq at genesis outright was rejected as a blanket prohibition on a configuration the kernel is supposed to support. ONE LIVENESS COST IS ACCEPTED AND RECORDED RATHER THAN GLOSSED: a genesis carrying a NON-ZERO commitment while requirePq is FALSE now requires the deployer to hold the key at deploy time. The clear-to-zero escape that rescues the ROTATION path does not exist at genesis, because pqKeyHash is enumerated into genesisSalt and a different commitment is a different vault. The remedy is to deploy with bytes32(0) and rotate the commitment in afterwards, which is the same cold-ceremony path and is tested; what is lost is the ability to pre-register a latent commitment for a key you do not yet hold.",
    invertedReproduction:
      "test/Sd34AuthenticationSatisfiability.test.ts runs the original 48-against-32 genesis and now asserts the deployment REVERTS, with a positive control deploying the consistent 32-byte form. test/Sd67CommitmentAdmission.test.ts carries the firsthand reproduction with its verdict moved; test/Sd67AdmissionInvariants.test.ts carries the regression matrix plus the pinned genesisSalt identity constant.",
    residual: "SD-8-genesis-exhibit-cannot-prove-well-formedness",
  },
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
    // SD-1 originally declared SD-4 as its residual and was re-pointed at SD-5,
    // the permanence of a shape once declared, which is what actually survives
    // from the freeze this entry introduced. CORRECTION: the note that
    // accompanied that re-pointing claimed "SD-4 has since been REMEDIATED in
    // its own right". It never was — the interlock was built, measured and
    // REMOVED, and SD-4 is still in SUSTAINED_DEFECTS below. The re-pointing was
    // right; its stated reason was not.
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
