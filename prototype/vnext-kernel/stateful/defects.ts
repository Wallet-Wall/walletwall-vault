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
 * EIGHT HAVE SINCE BEEN REMEDIATED — SD-1 by `I-FLOOR-SHAPE-IMMUTABLE`, SD-3 by
 * `I-DECLARATION-EXHIBITED`, SD-6 and SD-7 together by
 * `I-COMMITMENT-EXHIBITED-AT-ADMISSION`, and SD-9b, SD-9c, SD-9d and SD-9e
 * together by Lane W2's recovery lifecycle (K-9 mechanism B,
 * `I-RECOVERY-EFFECTIVE-LIVENESS`, `I-RECOVERY-CHALLENGE-EPOCH`; Commit A
 * c182db1099d92ff5830ae71116613c739b034bd9), and SD-10 by Lane SD10-I's removal
 * of `executeRecovery`'s execution-time generation re-check
 * (`I-APPROVED-REQUEST-PRESERVATION`; Commit A
 * c32e0d748390b79f4163ad4a783c2467cf502e30). SD-2, SD-4, SD-5 and SD-8 stand,
 * each for a stated reason rather than for want of effort. The history of each closure is
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
 * residual of SD-7's fix; SD-9b, SD-9c, SD-9d and SD-9e were recorded by Lane W1
 * (4b912726 — outside this file, by that lane's choice) and left with Lane W2's
 * implementation; SD-10, recorded by the same lane, arrived here as sustained
 * and then LEFT with Lane SD10-I, whose one-statement removal also discharged
 * SD-9d's residual pointer. Every one of those arrivals came from RE-DERIVING what
 * the previous lane had recorded instead of trusting it, and each round found a
 * wrong claim: SD-3's title overstated its severity; SD-3's own minimal fix
 * sketch would not have closed it; SD-7's deferral rested on a false statement
 * about genesisSalt; and this lane's own first draft claimed vault addresses were
 * unchanged when only the SALT is. That last one was caught by hostile review of
 * the finished work, which is the argument for reviewing a remediation as
 * adversarially as the defect it closes.
 *
 * SD-9a IS IN NEITHER ARRAY, DELIBERATELY. It is a remediation hazard and a
 * specification gap — no executed path of any kernel revision ever refunded
 * the challenge epoch on a request-lifetime exit — so listing it as a defect
 * would misstate what the kernel did. Its disposition is carried in the
 * receipt's `knownGaps` (generate-stateful-evidence.ts, the narrowest surface
 * the receipt already publishes for non-defects) and in
 * SD9_RECOVERY_LIFECYCLE_DEFECTS.md; the hazardous remediation is a permanently
 * killed mutant (`M-K9-expiry-refunds-budget`).
 *
 * SD-4 IS STILL OPEN AFTER W2 TOO, and not because W2 overlooked it: its
 * sustained property `G-DECLARATION-SUBORDINATE-TO-RECOVERY` observes the
 * TRANSITION (a valid declaration destroying an approved request, uncounted)
 * and still fires on the W2 kernel — three known-defect hits per campaign run,
 * and the deterministic reproduction still asserts the destruction. What W2
 * changed is the availability of the REMEDY, which the entry now records in
 * place of the general conclusions that were refuted after #188 wrote them.
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
      "It reduces no cut. On an ECDSA-only vault the asset-control cut is already 1, so the principal doing this already controls the vault outright. What it falsifies is the separate 'permanent recovery veto is unreachable' row: the REMEDY is deniable for one episode, raising the cut-1 recovery-delay denial from the 14 days `I-VETO-BOUND` implies (2 metered cancellations) to 21 (2 metered plus 1 unmetered). The quorum self-heals through the architecture-native exit: while the destroyed request is still effectively live, `cancelRecoveryByQuorum` (K-9 mechanism B, implemented in Lane W2) and then a correctly-shaped fresh recovery; once it has expired, a fresh recovery directly. One extra cycle at most, and no clock is touched.",
    minimalFixSketch:
      "TWO FAMILIES WERE BUILT AND BOTH REJECTED, and recording why is the point of this entry. (1) An INTERLOCK refusing the declaration while a live approved request exists was implemented, measured and REMOVED: the declaration is one-shot and no guardian path can ever write `securityFloor`, so the refusal hands the quorum a renewable, uncounted veto over a capability it cannot itself exercise — the quorum's renewal is unmetered (at the time a direct overwrite; since Lane W2 `cancelRecoveryByQuorum` followed by a fresh initiation, so the veto is unchanged and the rejection stands) while the credential's counter-move is capped — pinning an ECDSA-only vault at cut 1 forever. Trading a bounded one-shot credential harm for an unbounded guardian one is not a remediation. (2) METERING the destruction against `challengesUsed` fails for a subtler reason: a counter has teeth only through its REFUSAL, and refusing a ONE-SHOT transition is permanent deprivation, so metering moves the irreversibility from the attacker to the defender. (3) THAT CLAIM WAS WRONG, AND THE CORRECTION IS EXECUTABLE. This field previously ended: 'The only design that closes this soundly RECORDS THE PROPOSED KEY AND SIGNATURE LENGTHS IN RecoveryRequest at initiateRecovery and measures the recovery against the REQUEST rather than the live floor.' That design was BUILT — the two uint32 fields added, bound into the guardian digest, threaded into `_requireIncomingPossession`, with `rotateCredential` left on the live floor — compiled and executed in test/Sd4SnapshotAdjudication.test.ts. It DOES close SD-4, and it BRICKS THE VAULT: the recovery installs a commitment of the request's shape under a floor frozen at a different one, so `_authorise` then demands both `|pqKey| == floor.pqPublicKeyLength` and `keccak256(pqKey) == pqPublicKeyHash`, which are jointly unsatisfiable. The remedy APPEARS to succeed and the vault is dead — strictly worse than today, where the quorum sees a revert and re-proposes at the correct shape for the same one-cycle cost. It also drives a commitment past the shape agreement that `I-DECLARATION-EXHIBITED` and `I-COMMITMENT-EXHIBITED-AT-ADMISSION` exist to enforce. (4) THE ONLY FAMILY THAT CAN ACTUALLY PRESERVE THE REMEDY — letting a completed recovery RE-DECLARE the floor shape to the material it just proved — was also built and executed. It works, and it moves AUTHORITY.md's 'Silent crypto downgrade' row from `unreachable` to `k`: two guardians alone drive an honestly-armed 32/65 vault to a one-byte key and one-byte signature shape, with no credential participation. (5) THE GENERAL CONCLUSION THAT FOLLOWED — an inherent liveness cost, with no further family possible — was REFUTED in Lanes T–W1.2 (a ratification family that is neither design A nor design E exists) and is deliberately NOT restated here; every intermediate conclusion, the refuted ones included, is preserved by pointer in prototype/vnext-kernel/SD4_TEMPORAL_ADJUDICATION.md, SD4_LANE_U_ADJUDICATION.md, SD4_LANE_V_ADJUDICATION.md, SD4_LANE_V2_ADJUDICATION.md and SD4_LANE_W_SEMANTIC_FREEZE.md, and in AUTHORITY.md's append-only correction. Every such family was then itself killed on temporal authority or by the generalised CLOCK RULE of docs/Vault_vNext_Architecture.md ('no state transition may reset, extend, or suspend' any clock), and the architecture-native path dominates them all. THE STANDING DISPOSITION, canonical in docs/Vault_vNext_Recovery_Amendment.md section 4: SD4_DEDICATED_REMEDIATION = NOT_REQUIRED; G_PRIME_INCREMENTAL_VALUE = NONE_ESTABLISHED; the exit is architecture-native — LIVE request: guardian-quorum cancellation (cancelRecoveryByQuorum, K-9 mechanism B, implemented in Lane W2) and then a correctly-shaped fresh recovery; EXPIRED request: a fresh recovery directly. That exit repairs SD-4 at every timing without touching a clock and is executable on the W2 kernel (test/W2RecoveryLifecycle.test.ts sections A and D; test/Sd4SnapshotAdjudication.test.ts's conformant cancel-then-re-propose), and it does NOT close SD-4: the destroying transition is still admitted and uncounted, which is why this entry stays SUSTAINED and its property still fires. What survives of the earlier prose is the narrow fact: once requirePq holds, the floor shape is the vault's permanent authentication policy, so designs A and E remain rejected.",
    reproducedBy:
      "prototype/vnext-kernel/test/Sd34AuthenticationSatisfiability.test.ts (the sustained sequence); test/Sd4RecoverySemantics.test.ts (the exact predicate, both length branches, the digest proof and a positive control); test/Sd4SnapshotAdjudication.test.ts (the two candidate fixes, COMPILED AND EXECUTED, and why each is rejected); test/Sd1RecoveryFloorBinding.test.ts ('RESIDUAL — SD-4 ... STILL SUSTAINED', re-run on the W2 kernel in Lane W2P)",
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
  /**
   * The branch carrying the remediation. Entries up to SD-7 name the branch and
   * leave the exact head to the evidence receipt; from Lane W2 on, an entry names
   * the exact 40-hex commit that carries the remediation (branch in parentheses),
   * so the ledger states its own source identity instead of deferring it.
   */
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
  {
    id: "SD-9b-expired-request-retains-blocking-effect",
    title:
      "An expired recovery request kept its stored `active` flag forever, and bindMigration tested that raw flag, so a dead request blocked migration until a PRINCIPAL acted — the exact thing I-RECOVERY-TERMINATION says expiry must never need",
    sustainedAt: "4b9127269602d8eab3700d96dda4d5cfcf2e0d55",
    remediatedOn: "c182db1099d92ff5830ae71116613c739b034bd9 (security/vnext-recovery-lifecycle-implementation, Lane W2 Commit A)",
    invariant:
      "I-RECOVERY-EFFECTIVE-LIVENESS (docs/Vault_vNext_Recovery_Amendment.md section 3) composed with I-RECOVERY-TERMINATION — a request holds authority on the half-open window [executableAt, expiresAt) and on that window only; every authority or blocking decision in the kernel consults `_recoveryIsLive()` (active && block.timestamp < expiresAt), never the stored flag, so an expired request's stale bytes carry zero execution authority, zero cancellation-target authority and zero blocking effect, and expiry requires no principal to act.",
    sourceDelta:
      "One internal view helper `_recoveryIsLive()`; `bindMigration`'s guard changed from `if (recovery.active)` to `if (_recoveryIsLive())`; `cancelRecovery`'s target check changed from `!recovery.active` to `!_recoveryIsLive()`; `initiateRecovery` reads the same predicate for its new overwrite refusal (SD-9d). No storage, no new state, no sweeper, no liveness selector (Option E0). The stored `active` byte is documented as authority, not liveness, at the struct field.",
    rejectedAlternatives:
      "A PERMISSIONLESS SWEEPER that deletes an expired request — rejected: `delete recovery` refunds the credential's challenge epoch (the SD-9a hazard, measured in Lane V2's probe), and a sweeper is a transaction, so expiry would again require an act; it is now a permanently killed mutant (M-K9-expiry-refunds-budget). A sweeper that clears only `active` — rejected on the second ground alone. A PUBLIC liveness getter (W1 Option B / the E1 probe's effectiveLiveRecovery()) — rejected as NOT_REQUIRED in Lane W1R: liveness is a pure function of two fields the recovery() getter already exposes and the block a reader is in, so it costs a selector and buys nothing an observatory cannot derive; the E1 build remains a measurement instrument only. Reading the raw flag anywhere — that is the defect, and three raw-flag mutants (M-K9-expired-request-blocks-migration, M-K9-expired-request-blocks-initiation, M-K9-expired-request-still-challengeable) are permanently killed.",
    invertedReproduction:
      "test/W2RecoveryLifecycle.test.ts section B (the expiresAt / expiresAt+1 matrix: migration BINDS, a fresh initiation is not overwrite, both cancellations refuse with NoRecovery and consume nothing), C3 (initiation after expiry with the count preserved and no cleanup transaction) and F1 (a LIVE request still blocks migration — the positive control). The original measurement, Sd4LaneV 'C the five proofs', is pinned to the byte-exact pre-W2 kernel (test/fixtures/VaultKernelPrototype.pre-w2.e6964aeb.sol) so it still measures the defect it recorded.",
    residual: null,
  },
  {
    id: "SD-9c-guardian-quorum-cancellation-absent",
    title:
      "K-9 promises two cancellation mechanisms — the credential's bounded challenge OR the guardian quorum — and the kernel implemented only the first: the quorum had no exit from a live request except overwriting it",
    sustainedAt: "4b9127269602d8eab3700d96dda4d5cfcf2e0d55",
    remediatedOn: "c182db1099d92ff5830ae71116613c739b034bd9 (security/vnext-recovery-lifecycle-implementation, Lane W2 Commit A)",
    invariant:
      "K-9 mechanism B (KERNEL_ADMISSION.md K-9; docs/Vault_vNext_Architecture.md section 8.1 grants the guardian quorum CANCEL_RECOVERY) — an effectively-live request is terminable by a quorum of the CURRENT roster, under a digest bound to guardianGeneration, consuming one DOMAIN_GUARDIAN nonce, clearing request authority only (challengesUsed neither consumed nor refunded, I-RECOVERY-CHALLENGE-EPOCH) and emitting a terminal event distinct from the credential's.",
    sourceDelta:
      "One new external function cancelRecoveryByQuorum(QuorumProof,uint256,uint64) (selector 02abce4e): _requireRecoveryOpen; refuse unless _recoveryIsLive (NoRecovery); digest = _digest(ACTION_RECOVER, guardianGeneration, keccak256('QUORUM_CANCEL_RECOVERY'), DOMAIN_GUARDIAN, nonce, deadline); _requireQuorum BEFORE _consume; recovery.active = false; emit RecoveryCancelledByQuorum(challengesUsed). One new event. No storage change; +1 selector, +1 event; recovery() byte-identical. Manifest entry VaultKernelPrototype:02abce4e, mechanism QUORUM, cut k.",
    rejectedAlternatives:
      "A REQUEST IDENTIFIER or hash bound into the cancellation digest — rejected: GUARDIAN_NONCE_SERIALIZATION_SUFFICIENT (Lane W1.2 section D, amendment section 5): every request is created by initiateRecovery, which always consumes a DOMAIN_GUARDIAN nonce, and a live request is never overwritten, so a cancellation pre-signed for request n is nonce-invalid by the time n+1 exists or finds no live target and consumes nothing. That proof's two load-bearing premises are now PERMANENT MUTANTS rather than paragraphs: M-K9-guardian-cancel-nonce-replay (the cancellation stops consuming) and M-K9-initiation-does-not-consume-guardian-nonce (the creator stops consuming — the future-danger case Lane W2R found unguarded, added in Lane W2P), both killed by the stale-cancel replay property observing an R1 authorisation reach R2. A whole-struct delete in the quorum cancel — rejected (refunds the epoch; mutant M-K9-quorum-cancel-refunds-budget). Credential-signature authority for the quorum's cancellation — rejected (principal separation; mutant M-K9-guardian-cancel-wrong-authority). Metering the quorum's cancellation by CHALLENGE_LIMIT — rejected: the quorum is the recovery trust root and needs no metered veto over its own remedy. Keeping overwrite as the quorum's exit — that is SD-9d.",
    invertedReproduction:
      "test/W2RecoveryLifecycle.test.ts section A (A1 the exact frozen surface; A2 a current quorum terminates a live request with the epoch and every other slot untouched and one guardian nonce; A3 below quorum / wrong principal / wrong digest refused as QuorumNotMet with nothing consumed; A4 two domains, two events; A5 a fresh request after the cancellation carries the epoch and completes) and section E (a stale cancellation never reaches R2). The original measurement, Sd4LaneV B1, is pinned to the pre-W2 fixture and additionally asserts the exit now exists on the shipped kernel; the stateful campaign gained the action CANCEL_RECOVERY_BY_QUORUM, the outcome RECOVERY_QUORUM_CANCEL at cut k, the profile recovery-lifecycle and the seam tallies.",
    residual: null,
  },
  {
    id: "SD-9d-live-request-overwrite",
    title:
      "initiateRecovery replaced an effectively-live, quorum-approved request outright: overwrite stood in for explicit termination, emitted no terminal event, and left a stale-authorisation surface where a cancellation aimed at request n could meet n+1 in the same slot",
    sustainedAt: "4b9127269602d8eab3700d96dda4d5cfcf2e0d55",
    remediatedOn: "c182db1099d92ff5830ae71116613c739b034bd9 (security/vnext-recovery-lifecycle-implementation, Lane W2 Commit A)",
    invariant:
      "APPROVED_REQUEST_OVERWRITE = REFUSED while effectively live (SD9_RECOVERY_LIFECYCLE_DEFECTS.md; amendment section 5, premise 2) — a live request leaves the system only by execution, the credential's bounded challenge, the quorum's cancellation, or expiry; a fresh initiation over a live slot reverts BadState BEFORE any nonce is consumed, so a refused overwrite burns no guardian nonce. An EXPIRED request is not live, and replacing it is not overwrite.",
    sourceDelta:
      "One guard at the top of initiateRecovery, immediately after _requireRecoveryOpen and before the ZeroAddress checks, the digest and _consume: `if (_recoveryIsLive()) revert BadState();`. The carry-forward of challengesUsed into the fresh request is unchanged.",
    rejectedAlternatives:
      "KEEPING OVERWRITE as the quorum's only exit — Lane V's AUTHORITY_GENUINELY_CONFLICTS verdict — superseded once K-9 mechanism B exists in the architecture (its load-bearing reason was that overwrite was the sole exit). Refusing AFTER _consume — rejected: it would burn a guardian nonce on a refused call and break premise 4 of the replay proof (a stale cancel before a replacement consumes nothing). Refusing on the raw stored flag — rejected: stale expired storage would block a fresh request forever (mutant M-K9-expired-request-blocks-initiation). Removing the guard altogether is the defect itself and is the permanently killed mutant M-K9-live-overwrite-allowed.",
    invertedReproduction:
      "test/W2RecoveryLifecycle.test.ts C1/C2 (live before and after maturity: BadState, guardian nonce unconsumed, request intact), E3 (same block, both orders: exactly one transaction succeeds and it is the initiation) and G1 (overwrite ordering: refused while live; cancel-then-R2 and expire-then-R2 both create R2). The original measurements, Sd4LaneV B2 and A1, are pinned to the pre-W2 fixture; the stateful model's recordInitiation now returns an SD-9d violation if the previous episode is still live at the mined timestamp.",
    // RESIDUAL DISCHARGED, and recorded rather than silently blanked. This entry
    // named SD-10-approved-request-stranded-by-guardian-rotation as the residual
    // W2 did not close: W2 changed the stranding's blast radius (a stranded
    // request became effectively live, so it blocked re-initiation and migration
    // until the new quorum cancelled it) without touching the stranding itself.
    // Lane SD10-I closed SD-10 on Commit A c32e0d74, so the pointer is now null:
    // this file's own contract is that "a residual pointing at a closed defect
    // would be stale evidence", and the ledger test refuses it. The history is
    // kept here in prose and in SD-10's own REMEDIATED entry, which names this
    // one's head as the point from which it was still open.
    residual: null,
  },
  {
    id: "SD-9e-expiry-equality-boundary",
    title:
      "executeRecovery admitted execution AT expiresAt (`block.timestamp > expiresAt` reverted, so the instant expiresAt itself was live) where the reference model treats every expiry as `>=` and the kernel's own containment already expires at `>= containedUntil` — a one-second conformance defect",
    sustainedAt: "4b9127269602d8eab3700d96dda4d5cfcf2e0d55",
    remediatedOn: "c182db1099d92ff5830ae71116613c739b034bd9 (security/vnext-recovery-lifecycle-implementation, Lane W2 Commit A)",
    invariant:
      "LIVE_WINDOW = [executableAt, expiresAt) — half-open, everywhere: `_recoveryIsLive()` is `block.timestamp < expiresAt`, `executeRecovery` refuses at `>= expiresAt` (Expired), and TooEarly is retained below executableAt. Deadlines stay inclusive; expiries are exclusive, the convention the reference model applies to every expiry (Lane W1 boundary correction).",
    sourceDelta:
      "One comparison in executeRecovery: `if (block.timestamp > r.expiresAt)` became `if (block.timestamp >= r.expiresAt)`, and the new `_recoveryIsLive()` predicate uses the strict `<` on the same field, so no consumer disagrees about the last live instant (expiresAt - 1).",
    rejectedAlternatives:
      "KEEPING `>` and documenting a closed window — rejected: the model is uniformly `>=` on every expiry and `>` only on a deadline, and the kernel's own containment uses `>= containedUntil`, so the outlier was a conformance defect rather than a convention; Lane W's earlier `<=` reading was itself superseded by Lane W1 after re-deriving the boundary from the model rather than from the artifact under review. Closing BOTH the predicate and the execute check (`<=` and `>`) — that is the permanently killed mutant M-K9-expiry-inclusive-off-by-one.",
    invertedReproduction:
      "test/W2RecoveryLifecycle.test.ts B1–B4 (the expiresAt-1 / expiresAt / expiresAt+1 matrix with mined-block timestamps: live, expired, expired) and G3 (the exact race — three transactions mined at consecutive instants in ONE world). The boundary probes carry an explicit gasLimit so Hardhat mines the reverting transaction and the asserted timestamp is the mined one. The original measurement, Sd4LaneW1's E-series, recorded `>` on c67d1439.",
    residual: null,
  },
  {
    id: "SD-10-approved-request-stranded-by-guardian-rotation",
    title:
      "setGuardians was admitted while a quorum-approved recovery request was live, and the generation bump STRANDED the request: stored active, unexecutable at maturity (BadRoster), cleared by no principal until it expired or the NEW quorum cancelled it",
    sustainedAt: "4b9127269602d8eab3700d96dda4d5cfcf2e0d55",
    remediatedOn: "c32e0d748390b79f4163ad4a783c2467cf502e30 (security/vnext-sd10-approved-recovery-preservation, Lane SD10-I Commit A)",
    invariant:
      "I-APPROVED-REQUEST-PRESERVATION (docs/Vault_vNext_Architecture.md:951): 'Once a request reaches quorum, a guardian-set replacement cannot clear it.' PRESERVED MEANS STILL EXECUTABLE, not merely still stored — the defect left the request in storage and destroyed it as authority. ROOT CAUSE: executeRecovery REVALIDATED an already-admitted recovery against the CURRENT guardianGeneration. REMEDIATION: remove that execution-time invalidation. RETAINED: boundGuardianGeneration remains the generation that APPROVED the request and remains bound into recoveryPossessionDigest(), so a possession proof signed before a rotation is still the right proof after one. FRESH AUTHORITY IS UNCHANGED: every new guardian authorization — initiation, quorum cancellation, setGuardians, containment, migration binding — still binds the CURRENT guardian commitment and the CURRENT generation, so a replaced roster holds no fresh authority of any kind. Guardian-generation binding was NOT removed; only its misuse as a re-check on an effect the kernel had already admitted.",
    sourceDelta:
      "ONE statement deleted from executeRecovery: `if (r.boundGuardianGeneration != guardianGeneration) revert BadRoster();`, and its comment replaced by a @dev note distinguishing the two generations. Nothing else in Solidity: the RecoveryRequest struct, storage layout, ABI, 46 selectors, 15 events and 24 errors are unchanged, the factory's executable prefix is byte-identical, setGuardians is untouched, no clock moves and no possession gate is relaxed. Measured on the pinned solc (0.8.24, cancun, optimizer runs 200): kernel runtime 18,425 -> 18,367 B (-58), initcode 18,466 -> 18,408 B (-58).",
    rejectedAlternatives:
      "T (setGuardians clears recovery.active on rotation) — a DIRECT violation and worse than the defect: it destroys the effect rather than stranding it, and Hazard Register H-03 names exactly that legacy behaviour as a T1 hazard CAUSE; permanent mutant M-SD10-T-ROTATION-AUTO-TERMINATES-REQUEST. B (setGuardians reverts while a recovery is effectively live) — CONFORMANT with the invariant and NOT an authority-cut violation, rejected as an unnecessary liveness/governance restriction that makes rotating a compromised seat out conditional on first terminating the quorum's own pending remedy; permanent mutant M-SD10-B-ROTATION-BLOCKED-WHILE-REQUEST-LIVE. R (ratify the request under the new generation) — +1 selector, +1 event, ~292 bytes, an extra guardian act, and it REBINDS the possession digest so a pre-signed proof is refused; its end state is identical to the adopted design, so it buys nothing. RE-BINDING boundGuardianGeneration to the new generation — the family THIS ENTRY's own former minimalFixSketch considered and rejected, on the grounds that a request re-bound to a roster that never approved it is mutant M16 wearing a different hat; that rejection STANDS and is not what was built. The adopted design is a third family the old sketch never enumerated: freeze the provenance, remove only the re-check.",
    invertedReproduction:
      "prototype/vnext-kernel/test/StatefulSustainedDefects.test.ts (the ORIGINAL sequence, step for step, with the verdict moved: the same formerly-stranded R1 now executes after the same roster re-commitment); test/Sd10ApprovedRequestPreservation.test.ts (23 tests — preservation across one and three rotations, the replaced roster's total loss of fresh authority with positive controls, the current quorum's cancellation, the half-open expiry boundary at expiresAt-1/expiresAt/expiresAt+1 at mined instants, same-block ordering in both directions, four incoming-possession probes, and the challenge epoch); test/Sd10PreservationMutations.test.ts (the inverse mutant M-SD10-GENERATION-INVALIDATES-APPROVED-REQUEST, which reinstates the exact deleted statement and is denied kill credit unless the observation is precisely a preserved, mature, validly-proven request being refused); test/W2RecoveryLifecycle.test.ts H1, test/Sd1RecoveryFloorBinding.test.ts R7b and test/Sd4LaneV.test.ts D (three further reproductions inverted in place — Lane V's D had recorded a TWO-SIDED divergence, kernel admitted-then-refused versus model refused, now closed on both sides).",
    residual: null,
  },
];

/** Campaign properties whose violation is EXPLAINED by a listed defect. */
export const KNOWN_DEFECT_PROPERTIES: ReadonlySet<string> = new Set(
  SUSTAINED_DEFECTS.map((d) => d.property).filter((p): p is string => p !== null),
);

export const explains = (property: string): SustainedDefect | undefined =>
  SUSTAINED_DEFECTS.find((d) => d.property === property);
