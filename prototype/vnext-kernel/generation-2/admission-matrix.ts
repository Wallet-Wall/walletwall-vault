/**
 * EXPERIMENTAL PROTOTYPE ADMISSION RECORD — NOT PRODUCTION.
 *
 * THE MATRIX, AS MEASURED. Every row of ADMISSION_CRITERIA.json, which was committed before the candidate
 * existed, classified on the candidate and pointing at executable evidence that test/Gen2AdmissionMatrix.test.ts
 * resolves: a test title that must exist in that file, a property the campaign really checks, a mutant in a real
 * catalogue. A row cannot leave UNPROVEN by assertion, and the verdict is DERIVED from the rows, the decisions and
 * what the heavy suites recorded, so editing one of those is the only way to move it and any such edit is reviewable.
 */

export type Classification = "PASS" | "PASS_WITH_DECLARED_RESIDUAL" | "FAIL" | "NOT_APPLICABLE" | "UNPROVEN";
export type AdmissionVerdict =
  "GEN2_ADMITTED" | "GEN2_ADMITTED_WITH_DECLARED_RESIDUALS" | "GEN2_NOT_ADMITTED" | "GEN2_ADMISSION_BLOCKED";

export interface Evidence {
  /** A suite under prototype/vnext-kernel/test/ and text its titles must contain. */
  tests?: readonly (readonly [file: string, title: string])[];
  properties?: readonly string[];
  mutants?: readonly string[];
  receipts?: readonly string[];
}

export interface MatrixRow {
  classification: Classification;
  note: string;
  evidence: Evidence;
  /** The ids in RESIDUALS this row rests on. Required exactly when the row is PASS_WITH_DECLARED_RESIDUAL. */
  residuals?: readonly string[];
  /** What the candidate had to change for this row, where measured Variant A did not pass. */
  admissionDelta?: string;
  /** The decision that answers a row this lane cannot: FAIL or UNPROVEN only. */
  blockedOnDecision?: string;
  /** A T0 row with a residual: why the invariant itself still holds with the residual outside it. */
  whyTheT0Holds?: string;
}

/**
 * THE CLOSED LIST, quoted from ADMISSION_CRITERIA.json's residualPolicy. A residual names one of these or it is not a
 * residual. An earlier version of this file carried four with clauses of its own invention, and a fresh-context
 * review caught them: what has no clause is now a disclosed narrowing, and no row may rest on one.
 */
export const POLICY_CLAUSES = [
  "a declared accepted condition (architecture section 2.2)",
  "a declared trust root (D1)",
  "a plane denial with cut 1 (section 24.2)",
  "an external asset behaviour the custody adjudication assigns to the asset boundary (custody doc sections 7.1, 8 D-5; architecture section 13.4)",
  "a sustained defect the ledger already carries with its own stated disposition (stateful/defects.ts)",
  "a generation-publisher discovery residual (H-32)",
] as const;
export type PolicyClause = (typeof POLICY_CLAUSES)[number];

const EXTERNAL_ASSET: PolicyClause = POLICY_CLAUSES[3];
const SUSTAINED_DEFECT: PolicyClause = POLICY_CLAUSES[4];
const PUBLISHER_DISCOVERY: PolicyClause = POLICY_CLAUSES[5];

export interface Residual {
  id: string;
  title: string;
  policyClause: PolicyClause;
  statement: string;
  pinnedBy: readonly (readonly [file: string, title: string])[];
  ownerDecision?: string;
}

/** Where the candidate is narrower than a document says, and no row rests on it. Disclosed, not excused. */
export interface Narrowing {
  id: string;
  title: string;
  against: string;
  statement: string;
  pinnedBy: readonly (readonly [file: string, title: string])[];
}

const AI = "Gen2AssetIdentity.test.ts";
const ST = "Gen2Settlement.test.ts";
const VA = "Gen2VerifierAdjudication.test.ts";
const RE = "Gen2Reentrancy.test.ts";
const MI = "Gen2Migration.test.ts";
const KR = "Gen2KernelRows.test.ts";
const CD = "Gen2CarriedDefects.test.ts";
const CE = "Gen2AuthorityCensus.test.ts";
const ME = "Gen2Measurement.test.ts";
const SC = "Gen2Scanner.test.ts";
const FI = "Gen2AdmissionFindings.test.ts";
const CA = "Gen2StatefulCampaign.test.ts";
const MU = "Gen2MutationAdequacy.test.ts";
const PR = "Gen2Provenance.test.ts";
const DE = "Gen2CandidateDerivation.test.ts";

export const RESIDUALS: readonly Residual[] = [
  {
    id: "R-ASSET-BOUNDARY",
    title: "What a sender cannot observe, and what an issuer can do without the kernel",
    policyClause: EXTERNAL_ASSET,
    statement:
      "The kernel's settlement proof is an exact observed decrease of its own balance. A recipient-side fee settles, and a balanceOf that lies by exactly the expected debit settles with nothing moved and the nonce burned. An issuer can debit the clone on its own ledger with no kernel act at all, by seizure or a downward rebase, can blocklist the clone itself, which stops its spend and egress until lifted (the one case architecture 13.4 keeps, and D-5), and can change any of this for every vault at once by upgrade. No kernel check can close these: asset admission must. A false-returning token that moves settles too, because the boolean is trusted in neither direction. Custody names blocklisting and freezing; 'Issuer controls are external' is the class, and the owner's lane requirements 6 and 12 place the rest of it on asset admission.",
    pinnedBy: [
      [ST, "ASSET BOUNDARY: a recipient-side fee settles"],
      [ST, "ASSET BOUNDARY: a balanceOf that lies by exactly the expected debit"],
      [ST, "ASSET BOUNDARY: the token can debit the clone with no kernel act"],
      [ST, "the boolean is trusted in NEITHER direction"],
      [MI, "a token blocklisting the SOURCE stops its egress until lifted"],
    ],
  },
  {
    id: "R-SD4",
    title: "SD-4: the ECDSA-only declaration destroys an approved recovery at cut 1",
    policyClause: SUSTAINED_DEFECT,
    statement:
      "PRESERVED, not worsened. The remedy is deniable for one episode, 21 days against the 14 I-VETO-BOUND implies, and the quorum self-heals with no clock touched. Not reachable through the asset except as a carrier for the same credential signature.",
    pinnedBy: [
      [CD, "PRESERVED: the declaration is still admitted"],
      [CD, "NOT WORSENED: the architecture-native exit still repairs it"],
      [CD, "NOT REACHABLE THROUGH THE ASSET"],
    ],
  },
  {
    id: "R-SD8",
    title: "SD-8: an exhibited preimage proves no key is well-formed",
    policyClause: SUSTAINED_DEFECT,
    statement:
      "PRESERVED, not worsened. A deliberate empty key arms and refuses every spend at cut 0, on the deployer's own vault; recovery and migration both still reach the asset.",
    pinnedBy: [
      [CD, "PRESERVED: a deliberately empty key commits"],
      [CD, "NOT WORSENED, AND THE ASSET IS NOT TRAPPED"],
      [CD, "the migration exit from the same dead state"],
    ],
  },
  {
    id: "R-SD11-CONDITION",
    title: "SD-11A and SD-11B hold on a factory that binds the real root",
    policyClause: PUBLISHER_DISCOVERY,
    statement:
      "The kernel bytes do not pin the root, so the same bytes under another root admit what that root approves. Checkable offline from bytes 8..28 of each clone's own args. Which root, implementation and asset a factory binds, and that its generation is 2, are deployment facts: the factory enforces non-zero only.",
    pinnedBy: [
      [CD, "THE CONDITION, STATED BY EXECUTION"],
      [AI, "the factory does not choose the generation number's meaning"],
    ],
  },
];

export const DISCLOSED_NARROWINGS: readonly Narrowing[] = [
  {
    id: "N-EGRESS-WINDOW",
    title: "Nothing can stop a bound egress during its 7 days",
    against:
      "H-11 Detection promises 'a delay-bounded warning window' and names no remedy; I-MIGRATION-SUBORDINATE-TO-RECOVERY asks for the time and no more",
    statement:
      "The delay gives time and visibility, and no principal a way to act on them: MIGRATION_ONLY refuses containment, recovery, spending and a rebind. It also makes every honest migration wait 7 days. Whether a warning with no remedy is what the owner wants is part of OD-EGRESS-DELAY.",
    pinnedBy: [
      [MI, "OWNER-REVIEWABLE: the delay buys time and visibility only"],
      [FI, "WHAT THE DELAY COST"],
    ],
  },
  {
    id: "N-BINDING-SCOPE",
    title: "What a code hash does not prove about a destination",
    against:
      "H-10 Residual risk: 'A code hash proves which code, never that the code is correct. Destination auditing is out of band'",
    statement:
      "The destination's generation is signed and otherwise unchecked. Whether its asset matches is the signers' responsibility at k+1: a mismatched asset arrives as an unsolicited holding, which can leave and cannot be spent. A hash also says nothing about whether the destination will take what it is sent: one with no receive() keeps native value in the vault. Under EIP-7702 a delegated account has code whose hash its owner can change at will, so a binding naming one is refused at egress until its owner restores it: NOT MEASURED here, because the pinned EVM is cancun. Each of those waits has no bound, which is K-12-VETO.",
    pinnedBy: [
      [MI, "a destination's generation is signed, and otherwise a label"],
      [AI, "a vault of a DIFFERENT asset holds what arrives as an unsolicited holding"],
      [FI, "A destination that refuses native value keeps that holding"],
    ],
  },
  {
    id: "N-LATTICE",
    title: "The kernel's state machine is narrower than the architecture's table",
    against: "architecture section 6: the transition table and the action matrix; 13.1's per-entry manifest",
    statement:
      "A live recovery blocks binding and MIGRATION_ONLY refuses recovery, so the two never coexist, where the table keeps recovery execution available. RECOVERY_ONLY is never assigned. The kernel generation does not advance on RETIRED, because it is code. There is no manifest and no per-entry status: one egress call is one entry, and a failed one reverts itself and nothing else. That the flip is immediate and one-way where the table reads delayed and reversible is K-12-VETO, and who reaches RETIRED is K-RETIRE.",
    pinnedBy: [
      [MI, "OWNER-REVIEWABLE: the delay buys time and visibility only"],
      [MI, "I-EGRESS-RETRY-PERPETUAL"],
    ],
  },
  {
    id: "N-DESTINATION-EXISTS",
    title: "A destination must have code to be bound",
    against:
      "Nothing written: 13.5 presumes a check at preparation and H-10 says 'code-bearing at proposal time'. Measured Variant A and Generation 1 accepted a counterfactual address and a funded account",
    statement:
      "The check at binding refuses an address with no code, funded or not, so a migration deploys its destination first and cannot name an externally-owned account. The factory is permissionless, so this costs one transaction and no authority.",
    pinnedBy: [
      [MI, "a destination must have code to be bound"],
      [FI, "THE CANDIDATE refuses both at binding"],
    ],
  },
  {
    id: "N-ONE-SPENDABLE-ASSET",
    title: "Only the admitted asset can be spent",
    against: "Generation 1, whose execute moved native value; the admitted-asset plane is what this candidate is",
    statement:
      "Native value and unsolicited ERC-20 holdings cannot be spent at all: they leave only through a migration's egress.",
    pinnedBy: [[ST, "a spend moves no native value"]],
  },
  {
    id: "N-NESTED-ACTS",
    title: "An authorised act nested in a token's hook or a policy plane takes effect before the outer spend settles",
    against: "Nothing: serial equivalence is the claim, and this is what it looks like from the inside",
    statement:
      "A containment, rotation, roster change, recovery initiation or binding, signed by whoever holds that authority, can run inside the transfer or inside the plane's admit, and the outer spend still settles after it, in the state the nested act left: a spend can settle while contained. The nonce and the exact delta hold either way, and the outcome is the one the ordering spend-then-act gives. A token with a hook is what asset admission refuses. A plane is one the credential installed.",
    pinnedBy: [
      [RE, "a rotation from the hook is spend-then-rotate"],
      [RE, "a roster change from the hook is spend-then-replace"],
      [RE, "a recovery begun from the hook is spend-then-initiate"],
      [RE, "cannot escape a safe state"],
      [RE, "a plane nesting a quorum-signed containment is spend-then-contain too"],
    ],
  },
];

export interface OwnerDecision {
  id: string;
  decision: string;
  previousState: string;
  measurementEvidence: string;
  admissionEvidence: string;
  recommendation: string;
  ownerDecisionRequired: boolean;
  /** True only if this verdict cannot stand until the owner answers. */
  blocksAdmission: boolean;
}

export const OWNER_DECISIONS: readonly OwnerDecision[] = [
  {
    id: "10.1",
    decision: "Pin the admitted asset in immutable args",
    previousState: "Recommended yes (custody 10.1)",
    measurementEvidence: "#237: a clone is 93 bytes with the asset as args field 3; the factory gains one immutable.",
    admissionEvidence:
      "G2-ASSET-1..10 PASS, offline five-link chain, M-G2-2 and M-G2-15/16 killed. This lane's brief also requires it outright.",
    recommendation:
      "Yes. Treated as settled by the brief; the owner's next decision is the value, per generation, in a later lane.",
    ownerDecisionRequired: false,
    blocksAdmission: false,
  },
  {
    id: "10.2",
    decision: "Ship v1 with requirePq = false",
    previousState: "Recommended yes, owner-reserved (custody 10.2)",
    measurementEvidence: "None directly. #237 kept both floors available.",
    admissionEvidence:
      "Kernel-neutral: the candidate admits both floors and is tested on both. On a dormant floor no attestor statement is needed anywhere (G2-VERIFIER-3,8). An armed floor stakes spending on the installed verifier's attestor, and its recovery on some attestor's statement, which the recovering party can make itself (K-7's third test). Migration by quorum and ECDSA needs none.",
    recommendation: "Yes, unchanged. Admission does not depend on the answer.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
  {
    id: "10.3",
    decision: "WalletWall guardian seats in v1",
    previousState: "Recommended none, owner-reserved (custody 10.3)",
    measurementEvidence: "None.",
    admissionEvidence: "Kernel-neutral: a roster is genesis configuration, and no seat is privileged by identity.",
    recommendation: "None, unchanged. Admission does not depend on the answer.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
  {
    id: "10.4",
    decision: "Production constants (custody 7.3), and the EIP-712 name and version",
    previousState: "Open, owner-reserved (architecture B-3)",
    measurementEvidence: "None.",
    admissionEvidence:
      "The candidate carries the prototype's constants and domain strings. A production build changes the bytes, so it is a NEW identity that must re-run this suite. Not a kernel-semantics blocker.",
    recommendation:
      "Decide in the deployment lane. This admission is of these bytes; different constants are a different candidate.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
  {
    id: "10.5",
    decision: "Chain scope: Base Mainnet (8453) only in v1",
    previousState: "Recommended, owner-reserved (custody 10.5)",
    measurementEvidence: "None.",
    admissionEvidence:
      "Kernel-neutral: the domain separator carries the live chain id and no chain is named in the candidate. No Base configuration was added.",
    recommendation: "Unchanged. Admission does not depend on the answer.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
  {
    id: "10.6",
    decision: "Whether the new generation accepts a null verifier when requirePq == false",
    previousState: "Measured by #237: Variant B is 57 B larger; recommended keep the requirement",
    measurementEvidence: "Variant B 18,629 B vs Variant A 18,572 B, re-asserted in this lane.",
    admissionEvidence:
      "All eight proofs executed: G2-VERIFIER-1..8 PASS. The verifier is not consulted on a dormant floor, a stranger can create one without WalletWall, a bare mock is refused at all three edges under the real root, and neither migration nor recovery depends on the installed one.",
    recommendation:
      "Keep the requirement: Variant A. This lane's evidence supports the measurement; it does not overturn it.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
  {
    id: "OD-BINDING-LIFETIME",
    decision:
      "NEW, AND BLOCKING. A binding never lifts, and I-VETO-BOUND and I-MIGRATION-NONTRAP (T0) say it must not trap. Change the words or change the kernel",
    previousState:
      "Architecture section 6 reads 'delayed, reversible', 13.1 and H-10 give a binding a deadline, I-VETO-BOUND names it, 13.0's failure 1 names a blacklisted destination as the trap, and 13.4 keeps only the source case. Every kernel here binds immediately, one-way, with no deadline, and retire is permissionless. Generation 1's M-K23 pins that a second destination cannot be bound. No document records the disagreement",
    measurementEvidence: "None. #237 did not reach it.",
    admissionEvidence:
      "K-12-VETO, K-13 and K-RETIRE FAIL on all three kernels, by execution: ten years on, with egress blocked, the vault is MIGRATION_ONLY with spending, rotation, recovery, containment and rebinding all refused. Only the issuer can end it. What the kernel can see at binding no longer reaches this state (K-13-DEAD-BINDING). An issuer's block of the destination still does, and on the candidate the delay has made it worse.",
    recommendation:
      "(A) Amend: section 6's transitions, action matrix and Required invariants, I-VETO-BOUND's binding clause, NONTRAP's head sentence and 13.0's failure 1, section 16's T0 scope, 22 D2's RETIRE row, 24.2's 'Permanent recovery veto: unreachable' and the 'no veto outcome' summary under it, AUTHORITY.md's matching row, and 2.2 and 13.4 to declare the blocked destination. No bytes change. (B) Build: a dedicated lane adds a self-lifting lapse and re-runs this whole suite on the new bytes. A sketch only, not adjudicated: a binding under which the admitted asset has moved nothing lapses at bind + BIND_DELAY + a window; only admitted-asset movement pins it, because native value or unsolicited dust is griefable; permissionless retire could pin a blocked binding, so it may need D2's conjunction. A lapse matters only when egress cannot succeed, since anyone can egress at day 7. Recommended: (B), because headroom is ample and it makes a T0 true rather than rewriting it. Rewriting a T0 is the owner's alone either way.",
    ownerDecisionRequired: true,
    blocksAdmission: true,
  },
  {
    id: "OD-NONFUNGIBLE-EXIT",
    decision:
      "NEW, AND BLOCKING. A non-fungible holding cannot leave, and the architecture and custody both say it can. Change the words or change the kernel",
    previousState:
      "Architecture 13.1 calls ERC-721 and ERC-1155 'workable' through the caller's asset identifier, H-25 says NFT custody arrives for free, and custody 7.1 says anything else that lands on the clone is reachable by egress. AUTHORITY.md section 5 records the fixed selectors and not this consequence",
    measurementEvidence: "None. #237 did not reach it.",
    admissionEvidence:
      "K-13-NONFUNGIBLE FAIL on all three kernels, by execution. It vetoes nothing else: every other holding leaves.",
    recommendation:
      "(A) Amend: scope this kernel's egress to holdings with the ERC-20 transfer shape, in NONTRAP and 13.1, 13.0a, H-25 and custody 7.1, and declare an unsolicited non-fungible holding in 2.2. No bytes change. (B) Build: a lane adds a per-class egress: new selectors, token-id discretion under the same no-recipient rule, settlement on observed ownership, and a callback into the destination on the safe paths. Recommended: (A), because a generation whose purpose is one admitted fungible asset gains little from a new call shape in the kernel, and nothing else is affected. The words have to change, and only the owner can change them.",
    ownerDecisionRequired: true,
    blocksAdmission: true,
  },
  {
    id: "OD-RECOVERY-LOCALITY",
    decision:
      "NEW, AND BLOCKING. Recovery consults two things I-RECOVERY-LOCALITY-V2's closed list does not name, and reads state its last clause forbids",
    previousState:
      "The invariant lists the clone's implementation, precompiles and committed guardians, and forbids reading state any principal outside that constituency can write. KERNEL_ADMISSION K-8 repeats it. AUTHORITY.md section 5 records both calls, lane SD-11 added the root's, and SD-4 and the bounded challenge are the two reads. Nothing reconciles them, and K-7's own registered statement repeated the list",
    measurementEvidence: "None. #237 did not reach it.",
    admissionEvidence:
      "K-7 FAIL as registered, by execution: initiation asks the provenance root on every floor; execution on an armed floor asks the verifier the approved request names; execution reads the credential-writable floor (SD-4) and the challenge-writable active flag (K-9). What the invariant says its words are for, 'no replaceable component's failure can stop recovery', holds: the root is ownerless and can only refuse, its cure is permissionless, a dead proposal stops only that request, and a recovering party can run its own attestor with no other infrastructure.",
    recommendation:
      "(A) Amend: add both calls to the closed list, naming their bounds, and narrow its last clause to except the credential's bounded challenge and SD-4's disposition; KERNEL_ADMISSION K-8 and the registered K-7 statement move with it. No bytes change. Recommended, because the alternative is not really available: removing the root's call reopens SD-11, and removing the armed possession proof contradicts I-INCOMING-CREDENTIAL-POSSESSION, which K-4 passes on.",
    ownerDecisionRequired: true,
    blocksAdmission: true,
  },
  {
    id: "OD-SECURITY-PROFILE",
    decision:
      "NEW, AND BLOCKING. Section 12's strength policy was deferred to a future generation, and this is one. Defer it again, or build it",
    previousState:
      "KERNEL_ADMISSION K-15: SECURITY_PROFILE_DISPOSITION = DEFERRED_TO_FUTURE_GENERATION; Generation 1 'claims no strength policy at all'. Custody's list of what the production-asset generation needs does not mention it. 24.2 still says a silent downgrade is refused by section 12's partial order",
    measurementEvidence: "None. #237 did not reach it.",
    admissionEvidence:
      "K-SECURITY-PROFILE FAIL: the floor is four flat fields, as on Generation 1, and H-05's Prevention is not implemented. K-15 passes on what it states: requirePq is one-way, and the metadata authorises nothing.",
    recommendation:
      "(A) Defer again, saying so: this generation claims no strength policy either, and 24.2's row and H-05 are corrected to what is built. No bytes change. (B) Build: a large lane. Recommended: (A) for a generation custody 10.2 recommends shipping with requirePq = false, with the policy as a condition of the first generation that arms PQ for real value.",
    ownerDecisionRequired: true,
    blocksAdmission: true,
  },
  {
    id: "OD-EGRESS-DELAY",
    decision: "NEW. Accept the admission delta that enforces BIND_DELAY at egress",
    previousState:
      "Absent: measured Variant A and Generation 1 egress in the bind block; architecture 13.2 and H-11 say otherwise",
    measurementEvidence: "See section 11 of GEN2_ADMISSION.md: spend gas unchanged, egress slightly up.",
    admissionEvidence:
      "K-12-TIME was FAIL on measured Variant A: {k guardians, ECDSA, no PQ} drained an armed vault in 0 s against 7 d for recovery. PASS on the candidate; M-G2-11 killed. Its cost is measured too: atomic bind-and-egress is gone, and it adds a week to every honest migration (N-EGRESS-WINDOW, row K-13).",
    recommendation:
      "Accept: I-MIGRATION-SUBORDINATE-TO-RECOVERY is T0 and this is the smallest change that satisfies it. Removing it returns the row to FAIL on armed floors. Should the owner prefer the invariant restated instead, that is an architecture amendment and a new admission.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
  {
    id: "OD-DEAD-BINDING",
    decision: "NEW. Accept the admission delta that checks the destination at binding",
    previousState:
      "Absent: measured Variant A and Generation 1 accept any non-zero hash, against the check at preparation architecture 13.5 presumes",
    measurementEvidence: "See section 11 of GEN2_ADMISSION.md.",
    admissionEvidence:
      "K-13-DEAD-BINDING was FAIL on measured Variant A and is PASS here; M-G2-23 and M-G2-24 killed. The re-check at egress stays, and is shown live on a destination destroyed in its creating transaction. It costs counterfactual and externally-owned destinations (N-DESTINATION-EXISTS).",
    recommendation: "Accept: one honest mistake at k+1 should not end a vault, and this moves no cut.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
  {
    id: "OD-ROOT",
    decision: "NEW. Reuse the Generation-1 provenance root, or deploy a new one",
    previousState: "Unstated",
    measurementEvidence: "None.",
    admissionEvidence:
      "Deployment-only and authority-neutral: the root has no owner, and its identity is checkable from every clone's own code. The candidate compiles the existing class unchanged.",
    recommendation: "Either is safe. Decide in the deployment lane.",
    ownerDecisionRequired: true,
    blocksAdmission: false,
  },
];

const census = "GEN2_AUTHORITY_CENSUS.json";
const stateful = "GEN2_STATEFUL_AUTHORITY_EVIDENCE.json";
const scanner = "GEN2_SCANNER_EVIDENCE.json";

export const MATRIX: Readonly<Record<string, MatrixRow>> = {
  "K-1": {
    classification: "PASS_WITH_DECLARED_RESIDUAL",
    note: "The clone holds the asset under the token's ledger; no storage word holds a balance; every unit is at an account the harness can name, in every history. The statement's 'no path removes value' is true of paths through the vault: the token's own ledger can move value with no kernel act at all.",
    evidence: {
      tests: [
        [ST, "no storage word holds a balance"],
        [ST, "ASSET BOUNDARY: the token can debit the clone with no kernel act"],
      ],
      properties: ["P-CONSERVATION", "P-BALANCE-SPENDABLE"],
      mutants: ["M-G2-14-relayer-chooses-recipient", "M-G2-20-full-balance-unspendable"],
    },
    residuals: ["R-ASSET-BOUNDARY"],
    whyTheT0Holds:
      "I-CUSTODY-CONSERVATION as a kernel can hold it: nothing leaves through the vault without an authorisation its rules accept, and that is what the properties check. An issuer acting on its own ledger goes round the vault. G1's 'component failure' is the widest reading of the words, and a token is not one of section 2.1's components. The placement rests on custody's class, 'Issuer controls are external', with the owner's lane requirements 6 and 12, rather than on a sentence naming each behaviour.",
  },
  "K-2": {
    classification: "PASS",
    note: "One fixed selector on one code-bound asset, recipient and amount signed; no payable entrypoint; the census lists exactly the new edges.",
    evidence: {
      tests: [
        [ST, "K-2: the kernel's only external call shapes"],
        [CE, "the ERC-20 call is modelled as what it is"],
      ],
      properties: ["P-SPEND-TOUCHES-ONLY-ASSET"],
      mutants: ["M-G2-1-caller-chooses-token"],
      receipts: [census],
    },
  },
  "K-3": {
    classification: "PASS",
    note: "Four domains, independent; a refused act consumes nothing, on a really mined refusal; the nonce is consumed before anything external runs.",
    evidence: {
      tests: [
        [KR, "four separate domains"],
        [KR, "a wrong nonce and a passed deadline"],
        [RE, "finds the nonce already consumed"],
      ],
      properties: ["P-NO-REPLAY", "P-NONCE-SPENT-BEFORE-TOKEN-RUNS"],
      mutants: [
        "M-G2-6-nonce-after-token-call",
        "M-G2-13-spend-nonce-not-consumed",
        "M-G2-18-spent-nonce-accepted",
        "M10-nonce-not-consumed",
      ],
    },
  },
  "K-4": {
    classification: "PASS_WITH_DECLARED_RESIDUAL",
    note: "Every commitment written carries an exhibited preimage and every install proves incoming possession. What a preimage cannot prove is SD-8.",
    evidence: {
      tests: [
        [KR, "a rotation proves possession of the INCOMING credential"],
        [KR, "a non-zero commitment needs its preimage"],
      ],
      properties: ["P-INCOMING-POSSESSION", "G-COMMITMENT-ATTESTED"],
      mutants: [
        "M7-pop-checks-outgoing-key",
        "M21-admission-not-exhibited",
        "M22-admission-bound-to-the-OUTGOING-commitment",
      ],
    },
    residuals: ["R-SD8"],
  },
  "K-5": {
    classification: "PASS",
    note: "With every plane removed and an always-true verifier installed, the kernel's own ecrecover still decides, on every credential-changing path.",
    evidence: {
      tests: [
        [KR, "the kernel's own ecrecover still decides"],
        [KR, "rotation, verifier and policy changes each contain the same floor"],
      ],
      properties: ["P-CUT/ASSET_MOVEMENT", "P-CUT/CREDENTIAL_REPLACEMENT"],
      mutants: [
        "M1-asset-path-one-root",
        "M2-rotate-floor-only",
        "M3-setverifier-floor-only",
        "M4-setpolicy-floor-only",
      ],
    },
  },
  "K-6": {
    classification: "PASS",
    note: "A forged roster, a sub-quorum, an out-of-order index and a duplicate principal are each refused; four kinds of faulty ERC-1271 guardian change nothing for the others.",
    evidence: {
      tests: [
        [KR, "the roster arrives as untrusted calldata"],
        [KR, "a roster with one principal in two seats"],
        [KR, "ERC-1271 guardian changes nothing for the others"],
      ],
      properties: ["P-CUT/GUARDIAN_TRANSITION"],
      mutants: ["M9-duplicate-guardian-principal", "M13-quorum-counts-indices-not-principals"],
    },
  },
  "K-7": {
    classification: "FAIL",
    note: "As registered, the statement is false. One writer, the half-open window and 'never the asset' all hold. 'Only the clone's implementation, precompiles and committed guardians, never a plane' does not: initiation asks the provenance root on every floor, and execution on an armed floor asks the verifier the approved request names. I-RECOVERY-LOCALITY-V2's last clause also forbids reading state a principal outside the constituency can write, and execution reads the credential-writable floor (SD-4) and the challenge-writable active flag. The class is a T1 text the kernel does not meet, on all three kernels, with no clause of the residual policy to place it under: 24.2's accepted denial is of spending, and it says recovery stays available.",
    evidence: {
      tests: [
        [KR, "recovery never consults the asset"],
        [KR, "the window is half-open"],
        [VA, "CONSULT 1, REAL ROOT, EVERY FLOOR"],
        [VA, "CONSULT 2, FIXTURE ROOT, ARMED"],
        [VA, "WHAT THE WORDS ARE FOR STILL HOLDS"],
        [VA, "the same two consults are on the kernel's own record"],
        [CD, "PRESERVED: the declaration is still admitted"],
        [KR, "the credential's veto is capped"],
      ],
      properties: ["G-RECOVERY-COMMITMENT-BINDS", "P-MODEL"],
      mutants: ["M8-recovery-commitment-drops-verifier"],
    },
    blockedOnDecision: "OD-RECOVERY-LOCALITY",
  },
  "K-8": {
    classification: "PASS",
    note: "An approved request survives a roster replacement and matures, and the recovered credential spends the admitted asset: the composition #237 had not run.",
    evidence: {
      tests: [
        [KR, "I-APPROVED-REQUEST-PRESERVATION"],
        [AI, "every guardian act, recovery included"],
      ],
      properties: ["P-MODEL"],
      mutants: ["M5-recovery-replay-enabled", "M6-cancel-does-not-invalidate"],
    },
  },
  "K-9": {
    classification: "PASS_WITH_DECLARED_RESIDUAL",
    note: "Both mechanisms present, the credential's veto capped, the epoch reset only by a successful recovery. SD-4 raises the bound on one episode to 21 days, and the veto still self-lifts.",
    evidence: {
      tests: [
        [KR, "the credential's veto is capped"],
        [KR, "a stranger can cancel nothing"],
      ],
      properties: ["P-CUT/RECOVERY_QUORUM_CANCEL", "G-CHALLENGE-EPOCH"],
      mutants: ["M6-cancel-does-not-invalidate"],
    },
    residuals: ["R-SD4"],
    whyTheT0Holds:
      "I-VETO-BOUND holds for this veto: it still lifts with no principal acting. SD-4 moves its bound on one episode to 21 days, and the ledger carries that with its disposition.",
  },
  "K-10": {
    classification: "PASS",
    note: "True as registered: spending is NORMAL only, recovery stays live in every non-terminal state the kernel can hold a request in, egress stays open from RETIRED, and every state has a plane-free exit for whoever holds the authority to take it. With the credential lost on an armed floor the way back is recovery, which consults the verifier the request names: K-7. Narrower than the architecture's table: N-LATTICE. A state the vault cannot leave is K-12-VETO.",
    evidence: {
      tests: [
        [KR, "spending is NORMAL only"],
        [KR, "recovery stays live in CONTAINED"],
      ],
      properties: ["G-EFFECTIVE-STATE-DERIVATION", "P-EXIT-REACHABLE"],
      mutants: ["M15-effective-state-ignores-expiry"],
    },
  },
  "K-11": {
    classification: "PASS",
    note: "Self-expiry on the wall clock, no extension, and the 6-in-30-day budget measured by an oracle that rebuilds episodes from timestamps.",
    evidence: {
      tests: [
        [KR, "containment self-expires on the wall clock"],
        [KR, "the historical straddle stops at the declared 6 days"],
        [KR, "re-entry cannot extend it"],
      ],
      properties: ["G-CONTAINMENT-ROLLING-BUDGET"],
      mutants: [
        "M14-containment-budget-removed",
        "M23-tumbling-reset-restored",
        "M24-tracks-only-the-most-recent-start",
      ],
    },
  },
  "K-12": {
    classification: "PASS",
    note: "True as registered: quorum AND credential; destination vault and code hash fixed; no amount and no asset set; never rebound by a caller. What its signatures commit to is K-12-SCOPE, and that it never lifts is K-12-VETO.",
    evidence: {
      tests: [
        [MI, "the credential alone is refused, the quorum alone is refused"],
        [MI, "a binding cannot be rebound"],
        [MI, "a binding names no amount and no asset set"],
        [MI, "a LIVE recovery blocks binding"],
      ],
      properties: ["P-CUT/MIGRATION_BINDING"],
      mutants: ["M12-migration-quorum-only"],
    },
  },
  "K-12-SCOPE": {
    classification: "PASS",
    note: "H-10's list, field by field. In the domain: the source and the chain. In the digest: destination, code hash and destination generation; the guardian and credential generations, which move whenever those commitments do; the policy plane; the safe state; the nonce; a signature deadline. Withdrawn by 13.1: an asset set and an amount. A binding signed before any of them changes is refused after. That the deadline is the signature's and not the binding's is K-12-VETO.",
    evidence: {
      tests: [
        [MI, "a binding signed before a credential rotation"],
        [MI, "a binding signed before a policy change"],
        [MI, "a binding signed in one safe state"],
        [MI, "the deadline it signs is the signature's"],
        [FI, "F-BINDING-SCOPE"],
      ],
      properties: ["P-CUT/MIGRATION_BINDING"],
      mutants: ["M12-migration-quorum-only"],
    },
    admissionDelta:
      "bindMigration's digest: `keccak256(abi.encode(destination.vault, destination.codeHash, destination.generation, credentialGeneration, policyEngine, _effectiveState()))`",
  },
  "K-12-VETO": {
    classification: "FAIL",
    note: "T0, on a reachable state, on all three kernels. A binding has no deadline, nothing lifts it, and while it stands every capability but egress is refused, recovery included. With egress blocked by the asset's own contract the vault waits on nobody it can reach. The block is an external behaviour; the unbounded wait is the kernel's, and the policy says a T0 failing on a reachable state is not a residual. Curing it means changing a T0's words or building a new state edge, and neither is this lane's to choose. It also makes 24.2's 'Permanent recovery veto: unreachable' untrue at k+1 plus an issuer.",
    evidence: {
      tests: [
        [FI, "F-VETO"],
        [FI, "THE CANDIDATE: the destination frozen, ten years pass"],
        [FI, "MEASURED VARIANT A and GENERATION 1 carry the same shape"],
        [FI, "A destination that refuses native value keeps that holding"],
      ],
    },
    blockedOnDecision: "OD-BINDING-LIFETIME",
  },
  "K-12-CLOCK": {
    classification: "PASS",
    note: "A binding made while contained moves no clock word, read from storage, and containment cannot start once bound. A live recovery blocks binding and an expired one holds nothing, so no recovery clock can meet a binding. This kernel has no queue.",
    evidence: {
      tests: [
        [MI, "I-MIGRATION-CLOCK-NEUTRAL"],
        [MI, "a LIVE recovery blocks binding"],
      ],
      properties: ["G-EFFECTIVE-STATE-DERIVATION", "G-CONTAINMENT-ROLLING-BUDGET"],
    },
  },
  "K-12-TIME": {
    classification: "PASS",
    note: "Every holding is refused until bind + 7 d and leaves at that exact second, on armed and dormant floors, and the coalition from the finding takes as long to migrate as to recover. Owner-reviewable: OD-EGRESS-DELAY.",
    evidence: {
      tests: [
        [MI, "the two delays are the same constant"],
        [MI, "floor: every holding is refused until exactly bind + 7 d"],
        [MI, "ARMED FLOOR, THE COALITION THE DEFECT CONCERNED"],
        [FI, "F-TIME"],
      ],
      properties: ["P-MIGRATION-TIME"],
      mutants: ["M-G2-11-egress-delay-removed"],
    },
    admissionDelta: "egress: `if (block.timestamp < b.boundAt + BIND_DELAY) revert TooEarly();`",
  },
  "K-13": {
    classification: "FAIL",
    note: "The registered statement is literally true: permissionless with no discretion, entries independent, retry perpetual, hostile holdings veto nothing, and exit reachable at the end of every campaign history with the token behaving. The row still fails, because its source does. I-MIGRATION-NONTRAP's head sentence forbids an asset state with no authorized exit, an issuer's block of the bound destination is one, 13.0's failure 1 names exactly that as the trap, and 13.4 keeps only the source case. An earlier draft placed it under the external-asset clause, and the classification registered on Variant A did too, while saying it was declared nowhere. The block is external and the trap is not: only a binding that can lift would avoid it. Worse here than on measured Variant A, where a wrapper could bind and egress atomically.",
    evidence: {
      tests: [
        [MI, "a stranger's call moves the full balance"],
        [MI, "hostile holdings fail alone and veto nothing"],
        [MI, "I-EGRESS-RETRY-PERPETUAL"],
        [FI, "F-FREEZE"],
        [FI, "WHAT THE DELAY COST"],
      ],
      properties: ["P-EGRESS-RECIPIENT", "P-EXIT-REACHABLE"],
      mutants: ["M-G2-8-migration-caller-chooses-token", "M-G2-9-migration-caller-chooses-recipient"],
    },
    blockedOnDecision: "OD-BINDING-LIFETIME",
  },
  "K-13-DEAD-BINDING": {
    classification: "PASS",
    note: "A destination with no code, the vault itself, and a hash the destination's code does not have are each refused at binding, consuming nothing and flipping nothing. The re-check at execution stays, because code can still vanish in the transaction that created it, and re-creating it at the same address restores the exit where the creator can. On measured Variant A each of the three shut the vault for good. This row covers what the kernel can see: what it cannot is K-12-VETO's.",
    evidence: {
      tests: [
        [FI, "F-DEAD-BINDING"],
        [FI, "THE CANDIDATE refuses it at binding"],
        [FI, "THE CANDIDATE refuses both at binding"],
        [MI, "K-13-DEAD-BINDING"],
        [MI, "a destination that lost its code after binding is refused"],
        [MI, "MUTANT: with the re-check removed"],
        [MI, "MUTANT: with the no-code check removed"],
      ],
      properties: ["P-EXIT-REACHABLE"],
      mutants: ["M-G2-23-dead-binding-accepted", "M-G2-24-self-binding-accepted"],
    },
    admissionDelta:
      "bindMigration: `if (destination.vault.code.length == 0 || destination.vault == address(this)) revert DestinationMismatch();` and `if (destination.vault.codehash != destination.codeHash) revert DestinationMismatch();`",
  },
  "K-13-NONFUNGIBLE": {
    classification: "FAIL",
    note: "T0, on a reachable state, on all three kernels. Egress has one call shape, so an unsolicited ERC-721 or ERC-1155 has no exit at all, though it vetoes nothing else. NONTRAP's head sentence forbids that, 13.1 calls the classes workable, and custody 7.1 says anything else that lands on the clone is reachable by egress. The policy has no clause for it.",
    evidence: {
      tests: [
        [FI, "F-NONFUNGIBLE"],
        [FI, "MEASURED VARIANT A, GENERATION 1 and THE CANDIDATE alike"],
        [MI, "OWNER DECISION OD-NONFUNGIBLE-EXIT"],
      ],
    },
    blockedOnDecision: "OD-NONFUNGIBLE-EXIT",
  },
  "K-RETIRE": {
    classification: "FAIL",
    note: "On all three kernels a stranger can force RETIRED once the delay has passed, with no migration completed, where section 6 says only a completed migration reaches it and D2 says the binding's own conjunction does. Today it closes nothing a binding has not already closed, so no cut moves. It stops being harmless if a binding can lapse, which is why it goes with that decision.",
    evidence: {
      tests: [[MI, "retire waits for the same instant, and gates nothing"]],
      properties: ["G-RETIRED-IS-TERMINAL"],
    },
    blockedOnDecision: "OD-BINDING-LIFETIME",
  },
  "K-13-SETTLE": {
    classification: "PASS",
    note: "A failed or short balance query refuses, before and after, on spend and on egress, and a native egress publishes what the balance lost, so a destination handing the value back cannot be reported as paid. Measured Variant A read a failed query as an observed zero and settled a full-balance spend with nothing moved, and published native value as moved because the call returned.",
    evidence: {
      tests: [
        [FI, "F-SETTLE"],
        [FI, "publish native value as moved because the call returned"],
        [FI, "THE CANDIDATE refuses a native egress that lost nothing"],
        [MI, "I-NO-FALSE-SETTLEMENT on the way out"],
      ],
      properties: ["P-SETTLEMENT-EXACT", "P-EGRESS-PUBLISHES-THE-TRUTH"],
      mutants: [
        "M-G2-12-lenient-balance-read",
        "M-G2-22-egress-publishes-the-whole-balance",
        "M-G2-25-native-published-unobserved",
      ],
    },
    admissionDelta:
      "_balanceOf: `if (!ok || data.length < 32) revert TransferFailed();` in place of `return 0`; egress: the native branch reads the balance after the call, and publishes the decrease",
  },
  "K-14": {
    classification: "PASS",
    note: "Only a root-created verifier becomes active, at all three edges, under the real root. The escape from a dead or lost verifier does not need that verifier.",
    evidence: {
      tests: [
        [VA, "a mock verifier is refused at genesis, at setVerifier and at initiateRecovery"],
        [VA, "the guardian recovery escapes to a live verifier"],
      ],
      properties: ["P-VERIFIER-PROVENANCE", "P-CUT/VERIFIER_REPLACEMENT"],
      mutants: ["M3-setverifier-floor-only", "M-G2-21-verifier-provenance-unchecked"],
    },
  },
  "K-15": {
    classification: "PASS",
    note: "requirePq is one-way, and the three metadata fields cannot move an approved recovery's executability.",
    evidence: {
      tests: [
        [VA, "requirePq is one-way"],
        [KR, "I-RECOVERY-SATISFIABILITY-METADATA-INDEPENDENCE"],
      ],
      properties: ["G-FLOOR-NO-DOWNGRADE"],
      mutants: ["M19-declaration-not-exhibited"],
    },
  },
  "K-GENERATION": {
    classification: "PASS",
    note: "A signature by the current key under a past credential generation is refused, and by the current roster under a past guardian generation, each passing under the live one. Both counters only rise, across every campaign history. A binding's digest now names both generations, so its credential leg dies with a rotation too.",
    evidence: {
      tests: [
        [KR, "I-GENERATION-MONOTONE"],
        [MI, "a binding signed before a credential rotation"],
        [FI, "F-BINDING-SCOPE"],
      ],
      properties: ["G-CRED-GENERATION-MONOTONIC", "G-GUARDIAN-GENERATION-MONOTONIC", "G-NONCES-MONOTONIC"],
    },
    admissionDelta: "The same as K-12-SCOPE.",
  },
  "K-6-ATTESTATION": {
    classification: "PASS",
    note: "An ERC-1271 answer counts only if the whole returned word is the magic value. On measured Variant A magic in the first four bytes and anything in the rest reached quorum.",
    evidence: {
      tests: [
        [FI, "F-ATTESTATION"],
        [FI, "THE CANDIDATE counts no such answer"],
        [KR, "ERC-1271 guardian changes nothing for the others"],
      ],
    },
    admissionDelta: "_attests: `return ok && answer == bytes32(ERC1271_MAGIC);` in place of comparing `bytes4(answer)`",
  },
  "K-SECURITY-PROFILE": {
    classification: "FAIL",
    note: "The floor is four flat fields, the construct section 12 withdrew, as on Generation 1, whose admission deferred the rules to a future generation. This is a future generation, and nothing says whether the deferral carries over. H-05's Prevention, a kernel-recorded strength per scheme, is not here, and 24.2's 'refused by the partial order' describes something no kernel built so far has. K-15 passes on what it states. On a dormant floor there is no PQ strength to rate, so a further deferral is coherent, and the owner has to say so.",
    evidence: { tests: [[KR, "the floor is four flat fields"]], properties: ["G-FLOOR-NO-DOWNGRADE"] },
    blockedOnDecision: "OD-SECURITY-PROFILE",
  },
  "K-INGRESS": {
    classification: "PASS",
    note: "The kernel books nothing: no storage word holds a balance, in any state, so the invariant has nothing to be broken by. What arrives with no kernel function, a direct transfer, is what its scope correction excludes.",
    evidence: { tests: [[ST, "no storage word holds a balance"]], properties: ["P-CONSERVATION"] },
  },
  "OFF-KERNEL-INVARIANTS": {
    classification: "NOT_APPLICABLE",
    note: "No kernel subject, per invariant, in the criterion's source. Recorded so absence is not read as coverage. test/Gen2AdmissionMatrix.test.ts scans the normative documents, so a newly named invariant fails until a criterion names it.",
    evidence: {},
  },
  "PLANE-ISOLATION": {
    classification: "PASS",
    note: "A plane may only refuse. It runs after the nonce and before the snapshot, so it cannot touch the observation, and no plane is consulted on the way out. IKernelPolicy.admit names no asset, which a single-asset vault does not need.",
    evidence: {
      tests: [
        [RE, "a plane nesting an authorised spend cannot touch the observation"],
        [RE, "a plane that always allows grants nothing"],
        [RE, "no plane is consulted on the way out"],
      ],
      properties: ["P-PLANE-SUBTRACTIVE"],
      mutants: ["M11-plane-denial-ignored"],
    },
  },
  "IMPL-IMMUTABILITY": {
    classification: "PASS",
    note: "Zero immutable slots; a clone byte-exactly template + implementation + 48 args; the bare implementation cannot be initialised, and its asset read is meaningless bytes with no authority behind them.",
    evidence: {
      tests: [
        [AI, "every link is reconstructible from public facts"],
        [AI, "I-PURE-CONSTRUCTOR"],
        [AI, "I-DIRECT-IMPL-CALL-INERT"],
        [AI, "I-DEPLOY-INIT-ATOMIC"],
      ],
      properties: ["P-ASSET-CODE-IDENTITY"],
      mutants: ["M-G2-2-asset-outside-the-identity"],
      receipts: ["GEN2_ADMISSION_EVIDENCE.json"],
    },
  },
  "FACTORY-GENERATION": {
    classification: "PASS_WITH_DECLARED_RESIDUAL",
    note: "One immutable factory per generation, with no setter and no storage, and a salt that binds the whole genesis. What a given factory was constructed with is a publisher fact, checkable offline.",
    evidence: {
      tests: [
        [AI, "the factory exposes no owner, role or registry"],
        [AI, "I-COUNTERFACTUAL-IDENTITY-BINDING"],
        [AI, "a codeless asset, a zero asset, a zero generation"],
      ],
      mutants: ["M-G2-2-asset-outside-the-identity"],
    },
    residuals: ["R-SD11-CONDITION"],
  },
  "AUTH-COMPLETENESS": {
    classification: "PASS",
    note: "The real checker, unchanged, classifies all 18 gated entries under a Generation-2 manifest, 16 PASS and 2 PASS_WITH_DECLARED_EXCEPTION. The derived comparison finds NO_NEW_PRIVILEGED_PRINCIPAL, and mutants prove that verdict can change.",
    evidence: {
      tests: [
        [CE, "the real checker classifies every state-changing function"],
        [CE, "derived verdict: NO_NEW_PRIVILEGED_PRINCIPAL"],
        [CE, "the verdict has teeth"],
      ],
      mutants: ["M-G2-10-relayer-identity-gains-privilege"],
      receipts: [census],
    },
  },
  "AUTH-SATISFIABILITY": {
    classification: "PASS",
    note: "No accepted transition leaves a mandatory conjunct with no possible witness; a dead vault is reachable only by SD-8's declared deliberate route, and that route still has both exits. Bindings the kernel can see are dead were other routes to one on measured Variant A, and the K-13-DEAD-BINDING delta closes them.",
    evidence: {
      tests: [
        [KR, "no vault is born with a mandatory conjunct nothing can satisfy"],
        [VA, "arming needs the exact preimage"],
        [CD, "NOT WORSENED, AND THE ASSET IS NOT TRAPPED"],
        [FI, "THE CANDIDATE refuses it at binding"],
        [FI, "THE CANDIDATE refuses both at binding"],
      ],
      properties: ["G-PQ-COMMITMENT-SATISFIABLE", "P-EXIT-REACHABLE"],
      mutants: [
        "M19-declaration-not-exhibited",
        "M20-declaration-unbound-from-the-commitment",
        "M-G2-23-dead-binding-accepted",
        "M-G2-24-self-binding-accepted",
      ],
    },
  },
  "STATEFUL-COMPOSITION": {
    classification: "PASS",
    note: "Generation 1's fixed seeds and depths, on the candidate, across every inherited profile and thirteen ERC-20 profiles: no violation unexplained by the ledger; every positive control, action, outcome and seam reached. Mutation adequacy on both catalogues, each kill against a clean baseline of the same seed, and every Generation-2 property shown to fire. Exact outcomes are in GEN2_RUN_RECORD.json, which the suites compare themselves with and the verdict reads.",
    evidence: {
      tests: [
        [CA, "every positive control passed in every campaign"],
        [CA, "every Generation-2 seam was actually reached"],
        [CA, "every sustained defect with a campaign property"],
        [CA, "the outcome is the committed record"],
        [MU, "every mutant in both catalogues was killed"],
        [MU, "every Generation-2 property has a mutant that dies by it"],
        [MU, "the outcome is the committed record"],
      ],
      properties: ["P-CUT/ASSET_MOVEMENT", "P-VACUITY"],
      receipts: [stateful],
    },
  },
  "SCANNER-BOUNDARY": {
    classification: "PASS",
    note: "Slither at the pinned commit ran on the candidate's own tree. Every own-code finding is adjudicated by semantic identity, and each on the candidate names its dynamic property and mutant. CodeQL has no Solidity extractor and was not run locally: stated, not implied.",
    evidence: {
      tests: [
        [SC, "every finding on the candidate's kernel and factory"],
        [SC, "the opcode sweep"],
      ],
      receipts: [scanner],
    },
  },
  PROVENANCE: {
    classification: "PASS",
    note: "The identity reconstructs from committed source through the pinned compiler. Receipts name their subject, never their container, and currency is by byte equality of the measured inputs. No timestamp or machine path enters.",
    evidence: {
      tests: [
        [PR, "the identity in the evidence is what the source compiles to"],
        [PR, "no receipt carries a timestamp, a machine path or a container"],
        [DE, "the candidate differs from Variant A in exactly the declared statements"],
      ],
      receipts: ["GEN2_ADMISSION_EVIDENCE.json"],
    },
  },
  "RUNTIME-CEILING": {
    classification: "PASS",
    note: "Re-measured after the admission changes, with every delta from measured Variant A published. See `identity.measurement` in the evidence.",
    evidence: {
      tests: [
        [ME, "the candidate clears TARGET_KERNEL_CEILING"],
        [ME, "the delta from measured Variant A is computed"],
      ],
      receipts: ["GEN2_ADMISSION_EVIDENCE.json"],
    },
  },
  "G2-ASSET-1": {
    classification: "PASS",
    note: "A vault's asset is its factory's constructor argument from its first block.",
    evidence: {
      tests: [
        [AI, "a vault's asset is its factory's constructor argument"],
        [AI, "the factory's asset is immutable bytes"],
      ],
      properties: ["P-ASSET-CODE-IDENTITY"],
      mutants: ["M-G2-2-asset-outside-the-identity"],
    },
  },
  "G2-ASSET-2": {
    classification: "PASS",
    note: "No setter on either, from the ABI and from the storage layout, and no storage word holds the value in a live vault.",
    evidence: {
      tests: [
        [AI, "the kernel's only functions naming an asset"],
        [AI, "no storage word of the kernel holds the asset"],
        [AI, "a setter selector dispatches to nothing"],
      ],
    },
  },
  "G2-ASSET-3": {
    classification: "PASS",
    note: "No asset parameter exists, and appended calldata changes nothing.",
    evidence: {
      tests: [
        [AI, "execute has no asset parameter"],
        [AI, "a relayer appending another token"],
      ],
      properties: ["P-SPEND-TOUCHES-ONLY-ASSET"],
      mutants: ["M-G2-1-caller-chooses-token"],
    },
  },
  "G2-ASSET-4": {
    classification: "PASS",
    note: "A relayer can choose whether and when; rewriting a signed field is refused and consumes nothing.",
    evidence: {
      tests: [
        [AI, "a relayer rewriting the recipient or the amount"],
        [AI, "a relayer has no identity to the kernel"],
      ],
      properties: ["P-UNAUTHORISED-INPUT-NEVER-SETTLES"],
      mutants: [
        "M-G2-14-relayer-chooses-recipient",
        "M-G2-17-signed-recipient-unbound",
        "M-G2-10-relayer-identity-gains-privilege",
      ],
    },
  },
  "G2-ASSET-5": {
    classification: "PASS",
    note: "Every credential act leaves the code byte-identical, across every campaign history.",
    evidence: {
      tests: [[AI, "every credential act leaves the vault's code"]],
      properties: ["P-ASSET-CODE-IDENTITY"],
      mutants: ["M-G2-15-credential-moves-the-asset-in-place"],
    },
  },
  "G2-ASSET-6": {
    classification: "PASS",
    note: "Every guardian act, recovery included, leaves the code byte-identical.",
    evidence: {
      tests: [
        [AI, "every guardian act, recovery included"],
        [AI, "a replaced roster's quorum cannot move it"],
      ],
      properties: ["P-ASSET-CODE-IDENTITY"],
      mutants: ["M-G2-16-quorum-moves-the-asset-in-place"],
    },
  },
  "G2-ASSET-7": {
    classification: "PASS_WITH_DECLARED_RESIDUAL",
    note: "No owner, role, registry or storage; any deployer gets identical bytes for identical arguments. The one choice is the constructor argument, spent before any vault exists.",
    evidence: {
      tests: [
        [AI, "the only choice is the constructor's"],
        [AI, "the factory's deployer holds no privilege over a clone"],
      ],
      receipts: [census],
    },
    residuals: ["R-SD11-CONDITION"],
  },
  "G2-ASSET-8": {
    classification: "PASS",
    note: "A migration moves the asset; it never converts it. To a vault of another asset it arrives as a holding that can leave and cannot be spent.",
    evidence: {
      tests: [
        [AI, "a migration moves the admitted asset to a vault of the same asset"],
        [AI, "a vault of a DIFFERENT asset holds what arrives"],
        [AI, "a binding never changes the source vault's asset read"],
      ],
    },
  },
  "G2-ASSET-9": {
    classification: "PASS",
    note: "With factory, salt, genesis and implementation fixed, the asset alone moves the address, and with it the domain separator.",
    evidence: {
      tests: [
        [AI, "the asset alone moves the CREATE2 address"],
        [AI, "two real vaults of two assets"],
      ],
      mutants: ["M-G2-2-asset-outside-the-identity"],
    },
  },
  "G2-ASSET-10": {
    classification: "PASS",
    note: "Both directions, over histories, with one credential on both vaults, and neither burns a nonce.",
    evidence: {
      tests: [[AI, "a spend signed for this vault fails at the other"]],
      properties: ["P-CROSS-ASSET"],
      mutants: ["M-G2-3-cross-asset-replay-accepted"],
    },
  },
  "G2-SEM-KERNEL": {
    classification: "PASS",
    note: "Settlement is the observed exact decrease; the boolean is trusted in neither direction; a failed query refuses; every refusal is atomic. What the kernel cannot observe is R-ASSET-BOUNDARY, a residual of asset admission and not of this row.",
    evidence: {
      tests: [
        [ST, "refused as TransferFailed, atomically"],
        [ST, "the boolean is trusted in NEITHER direction"],
        [ST, "a zero-amount spend needs a transfer that COMPLETED"],
      ],
      properties: ["P-SETTLEMENT-EXACT", "P-SPEND-COMPLETED-TRANSFER"],
      mutants: ["M-G2-4-boolean-trust", "M-G2-5-any-decrease-accepted", "M-G2-7-failed-transfer-ignored"],
    },
    admissionDelta: "Same as K-13-SETTLE.",
  },
  "G2-SEM-BOUNDARY": {
    classification: "PASS_WITH_DECLARED_RESIDUAL",
    note: "The checklist exists and names every semantic the kernel cannot observe; no real token is admitted and no real address appears.",
    evidence: {
      tests: [
        [ST, "ASSET BOUNDARY: a recipient-side fee settles"],
        [DE, "the source of the candidate carries the NOT PRODUCTION label"],
      ],
    },
    residuals: ["R-ASSET-BOUNDARY"],
  },
  "G2-NO-ALLOWANCE": {
    classification: "PASS",
    note: "No approve call and no 1271 entrypoint, and a token's permit and signature-transfer paths cannot debit the vault, signed by the credential itself or not. The adversary is shown real on a contract that does answer.",
    evidence: {
      tests: [
        [ST, "the runtime contains no approve call"],
        [ST, "a token's permit and signature-transfer paths cannot debit the vault"],
      ],
    },
  },
  "G2-VERIFIER-1": {
    classification: "PASS",
    note: "Neither root nor class has an owner, setter or vault reference, and an attestor key used as a credential is refused.",
    evidence: {
      tests: [
        [VA, "neither the root nor the class exposes an owner"],
        [VA, "the attestor key behind the vault's verifier authorises nothing"],
      ],
      receipts: [census],
    },
  },
  "G2-VERIFIER-2": {
    classification: "PASS",
    note: "A spend settles with a reverting verifier installed, which it could not if the verifier were called.",
    evidence: {
      tests: [
        [VA, "a spend settles on an ECDSA-only floor with a "],
        [VA, "an always-true verifier gives an attacker with no ECDSA key nothing"],
      ],
    },
  },
  "G2-VERIFIER-3": {
    classification: "PASS",
    note: "A complete lifecycle with no attestor statement anywhere, and a vault created with no WalletWall involved at all.",
    evidence: {
      tests: [
        [VA, "all complete with NO attestor statement anywhere"],
        [VA, "a vault can be created without WalletWall"],
      ],
    },
  },
  "G2-VERIFIER-4": {
    classification: "PASS",
    note: "The root is permissionless and records only what it created; a byte-identical copy outside it is refused.",
    evidence: {
      tests: [
        [VA, "the outsider created every verifier in a root world"],
        [VA, "the class's attestor is immutable"],
      ],
    },
  },
  "G2-VERIFIER-5": {
    classification: "PASS",
    note: "All three edges under the real root; on an armed floor one root cannot change the verifier.",
    evidence: {
      tests: [
        [VA, "a mock verifier is refused at genesis"],
        [VA, "one root cannot change the verifier"],
      ],
      properties: ["P-CUT/VERIFIER_REPLACEMENT", "P-VERIFIER-PROVENANCE"],
      mutants: ["M3-setverifier-floor-only"],
    },
  },
  "G2-VERIFIER-6": {
    classification: "PASS",
    note: "A bare always-true contract is refused under the real root. A root-created verifier under an attacker's own attestor is admissible, since the root checks the class and not the attestor: installing it takes what installing any verifier takes, and it then voids only the PQ factor, the declared degradation. It reaches the asset no other way.",
    evidence: {
      tests: [
        [VA, "a bare always-true contract cannot be installed"],
        [VA, "a verifier under an attacker's own attestor IS admissible"],
        [VA, "installed anyway, it voids only the PQ factor"],
        [VA, "it cannot reach the asset any other way"],
      ],
    },
  },
  "G2-VERIFIER-7": {
    classification: "PASS",
    note: "With the verifier down, spending stops and a binding by quorum and ECDSA does not; the egress moves everything; recovery escapes.",
    evidence: {
      tests: [
        [VA, "spending stops, a binding by quorum and ECDSA does not"],
        [VA, "the guardian recovery escapes to a live verifier"],
      ],
    },
  },
  "G2-VERIFIER-8": {
    classification: "PASS",
    note: "No attestor is needed on a dormant floor. On an armed floor no particular one is: migration by quorum and ECDSA needs none, and a recovery needs some attestor's statement, which the recovering party can make itself. A compromised attestor alone moves nothing.",
    evidence: {
      tests: [
        [VA, "ATTESTOR GONE"],
        [VA, "a compromised attestor alone moves nothing"],
        [VA, "WHAT THE WORDS ARE FOR STILL HOLDS"],
      ],
    },
  },
  "G2-REENTRANCY": {
    classification: "PASS",
    note: "No guard, and none earned: double-spend, replay, disposition, safe state, nonce order, atomicity and the observation each adversarially exercised, hook before and after the debit, deterministically and over histories. Rotation, roster change and recovery initiation are exercised from inside the hook too, and each is the ordering spend-then-act (N-NESTED-ACTS).",
    evidence: {
      tests: [
        [RE, "cannot double-spend"],
        [RE, "cannot replay"],
        [RE, "cannot alter the migration disposition"],
        [RE, "cannot escape a safe state"],
        [RE, "finds the nonce already consumed"],
        [RE, "failure is atomic"],
        [RE, "the settlement observation cannot be manipulated"],
        [RE, "a rotation from the hook is spend-then-rotate"],
        [RE, "a roster change from the hook is spend-then-replace"],
        [RE, "a recovery begun from the hook is spend-then-initiate"],
      ],
      properties: ["P-NONCE-SPENT-BEFORE-TOKEN-RUNS", "P-REENTRY-NO-REPLAY"],
      mutants: ["M-G2-6-nonce-after-token-call", "M-G2-19-replay-accepted-inside-the-transfer"],
    },
  },
  "DEFECT-CARRY": {
    classification: "PASS_WITH_DECLARED_RESIDUAL",
    note: "SD-4 and SD-8 re-executed and preserved; SD-11A and SD-11B preserved under their condition. None worsened, none reachable through the asset, none accidentally fixed.",
    evidence: {
      tests: [
        [CD, "the ledger this suite answers is the ledger"],
        [CD, "PRESERVED: the declaration is still admitted"],
        [CD, "PRESERVED UNDER THE REAL ROOT"],
      ],
    },
    residuals: ["R-SD4", "R-SD8", "R-SD11-CONDITION"],
  },
  "OBSERVATORY-CLAIMS": {
    classification: "NOT_APPLICABLE",
    note: "Observatory by architecture 16.1: no assurance here. Recorded so absence is not read as coverage.",
    evidence: {},
  },
};

/**
 * EVERY T0 AND T1 HAZARD IN THE REGISTER, BY THE ROW THAT ANSWERS IT. A scan of invariant names cannot see a hazard's
 * Prevention, which is how H-05 and H-10 went unnoticed until a review read them. test/Gen2AdmissionMatrix.test.ts
 * parses the register, so a hazard with no entry here fails, and so does an entry naming no row.
 */
export const HAZARD_COVERAGE: Readonly<Record<string, { rows: readonly string[]; note: string }>> = {
  "H-01": {
    rows: ["AUTH-COMPLETENESS"],
    note: "An admin pause: the kernel has no owner and no pause, and the census would notice one.",
  },
  "H-02": {
    rows: ["FACTORY-GENERATION", "K-4"],
    note: "Identity is the clone's address and authority is rotatable state.",
  },
  "H-03": {
    rows: ["K-9"],
    note: "Its Prevention reads 'guardian-quorum authority only'. D1 superseded that with a bounded credential challenge, and that is what K-9 holds the kernel to.",
  },
  "H-04": { rows: ["K-4"], note: "Possession of every incoming credential, on both write paths." },
  "H-05": { rows: ["K-SECURITY-PROFILE"], note: "Not implemented, on any kernel here. Blocking." },
  "H-10": { rows: ["K-12-SCOPE", "K-13-DEAD-BINDING"], note: "The binding's fields, and the code hash at both ends." },
  "H-11": { rows: ["K-12", "K-12-TIME"], note: "Decomposed authority, and the warning window it promises." },
  "H-12": { rows: ["K-11", "K-10"], note: "Containment self-expires, and recovery stays live through it." },
  "H-13": { rows: ["K-10", "K-11"], note: "No capability exists only in CONTAINED." },
  "H-15": { rows: ["K-6"], note: "Not prevented: accepted by owner decision D1, and K-6 does not claim otherwise." },
  "H-17": {
    rows: ["G2-VERIFIER-3", "G2-VERIFIER-8"],
    note: "No infrastructure dependency, on a dormant floor or for exit.",
  },
  "H-18": { rows: ["OBSERVATORY-CLAIMS"], note: "An assurance plane this prototype does not contain." },
  "H-19": { rows: ["K-6"], note: "Guardian membership is kernel state, with no plane to take over." },
  "H-20": { rows: ["RUNTIME-CEILING"], note: "One vault's semantics, and a published byte budget." },
  "H-21": { rows: ["IMPL-IMMUTABILITY", "AUTH-SATISFIABILITY"], note: "Guardians bound atomically with creation." },
  "H-23": { rows: ["K-2", "G2-NO-ALLOWANCE"], note: "No generic execution and no ERC-1271 surface on the vault." },
  "H-24": { rows: ["G2-VERIFIER-4"], note: "The admitted class's attestor is immutable." },
  "H-25": {
    rows: ["K-1", "K-INGRESS"],
    note: "No second number. The hazard's aside that NFT custody arrives for free is K-13-NONFUNGIBLE.",
  },
  "H-26": { rows: ["G2-ASSET-10"], note: "The domain separates vaults." },
  "H-27": { rows: ["K-6"], note: "The roster is emitted with every write of its commitment." },
  "H-28": { rows: ["K-13"], note: "Per-entry independence holds. The row fails on another clause." },
  "H-29": { rows: ["IMPL-IMMUTABILITY"], note: "Zero immutable slots." },
  "H-30": { rows: ["K-11"], note: "No extension, and a rolling budget with B < W." },
  "H-31": { rows: ["K-6"], note: "Not prevented, in the register's own words. Unchanged here." },
  "H-32": { rows: ["FACTORY-GENERATION"], note: "One immutable factory per generation." },
};

/**
 * The verdict, from the rows, the decisions and whatever stops the recorded runs supporting admission. A row that does
 * not pass leaves it NOT_ADMITTED unless it names a blocking decision, which then makes it BLOCKED: "rather than
 * guessing". Suites that did not come out clean leave it NOT_ADMITTED whatever the rows say.
 */
export function deriveAdmissionVerdict(
  rows: readonly MatrixRow[],
  decisions: readonly OwnerDecision[],
  executionProblems: readonly string[],
): AdmissionVerdict {
  if (executionProblems.length > 0) return "GEN2_NOT_ADMITTED";
  const unmet = rows.filter((r) => r.classification === "FAIL" || r.classification === "UNPROVEN");
  const blocking = new Set(decisions.filter((d) => d.blocksAdmission).map((d) => d.id));
  if (unmet.some((r) => r.blockedOnDecision === undefined || !blocking.has(r.blockedOnDecision)))
    return "GEN2_NOT_ADMITTED";
  if (unmet.length > 0 || blocking.size > 0) return "GEN2_ADMISSION_BLOCKED";
  if (rows.some((r) => r.classification === "PASS_WITH_DECLARED_RESIDUAL"))
    return "GEN2_ADMITTED_WITH_DECLARED_RESIDUALS";
  return "GEN2_ADMITTED";
}
