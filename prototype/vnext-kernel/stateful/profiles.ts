/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * CAMPAIGN PROFILES — who is compromised, and what the generator reaches for.
 *
 * A profile is the experimental design. Each one fixes an ADVERSARY MODEL
 * (which roots are compromised) and an ACTION MIX, and the campaign then asks
 * whether ANY history under that model reduces a protected outcome below its
 * declared cut.
 *
 * Every profile includes the fully-honest actor, because a campaign in which
 * every action reverts proves nothing. Its share of the action budget is what
 * drives the vault through legitimate state transitions so the attacker has a
 * varied, deep history to attack — an adversary-only campaign would spend its
 * whole depth bouncing off the first gate.
 */
import { ALL_MATERIAL, makeActor, type Actor, type VerifierKind } from "./world.js";
import type { ActionKind } from "./actions.js";

/** Holds EVERY key, whatever rotation or roster change has happened. The positive control. */
export const ALL_MATERIAL_ACTOR: Actor = makeActor("honest", [ALL_MATERIAL], "deployer");

/**
 * Holds the GENESIS ECDSA credential and nothing else. This is the exact
 * "one root compromised" scenario the published `min(2, k)` claim says must be
 * survivable, and the scenario under which findings A1 and A2 were originally
 * reproduced against an earlier kernel.
 */
export const ECDSA_ONLY_ATTACKER: Actor = makeActor("attacker-ecdsa-only", ["cred"]);

/** Holds the GENESIS PQ credential and nothing else. */
export const PQ_ONLY_ATTACKER: Actor = makeActor("attacker-pq-only", ["pq"]);

/** Holds exactly ONE guardian principal — below `k = 2`. */
export const ONE_GUARDIAN_ATTACKER: Actor = makeActor("attacker-one-guardian", ["guardian-0"]);

/**
 * Holds ONE guardian AND the ECDSA credential: two roots, but from DIFFERENT
 * families. It is below `k` for guardian-gated outcomes and below `k+1` for
 * migration, so it is the sharpest test of whether the kernel adds roots across
 * families that should not combine.
 */
export const MIXED_ATTACKER: Actor = makeActor("attacker-guardian-plus-credential", ["guardian-0", "cred"]);

/**
 * Holds TWO guardian principals — AT the declared guardian cut k = 2, but NO
 * credential. It is the only actor that can reach a quorum without the
 * credential leg, which makes it the one that can tell whether migration's
 * declared "k + 1" really needs the "+ 1", or whether k alone suffices.
 */
export const TWO_GUARDIAN_ATTACKER: Actor = makeActor("attacker-two-guardians", ["guardian-0", "guardian-1"]);

/** Holds NOTHING. Exercises every permissionless path and every replay. */
export const STRANGER: Actor = makeActor("stranger", []);

export interface CampaignProfile {
  name: string;
  description: string;
  actors: Actor[];
  /** Same length as `actors`. */
  actorWeights: number[];
  /** Relative frequency per action kind. Absent or 0 means the profile never generates it. */
  weights: Partial<Record<ActionKind, number>>;
  /** Which verifier the vault is born under. */
  verifier?: VerifierKind;
  /** Born with an ECDSA-only floor. The ONLY way to reach a requirePq false -> true transition. */
  ecdsaOnlyFloor?: boolean;
  /**
   * With `ecdsaOnlyFloor`, commit a PQ key at genesis anyway — a legal genesis,
   * since `initialize` refuses only `requirePq` WITH a zero commitment.
   *
   * Since `I-DECLARATION-EXHIBITED` this is the ONLY vault class on which the
   * `requirePq` false -> true declaration can SUCCEED, because the satisfiability
   * witness has something to be a witness for. Without a profile carrying it the
   * campaign would only ever observe the REFUSAL, and the armed post-state — the
   * one `G-PQ-COMMITMENT-SATISFIABLE` exists to police — would be unreachable.
   */
  commitPqKeyOnEcdsaOnlyFloor?: boolean;
  /**
   * Makes `ROTATE_CREDENTIAL` FABRICATE its incoming commitment on a
   * deterministic subset of steps — a hash nothing in the campaign holds a
   * preimage for, supplied with an empty exhibit. This is the SD-6 attack,
   * generated rather than argued, and it is what gives `G-COMMITMENT-ATTESTED`
   * teeth: a property whose violating transition no profile ever attempts is
   * green for the worst possible reason.
   *
   * The subset is derived from the EXISTING `target` draw, so no `prng` call is
   * added anywhere, and only the appended `commitment-forgery` profile sets it.
   */
  fabricateCommitments?: boolean;
  /** Shifts the ADVANCE_TIME distribution into a pending recovery executable window. */
  timeBias?: "default" | "maturation" | "duty-cycle";
  /** Proposes a LIVE verifier and rarely a stale PoP, so the recovery seam is reachable. */
  honestRecoveryBias?: boolean;
}

/** The default mix: broad coverage of every transition. */
const BROAD: Partial<Record<ActionKind, number>> = {
  FUND: 3,
  SPEND: 10,
  ROTATE_CREDENTIAL: 6,
  SET_VERIFIER: 6,
  SET_POLICY: 5,
  SET_GUARDIANS: 5,
  INITIATE_RECOVERY: 8,
  CANCEL_RECOVERY: 5,
  EXECUTE_RECOVERY: 7,
  ENTER_CONTAINMENT: 5,
  BIND_MIGRATION: 3,
  RETIRE: 2,
  EGRESS_NATIVE: 3,
  EGRESS_TOKEN: 2,
  ADVANCE_TIME: 12,
  REPLAY_PAST_CALL: 6,
  FACTORY_DEPLOY_TWIN: 1,
};

/** Recovery-weighted: PHASE 6 is the highest-value composition surface. */
const RECOVERY_HEAVY: Partial<Record<ActionKind, number>> = {
  ...BROAD,
  INITIATE_RECOVERY: 16,
  CANCEL_RECOVERY: 14,
  EXECUTE_RECOVERY: 16,
  ADVANCE_TIME: 20,
  ROTATE_CREDENTIAL: 10,
  SET_GUARDIANS: 10,
  SPEND: 6,
  FACTORY_DEPLOY_TWIN: 0,
};

/** Replay-weighted: PHASE 9. */
const REPLAY_HEAVY: Partial<Record<ActionKind, number>> = {
  ...BROAD,
  REPLAY_PAST_CALL: 22,
  ADVANCE_TIME: 14,
  ROTATE_CREDENTIAL: 9,
  SET_VERIFIER: 9,
  SET_GUARDIANS: 9,
  FACTORY_DEPLOY_TWIN: 0,
};

/** Containment / safe-state weighted: PHASE 8. */
const CONTAINMENT_HEAVY: Partial<Record<ActionKind, number>> = {
  ...BROAD,
  ENTER_CONTAINMENT: 18,
  ADVANCE_TIME: 24,
  BIND_MIGRATION: 8,
  RETIRE: 6,
  EGRESS_NATIVE: 6,
  FACTORY_DEPLOY_TWIN: 0,
};

export const PROFILES: readonly CampaignProfile[] = [
  {
    name: "ecdsa-only-attacker",
    description:
      "One root compromised: the ECDSA credential. The published min(2,k) claim says every protected outcome must stay out of reach. Findings A1 and A2 were both reproduced under exactly this model.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [4, 5, 2],
    weights: BROAD,
  },
  {
    name: "one-guardian-attacker",
    description: "One guardian principal compromised — below k = 2. Targets I-E (guardian cut) and the quorum-shape attacks.",
    actors: [ALL_MATERIAL_ACTOR, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [4, 5, 2],
    weights: BROAD,
  },
  {
    name: "mixed-roots-attacker",
    description:
      "One guardian AND the ECDSA credential: two roots from different families. Below k for guardian outcomes and below k+1 for migration, so it tests whether roots that should not combine are being added together.",
    actors: [ALL_MATERIAL_ACTOR, MIXED_ATTACKER, STRANGER],
    actorWeights: [4, 5, 2],
    weights: BROAD,
  },
  {
    name: "recovery-composition",
    description: "Recovery lifecycle under an ECDSA-only adversary: stale, cancelled, superseded, finalised and replayed recoveries (R1-R7).",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [5, 4, 3],
    weights: RECOVERY_HEAVY,
  },
  {
    name: "recovery-maturation",
    description:
      "The one profile that reliably drives a recovery THROUGH to execution. The broad mix generates roster changes and cancellations so often that a pending request almost never survives to maturity, so executeRecovery never succeeded across 145 campaigns and R2-R7 were never exercised end-to-end — a hole the anti-vacuity assertion caught. Here SET_GUARDIANS is off (its generation binding voids pending requests by design) and ADVANCE_TIME is biased into the executable window. Adversarial interference with recovery is still covered by recovery-composition, which keeps both.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [6, 2, 2],
    weights: {
      FUND: 3,
      SPEND: 6,
      ROTATE_CREDENTIAL: 4,
      SET_VERIFIER: 3,
      SET_POLICY: 2,
      SET_GUARDIANS: 0,
      INITIATE_RECOVERY: 14,
      CANCEL_RECOVERY: 4,
      EXECUTE_RECOVERY: 16,
      ENTER_CONTAINMENT: 3,
      BIND_MIGRATION: 1,
      RETIRE: 1,
      EGRESS_NATIVE: 1,
      EGRESS_TOKEN: 1,
      ADVANCE_TIME: 22,
      REPLAY_PAST_CALL: 6,
      FACTORY_DEPLOY_TWIN: 0,
    },
    timeBias: "maturation",
    honestRecoveryBias: true,
  },
  {
    name: "replay-composition",
    description: "Cross-operation, cross-state and cross-generation replay after arbitrary intervening transitions (PHASE 9).",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [5, 3, 4],
    weights: REPLAY_HEAVY,
  },
  {
    name: "containment-composition",
    description: "Stored-vs-effective safe state, containment budget across window boundaries, and migration/retire/egress interaction (PHASE 8).",
    actors: [ALL_MATERIAL_ACTOR, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [5, 3, 4],
    weights: CONTAINMENT_HEAVY,
  },
  {
    name: "dead-verifier-escape",
    description:
      "The vault is BORN under a permanently reverting verifier. Spending is denied — a DECLARED, ACCEPTED liveness cut of 1 — and the property under test is that the guardian recovery ESCAPE remains usable after arbitrary prior transitions, not that spending works.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [6, 3, 3],
    weights: RECOVERY_HEAVY,
    verifier: "reverting",
  },
  {
    name: "byzantine-verifier",
    description:
      "The vault is born under an ALWAYS-TRUE verifier: the PQ conjunct is structurally satisfied by anyone. HYBRID must then collapse to ECDSA security — never to unauthenticated authorization — so guardian-gated outcomes must still require k.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [4, 4, 3, 2],
    weights: BROAD,
    verifier: "alwaysTrue",
  },
  {
    name: "ecdsa-only-floor",
    description:
      "A vault born with an ECDSA-ONLY floor — a configuration initialize permits. It is the ONLY way to reach a requirePq false -> true transition, because _requireNoDowngrade makes the reverse unrepresentable, and it is therefore the only profile that can exercise setVerifier's floor-satisfiability seam at all. Its credential is ONE root, so the declared cuts differ here and the model counts them accordingly.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [5, 3, 2, 2],
    weights: BROAD,
    ecdsaOnlyFloor: true,
  },
  {
    name: "quorum-without-credential",
    description:
      "An adversary holding TWO guardian principals — AT the guardian cut — but NO credential. It is the only model that can distinguish migration's declared k+1 from k, and the only one that can reach a quorum-gated outcome without the credential leg. Guardian-shape attacks (duplicate rosters, repeated seats, sentinel indices) are weighted heavily here.",
    actors: [ALL_MATERIAL_ACTOR, TWO_GUARDIAN_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [3, 5, 3, 1],
    weights: {
      ...BROAD,
      SET_GUARDIANS: 14,
      BIND_MIGRATION: 12,
      ENTER_CONTAINMENT: 12,
      INITIATE_RECOVERY: 12,
      ADVANCE_TIME: 14,
      SPEND: 6,
      FACTORY_DEPLOY_TWIN: 0,
    },
  },
  {
    name: "policy-plane-denial",
    description:
      "Heavy on SET_POLICY and SPEND. The policy plane is declared SUBTRACTIVE — it may refuse and can never grant — so a vault carrying the DENYING plane must not move value. This is the only profile that reliably installs that plane and then attempts to spend through it.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, STRANGER],
    actorWeights: [6, 3, 1],
    weights: {
      ...BROAD,
      SET_POLICY: 18,
      SPEND: 20,
      FUND: 6,
      ADVANCE_TIME: 8,
      SET_GUARDIANS: 2,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      EGRESS_NATIVE: 0,
      EGRESS_TOKEN: 0,
      FACTORY_DEPLOY_TWIN: 0,
    },
  },
  {
    name: "containment-duty-cycle",
    description:
      "ENTER_CONTAINMENT repeated with CONTAINMENT_MAX-sized time steps, so several containments land inside ONE budget window. I-CONTAINMENT-BUDGET says denial is a bounded duty cycle rather than a state; this profile is what puts that bound under pressure.",
    actors: [ALL_MATERIAL_ACTOR, TWO_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [6, 3, 1],
    weights: {
      ...BROAD,
      ENTER_CONTAINMENT: 26,
      ADVANCE_TIME: 26,
      SPEND: 6,
      SET_GUARDIANS: 2,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      FACTORY_DEPLOY_TWIN: 0,
    },
    timeBias: "duty-cycle",
  },
  {
    name: "recovery-vs-roster",
    description:
      "Matures recoveries (maturation timing, live proposed verifiers) WHILE changing the guardian roster, so the constituency in force can differ from the one that approved a pending request. recovery-maturation deliberately turns SET_GUARDIANS off to reach executeRecovery at all; this profile turns it back on, which is the only way to exercise R1's generation binding end-to-end.",
    actors: [ALL_MATERIAL_ACTOR, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [7, 2, 1],
    weights: {
      ...BROAD,
      INITIATE_RECOVERY: 14,
      EXECUTE_RECOVERY: 16,
      SET_GUARDIANS: 12,
      CANCEL_RECOVERY: 3,
      ADVANCE_TIME: 22,
      SPEND: 4,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      FACTORY_DEPLOY_TWIN: 0,
    },
    timeBias: "maturation",
    honestRecoveryBias: true,
  },
  {
    name: "stranger-only",
    description: "An adversary holding NOTHING. Every permissionless path and every replay, with no authority at all.",
    actors: [ALL_MATERIAL_ACTOR, STRANGER],
    actorWeights: [3, 7],
    weights: BROAD,
  },
  {
    /**
     * APPENDED, NOT SUBSTITUTED, and that is deliberate. Setting
     * `commitPqKeyOnEcdsaOnlyFloor` on the existing `ecdsa-only-floor` profile
     * would change its genesis, hence its CREATE2 salt (`genesisSalt` binds both
     * `g.floor` and `g.pqKeyHash`), hence every history and every kill seed it
     * carries. Appending leaves all fifteen existing profiles byte-identical and
     * costs only the new profile's own campaigns.
     */
    name: "ecdsa-only-committed",
    description:
      "A vault born with an ECDSA-only floor but a PQ key ALREADY COMMITTED — legal, since initialize refuses only requirePq WITH a zero commitment. Since I-DECLARATION-EXHIBITED this is the only class on which the requirePq false -> true DECLARATION can succeed, so it is the only profile that reaches the armed post-state at all; the sibling ecdsa-only-floor profile reaches only the refusal. It is also the class SD-4 was reproduced on, so the recovery interlock is exercised here and nowhere else.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [5, 3, 2, 2],
    /**
     * WEIGHTED SO THE REMEDY COMES FIRST. The declaration is ONE-SHOT — once
     * `requirePq` holds it can never be taken again — so a profile that arms in
     * its opening steps observes the edge exactly once, with no recovery live,
     * and can never reach the interlock seam at all. Recovery is therefore
     * weighted well above `SET_VERIFIER`, so a quorum-approved request is
     * usually pending by the time the first arming attempt is generated.
     */
    weights: {
      ...BROAD,
      SET_VERIFIER: 5,
      INITIATE_RECOVERY: 22,
      EXECUTE_RECOVERY: 6,
      CANCEL_RECOVERY: 3,
      SET_GUARDIANS: 2,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      FACTORY_DEPLOY_TWIN: 0,
      ADVANCE_TIME: 12,
      SPEND: 4,
    },
    ecdsaOnlyFloor: true,
    commitPqKeyOnEcdsaOnlyFloor: true,
  },
  {
    /**
     * APPENDED, never substituted. Every profile above keeps its exact action
     * stream, kill seeds and step indices, because this one adds no `prng` draw
     * and changes no existing profile's flags.
     */
    name: "commitment-forgery",
    description:
      "An ECDSA-only vault whose credential principal repeatedly attempts to install a PQ commitment it holds no preimage for — the SD-6 attack, generated. This is the ONLY profile on which G-COMMITMENT-ATTESTED's violating transition is ever ATTEMPTED, which is what separates 'the kernel refuses it' from 'no campaign ever tried'. A green campaign without this profile would be absent evidence.",
    actors: [ALL_MATERIAL_ACTOR, ECDSA_ONLY_ATTACKER, ONE_GUARDIAN_ATTACKER, STRANGER],
    actorWeights: [5, 4, 2, 1],
    weights: {
      ...BROAD,
      ROTATE_CREDENTIAL: 26,
      SET_VERIFIER: 8,
      INITIATE_RECOVERY: 8,
      EXECUTE_RECOVERY: 5,
      CANCEL_RECOVERY: 2,
      SET_GUARDIANS: 2,
      BIND_MIGRATION: 0,
      RETIRE: 0,
      FACTORY_DEPLOY_TWIN: 0,
      ADVANCE_TIME: 8,
      SPEND: 4,
    },
    ecdsaOnlyFloor: true,
    commitPqKeyOnEcdsaOnlyFloor: true,
    fabricateCommitments: true,
  },
];
