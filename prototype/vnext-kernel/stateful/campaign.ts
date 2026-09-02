/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE CAMPAIGN ENGINE: generate, execute, judge, shrink, and emit a replay
 * artifact.
 *
 * DETERMINISM IS THE WHOLE CONTRACT
 * ---------------------------------
 * A campaign is a pure function of (seed, profile). Nothing consults the clock,
 * `Math.random`, or the environment. A failure therefore comes back from the
 * seed alone, and CI never depends on a random draw — the required job runs a
 * FIXED seed set, and broader random exploration is a manual, non-gating script.
 *
 * OUTCOME DETECTION IS OBSERVATIONAL, NOT FUNCTION-KEYED
 * -----------------------------------------------------
 * A protected outcome is detected by DIFFING the kernel's own state across the
 * step, never by asking "which function did we just call?". That matters: if a
 * credential replacement were ever caused by some path nobody expected, a
 * function-keyed check would look right past it, while a state diff cannot.
 *
 * ATTRIBUTION IS TO THE AUTHORISING ROOTS
 * ---------------------------------------
 * `executeRecovery`, `egress` and `retire` are PERMISSIONLESS BY DESIGN and
 * carry no discretion. Charging their effects to whoever paid the gas would
 * manufacture violations on correct code. They are charged instead to the roots
 * that authorised the pre-committed decision — the quorum that initiated the
 * recovery episode, or the quorum-plus-credential that bound the migration.
 */
import { ethers } from "../test/connection.js";
import { networkHelpers } from "../test/connection.js";
import { makePrng, type Prng } from "./prng.js";
import {
  DECLARED_CUTS,
  DOCUMENTED,
  freshAbstractState,
  judgeCut,
  type Outcome,
} from "./model.js";
import { KNOWN_DEFECT_PROPERTIES, explains } from "./defects.js";
import {
  ACTION_KINDS,
  QUORUM_SHAPES,
  executeAction,
  rootsNow,
  type ActionKind,
  type Ctx,
  type GeneratedAction,
} from "./actions.js";
import {
  checkGlobals,
  checkRecoveryCommitment,
  digestSnapshot,
  snapshot,
  type InvariantViolation,
  type KernelSnapshot,
} from "./invariants.js";
import {
  ALL_MATERIAL_ACTOR,
  PROFILES,
  type CampaignProfile,
} from "./profiles.js";
import { addrOf, deployWorld, makeActor, materialiseActor, type Actor, type World } from "./world.js";
import { SAFE_STATE } from "./invariants.js";

const SAFE_STATE_NAMES = ["NORMAL", "CONTAINED", "RECOVERY_ONLY", "MIGRATION_ONLY", "RETIRED"];

// =====================================================================
// Outcome detection — by STATE DIFF, never by which function was called
// =====================================================================

export function detectOutcomes(pre: KernelSnapshot, post: KernelSnapshot): Outcome[] {
  const out: Outcome[] = [];
  if (post.nativeBalance < pre.nativeBalance || post.tokenBalance < pre.tokenBalance) {
    out.push("ASSET_MOVEMENT");
  }
  if (post.ecdsaSigner !== pre.ecdsaSigner || post.pqPublicKeyHash !== pre.pqPublicKeyHash) {
    out.push("CREDENTIAL_REPLACEMENT");
  }
  if (post.pqVerifier !== pre.pqVerifier) out.push("VERIFIER_REPLACEMENT");
  if (post.policyEngine !== pre.policyEngine) out.push("POLICY_CHANGE");
  if (post.guardianCommitment !== pre.guardianCommitment) out.push("GUARDIAN_TRANSITION");
  if (!pre.migration.bound && post.migration.bound) out.push("MIGRATION_BINDING");
  if (pre.safeStateStored !== SAFE_STATE.CONTAINED && post.safeStateStored === SAFE_STATE.CONTAINED) {
    out.push("CONTAINMENT");
  }
  return out;
}

// =====================================================================
// Failure artifact — everything needed to replay a failure exactly
// =====================================================================

export interface StepRecord {
  step: number;
  kind: ActionKind;
  caller: string;
  callerRootsHeld: string[];
  params: Record<string, string | number | boolean>;
  ok: boolean;
  revert: string | null;
  outcomesObserved: Outcome[];
  preDigest: string;
  postDigest: string;
  preState: string;
  postState: string;
}

export interface PropertyViolation {
  property: string;
  detail: string;
  step: number;
}

export interface CampaignResult {
  profile: string;
  seed: number;
  depth: number;
  steps: StepRecord[];
  /** Violations that are NOT explained by a listed sustained defect. Must be empty. */
  violations: PropertyViolation[];
  /** Violations explained by `defects.ts`. Recorded, not suppressed — see that file. */
  knownDefectHits: (PropertyViolation & { defect: string })[];
  transitionsExercised: number;
  successfulTransitions: number;
  outcomeCounts: Record<string, number>;
  revertCounts: Record<string, number>;
  actionCoverage: Record<string, number>;
  positiveControlsPassed: number;
  positiveControlsAttempted: number;
  minimalSequence: GeneratedAction[] | null;
}

// =====================================================================
// Plan generation — a pure function of the seed
// =====================================================================

/**
 * ADVANCE_TIME durations. The DEFAULT set straddles every timing constant the
 * kernel has. The MATURATION set is biased into the executable window of a
 * pending recovery — [RECOVERY_DELAY, RECOVERY_DELAY + RECOVERY_EXPIRY] — because
 * the default mix hits that band so rarely that executeRecovery NEVER SUCCEEDED
 * across 145 campaigns. The anti-vacuity assertion caught it; this is the fix.
 * It biases the DISTRIBUTION, it does not pre-filter any sequence: every profile
 * still generates roster changes, cancellations and expiries that kill a pending
 * recovery, and the adversarial profiles still use the default spread.
 */
const TIME_DEFAULT = [3600, 86400, 3 * 86400, 7 * 86400 + 1, 15 * 86400, 22 * 86400, 31 * 86400];
const TIME_MATURATION = [7 * 86400 + 1, 7 * 86400 + 1, 8 * 86400, 10 * 86400, 3600, 15 * 86400, 22 * 86400, 31 * 86400];
/** CONTAINMENT_MAX-dominant, so repeated containments land inside ONE budget window. */
const TIME_DUTY_CYCLE = [3 * 86400, 3 * 86400, 3 * 86400 + 1, 86400, 7 * 86400 + 1, 31 * 86400];

function genParams(
  kind: ActionKind,
  prng: Prng,
  profile: CampaignProfile,
): Record<string, string | number | boolean> {
  const timeBias = profile.timeBias ?? "default";
  /**
   * A profile that must DRIVE RECOVERY THROUGH TO EXECUTION cannot also spend
   * its budget proposing verifiers that refuse the incoming possession proof, or
   * poisoning the floor lengths the same proof is measured against. Those are
   * real, deliberately-generated adversarial behaviours — they stay ON in every
   * other profile — but a profile whose job is to reach the seam must be able to
   * reach it. Distribution, not filtering.
   */
  const cleanRecovery = profile.honestRecoveryBias === true;
  switch (kind) {
    case "FUND":
      return { eth: prng.pick(["0.5", "1", "2"]) };
    case "ADVANCE_TIME":
      return {
        seconds: prng.pick(
          timeBias === "maturation" ? TIME_MATURATION : timeBias === "duty-cycle" ? TIME_DUTY_CYCLE : TIME_DEFAULT,
        ),
      };
    case "SPEND":
      return { eth: prng.pick(["0.5", "1", "2"]), toSelf: prng.chance(0.1) };
    case "ROTATE_CREDENTIAL":
      return { target: prng.int(3), popStale: prng.chance(0.25) };
    case "SET_VERIFIER":
      return {
        verifier: prng.pick(["honest", "alwaysTrue", "alwaysFalse", "reverting"]),
        bumpLevel: prng.chance(0.3),
        // `shrinkLengths` changes the two floor LENGTHS, which _requireNoDowngrade
        // does not compare; `raisePq` turns the conjunct ON, which initialize
        // guards against a zero key commitment and setVerifier does not. Both are
        // reachable transitions and both are generated deliberately.
        shrinkLengths: !cleanRecovery && prng.chance(0.25),
        raisePq: prng.chance(0.35),
      };
    case "SET_POLICY":
      return { policy: prng.pick(["none", "allow", "deny", "stateful", "codeless"]) };
    case "SET_GUARDIANS":
      return {
        quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]),
        newThreshold: prng.pick([1, 2, 3]),
        rosterGen: prng.between(1, 3),
        // A roster in which one PRINCIPAL holds two seats. Unrepresentable on the
        // real kernel; the point is to notice if it ever stops being so.
        duplicateRoster: prng.chance(0.2),
      };
    case "INITIATE_RECOVERY":
      return {
        quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]),
        target: prng.int(3),
        // A recovery whose PROPOSED verifier refuses the incoming possession proof
        // can never execute. That is correct kernel behaviour and worth generating,
        // but a profile whose job is to reach executeRecovery proposes a live one.
        verifier: cleanRecovery
          ? "honest"
          : prng.weighted(["honest", "alwaysTrue", "alwaysFalse", "reverting"], [5, 2, 1, 1]),
      };
    case "EXECUTE_RECOVERY":
      // popStale proves possession of the OUTGOING factors instead of the incoming
      // ones — property R4. It MUST fail, so a profile that also has to observe a
      // SUCCESSFUL recovery generates it less often.
      return { popStale: prng.chance(cleanRecovery ? 0.1 : 0.3) };
    case "ENTER_CONTAINMENT":
    case "BIND_MIGRATION":
      return { quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]) };
    case "REPLAY_PAST_CALL":
      return { index: prng.int(64) };
    default:
      return {};
  }
}

export function generatePlan(profile: CampaignProfile, seed: number, depth: number): GeneratedAction[] {
  const prng = makePrng(seed);
  const kinds = ACTION_KINDS.filter((k) => (profile.weights[k] ?? 0) > 0);
  const weights = kinds.map((k) => profile.weights[k]!);
  const plan: GeneratedAction[] = [];
  for (let i = 0; i < depth; i++) {
    const kind = prng.weighted(kinds, weights);
    const actorName = prng.weighted(
      profile.actors.map((a) => a.name),
      profile.actorWeights,
    );
    plan.push({ kind, actorName, params: genParams(kind, prng, profile) });
  }
  return plan;
}

// =====================================================================
// Execution
// =====================================================================

/**
 * `deployWorld` sorts the roster into ASCENDING ADDRESS ORDER, which is the
 * kernel's distinctness rule. That sort scrambles the derivation order, so the
 * label behind each SEAT must be recovered by matching addresses rather than
 * assumed — getting this wrong would silently mis-attribute guardian roots and
 * quietly weaken every guardian property in the campaign.
 */
function seatLabels(world: World): string[] {
  return world.gKeys.map((k) => {
    for (let i = 0; i < 3; i++) {
      const label = world.opts.label + "-guardian-" + i;
      if (addrOf(new ethers.SigningKey(ethers.id(label))) === addrOf(k)) return label;
    }
    throw new Error("harness bug: a roster seat has no known key label");
  });
}

function freshCtx(world: World): Ctx {
  return {
    world,
    abstract: freshAbstractState(world.opts.label + "-cred"),
    credKey: world.credKey,
    credLabel: world.opts.label + "-cred",
    pqKey: world.pqKey,
    pqLabel: world.opts.label + "-pq",
    guardianKeys: world.gKeys.slice(),
    guardianLabels: seatLabels(world),
    guardianIsContract: world.guardianIsContract.slice(),
    threshold: world.threshold,
    verifierKind: world.opts.verifier,
    requirePqNow: !world.opts.ecdsaOnlyFloor,
    policyKind: "none",
    history: [],
    step: 0,
  };
}

async function runPlan(
  world: World,
  plan: GeneratedAction[],
  profile: CampaignProfile,
  seed: number,
  collectSteps: boolean,
): Promise<{ steps: StepRecord[]; violations: PropertyViolation[]; stats: Omit<CampaignResult, "profile" | "seed" | "depth" | "steps" | "violations" | "minimalSequence"> }> {
  // A SECOND stream, derived from but distinct from the plan's, so adversarial
  // choices made during execution (which seat a duplicate-index proof reuses)
  // do not perturb the plan itself. Both are seeded, so both replay.
  const prng = makePrng(seed ^ 0x5f3759df);
  const ctx = freshCtx(world);

  // ROLES -> the concrete key labels of THIS world. Skipping this is what made
  // every attacker inert; see the note on materialiseActor.
  const byName = new Map<string, Actor>(
    profile.actors.map((a) => [a.name, materialiseActor(a, world.opts.label)]),
  );
  const steps: StepRecord[] = [];
  const violations: PropertyViolation[] = [];
  const outcomeCounts: Record<string, number> = {};
  const revertCounts: Record<string, number> = {};
  const actionCoverage: Record<string, number> = {};

  let prev: KernelSnapshot | null = null;
  let successful = 0;
  /**
   * The previous step's POST-state is this step's PRE-state: nothing happens
   * between them. Carrying it forward halves the number of full state reads,
   * which is the dominant cost of a long campaign — a deep tier was taking
   * minutes purely on redundant RPC round trips.
   */
  let carried: KernelSnapshot | null = null;

  for (let i = 0; i < plan.length; i++) {
    const action = plan[i]!;
    const actor = byName.get(action.actorName) ?? materialiseActor(ALL_MATERIAL_ACTOR, world.opts.label);
    ctx.step = i;
    actionCoverage[action.kind] = (actionCoverage[action.kind] ?? 0) + 1;

    const pre = carried ?? (await snapshot(world));
    const heldBefore = rootsNow(actor, ctx);
    const res = await executeAction(action, actor, ctx, prng);
    const post = await snapshot(world);
    carried = post;

    if (res.ok) successful++;
    if (res.revert) revertCounts[res.revert] = (revertCounts[res.revert] ?? 0) + 1;

    const observed = detectOutcomes(pre, post);
    for (const o of observed) outcomeCounts[o] = (outcomeCounts[o] ?? 0) + 1;

    // ---- P-CUT: the central authority property (I-A .. I-F) ----------
    //
    // The cut is recomputed from the LIVE floor: `min(2, k)` is a formula, and
    // on a vault whose credential family has one factor it evaluates to 1. The
    // cut is taken from the state BEFORE the action, because that is the
    // authority the action had to clear.
    const credentialFactors = pre.floor.requirePq ? 2 : 1;
    const k = Number(pre.guardianThreshold);
    for (const outcome of observed) {
      const charged = res.attributedRoots;
      const j = judgeCut(charged, outcome, credentialFactors, k);
      if (!j.entitled) {
        violations.push({
          property: "P-CUT/" + outcome,
          step: i,
          detail:
            outcome +
            " occurred with roots {" +
            ([...charged].sort().join(",") || "NONE") +
            "} = credential:" + j.held.credential + " guardians:" + j.held.guardians +
            ", which satisfies NO authority path. Required: " + j.requirement +
            " (" + DOCUMENTED[outcome] + "; live k=" + k + ", credential factors=" + credentialFactors + ")" +
            ". Issued by " + actor.name + " via " + action.kind,
        });
      }
    }

    // ---- P-INCOMING-POSSESSION (R4) ---------------------------------
    //
    // The harness KNOWS when it deliberately signed the possession proofs with
    // the OUTGOING factors instead of the incoming ones. Such a call must never
    // succeed: I-INCOMING-CREDENTIAL-POSSESSION exists precisely so an approved
    // credential cannot be installed by someone who does not hold it. This is a
    // model-side judgement — it reads the harness's own record of what it signed,
    // not the kernel's opinion of it.
    if (res.ok && res.usedStalePossession === true) {
      violations.push({
        property: "P-INCOMING-POSSESSION",
        step: i,
        detail:
          action.kind +
          " SUCCEEDED while proving possession of the OUTGOING credential instead of the INCOMING one. " +
          "A credential can therefore be installed by a party that does not hold it (R4).",
      });
    }

    // ---- P-PLANE-SUBTRACTIVE: a plane that DENIES must actually deny -------
    //
    // The policy plane is declared SUBTRACTIVE: it may refuse and can never
    // grant. The harness knows which plane it installed, so it can hold the
    // kernel to that declaration without re-implementing the call: if the
    // installed plane is the DENYING one, no spend may move value.
    if (
      ctx.policyKind === "deny" &&
      action.kind === "SPEND" &&
      observed.includes("ASSET_MOVEMENT") &&
      post.nativeBalance < pre.nativeBalance
    ) {
      violations.push({
        property: "P-PLANE-SUBTRACTIVE",
        step: i,
        detail:
          "a SPEND moved value while the installed policy plane denies every admission — " +
          "the plane's refusal was not honoured, so admission is not a precondition of asset movement",
      });
    }

    // ---- P-MODEL: judgements the abstract model made on its own -------
    if (res.modelViolation) {
      violations.push({ property: "P-MODEL", step: i, detail: res.modelViolation });
    }

    // ---- P-ATOMICITY: a REVERTED action must change NOTHING ----------
    if (!res.ok && action.kind !== "ADVANCE_TIME" && action.kind !== "FUND") {
      const preD = digestSnapshot({ ...pre, blockTimestamp: 0n, nativeBalance: 0n, tokenBalance: 0n });
      const postD = digestSnapshot({ ...post, blockTimestamp: 0n, nativeBalance: 0n, tokenBalance: 0n });
      if (preD !== postD) {
        violations.push({
          property: "P-ATOMICITY",
          step: i,
          detail:
            action.kind +
            " REVERTED (" +
            res.revert +
            ") yet kernel state changed — a half-transition. Reverts must be total.",
        });
      }
    }

    // ---- G-*: global structural invariants, every step ----------------
    for (const v of checkGlobals(post, prev, world)) {
      violations.push({ property: v.name, step: i, detail: v.detail });
    }
    for (const v of await checkRecoveryCommitment(world, post)) {
      violations.push({ property: v.name, step: i, detail: v.detail });
    }

    if (collectSteps) {
      steps.push({
        step: i,
        kind: action.kind,
        caller: actor.name,
        callerRootsHeld: [...heldBefore].sort(),
        params: action.params,
        ok: res.ok,
        revert: res.revert,
        outcomesObserved: observed,
        preDigest: digestSnapshot(pre),
        postDigest: digestSnapshot(post),
        preState: SAFE_STATE_NAMES[pre.safeStateEffective] ?? "?",
        postState: SAFE_STATE_NAMES[post.safeStateEffective] ?? "?",
      });
    }
    prev = post;
  }

  return {
    steps,
    violations,
    stats: {
      transitionsExercised: plan.length,
      successfulTransitions: successful,
      outcomeCounts,
      revertCounts,
      actionCoverage,
      positiveControlsPassed: 0,
      positiveControlsAttempted: 0,
    },
  };
}

// =====================================================================
// Shrinking — delta-debug over the recorded action list
// =====================================================================

/**
 * Removes one action at a time, re-running from a restored EVM snapshot, and
 * keeps every removal that still reproduces a violation of the SAME property.
 *
 * Restoring the snapshot rather than redeploying is deliberate: a redeployed
 * world would derive DIFFERENT addresses, and because the guardian roster is
 * canonicalised by ADDRESS ORDER, a different address set is a different
 * fixture. A minimised sequence that only fails in a different fixture is not a
 * minimisation, it is a second bug report.
 */
async function shrink(
  world: World,
  plan: GeneratedAction[],
  profile: CampaignProfile,
  seed: number,
  targetProperty: string,
  firstViolationStep: number,
  restore: () => Promise<void>,
  maxAttempts = 120,
): Promise<GeneratedAction[]> {
  let attempts = 0;
  const reproduces = async (candidate: GeneratedAction[]): Promise<boolean> => {
    attempts++;
    await restore();
    const { violations } = await runPlan(world, candidate, profile, seed, false);
    return violations.some((v) => v.property === targetProperty);
  };

  // STEP 1 — TRUNCATE. Everything after the first violation is, by definition,
  // not needed to cause it. On a 150-action plan that failed at step 20 this is
  // worth more than every later removal combined, and it costs ONE run.
  let best = plan.slice();
  const truncated = plan.slice(0, Math.min(plan.length, firstViolationStep + 1));
  if (truncated.length < best.length && (await reproduces(truncated))) best = truncated;

  // STEP 2 — remove single actions, restarting the scan after each success.
  let improved = true;
  while (improved && attempts < maxAttempts) {
    improved = false;
    for (let i = 0; i < best.length && attempts < maxAttempts; i++) {
      const candidate = best.slice(0, i).concat(best.slice(i + 1));
      if (await reproduces(candidate)) {
        best = candidate;
        improved = true;
        break;
      }
    }
  }
  return best;
}

// =====================================================================
// Positive controls — the vacuity guard
// =====================================================================

/**
 * Without this, a campaign in which EVERY action reverts passes every safety
 * property while proving nothing at all — the exact vacuity failure the
 * prototype's own suite header calls out. So each campaign additionally runs a
 * short, fully-honest, fully-authorised sequence on a RESTORED fixture and
 * requires it to actually move value and actually rotate a credential.
 */
export async function runPositiveControls(
  world: World,
  restore: () => Promise<void>,
  profile: CampaignProfile,
): Promise<{ attempted: number; passed: number; failures: string[]; skipped: string[] }> {
  const failures: string[] = [];
  const skipped: string[] = [];
  let attempted = 0;
  let passed = 0;

  const honestProfile: CampaignProfile = {
    name: "positive-control",
    description: "fully-honest, fully-authorised actions that MUST succeed",
    actors: [ALL_MATERIAL_ACTOR],
    actorWeights: [1],
    weights: {},
  };

  /**
   * A profile whose vault is BORN under a dead or lying verifier is DELIBERATELY
   * spend-denied — that is the declared, accepted liveness cut of 1, not a
   * broken fixture. Demanding a successful spend there would raise a vacuity
   * alarm on correct behaviour. Those profiles are instead held to the control
   * that actually matters for them: the guardian ESCAPE still works.
   */
  const credentialPathDead = world.opts.verifier === "reverting" || world.opts.verifier === "alwaysFalse";

  const controls: { name: string; plan: GeneratedAction[]; expect: Outcome; needsLiveVerifier: boolean }[] = [
    {
      name: "honest spend moves value",
      plan: [{ kind: "SPEND", actorName: ALL_MATERIAL_ACTOR.name, params: { eth: "1" } }],
      expect: "ASSET_MOVEMENT",
      needsLiveVerifier: true,
    },
    {
      name: "honest rotation replaces the credential",
      plan: [{ kind: "ROTATE_CREDENTIAL", actorName: ALL_MATERIAL_ACTOR.name, params: { target: 0 } }],
      expect: "CREDENTIAL_REPLACEMENT",
      needsLiveVerifier: true,
    },
    {
      name: "honest quorum enters containment",
      plan: [{ kind: "ENTER_CONTAINMENT", actorName: ALL_MATERIAL_ACTOR.name, params: { quorumShape: "honest" } }],
      expect: "CONTAINMENT",
      needsLiveVerifier: false,
    },
    {
      // R6 AND the dead-verifier escape in one control: recovery must not merely
      // update storage, it must leave authority USABLE, proven by a real balance
      // change under the NEW credential and the REPLACEMENT verifier.
      name: "honest quorum recovers end-to-end and the NEW credential can spend (R6 / verifier escape)",
      plan: [
        { kind: "INITIATE_RECOVERY", actorName: ALL_MATERIAL_ACTOR.name, params: { quorumShape: "honest", target: 1, verifier: "honest" } },
        { kind: "ADVANCE_TIME", actorName: ALL_MATERIAL_ACTOR.name, params: { seconds: 7 * 86400 + 1 } },
        { kind: "EXECUTE_RECOVERY", actorName: ALL_MATERIAL_ACTOR.name, params: {} },
        { kind: "SPEND", actorName: ALL_MATERIAL_ACTOR.name, params: { eth: "1" } },
      ],
      expect: "ASSET_MOVEMENT",
      needsLiveVerifier: false,
    },
    {
      name: "honest quorum plus credential binds a migration",
      plan: [{ kind: "BIND_MIGRATION", actorName: ALL_MATERIAL_ACTOR.name, params: { quorumShape: "honest" } }],
      expect: "MIGRATION_BINDING",
      needsLiveVerifier: true,
    },
  ];

  for (const c of controls) {
    if (c.needsLiveVerifier && credentialPathDead) {
      skipped.push(c.name + " — profile " + profile.name + " deliberately starts with a " + world.opts.verifier + " verifier");
      continue;
    }
    attempted++;
    await restore();
    const { steps } = await runPlan(world, c.plan, honestProfile, 1, true);
    const sawOutcome = steps.some((s) => s.outcomesObserved.includes(c.expect));
    if (sawOutcome) passed++;
    else {
      const trail = steps.map((s) => s.kind + (s.ok ? " ok" : " REVERT:" + s.revert)).join(" | ");
      failures.push(c.name + " — expected " + c.expect + ", trail: " + trail);
    }
  }
  return { attempted, passed, failures, skipped };
}

// =====================================================================
// Entry point
// =====================================================================

export interface CampaignOptions {
  /**
   * A mutated kernel to run the campaign against INSTEAD of the real one. Used
   * only by the mutation-adequacy suite. When present, positive controls are
   * skipped: a deliberately weakened kernel is not required to behave, and a
   * failed control there would say nothing about the real kernel's fixture.
   */
  implOverride?: { abi: unknown[]; bytecode: string };
}

export async function runCampaign(
  profileName: string,
  seed: number,
  depth: number,
  label: string,
  options: CampaignOptions = {},
): Promise<CampaignResult> {
  const profile = PROFILES.find((p) => p.name === profileName);
  if (!profile) throw new Error("unknown campaign profile " + profileName);

  const world = await deployWorld({
    label,
    verifier: profile.verifier ?? "honest",
    ecdsaOnlyFloor: profile.ecdsaOnlyFloor ?? false,
    implOverride: options.implOverride,
  });
  const snap = await networkHelpers.takeSnapshot();
  const restore = async (): Promise<void> => {
    await snap.restore();
  };

  const plan = generatePlan(profile, seed, depth);
  const { steps, violations, stats } = await runPlan(world, plan, profile, seed, true);

  let minimal: GeneratedAction[] | null = null;
  if (violations.length > 0) {
    minimal = await shrink(
      world,
      plan,
      profile,
      seed,
      violations[0]!.property,
      violations[0]!.step,
      restore,
    );
  }

  const controls = options.implOverride
    ? { attempted: 0, passed: 0, failures: [] as string[], skipped: [] as string[] }
    : await runPositiveControls(world, restore, profile);
  for (const f of controls.failures) {
    violations.push({
      property: "P-VACUITY",
      step: -1,
      detail:
        "POSITIVE CONTROL FAILED — the fixture cannot perform an authorised action, so every safety " +
        "result in this campaign is vacuous: " +
        f,
    });
  }

  // THE SUSTAINED-DEFECT LEDGER, applied here and NOWHERE else.
  //
  // A violation whose property is explained by a listed, reproduced defect is
  // moved out of `violations` and into `knownDefectHits`. That is not a
  // suppression: StatefulSustainedDefects.test.ts independently requires every
  // listed defect to STILL REPRODUCE, so a fix cannot land silently — it makes
  // that suite fail and forces the ledger and AUTHORITY.md to move together.
  const real = violations.filter((v) => !KNOWN_DEFECT_PROPERTIES.has(v.property));
  const known = violations
    .filter((v) => KNOWN_DEFECT_PROPERTIES.has(v.property))
    .map((v) => ({ ...v, defect: explains(v.property)?.id ?? "unknown" }));

  return {
    profile: profileName,
    seed,
    depth,
    steps,
    violations: real,
    knownDefectHits: known,
    ...stats,
    positiveControlsAttempted: controls.attempted,
    positiveControlsPassed: controls.passed,
    minimalSequence: minimal,
  };
}

/** The deterministic replay artifact for a failure. */
export function replayArtifact(r: CampaignResult, head: string, tree: string): Record<string, unknown> {
  return {
    schema: "vnext-kernel-stateful-replay.v1",
    head,
    tree,
    compiler: { solcVersion: "0.8.24", evmVersion: "cancun", optimizer: { enabled: true, runs: 200 } },
    profile: r.profile,
    seed: r.seed,
    depth: r.depth,
    reproduce:
      "npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test " +
      "prototype/vnext-kernel/test/StatefulAuthorityFuzz.test.ts  " +
      "(seed " + r.seed + ", profile " + r.profile + ", depth " + r.depth + ")",
    violations: r.violations,
    minimalSequence: r.minimalSequence,
    steps: r.steps,
  };
}

export { makeActor };
