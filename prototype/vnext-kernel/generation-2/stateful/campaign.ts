/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE GENERATION-2 CAMPAIGN ENGINE: generate, execute, judge. A campaign's decisions are a function of
 * (profile, seed, depth, label): nothing here consults the clock, Math.random or the environment, so a
 * failure replays from the seed printed beside it. The chain's own clock follows the wall between time
 * advances, and every advance is at least an hour, so only a stall of that order could change a decision,
 * and that fails loudly against the committed record rather than passing falsely. It keeps Generation 1's judgement unchanged: one asymmetric
 * implication, in the safety direction only. IF a protected outcome occurred THEN the roots that
 * authorised it must satisfy a declared path in full. Outcomes come from STATE DIFF, never from which
 * function was called. It deliberately omits Generation 1's delta-debug shrink: a violation here
 * replays from its seed, and a shrink is a debugging aid rather than evidence.
 *
 * THE TWO LIVENESS PROPERTIES ARE TERMINAL, NOT PER-STEP. A refusal mid-history is never judged, because
 * judging one would copy the kernel's preconditions into the oracle. What IS judged is the end of the
 * history: with the token behaving again, can the money still leave? That needs no model of why any
 * particular step was refused.
 */
import { ethers, networkHelpers } from "../../test/connection.js";
import { makePrng, type Prng } from "../../stateful/prng.js";
import { DOCUMENTED, freshAbstractState, judgeCut, type Outcome } from "../../stateful/model.js";
import { KNOWN_DEFECT_PROPERTIES, explains } from "../../stateful/defects.js";
import { QUORUM_SHAPES, rootsNow, type Ctx } from "../../stateful/actions.js";
import { LIFECYCLE_SEAMS, detectOutcomes, type LifecycleSeam } from "../../stateful/campaign.js";
import { checkGlobals, type KernelSnapshot } from "../../stateful/invariants.js";
import { addrOf, materialiseActor, type Actor, type Root, type World } from "../../stateful/world.js";
import type { CompiledUnit } from "../../erc20-spend-plane/compile.js";
import { GENERATION_2 } from "../compile.js";
import { ZERO, deployGen2World, packedArgs, zoo, type Gen2World } from "../world.js";
import {
  ACTION_KINDS_G2,
  ASSET_EXTERNAL_ACTIONS,
  executeActionG2,
  syncModelFromChain,
  type ActionKindG2,
  type ExecOutcomeG2,
  type G2Ctx,
  type GeneratedActionG2,
  type HookKind,
} from "./actions.js";
import {
  LYING_TO_THE_SENDER,
  RECIPIENT_LEG_ONLY,
  checkRecoveryCommitmentG2,
  kernelDigest,
  snapshotG2,
  type SnapshotG2,
} from "./invariants.js";
import { ALL_MATERIAL_ACTOR, G2_PROFILES, type CampaignProfileG2 } from "./profiles.js";

export { LIFECYCLE_SEAMS };

/** The same fixed seeds and depths as Generation 1's required matrix: the candidate gets no easier test. */
export const CI_SEEDS_G2 = {
  shallow: [1, 2, 3, 5, 8, 13, 21, 34],
  medium: [101, 211, 331, 457],
  deep: [90210, 133742],
} as const;
export const DEPTHS_G2 = { shallow: 25, medium: 65, deep: 150 } as const;
export const MUTATION_SEEDS_G2 = [11, 29, 47, 83, 131, 197, 251, 307] as const;
export const MUTATION_DEPTH_G2 = 90;

const BIND_DELAY_ORACLE = 7n * 86400n;

/** Token behaviours whose egress would report a movement that did not happen. */
const FALSE_SETTLEMENT_MODES: ReadonlySet<string> = new Set([
  "RETURN_TRUE_NO_MOVE",
  "RETURN_FALSE_NO_MOVE",
  "QUERY_REVERTS_AFTER_TRANSFER",
  "QUERY_SHORT_AFTER_TRANSFER",
]);

/** The hooks that carry a signature. The others, a nonce read, an egress and a retire, are anyone's to make. */
const SIGNED_HOOKS: ReadonlySet<HookKind> = new Set<HookKind>([
  "replaySpend",
  "secondValidSpend",
  "contain",
  "bindMigration",
]);

/** Nonce-bearing calls: once one has succeeded, the same bytes can never succeed again. */
const NONCE_BEARING: ReadonlySet<string> = new Set([
  "SPEND",
  "ROTATE_CREDENTIAL",
  "SET_VERIFIER",
  "SET_POLICY",
  "SET_GUARDIANS",
  "INITIATE_RECOVERY",
  "CANCEL_RECOVERY",
  "CANCEL_RECOVERY_BY_QUORUM",
  "ENTER_CONTAINMENT",
  "BIND_MIGRATION",
]);

/** Reachability evidence, never a judgement. The suite requires every one non-zero across the matrix. */
export const G2_SEAMS = [
  "relayedSpendSettled",
  "unauthorizedSpendRefused",
  "directTransferObserved",
  "repeatedDirectTransfer",
  "spendAfterDirectTransfer",
  "drainSettled",
  "failedTransferRefused",
  "lyingResultRefused",
  "shortPayRefused",
  "senderFeeRefused",
  "rebaseDustRefused",
  "queryFailureRefused",
  "assetBoundaryObserved",
  "crossAssetReplayRefused",
  "migrationBound",
  "migrationEgressMoved",
  "egressTooEarlyRefused",
  "egressRefusedByFreeze",
  "egressFalseSettlementRefused",
  "wrongHashBindingRefused",
  "selfBindingRefused",
  "nativeBounceRefused",
  "nativeRefusedByDestination",
  "hostileHoldingVetoedNothing",
  "recoveryThenSpend",
  "containmentThenSpendRefused",
  "containmentExpiredThenSpend",
  "verifierTransitionThenSpend",
  "policyDenialThenSpendRefused",
  "replayedSpendRefused",
  "replayedMigrationRefused",
  "replayedEgressNoDiscretion",
  "hookFiredDuringTransfer",
  "hookNonceRead",
  "hookReplayRefused",
  "nestedSpendRefusedByExactDelta",
  "relayTamperRefused",
  "inadmissibleVerifierRefused",
  "refusalMined",
  "digestMovedOnSuccess",
  "exitControlExercised",
  "balanceControlExercised",
] as const;
export type G2Seam = (typeof G2_SEAMS)[number];

export interface PropertyViolationG2 {
  property: string;
  detail: string;
  step: number;
}

export interface StepRecordG2 {
  step: number;
  kind: ActionKindG2;
  caller: string;
  ok: boolean;
  revert: string | null;
  outcomes: Outcome[];
}

export interface CampaignResultG2 {
  profile: string;
  seed: number;
  depth: number;
  violations: PropertyViolationG2[];
  knownDefectHits: (PropertyViolationG2 & { defect: string })[];
  transitionsExercised: number;
  successfulTransitions: number;
  outcomeCounts: Record<string, number>;
  revertCounts: Record<string, number>;
  actionCoverage: Record<string, number>;
  actionsThatSucceeded: string[];
  seams: Record<string, number>;
  lifecycle: Record<string, number>;
  positiveControlsAttempted: number;
  positiveControlsPassed: number;
  controlFailures: string[];
  controlsPassedLabels: string[];
  steps: StepRecordG2[];
}

const TIME_DEFAULT = [3600, 86400, 3 * 86400, 7 * 86400 + 1, 15 * 86400, 22 * 86400, 31 * 86400];
const TIME_MATURATION = [7 * 86400 + 1, 7 * 86400 + 1, 8 * 86400, 10 * 86400, 3600, 15 * 86400, 22 * 86400, 31 * 86400];
const TIME_DUTY_CYCLE = [3 * 86400, 3 * 86400, 3 * 86400 + 1, 86400, 7 * 86400 + 1, 31 * 86400];
const TIME_STRADDLE = [3 * 86400, 3 * 86400, 6 * 86400, 12 * 86400, 21 * 86400, 24 * 86400, 27 * 86400];

function genParams(
  kind: ActionKindG2,
  prng: Prng,
  profile: CampaignProfileG2,
): Record<string, string | number | boolean> {
  const timeBias = profile.timeBias ?? "default";
  const cleanRecovery = profile.honestRecoveryBias === true;
  switch (kind) {
    case "FUND":
      return { eth: prng.pick(["0.5", "1", "2"]) };
    case "ADVANCE_TIME":
      return {
        seconds: prng.pick(
          timeBias === "maturation"
            ? TIME_MATURATION
            : timeBias === "duty-cycle"
              ? TIME_DUTY_CYCLE
              : timeBias === "straddle"
                ? TIME_STRADDLE
                : TIME_DEFAULT,
        ),
      };
    case "SPEND":
      return {
        units: prng.pick([0, 1, 5, 25, 100]),
        drain: prng.chance(0.12),
        toSelf: prng.chance(0.05),
        appendToken: prng.chance(0.15),
        relay: prng.chance(0.3),
      };
    case "ROTATE_CREDENTIAL":
      return { target: prng.int(3), popStale: prng.chance(0.25) };
    case "SET_VERIFIER":
      return {
        verifier: prng.pick(["honest", "honestB", "alwaysTrue", "alwaysFalse", "reverting"]),
        bumpLevel: prng.chance(0.3),
        raisePq: prng.chance(0.35),
      };
    case "SET_POLICY":
      return { policy: prng.pick(["none", "allow", "deny", "stateful", "codeless"]) };
    case "SET_GUARDIANS":
      return {
        quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]),
        newThreshold: prng.pick([1, 2, 3]),
        rosterGen: prng.between(1, 3),
        duplicateRoster: prng.chance(0.2),
      };
    case "INITIATE_RECOVERY":
      return {
        quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]),
        target: prng.int(3),
        verifier: cleanRecovery
          ? prng.pick(["honest", "honestB"])
          : prng.weighted(["honest", "honestB", "alwaysTrue", "alwaysFalse", "reverting"], [4, 2, 2, 1, 1]),
      };
    case "EXECUTE_RECOVERY":
      return { popStale: prng.chance(cleanRecovery ? 0.1 : 0.3) };
    case "ENTER_CONTAINMENT":
      // Only this flag draws here, so no other profile's history moves.
      if (profile.honestContainmentBias === true && prng.chance(0.85)) return { quorumShape: "honest" };
      return { quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]) };
    case "BIND_MIGRATION":
      // A binding is one-way, so only the FIRST success can be the bad one: the rate has to be high enough to meet it.
      return {
        quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]),
        badBinding: prng.weighted(["none", "wrongHash", "self"], [5, 2, 2]),
      };
    case "CANCEL_RECOVERY_BY_QUORUM":
      return { quorumShape: prng.weighted(QUORUM_SHAPES, [4, 3, 2, 2, 1, 1, 1]) };
    case "REPLAY_PAST_CALL":
      return { index: prng.int(64) };
    case "DIRECT_TRANSFER":
      return { units: prng.pick([1, 10, 500]) };
    case "UNSOLICITED_TRANSFER":
      return { units: prng.pick([1, 10]), hostility: prng.weighted([0, 1, 2], [3, 2, 1]) };
    case "EGRESS_NATIVE":
    case "EGRESS_TOKEN":
    case "EGRESS_OTHER":
      return { appendRecipient: prng.chance(0.2) };
    case "TOKEN_MODE":
      return { mode: prng.pick(profile.tokenModes ?? ["VANILLA"]) };
    case "TOKEN_BLOCKLIST":
      return { target: prng.pick(["recipient", "vault", "destination"]), flag: prng.chance(0.55) };
    case "DESTINATION_MODE":
      return { mode: prng.pick(["ACCEPT", "BOUNCE_ALL", "BOUNCE_HALF", "REFUSE"]) };
    case "TOKEN_REBASE":
      return { bps: prng.pick([9_000, 11_000, 10_001]) };
    case "ARM_HOOK":
      return {
        hook: prng.pick([
          "readNonce",
          "replaySpend",
          "secondValidSpend",
          "egress",
          "contain",
          "bindMigration",
          "retire",
        ]),
        afterDebit: prng.chance(0.5),
      };
    case "RELAY_TAMPER":
      return { field: prng.pick(["recipient", "amount"]) };
    case "CROSS_ASSET_REPLAY":
      return { variant: prng.pick(["mainSigAtSibling", "siblingSigHere"]) };
    default:
      return {};
  }
}

export function generatePlanG2(profile: CampaignProfileG2, seed: number, depth: number): GeneratedActionG2[] {
  const prng = makePrng(seed);
  const kinds = ACTION_KINDS_G2.filter((k) => (profile.weights[k] ?? 0) > 0);
  const weights = kinds.map((k) => profile.weights[k]!);
  const plan: GeneratedActionG2[] = [];
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

function seatLabels(w: Gen2World): string[] {
  return w.gKeys.map((k) => {
    for (let i = 0; i < 3; i++) {
      const label = w.opts.label + "-guardian-" + i;
      if (addrOf(new ethers.SigningKey(ethers.id(label))) === addrOf(k)) return label;
    }
    throw new Error("harness bug: a roster seat has no known key label");
  });
}

function freshCtx(w: Gen2World, fabricateCommitments: boolean): G2Ctx {
  return {
    world: w,
    abstract: freshAbstractState(w.opts.label + "-cred"),
    credKey: w.credKey,
    credLabel: w.opts.label + "-cred",
    pqKey: w.pqKey,
    pqLabel: w.opts.label + "-pq",
    guardianKeys: w.gKeys.slice(),
    guardianLabels: seatLabels(w),
    guardianIsContract: w.guardianIsContract.slice(),
    threshold: w.threshold,
    verifierKind: w.opts.verifier,
    requirePqNow: !w.opts.ecdsaOnlyFloor,
    policyKind: "none",
    fabricateCommitments,
    history: [],
    step: 0,
    tokenMode: "VANILLA",
    armedHook: null,
    armedHookRoots: new Set<Root>(),
    armedHookAfterDebit: false,
    frozen: new Set<string>(),
    destinationMode: "ACCEPT",
    lastSpendData: null,
    boundAtTimestamp: null,
  };
}

/** Generation 1's lifecycle tally, unchanged. It is a private function there and that file is frozen. */
function lifecycleSeamsHit(
  action: GeneratedActionG2,
  ok: boolean,
  revert: string | null,
  pre: SnapshotG2,
  hadSuccessfulRecovery: boolean,
): LifecycleSeam[] {
  const hit: LifecycleSeam[] = [];
  const storedActive = pre.recovery.active;
  const expiredStored = storedActive && !pre.recoveryEffectivelyLive;
  const priorRequestExisted = pre.recovery.proposedSigner !== ZERO;
  if (expiredStored) hit.push("expiredRequestObserved");
  if (action.kind === "CANCEL_RECOVERY" && revert === "ChallengeExhausted") hit.push("exhaustedBudgetRefusal");
  if (action.kind === "INITIATE_RECOVERY") {
    if (ok && priorRequestExisted && !storedActive) hit.push("reinitiationAfterCancellation");
    if (ok && expiredStored) hit.push("reinitiationAfterExpiry");
    if (!ok && revert === "BadState" && pre.recoveryEffectivelyLive) hit.push("liveOverwriteRefused");
    if (ok && hadSuccessfulRecovery) hit.push("recoveryAfterRecovery");
  }
  if (action.kind === "CANCEL_RECOVERY_BY_QUORUM") {
    if (ok) hit.push("quorumCancelSucceeded");
    if (!ok && revert === "QuorumNotMet" && pre.recoveryEffectivelyLive) hit.push("quorumCancelRefusedBelowQuorum");
  }
  if (
    (action.kind === "CANCEL_RECOVERY" || action.kind === "CANCEL_RECOVERY_BY_QUORUM") &&
    !ok &&
    revert === "NoRecovery" &&
    expiredStored
  ) {
    hit.push("expiredCancellationRefused");
  }
  if (action.kind === "CANCEL_RECOVERY" && ok && hadSuccessfulRecovery) hit.push("challengeAfterRecoveryReset");
  return hit;
}

interface Memory {
  directTransfers: number;
  recovered: boolean;
  verifierMoved: boolean;
  containedOnce: boolean;
  hostileRefused: boolean;
}

function seamsHit(
  action: GeneratedActionG2,
  ctx: G2Ctx,
  res: ExecOutcomeG2,
  hookFired: HookKind | undefined,
  hookSucceeded: boolean,
  armedBefore: HookKind | null,
  pre: SnapshotG2,
  post: SnapshotG2,
  mem: Memory,
  heldCredential: boolean,
): G2Seam[] {
  const hit: G2Seam[] = [];
  const { kind, params: p } = action;
  const r = res.revert;
  if (kind === "DIRECT_TRANSFER" && res.ok) {
    hit.push("directTransferObserved");
    if (mem.directTransfers >= 1) hit.push("repeatedDirectTransfer");
  }
  if (kind === "SPEND") {
    if (res.ok) {
      if (p.relay) hit.push("relayedSpendSettled");
      if (p.drain) hit.push("drainSettled");
      if (mem.directTransfers > 0) hit.push("spendAfterDirectTransfer");
      if (mem.recovered) hit.push("recoveryThenSpend");
      if (mem.verifierMoved) hit.push("verifierTransitionThenSpend");
      if (mem.containedOnce) hit.push("containmentExpiredThenSpend");
      if (LYING_TO_THE_SENDER.has(ctx.tokenMode) || RECIPIENT_LEG_ONLY.has(ctx.tokenMode))
        hit.push("assetBoundaryObserved");
    } else {
      if (!heldCredential && (r === "BadSignature" || r === "ECDSAInvalidSignature" || r === "VerifierDenied"))
        hit.push("unauthorizedSpendRefused");
      if (r === "TransferFailed") {
        const m = ctx.tokenMode;
        if (m === "REVERTS" || m === "RETURN_FALSE_NO_MOVE" || m === "VANILLA") hit.push("failedTransferRefused");
        if (m === "RETURN_TRUE_NO_MOVE") hit.push("lyingResultRefused");
        if (m === "SHORT_PAY") hit.push("shortPayRefused");
        if (m === "SENDER_FEE") hit.push("senderFeeRefused");
        if (m === "DUST_SHORT") hit.push("rebaseDustRefused");
        if (m === "QUERY_REVERTS_AFTER_TRANSFER" || m === "QUERY_SHORT_AFTER_TRANSFER") hit.push("queryFailureRefused");
        // The hook's own record rolled back with the outer call, so this seam is read from what was armed.
        if (
          armedBefore === "secondValidSpend" &&
          heldCredential &&
          res.spend !== undefined &&
          pre.tokenBalance >= res.spend.amount + 1_000_000n
        )
          hit.push("nestedSpendRefusedByExactDelta");
      }
      if (r === "BadState" && pre.safeStateEffective === 1) hit.push("containmentThenSpendRefused");
      if (r === "PolicyDenied") hit.push("policyDenialThenSpendRefused");
    }
  }
  if (kind === "CROSS_ASSET_REPLAY" && !res.ok) hit.push("crossAssetReplayRefused");
  if (kind === "RELAY_TAMPER" && !res.ok) hit.push("relayTamperRefused");
  if (!pre.migration.bound && post.migration.bound) hit.push("migrationBound");
  const egress = kind === "EGRESS_TOKEN" || kind === "EGRESS_NATIVE" || kind === "EGRESS_OTHER";
  if (
    egress &&
    res.ok &&
    (post.tokenBalance < pre.tokenBalance ||
      post.nativeBalance < pre.nativeBalance ||
      post.otherTokenBalance < pre.otherTokenBalance)
  ) {
    hit.push("migrationEgressMoved");
    if (kind === "EGRESS_TOKEN" && mem.hostileRefused) hit.push("hostileHoldingVetoedNothing");
  }
  if (egress && r === "TooEarly") hit.push("egressTooEarlyRefused");
  if (kind === "EGRESS_TOKEN" && r === "TransferFailed" && ctx.frozen.size > 0) hit.push("egressRefusedByFreeze");
  if (
    kind === "EGRESS_TOKEN" &&
    r === "TransferFailed" &&
    ctx.frozen.size === 0 &&
    FALSE_SETTLEMENT_MODES.has(ctx.tokenMode)
  )
    hit.push("egressFalseSettlementRefused");
  if (kind === "EGRESS_NATIVE" && r === "TransferFailed" && ctx.destinationMode === "BOUNCE_ALL")
    hit.push("nativeBounceRefused");
  if (kind === "EGRESS_NATIVE" && r === "TransferFailed" && ctx.destinationMode === "REFUSE")
    hit.push("nativeRefusedByDestination");
  if (kind === "BIND_MIGRATION" && p.badBinding === "wrongHash" && r === "DestinationMismatch")
    hit.push("wrongHashBindingRefused");
  if (kind === "BIND_MIGRATION" && p.badBinding === "self" && r === "DestinationMismatch")
    hit.push("selfBindingRefused");
  if (kind === "REPLAY_PAST_CALL" && res.replayed !== undefined) {
    if (!res.ok && res.replayed.kind === "SPEND" && res.replayed.priorOk) hit.push("replayedSpendRefused");
    if (!res.ok && res.replayed.kind === "BIND_MIGRATION" && res.replayed.priorOk) hit.push("replayedMigrationRefused");
    if (res.ok && res.replayed.kind.startsWith("EGRESS_")) hit.push("replayedEgressNoDiscretion");
  }
  if (hookFired !== undefined) hit.push("hookFiredDuringTransfer");
  if (hookFired === "readNonce") hit.push("hookNonceRead");
  if (hookFired === "replaySpend" && kind === "SPEND" && !hookSucceeded) hit.push("hookReplayRefused");
  if ((kind === "SET_VERIFIER" || kind === "INITIATE_RECOVERY") && r === "InadmissibleVerifier")
    hit.push("inadmissibleVerifierRefused");
  return hit;
}

interface RunOutput {
  violations: PropertyViolationG2[];
  steps: StepRecordG2[];
  successful: number;
  outcomeCounts: Record<string, number>;
  revertCounts: Record<string, number>;
  actionCoverage: Record<string, number>;
  seams: Record<string, number>;
  lifecycle: Record<string, number>;
  sawOutcome: Set<string>;
  ctx: G2Ctx;
}

async function runPlanG2(
  w: Gen2World,
  plan: GeneratedActionG2[],
  profile: CampaignProfileG2,
  seed: number,
): Promise<RunOutput> {
  const prng = makePrng(seed ^ 0x5f3759df);
  const ctx = freshCtx(w, profile.fabricateCommitments === true);
  const byName = new Map<string, Actor>(profile.actors.map((a) => [a.name, materialiseActor(a, w.opts.label)]));

  const out: RunOutput = {
    violations: [],
    steps: [],
    successful: 0,
    outcomeCounts: {},
    revertCounts: {},
    actionCoverage: {},
    seams: {},
    lifecycle: {},
    sawOutcome: new Set(),
    ctx,
  };
  const mem: Memory = {
    directTransfers: 0,
    recovered: false,
    verifierMoved: false,
    containedOnce: false,
    hostileRefused: false,
  };
  const token = zoo(w);

  const rootCreated = new Set<string>(
    w.opts.authority === "root" ? [w.verifiers.honest.toLowerCase(), w.verifiers.honestB.toLowerCase()] : [],
  );
  const expectedTail = packedArgs(GENERATION_2, w.authorityAddress, w.token).slice(2).toLowerCase();
  let prev: SnapshotG2 | null = null;
  const first = await snapshotG2(w);
  const initialCode = first.vaultCode;
  const initialSiblingAsset = first.siblingAsset;
  const initialSiblingNonce = first.siblingSpendNonce;
  let carried: SnapshotG2 = first;

  const violate = (property: string, step: number, detail: string): void => {
    out.violations.push({ property, step, detail });
  };

  for (let i = 0; i < plan.length; i++) {
    const action = plan[i]!;
    const actor = byName.get(action.actorName) ?? materialiseActor(ALL_MATERIAL_ACTOR, w.opts.label);
    ctx.step = i;
    out.actionCoverage[action.kind] = (out.actionCoverage[action.kind] ?? 0) + 1;

    const pre: SnapshotG2 = carried;
    const heldBefore = rootsNow(actor, ctx as unknown as Ctx);
    const modeBefore = ctx.tokenMode;
    const armedBefore = ctx.armedHook;
    const res = await executeActionG2(action, actor, ctx, prng);
    const post = await snapshotG2(w);
    carried = post;

    if (res.ok) out.successful++;
    if (res.revert) out.revertCounts[res.revert] = (out.revertCounts[res.revert] ?? 0) + 1;

    // ---- a hook fires inside ANY transfer the vault makes, so it is read after ANY action ----
    let hookFired: HookKind | undefined;
    let hookSucceeded = false;
    if (armedBefore !== null && action.kind !== "ARM_HOOK" && ((await token.hookFired()) as boolean)) {
      hookFired = armedBefore;
      hookSucceeded = (await token.hookSucceeded()) as boolean;
      ctx.armedHook = null;
    }
    // A nested call that moved value is what makes the outer step's own arithmetic not its own.
    const nestedMovedValue = hookSucceeded && (hookFired === "secondValidSpend" || hookFired === "egress");

    // ---- outcomes, by state diff. A rebase is the TOKEN acting on its own ledger: no authority to charge ----
    let observed = detectOutcomes(pre as KernelSnapshot, post as KernelSnapshot);
    if (ASSET_EXTERNAL_ACTIONS.has(action.kind)) observed = observed.filter((o) => o !== "ASSET_MOVEMENT");
    if (post.otherTokenBalance < pre.otherTokenBalance && !observed.includes("ASSET_MOVEMENT"))
      observed = [...observed, "ASSET_MOVEMENT"];
    for (const o of observed) {
      out.outcomeCounts[o] = (out.outcomeCounts[o] ?? 0) + 1;
      out.sawOutcome.add(o);
    }

    // ---- what a fired hook did is attributed to the roots behind ITS signatures too, if it had any and it worked ----
    const charged = new Set<Root>(res.attributedRoots);
    if (hookFired !== undefined && hookSucceeded && SIGNED_HOOKS.has(hookFired))
      for (const r of ctx.armedHookRoots) charged.add(r);
    // A binding that happened INSIDE a hook went through no action of the harness: record it by state diff.
    if (!pre.migration.bound && post.migration.bound && ctx.boundAtTimestamp === null) {
      ctx.boundAtTimestamp = post.blockTimestamp;
      ctx.abstract.migrationBound = true;
      ctx.abstract.migrationAuthorizedBy = new Set(charged);
    }

    const credentialFactors = pre.floor.requirePq ? 2 : 1;
    const k = Number(pre.guardianThreshold);
    for (const outcome of observed) {
      const j = judgeCut(charged, outcome, credentialFactors, k);
      if (!j.entitled) {
        violate(
          "P-CUT/" + outcome,
          i,
          `${outcome} occurred with roots {${[...charged].sort().join(",") || "NONE"}} = credential:${j.held.credential} guardians:${j.held.guardians}, which satisfies NO path. Required: ${j.requirement} (${DOCUMENTED[outcome]}; live k=${k}, credential factors=${credentialFactors}). Issued by ${actor.name} via ${action.kind}`,
        );
      }
    }

    if (res.ok && res.usedStalePossession === true)
      violate(
        "P-INCOMING-POSSESSION",
        i,
        action.kind + " SUCCEEDED while proving possession of the OUTGOING credential",
      );
    if (res.modelViolation) violate("P-MODEL", i, res.modelViolation);

    // ---- a plane that denies must deny ----
    if (ctx.policyKind === "deny" && action.kind === "SPEND" && res.ok) {
      violate("P-PLANE-SUBTRACTIVE", i, "a SPEND settled while the installed policy plane denies every admission");
    }

    // ---- a mined revert changes no storage word. A refusal in simulation would test nothing ----
    if (!res.ok && action.kind !== "ADVANCE_TIME" && action.kind !== "FUND") {
      if (kernelDigest(pre) !== kernelDigest(post))
        violate("P-ATOMICITY", i, `${action.kind} REVERTED (${res.revert}) yet a storage word changed`);
      if (post.blockNumber > pre.blockNumber) out.seams.refusalMined = (out.seams.refusalMined ?? 0) + 1;
    }
    if (res.ok && action.kind === "SPEND" && kernelDigest(pre) !== kernelDigest(post))
      out.seams.digestMovedOnSuccess = (out.seams.digestMovedOnSuccess ?? 0) + 1;

    // ---- calls the harness itself built to be unauthorised, and bytes already spent ----
    if (res.ok && action.kind === "RELAY_TAMPER")
      violate(
        "P-UNAUTHORISED-INPUT-NEVER-SETTLES",
        i,
        `a relayed spend whose ${String(action.params.field)} was rewritten SETTLED`,
      );
    if (res.ok && action.kind === "CROSS_ASSET_REPLAY")
      violate("P-CROSS-ASSET", i, `a signature made for another vault settled (${String(action.params.variant)})`);
    if (
      res.ok &&
      action.kind === "REPLAY_PAST_CALL" &&
      res.replayed !== undefined &&
      res.replayed.priorOk &&
      NONCE_BEARING.has(res.replayed.kind)
    ) {
      violate(
        "P-NO-REPLAY",
        i,
        `a ${res.replayed.kind} that had already succeeded succeeded AGAIN when resubmitted by ${actor.name}`,
      );
    }

    // ---- the asset properties. Oracle = the token's REAL ledger, never the kernel's view of it ----
    if (post.admittedAssetRead.toLowerCase() !== w.token.toLowerCase())
      violate("P-ASSET-CODE-IDENTITY", i, `admittedAsset() moved to ${post.admittedAssetRead}`);
    if (post.vaultCode !== initialCode) violate("P-ASSET-CODE-IDENTITY", i, "the vault's own code changed");
    if (!post.vaultCode.toLowerCase().endsWith(expectedTail))
      violate(
        "P-ASSET-CODE-IDENTITY",
        i,
        "the vault's code does not end in generation || verifierAuthority || admitted asset",
      );

    if (action.kind === "SPEND" && res.ok && res.spend) {
      const debit = pre.tokenBalance - post.tokenBalance;
      const nested = nestedMovedValue;
      if (post.nonces[0] <= pre.nonces[0])
        violate("P-NONCE-ON-SPEND", i, "a spend settled with no spend nonce consumed");
      if (post.transferCalls <= pre.transferCalls)
        violate(
          "P-SPEND-COMPLETED-TRANSFER",
          i,
          `a spend of ${res.spend.amount} settled under mode ${modeBefore} and the token completed no transfer`,
        );
      if (
        !LYING_TO_THE_SENDER.has(modeBefore) &&
        res.spend.to !== w.vaultAddress &&
        !nested &&
        debit !== res.spend.amount
      ) {
        violate(
          "P-SETTLEMENT-EXACT",
          i,
          `a spend of ${res.spend.amount} settled under token mode ${modeBefore} and the vault's REAL balance fell by ${debit}`,
        );
      }
      if (
        !LYING_TO_THE_SENDER.has(modeBefore) &&
        !RECIPIENT_LEG_ONLY.has(modeBefore) &&
        res.spend.to === w.recipient &&
        !nested
      ) {
        const credit = post.recipientAsset - pre.recipientAsset;
        if (credit !== res.spend.amount)
          violate(
            "P-SPEND-PAYS-RECIPIENT",
            i,
            `a spend of ${res.spend.amount} credited the signed recipient ${credit}`,
          );
      }
      if (post.otherTokenBalance !== pre.otherTokenBalance)
        violate(
          "P-SPEND-TOUCHES-ONLY-ASSET",
          i,
          `a spend moved ${pre.otherTokenBalance - post.otherTokenBalance} of a holding it does not spend`,
        );
      if (post.nativeBalance < pre.nativeBalance)
        violate("P-SPEND-TOUCHES-ONLY-ASSET", i, "a spend moved native value");
    }
    if (hookFired === "readNonce" && res.ok && action.kind === "SPEND" && hookSucceeded) {
      const [seen] = ethers.AbiCoder.defaultAbiCoder().decode(
        ["uint256"],
        (await token.hookReturn()) as string,
      ) as unknown as [bigint];
      if (seen <= pre.nonces[0])
        violate(
          "P-NONCE-SPENT-BEFORE-TOKEN-RUNS",
          i,
          `the token ran with the spend nonce still at ${seen}: the authorisation it sits inside was not yet consumed`,
        );
    }
    const tracked =
      post.tokenBalance +
      post.recipientAsset +
      post.destinationAsset +
      post.outsiderAsset +
      post.deployerAsset +
      post.sink;
    if (tracked !== post.totalSupply)
      violate(
        "P-CONSERVATION",
        i,
        `${post.totalSupply - tracked} units of the admitted asset are at an address nobody authorised`,
      );
    if (initialSiblingAsset !== null && post.siblingAsset !== initialSiblingAsset)
      violate("P-CROSS-ASSET", i, `the other asset's vault moved from ${initialSiblingAsset} to ${post.siblingAsset}`);
    if (initialSiblingNonce !== null && post.siblingSpendNonce !== initialSiblingNonce)
      violate("P-CROSS-ASSET", i, "the other asset's vault consumed a spend nonce");

    // ---- an egress, or a replay of one: the recipient is the binding's, whoever sent it ----
    const egressKind = action.kind === "REPLAY_PAST_CALL" ? res.replayed?.kind : action.kind;
    if (res.ok && egressKind === "EGRESS_TOKEN" && !RECIPIENT_LEG_ONLY.has(modeBefore)) {
      if (post.destinationAsset - pre.destinationAsset !== pre.tokenBalance - post.tokenBalance)
        violate("P-EGRESS-RECIPIENT", i, "an egress of the asset credited someone other than the destination");
    }
    if (res.ok && res.published !== undefined) {
      const lost: Record<string, bigint> = {
        EGRESS_TOKEN: pre.tokenBalance - post.tokenBalance,
        EGRESS_NATIVE: pre.nativeBalance - post.nativeBalance,
        EGRESS_OTHER: pre.otherTokenBalance - post.otherTokenBalance,
      };
      const real = egressKind === undefined ? undefined : lost[egressKind];
      const lyingAsset = egressKind === "EGRESS_TOKEN" && LYING_TO_THE_SENDER.has(modeBefore);
      if (real !== undefined && !lyingAsset && res.published !== real)
        violate(
          "P-EGRESS-PUBLISHES-THE-TRUTH",
          i,
          `${egressKind} published ${res.published} as moved, and the vault's real balance fell by ${real}`,
        );
    }
    if (
      res.ok &&
      egressKind === "EGRESS_NATIVE" &&
      post.destinationNative - pre.destinationNative !== pre.nativeBalance - post.nativeBalance
    ) {
      violate("P-EGRESS-RECIPIENT", i, "an egress of native value credited someone other than the destination");
    }
    if (
      res.ok &&
      egressKind === "EGRESS_OTHER" &&
      post.destinationOther - pre.destinationOther !== pre.otherTokenBalance - post.otherTokenBalance
    ) {
      violate(
        "P-EGRESS-RECIPIENT",
        i,
        "an egress of an unsolicited holding credited someone other than the destination",
      );
    }

    const leftTheVault =
      !ASSET_EXTERNAL_ACTIONS.has(action.kind) &&
      (post.tokenBalance < pre.tokenBalance ||
        post.nativeBalance < pre.nativeBalance ||
        post.otherTokenBalance < pre.otherTokenBalance);
    if (
      leftTheVault &&
      pre.migration.bound &&
      ctx.boundAtTimestamp !== null &&
      post.blockTimestamp < ctx.boundAtTimestamp + BIND_DELAY_ORACLE
    ) {
      violate(
        "P-MIGRATION-TIME",
        i,
        `a holding left ${post.blockTimestamp - ctx.boundAtTimestamp}s after the binding, inside the 7-day bound (${action.kind})`,
      );
    }

    if (w.opts.authority === "root") {
      if (!rootCreated.has(post.pqVerifier.toLowerCase()))
        violate("P-VERIFIER-PROVENANCE", i, `the active verifier ${post.pqVerifier} was not created by the root`);
      if (post.recovery.active && !rootCreated.has(post.recovery.proposedVerifier.toLowerCase()))
        violate(
          "P-VERIFIER-PROVENANCE",
          i,
          `a proposed verifier ${post.recovery.proposedVerifier} was not created by the root`,
        );
    }

    if (hookFired === "replaySpend" && action.kind === "SPEND" && hookSucceeded && res.ok) {
      violate("P-REENTRY-NO-REPLAY", i, "a same-payload replay fired from inside the token's transfer SUCCEEDED");
    }

    // ---- Generation 1's global invariants, unchanged, over a snapshot of their shape ----
    for (const v of checkGlobals(post as KernelSnapshot, prev as KernelSnapshot | null, w as unknown as World))
      violate(v.name, i, v.detail);
    const commitment = await checkRecoveryCommitmentG2(w, post);
    if (commitment) violate("G-RECOVERY-COMMITMENT-BINDS", i, commitment);

    // ---- reachability bookkeeping, observations only ----
    const hadRecovered = [...ctx.abstract.episodes.values()].some((e) => e.state === "CONSUMED");
    for (const seam of lifecycleSeamsHit(action, res.ok, res.revert, pre, hadRecovered))
      out.lifecycle[seam] = (out.lifecycle[seam] ?? 0) + 1;
    for (const s of seamsHit(
      action,
      ctx,
      res,
      hookFired,
      hookSucceeded,
      armedBefore,
      pre,
      post,
      mem,
      heldBefore.has("CRED_ECDSA"),
    ))
      out.seams[s] = (out.seams[s] ?? 0) + 1;
    if (action.kind === "DIRECT_TRANSFER" && res.ok) mem.directTransfers++;
    if (action.kind === "EXECUTE_RECOVERY" && res.ok) mem.recovered = true;
    if (action.kind === "SET_VERIFIER" && res.ok) mem.verifierMoved = true;
    if (post.safeStateEffective === 1) mem.containedOnce = true;
    if (action.kind === "EGRESS_OTHER" && res.revert === "TransferFailed") mem.hostileRefused = true;

    out.steps.push({
      step: i,
      kind: action.kind,
      caller: actor.name,
      ok: res.ok,
      revert: res.revert,
      outcomes: observed,
    });
    syncModelFromChain(ctx, {
      ecdsaSigner: post.ecdsaSigner,
      pqPublicKeyHash: post.pqPublicKeyHash,
      pqVerifier: post.pqVerifier,
      policyEngine: post.policyEngine,
      requirePq: post.floor.requirePq,
    });
    prev = post;
  }
  return out;
}

/**
 * THE END OF THE HISTORY. The token is put right first: what is under test is whether the KERNEL can
 * still let the money out, and a token that is down is the asset admission's problem and F-FREEZE's.
 * A condition that cannot be asked at this history's end is skipped and counted, never passed.
 */
async function terminalControls(w: Gen2World, run: RunOutput, steps: number): Promise<void> {
  const ctx = run.ctx;
  const token = zoo(w);
  const step = steps;
  const violate = (property: string, detail: string): void => {
    run.violations.push({ property, step, detail });
  };
  await (await token.setMode(0)).wait();
  ctx.tokenMode = "VANILLA";
  await (await token.disarmHook()).wait();
  ctx.armedHook = null;
  for (const account of [w.vaultAddress, w.recipient, w.destination])
    await (await token.setBlocklisted(account, false)).wait();
  await (await w.other.setHostility(0)).wait();
  await (await w.destinationFixture.setMode(0)).wait();
  ctx.destinationMode = "ACCEPT";

  const s = await snapshotG2(w);
  if (s.migration.bound) {
    const opensAt = s.migration.boundAt + BIND_DELAY_ORACLE;
    if (s.blockTimestamp < opensAt) await networkHelpers.time.increaseTo(opensAt);
    // The asset LAST, so an earlier egress of another class is what any first-caller effect would have to bite on.
    const classes: [string, string][] = [
      ["unsolicited", w.otherToken],
      ["native", ZERO],
      ["admitted", w.token],
    ];
    for (const [label, asset] of classes) {
      try {
        await (
          await w.outsider.sendTransaction({
            to: w.vaultAddress,
            data: w.vault.interface.encodeFunctionData("egress", [asset]),
            gasLimit: 3_000_000n,
          })
        ).wait();
      } catch (e) {
        violate(
          "P-EXIT-REACHABLE",
          `a stranger's egress of the ${label} holding was refused with the delay passed and the token behaving: ${String(e).slice(0, 160)}`,
        );
      }
    }
    const after = await snapshotG2(w);
    if (after.tokenBalance !== 0n)
      violate("P-EXIT-REACHABLE", `the admitted asset's balance is ${after.tokenBalance} after its egress`);
    if (after.nativeBalance !== 0n)
      violate("P-EXIT-REACHABLE", `the native balance is ${after.nativeBalance} after its egress`);
    if (after.otherTokenBalance !== 0n)
      violate("P-EXIT-REACHABLE", `the unsolicited holding is ${after.otherTokenBalance} after its egress`);
    run.seams.exitControlExercised = (run.seams.exitControlExercised ?? 0) + 1;
    return;
  }

  const verifierBroken = s.floor.requirePq && (ctx.verifierKind === "alwaysFalse" || ctx.verifierKind === "reverting");
  const planeAdmits = ctx.policyKind === "none" || ctx.policyKind === "allow";
  const keyHeld = addrOf(ctx.credKey).toLowerCase() === s.ecdsaSigner.toLowerCase();
  if (
    s.safeStateEffective !== 0 ||
    verifierBroken ||
    !planeAdmits ||
    !keyHeld ||
    s.tokenBalance === 0n ||
    (s.floor.requirePq && !s.commitmentAttestable)
  ) {
    run.seams.balanceControlSkipped = (run.seams.balanceControlSkipped ?? 0) + 1;
    return;
  }
  const holder: Actor = {
    ...materialiseActor(ALL_MATERIAL_ACTOR, w.opts.label),
    ownedLabels: new Set([ctx.credLabel, ctx.pqLabel]),
  };
  const prng = makePrng(1);
  const res = await executeActionG2(
    { kind: "SPEND", actorName: holder.name, params: { rawAmount: s.tokenBalance.toString() } },
    holder,
    ctx,
    prng,
  );
  if (!res.ok) {
    violate(
      "P-BALANCE-SPENDABLE",
      `the current credential could not spend the vault's whole real balance ${s.tokenBalance}: ${res.revert}`,
    );
  } else {
    const after = await snapshotG2(w);
    if (after.tokenBalance !== 0n)
      violate("P-BALANCE-SPENDABLE", `a spend of the whole balance left ${after.tokenBalance}`);
  }
  run.seams.balanceControlExercised = (run.seams.balanceControlExercised ?? 0) + 1;
}

export const POSITIVE_CONTROL_LABELS = {
  spend: "honest spend moves the admitted asset",
  directCredit: "a direct credit stays spendable: a spend of more than the previous balance settles",
  relayed: "a stranger relays an honest spend",
  rotation: "honest rotation",
  containment: "honest containment",
  recoveryToSpend: "recovery end-to-end, then the NEW credential spends the admitted asset",
  binding: "honest binding",
  egress: "a stranger egresses the admitted asset once the delay has passed",
  quorumCancel: "honest quorum cancels a live recovery",
} as const;

/** Fully-honest, fully-authorised sequences that MUST reach their outcome on a restored fixture. */
export async function runPositiveControlsG2(
  w: Gen2World,
  restore: () => Promise<void>,
): Promise<{ attempted: number; passed: number; failures: string[]; passedLabels: string[] }> {
  const honestProfile: CampaignProfileG2 = {
    name: "positive-control",
    description: "",
    actors: [ALL_MATERIAL_ACTOR],
    actorWeights: [1],
    weights: {},
  };
  const name = ALL_MATERIAL_ACTOR.name;
  const dead = w.opts.verifier === "reverting" || w.opts.verifier === "alwaysFalse";
  const L = POSITIVE_CONTROL_LABELS;
  const controls: { label: string; plan: GeneratedActionG2[]; expect: Outcome; needsLiveVerifier: boolean }[] = [
    {
      label: L.spend,
      plan: [{ kind: "SPEND", actorName: name, params: { units: 1 } }],
      expect: "ASSET_MOVEMENT",
      needsLiveVerifier: true,
    },
    {
      label: L.directCredit,
      plan: [
        { kind: "DIRECT_TRANSFER", actorName: name, params: { units: 2000 } },
        { kind: "SPEND", actorName: name, params: { units: 1500 } },
      ],
      expect: "ASSET_MOVEMENT",
      needsLiveVerifier: true,
    },
    {
      label: L.relayed,
      plan: [{ kind: "SPEND", actorName: name, params: { units: 1, relay: true } }],
      expect: "ASSET_MOVEMENT",
      needsLiveVerifier: true,
    },
    {
      label: L.rotation,
      plan: [{ kind: "ROTATE_CREDENTIAL", actorName: name, params: { target: 0 } }],
      expect: "CREDENTIAL_REPLACEMENT",
      needsLiveVerifier: true,
    },
    {
      label: L.containment,
      plan: [{ kind: "ENTER_CONTAINMENT", actorName: name, params: { quorumShape: "honest" } }],
      expect: "CONTAINMENT",
      needsLiveVerifier: false,
    },
    {
      label: L.recoveryToSpend,
      plan: [
        {
          kind: "INITIATE_RECOVERY",
          actorName: name,
          params: { quorumShape: "honest", target: 1, verifier: "honest" },
        },
        { kind: "ADVANCE_TIME", actorName: name, params: { seconds: 7 * 86400 + 1 } },
        { kind: "EXECUTE_RECOVERY", actorName: name, params: {} },
        { kind: "SPEND", actorName: name, params: { units: 1 } },
      ],
      expect: "ASSET_MOVEMENT",
      needsLiveVerifier: false,
    },
    {
      label: L.binding,
      plan: [{ kind: "BIND_MIGRATION", actorName: name, params: { quorumShape: "honest" } }],
      expect: "MIGRATION_BINDING",
      needsLiveVerifier: false,
    },
    {
      label: L.egress,
      plan: [
        { kind: "BIND_MIGRATION", actorName: name, params: { quorumShape: "honest" } },
        { kind: "ADVANCE_TIME", actorName: name, params: { seconds: 7 * 86400 + 1 } },
        { kind: "EGRESS_TOKEN", actorName: name, params: {} },
      ],
      expect: "ASSET_MOVEMENT",
      needsLiveVerifier: false,
    },
    {
      label: L.quorumCancel,
      plan: [
        {
          kind: "INITIATE_RECOVERY",
          actorName: name,
          params: { quorumShape: "honest", target: 1, verifier: "honest" },
        },
        { kind: "CANCEL_RECOVERY_BY_QUORUM", actorName: name, params: { quorumShape: "honest" } },
      ],
      expect: "RECOVERY_QUORUM_CANCEL",
      needsLiveVerifier: false,
    },
  ];
  let attempted = 0;
  let passed = 0;
  const failures: string[] = [];
  const passedLabels: string[] = [];
  for (const c of controls) {
    if (c.needsLiveVerifier && dead) continue;
    attempted++;
    await restore();
    const { steps, sawOutcome } = await runPlanG2(w, c.plan, honestProfile, 1);
    // Every step, or a later step could reach the outcome for a reason the control does not name.
    if (sawOutcome.has(c.expect) && steps.every((s) => s.ok)) {
      passed++;
      passedLabels.push(c.label);
    } else {
      failures.push(
        c.label +
          " expected " +
          c.expect +
          ", trail: " +
          steps.map((s) => s.kind + (s.ok ? " ok" : " REVERT:" + s.revert)).join(" | "),
      );
    }
  }
  return { attempted, passed, failures, passedLabels };
}

export interface CampaignOptionsG2 {
  implOverride?: CompiledUnit;
  factoryOverride?: CompiledUnit;
  /** The verifying contract honest digests name, for a mutant that changes the domain. */
  signingDomainVault?: string;
  /** The recipient honest spend digests name, for a mutant that stops binding it. */
  signedSpendRecipient?: string;
}

export async function runCampaignG2(
  profileName: string,
  seed: number,
  depth: number,
  label: string,
  options: CampaignOptionsG2 = {},
): Promise<CampaignResultG2> {
  const profile = G2_PROFILES.find((p) => p.name === profileName);
  if (!profile) throw new Error("unknown Generation-2 campaign profile " + profileName);

  const w = await deployGen2World({
    label,
    authority: profile.realRoot ? "root" : "ungated",
    verifier: profile.verifier ?? "honest",
    ecdsaOnlyFloor: profile.ecdsaOnlyFloor ?? false,
    commitPqKey: profile.commitPqKeyOnEcdsaOnlyFloor ?? false,
    fundEth: ethers.parseEther("10"),
    sibling: profile.sibling === true,
    implOverride: options.implOverride,
    factoryOverride: options.factoryOverride,
    signingDomainVault: options.signingDomainVault,
    signedSpendRecipient: options.signedSpendRecipient,
  });
  const snap = await networkHelpers.takeSnapshot();
  const restore = async (): Promise<void> => {
    await snap.restore();
  };

  const plan = generatePlanG2(profile, seed, depth);
  const run = await runPlanG2(w, plan, profile, seed);
  await terminalControls(w, run, plan.length);

  const controls = await runPositiveControlsG2(w, restore);
  // On the real candidate a failed control makes the campaign vacuous. On a mutant the control's result is
  // the mutant's liveness: generation-2/test/Gen2MutationAdequacy.test.ts reads it and reports INCONCLUSIVE rather than a kill.
  const mutated = options.implOverride !== undefined || options.factoryOverride !== undefined;
  if (!mutated) {
    for (const f of controls.failures) {
      run.violations.push({
        property: "P-VACUITY",
        step: -1,
        detail: "POSITIVE CONTROL FAILED, so every safety result in this campaign is vacuous: " + f,
      });
    }
  }

  const real = run.violations.filter((v) => !KNOWN_DEFECT_PROPERTIES.has(v.property));
  const known = run.violations
    .filter((v) => KNOWN_DEFECT_PROPERTIES.has(v.property))
    .map((v) => ({ ...v, defect: explains(v.property)?.id ?? "unknown" }));

  return {
    profile: profileName,
    seed,
    depth,
    violations: real,
    knownDefectHits: known,
    transitionsExercised: plan.length,
    successfulTransitions: run.successful,
    outcomeCounts: run.outcomeCounts,
    revertCounts: run.revertCounts,
    actionCoverage: run.actionCoverage,
    actionsThatSucceeded: [...new Set(run.steps.filter((s) => s.ok).map((s) => s.kind))],
    seams: run.seams,
    lifecycle: run.lifecycle,
    positiveControlsAttempted: controls.attempted,
    positiveControlsPassed: controls.passed,
    controlFailures: controls.failures,
    controlsPassedLabels: controls.passedLabels,
    steps: run.steps,
  };
}
