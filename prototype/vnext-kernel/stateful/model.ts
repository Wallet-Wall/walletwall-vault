/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE ABSTRACT SECURITY MODEL — the oracle.
 *
 * WHY THIS FILE IS NOT A SECOND COPY OF THE KERNEL
 * ------------------------------------------------
 * The failure mode of every model-based test is an oracle that reads the same
 * storage and re-evaluates the same conditions as the implementation, and
 * therefore agrees with it by construction — including when the implementation
 * is wrong. Such an oracle proves nothing.
 *
 * This model avoids that by refusing to predict SUCCESS at all. It maintains
 * only three things, and the third is the only one it judges on:
 *
 *   1. WHAT THE HARNESS DID.  Which actor issued each action, and — crucially —
 *      WHICH AUTHORITY ROOTS THAT ACTOR HOLDS. This is declared by the campaign
 *      when it constructs the actor; it is never read back from the chain. The
 *      kernel cannot influence it, so it cannot make the oracle agree with it.
 *
 *   2. DECLARED CUTS.  The minimum-compromise numbers are COPIED from
 *      AUTHORITY.md section 3 — see `DECLARED_CUTS`. They are an INPUT, not a
 *      derivation: this lane tests the implementation against the published
 *      claim, and if the claim itself is wrong that is a finding about the
 *      document, reported as such rather than silently absorbed.
 *
 *   3. OBSERVED OUTCOMES.  What actually changed on chain, read AFTER the fact
 *      from balances, storage and events.
 *
 * The judgement is then ONE asymmetric implication, in the safety direction
 * only:
 *
 *      IF a protected OUTCOME occurred
 *      AND the issuing actor held FEWER roots than that outcome's declared cut
 *      THEN the authority model is violated.
 *
 * It deliberately does NOT assert the converse ("sufficient roots implies
 * success"). Doing so would require re-implementing every nonce, deadline and
 * state-machine precondition in TypeScript — which is exactly the mirrored
 * oracle this design rejects, and which would make the harness fail on
 * perfectly correct denials. LIVENESS is instead proven by explicit POSITIVE
 * CONTROLS (see `positiveControls` in campaign.ts): a small number of
 * fully-honest actions that MUST succeed, so a campaign in which everything
 * reverts cannot score as a pass.
 *
 * The recovery-evidence state machine (item 1) is the second independent
 * judgement: the harness records for itself whether a recovery it created was
 * later CANCELLED or CONSUMED, and a subsequent success on that same evidence
 * is a violation regardless of what the kernel believes.
 */
import type { Root } from "./world.js";
import { GUARDIAN_ROOTS } from "./world.js";

/**
 * Copied from AUTHORITY.md section 3, "Minimum compromise cuts — RECOMPUTED
 * from the remediated implementation", for the n = 3, k = 2 fixture.
 *
 * `min(2, k)` with k = 2 is 2. Expressed as ROOT COUNTS, because a root is the
 * unit the table counts.
 *
 * POLICY_CHANGE has NO standalone row in that table. Its value here is
 * DERIVED FROM SOURCE — `setPolicy` calls `_authorise`, which is the ECDSA
 * conjunct AND the PQ conjunct, i.e. the same HYBRID gate as `execute` — and
 * the absence of the row is REPORTED as a documentation gap rather than
 * quietly invented. See `DOCUMENTED` below.
 */
export const DECLARED_CUTS = {
  ASSET_MOVEMENT: 2,
  CREDENTIAL_REPLACEMENT: 2,
  VERIFIER_REPLACEMENT: 2,
  POLICY_CHANGE: 2,
  GUARDIAN_TRANSITION: 2,
  MIGRATION_BINDING: 3,
  CONTAINMENT: 2,
} as const;

export type Outcome = keyof typeof DECLARED_CUTS;

/**
 * The cuts for a vault whose CREDENTIAL FAMILY has `credentialFactors` members.
 *
 * `min(2, k)` is a formula, not a number, and reading it as the constant 2 would
 * be wrong for a vault born with an ECDSA-ONLY floor — a configuration
 * `initialize` permits. There the credential family has ONE factor, so the
 * credential path costs 1 and the published cut evaluates to `min(1, 2) = 1`.
 * Holding the model to 2 there would report the vault's own declared design as a
 * violation on every single spend.
 *
 * The GUARDIAN outcomes are unaffected: they are `k` regardless of the floor.
 * MIGRATION stays `k + 1`, because its credential leg is `_floorAuthorises` —
 * the ECDSA conjunct ALONE — in both configurations.
 */
export function declaredCuts(credentialFactors: number, k = 2): Record<Outcome, number> {
  const credentialPath = Math.min(credentialFactors, k);
  return {
    ASSET_MOVEMENT: credentialPath,
    CREDENTIAL_REPLACEMENT: credentialPath,
    VERIFIER_REPLACEMENT: credentialPath,
    POLICY_CHANGE: credentialPath,
    GUARDIAN_TRANSITION: k,
    CONTAINMENT: k,
    MIGRATION_BINDING: k + 1,
  };
}

/** Which cuts AUTHORITY.md section 3 states explicitly, and which this lane had to derive. */
export const DOCUMENTED: Record<Outcome, "AUTHORITY.md-section-3" | "DERIVED-FROM-SOURCE"> = {
  ASSET_MOVEMENT: "AUTHORITY.md-section-3",
  CREDENTIAL_REPLACEMENT: "AUTHORITY.md-section-3",
  // AUTHORITY.md section 3's "Unauthorized asset control" row NAMES setVerifier
  // among the paths that call `_authorise`, and the "Silent crypto downgrade"
  // row is stated as unreachable, so the verifier cut is documented.
  VERIFIER_REPLACEMENT: "AUTHORITY.md-section-3",
  // NO standalone POLICY_CHANGE row exists in the table. Derived from source.
  POLICY_CHANGE: "DERIVED-FROM-SOURCE",
  GUARDIAN_TRANSITION: "AUTHORITY.md-section-3",
  MIGRATION_BINDING: "AUTHORITY.md-section-3",
  // The containment row in section 3 is "Permanent recovery veto: unreachable";
  // section 1 assigns enterContainment to the guardian quorum, i.e. k.
  CONTAINMENT: "AUTHORITY.md-section-3",
};

/**
 * Roots held, split by FAMILY. `held` is recomputed every step from which key
 * material is currently installed (see `rootsNow` in actions.ts), so an attacker
 * who held the credential before an honest recovery is not still credited with
 * it.
 *
 * Guardian roots are counted as a SET, which is where "a principal is an
 * ADDRESS, not an (address, mode) pair" is enforced on the MODEL side —
 * independently of the kernel's ascending-roster rule. An actor cannot reach two
 * by holding one guardian and using it twice, whatever calldata it submits.
 */
export function rootFamilies(held: ReadonlySet<Root>): { credential: number; guardians: number } {
  return {
    credential: (held.has("CRED_ECDSA") ? 1 : 0) + (held.has("CRED_PQ") ? 1 : 0),
    guardians: GUARDIAN_ROOTS.filter((g) => held.has(g)).length,
  };
}

/**
 * One way to legitimately reach an outcome. An outcome is entitled when the
 * held roots satisfy AT LEAST ONE path IN FULL.
 */
export interface AuthorityPath {
  name: string;
  credential: number;
  guardians: number;
}

/**
 * THE PATHS, and why this is a disjunction of conjunctions rather than a single
 * number.
 *
 * `min(2, k)` is a MINIMUM OVER PATHS, not a threshold on a pooled root count.
 * Collapsing it to one number — "the better of the two families" — was a real
 * defect in an earlier version of this model, and the mutation suite is what
 * exposed it: a campaign that had lowered the guardian threshold to 1 made
 * `min(2, k)` evaluate to 1, which then excused a ONE-CREDENTIAL-FACTOR spend
 * and let the historical finding-A1 mutation survive. The credential path and
 * the guardian path are separate routes with separate requirements, and an
 * actor must satisfy one of them COMPLETELY.
 *
 * The guardian route to a credential-gated outcome is TRANSITIVE — quorum
 * initiates a recovery, the recovery installs a credential, that credential
 * spends (AUTHORITY.md section 2, "Guardian quorum ... Yes — ACCEPTED
 * RESIDUAL") — and it is reached in the campaign through the attribution rule
 * for permissionless finalisers, never by pooling a guardian with a credential
 * factor it does not have.
 */
export function authorityPaths(outcome: Outcome, credentialFactors: number, k: number): AuthorityPath[] {
  switch (outcome) {
    case "ASSET_MOVEMENT":
    case "CREDENTIAL_REPLACEMENT":
    case "VERIFIER_REPLACEMENT":
    case "POLICY_CHANGE":
      return [
        { name: "credential", credential: credentialFactors, guardians: 0 },
        { name: "guardian-quorum-via-recovery", credential: 0, guardians: k },
      ];
    case "GUARDIAN_TRANSITION":
    case "CONTAINMENT":
      return [{ name: "guardian-quorum", credential: 0, guardians: k }];
    // bindMigration demands BOTH legs: a quorum AND the credential. That is the
    // `k + 1` in the published table, and the `+ 1` is a SECOND PRINCIPAL, not a
    // spare guardian — so it is one conjunctive path, never a sum.
    case "MIGRATION_BINDING":
      return [{ name: "quorum-and-credential", credential: 1, guardians: k }];
    default:
      return [];
  }
}

export interface CutJudgement {
  entitled: boolean;
  held: { credential: number; guardians: number };
  paths: AuthorityPath[];
  /** Human-readable requirement, for the failure message. */
  requirement: string;
}

/** The model's independent judgement: was this root set entitled to this outcome? */
export function judgeCut(
  held: ReadonlySet<Root>,
  outcome: Outcome,
  credentialFactors: number,
  k: number,
): CutJudgement {
  const families = rootFamilies(held);
  const paths = authorityPaths(outcome, credentialFactors, k);
  const entitled = paths.some((p) => families.credential >= p.credential && families.guardians >= p.guardians);
  return {
    entitled,
    held: families,
    paths,
    requirement: paths
      .map((p) => p.name + "(credential>=" + p.credential + " AND guardians>=" + p.guardians + ")")
      .join("  OR  "),
  };
}

// =====================================================================
// Recovery evidence — the harness's OWN record, not the kernel's
// =====================================================================

export type EvidenceState = "NONE" | "LIVE" | "CANCELLED" | "CONSUMED" | "SUPERSEDED";

/**
 * One recovery episode as the HARNESS remembers it. `id` increments per
 * initiation, so "the recovery that was cancelled" and "the recovery that is
 * live now" are distinguishable objects even though the kernel stores one slot.
 */
export interface RecoveryEvidence {
  id: number;
  state: EvidenceState;
  proposedSigner: string;
  proposedPqKeyHash: string;
  proposedVerifier: string;
  boundGuardianGeneration: number;
  initiatedAtStep: number;
  /**
   * The roots that AUTHORIZED this episode, captured at initiation.
   *
   * This is what makes attribution correct for a PERMISSIONLESS finaliser.
   * `executeRecovery` may be called by a stranger holding nothing, but it
   * carries NO DISCRETION: it installs only the credential this episode already
   * committed to. Charging the credential replacement to the stranger's (empty)
   * root set would manufacture a violation on correct code; charging it to the
   * quorum that initiated the episode is the true authority statement, and it is
   * the one this lane asserts.
   */
  authorizedBy: ReadonlySet<Root>;
  /**
   * The harness's OWN count of successful guardian transitions at the moment this
   * episode was approved. R1: a constituency change after approval must void the
   * request, and comparing the harness's counter to its current value is how that
   * is judged without re-reading the kernel's generation.
   */
  guardianTransitionsAtApproval: number;
}

/**
 * The complete abstract state. Note what is ABSENT: no nonces, no deadlines, no
 * safeState enum, no balances. Those are the kernel's business. Anything the
 * model would have to copy from the kernel to predict a REVERT is deliberately
 * not here.
 */
export interface AbstractState {
  /** Every recovery the harness ever initiated, by id. */
  episodes: Map<number, RecoveryEvidence>;
  /** The id of the episode the harness believes is currently live, or null. */
  liveEpisode: number | null;
  nextEpisodeId: number;
  /** Which actor, if any, the harness believes now controls the credential. */
  credentialControlledBy: string;
  /** Guardian roster generation as the harness has counted its OWN successful transitions. */
  guardianTransitions: number;
  /** Credential replacements the harness has counted. */
  credentialReplacements: number;
  /** True once the harness has successfully bound a migration. */
  migrationBound: boolean;
  /**
   * The roots that authorized the migration binding, captured at bind time.
   * `egress` and `retire` are permissionless finalisers of that decision, so
   * any asset movement they cause is attributed HERE — for the same reason
   * `RecoveryEvidence.authorizedBy` exists.
   */
  migrationAuthorizedBy: ReadonlySet<Root>;
  /** True once the harness has observed a successful retire(). */
  retired: boolean;
}

export function freshAbstractState(genesisController: string): AbstractState {
  return {
    episodes: new Map(),
    liveEpisode: null,
    nextEpisodeId: 1,
    credentialControlledBy: genesisController,
    guardianTransitions: 0,
    credentialReplacements: 0,
    migrationBound: false,
    migrationAuthorizedBy: new Set<Root>(),
    retired: false,
  };
}

export function recordInitiation(
  s: AbstractState,
  step: number,
  proposedSigner: string,
  proposedPqKeyHash: string,
  proposedVerifier: string,
  boundGuardianGeneration: number,
  authorizedBy: ReadonlySet<Root>,
): RecoveryEvidence {
  // A NEW initiation supersedes whatever the harness thought was live. The
  // kernel overwrites its single slot; the model records that the OLD evidence
  // is now dead, which is the fact R2/R3 are asserted against.
  if (s.liveEpisode !== null) {
    const prev = s.episodes.get(s.liveEpisode);
    if (prev && prev.state === "LIVE") prev.state = "SUPERSEDED";
  }
  const ev: RecoveryEvidence = {
    id: s.nextEpisodeId++,
    state: "LIVE",
    proposedSigner,
    proposedPqKeyHash,
    proposedVerifier,
    boundGuardianGeneration,
    initiatedAtStep: step,
    authorizedBy: new Set(authorizedBy),
    guardianTransitionsAtApproval: s.guardianTransitions,
  };
  s.episodes.set(ev.id, ev);
  s.liveEpisode = ev.id;
  return ev;
}

export function recordCancellation(s: AbstractState): void {
  if (s.liveEpisode === null) return;
  const ev = s.episodes.get(s.liveEpisode);
  if (ev) ev.state = "CANCELLED";
  s.liveEpisode = null;
}

export function recordExecution(s: AbstractState, newController: string): void {
  if (s.liveEpisode !== null) {
    const ev = s.episodes.get(s.liveEpisode);
    if (ev) ev.state = "CONSUMED";
  }
  s.liveEpisode = null;
  s.credentialControlledBy = newController;
  s.credentialReplacements += 1;
}

/**
 * R2 / R3, judged by the MODEL: a recovery execution succeeded — was there any
 * live evidence for it to consume?
 *
 * Returns the violated property name, or null.
 */
export function judgeRecoveryExecution(s: AbstractState): string | null {
  if (s.liveEpisode === null) return "R2/R3 — executeRecovery succeeded with NO live recovery evidence in the model";
  const ev = s.episodes.get(s.liveEpisode);
  if (!ev) return "R2/R3 — executeRecovery succeeded against an episode the model does not know";
  if (ev.state !== "LIVE") {
    return "R2/R3 — executeRecovery succeeded on evidence the model records as " + ev.state;
  }
  return null;
}
