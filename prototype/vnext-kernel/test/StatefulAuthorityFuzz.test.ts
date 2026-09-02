/**
 * EXPERIMENTAL PROTOTYPE — STATEFUL ADVERSARIAL AUTHORITY / RECOVERY CAMPAIGN.
 *
 * WHAT THIS LANE ASKS THAT THE OTHERS DO NOT
 * ------------------------------------------
 *   Slither (vNext Kernel / Slither) asks: do the IMPLEMENTATION PATTERNS look unsafe?
 *   authority/check.ts        asks: is EVERY privileged external path classified and
 *                                  routed to its intended authority mechanism?
 *   THIS FILE                 asks: can individually-valid, individually-correctly-gated
 *                                  transitions be COMPOSED OVER TIME into an outcome
 *                                  below its declared cut?
 *
 * It reasons about `STATE + ACTION + AUTHORITY -> NEXT STATE`, not about
 * `FUNCTION -> EXPECTED GATE`. It does not duplicate or replace either of the
 * other two, and it is not evidence that they are complete.
 *
 * DETERMINISM
 * -----------
 * Every campaign here is a pure function of (profile, seed, depth). There is NO
 * clock-derived or environment-derived randomness anywhere in this lane, so a
 * failure is reproducible from the seed printed beside it and CI never depends
 * on a lucky draw. Broader RANDOM exploration is available locally and is
 * deliberately NOT part of the required check — see stateful/README.md.
 *
 * WHAT A PASS HERE DOES NOT MEAN
 * ------------------------------
 * Not exhaustive. Not formal verification. Not an audit. It does not prove
 * guardian off-chain independence (H-31) and it makes no cryptographic claim
 * about the PQ scheme — the second factor is an INDEPENDENT ECDSA keypair
 * standing in for one, which makes "the attacker lacks the second root" a real
 * fact in this harness but says nothing about ML-DSA.
 */
import { expect } from "chai";
import { existsSync, readFileSync } from "node:fs";
import { PROFILES } from "../stateful/profiles.js";
import { MUTATIONS } from "../stateful/mutants.js";
import { runCampaign, type CampaignResult } from "../stateful/campaign.js";
import { DECLARED_CUTS } from "../stateful/model.js";
import { ACTION_KINDS } from "../stateful/actions.js";
import { GLOBAL_INVARIANTS } from "../stateful/invariants.js";
import { SUSTAINED_DEFECTS } from "../stateful/defects.js";

/**
 * THE FIXED CI SEED SET. Required CI runs exactly these; nothing here draws a
 * seed from the clock. Changing this list changes what CI proves, so it is a
 * deliberate, reviewable edit rather than a knob.
 */
export const CI_SEEDS = {
  /** Many shallow runs — broad reach into early-state combinations. */
  shallow: [1, 2, 3, 5, 8, 13, 21, 34],
  /** Moderate depth — where most composition actually lives. */
  medium: [101, 211, 331, 457],
  /** Long histories — stale authorizations, expiries, window rollovers. */
  deep: [90210, 133742],
} as const;

export const DEPTHS = { shallow: 25, medium: 65, deep: 150 } as const;

/** Collected across every campaign so the anti-vacuity assertions can be global. */
interface Aggregate {
  campaigns: number;
  transitions: number;
  successful: number;
  outcomes: Record<string, number>;
  actions: Record<string, number>;
  actionsThatSucceeded: Set<string>;
  reverts: Record<string, number>;
  violations: { profile: string; seed: number; depth: number; property: string; step: number; detail: string }[];
  controlsPassed: number;
  controlsAttempted: number;
  knownDefectHits: Record<string, number>;
}

const AGG: Aggregate = {
  campaigns: 0,
  transitions: 0,
  successful: 0,
  outcomes: {},
  actions: {},
  actionsThatSucceeded: new Set(),
  reverts: {},
  violations: [],
  controlsPassed: 0,
  controlsAttempted: 0,
  knownDefectHits: {},
};

function absorb(r: CampaignResult): void {
  AGG.campaigns++;
  AGG.transitions += r.transitionsExercised;
  AGG.successful += r.successfulTransitions;
  AGG.controlsPassed += r.positiveControlsPassed;
  AGG.controlsAttempted += r.positiveControlsAttempted;
  for (const [k, v] of Object.entries(r.outcomeCounts)) AGG.outcomes[k] = (AGG.outcomes[k] ?? 0) + v;
  for (const [k, v] of Object.entries(r.actionCoverage)) AGG.actions[k] = (AGG.actions[k] ?? 0) + v;
  for (const [k, v] of Object.entries(r.revertCounts)) AGG.reverts[k] = (AGG.reverts[k] ?? 0) + v;
  for (const s of r.steps) if (s.ok) AGG.actionsThatSucceeded.add(s.kind);
  for (const v of r.violations) {
    AGG.violations.push({ profile: r.profile, seed: r.seed, depth: r.depth, ...v });
  }
  for (const k of r.knownDefectHits) {
    AGG.knownDefectHits[k.defect] = (AGG.knownDefectHits[k.defect] ?? 0) + 1;
  }
}

/**
 * The failure message IS the replay instruction. A fuzz failure nobody can
 * reproduce is an anecdote, so every assertion below prints the exact seed,
 * profile, depth, minimised sequence and command.
 */
function describeFailure(r: CampaignResult): string {
  const lines: string[] = [
    "",
    "STATEFUL AUTHORITY VIOLATION",
    "  profile : " + r.profile,
    "  seed    : " + r.seed,
    "  depth   : " + r.depth,
    "",
    "  violations:",
  ];
  for (const v of r.violations) lines.push("    [" + v.property + "] step " + v.step + ": " + v.detail);
  if (r.minimalSequence) {
    lines.push("", "  MINIMISED SEQUENCE (" + r.minimalSequence.length + " actions):");
    r.minimalSequence.forEach((a, i) => {
      lines.push("    " + i + ". " + a.kind + " by " + a.actorName + " " + JSON.stringify(a.params));
    });
  }
  const firstBad = r.violations[0]?.step ?? 0;
  lines.push("", "  TRAIL around the first violation:");
  for (const s of r.steps.slice(Math.max(0, firstBad - 6), firstBad + 2)) {
    lines.push(
      "    " + s.step + ". " + s.kind + " by " + s.caller +
        " roots{" + s.callerRootsHeld.join(",") + "}" +
        " " + s.preState + "->" + s.postState +
        (s.ok ? " OK" : " REVERT:" + s.revert) +
        (s.outcomesObserved.length ? " outcomes=" + s.outcomesObserved.join("+") : ""),
    );
  }
  lines.push(
    "",
    "  REPRODUCE:",
    "    npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test \\",
    "      prototype/vnext-kernel/test/StatefulAuthorityFuzz.test.ts",
    "    (this exact case: profile=" + r.profile + " seed=" + r.seed + " depth=" + r.depth + ")",
    "",
  );
  return lines.join("\n");
}

describe("vNext kernel — STATEFUL ADVERSARIAL AUTHORITY CAMPAIGN", function () {
  // Deterministic and fast (roughly 15ms per transition), but the deep tier and
  // the per-campaign positive controls add up, so the budget is generous.
  this.timeout(900_000);

  for (const tier of ["shallow", "medium", "deep"] as const) {
    describe("campaign tier: " + tier + " (depth " + DEPTHS[tier] + ")", function () {
      for (const profile of PROFILES) {
        for (const seed of CI_SEEDS[tier]) {
          it(profile.name + " @ seed " + seed, async function () {
            const r = await runCampaign(profile.name, seed, DEPTHS[tier], tier + "-" + profile.name + "-" + seed);
            absorb(r);
            expect(r.violations, describeFailure(r)).to.deep.equal([]);
          });
        }
      }
    });
  }

  // =====================================================================
  // ANTI-VACUITY. Without these, a campaign in which every action reverted
  // would pass every safety property above while proving nothing at all.
  // =====================================================================
  describe("campaign adequacy — the results above are only meaningful if these hold", function () {
    it("every positive control passed in every campaign", function () {
      expect(AGG.controlsAttempted).to.be.greaterThan(0);
      expect(
        AGG.controlsPassed,
        "a fully-authorised honest action failed, so every safety result above is vacuous",
      ).to.equal(AGG.controlsAttempted);
    });

    it("every generated action kind SUCCEEDED at least once somewhere", function () {
      const never = ACTION_KINDS.filter((k) => !AGG.actionsThatSucceeded.has(k));
      expect(
        never,
        "these actions NEVER succeeded in any campaign, so the campaign never reached their seam: " +
          never.join(", "),
      ).to.deep.equal([]);
    });

    it("every protected OUTCOME was actually reached at least once", function () {
      const outcomes = Object.keys(DECLARED_CUTS);
      const never = outcomes.filter((o) => (AGG.outcomes[o] ?? 0) === 0);
      expect(
        never,
        "these protected outcomes NEVER occurred, so the cut property for them was never exercised: " +
          never.join(", "),
      ).to.deep.equal([]);
    });

    it("attacks actually reached the authority seams rather than failing on shape", function () {
      // A campaign whose attacks all die on malformed calldata proves nothing
      // about authority. BadSignature / QuorumNotMet / NotOrdered are the AUTHORITY
      // rejections; seeing them in volume is what shows the seam was reached.
      const authorityRejections =
        (AGG.reverts.BadSignature ?? 0) +
        (AGG.reverts.QuorumNotMet ?? 0) +
        (AGG.reverts.NotOrdered ?? 0) +
        (AGG.reverts.BadRoster ?? 0);
      expect(authorityRejections, "attacks never reached an authority gate").to.be.greaterThan(100);
      const harnessErrors = Object.entries(AGG.reverts).filter(([k]) => k.startsWith("HARNESS_ENCODE"));
      expect(harnessErrors, "the harness failed to encode calls: " + JSON.stringify(harnessErrors)).to.deep.equal([]);
    });

    it("every sustained defect with a campaign property is STILL reproducing", function () {
      // The ledger in stateful/defects.ts is not a suppression list. A listed
      // defect that stops surfacing means either a fix landed (in which case the
      // ledger and AUTHORITY.md must be updated together) or the campaign lost
      // the coverage that found it. Both need a human; neither may pass silently.
      const withProperty = SUSTAINED_DEFECTS.filter((d) => d.property !== null);
      const missing = withProperty.filter((d) => (AGG.knownDefectHits[d.id] ?? 0) === 0);
      expect(
        missing.map((d) => d.id),
        "these listed sustained defects did NOT reproduce in any campaign. Either they were fixed — " +
          "in which case update stateful/defects.ts, StatefulSustainedDefects.test.ts and AUTHORITY.md " +
          "together — or the campaign lost the coverage that found them.",
      ).to.deep.equal([]);
    });

    it("the evidence receipt describes the matrix that actually ran", function () {
      // A receipt that drifts from the executed matrix is worse than no receipt:
      // it publishes coverage nobody performed. The numbers are asserted here so
      // the two can only move together.
      const receiptPath = "prototype/vnext-kernel/STATEFUL_AUTHORITY_EVIDENCE.json";
      if (!existsSync(receiptPath)) {
        throw new Error(
          "STATEFUL_AUTHORITY_EVIDENCE.json is missing. Regenerate it: " +
            "npx tsx prototype/vnext-kernel/generate-stateful-evidence.ts",
        );
      }
      const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as {
        campaigns: { plannedCampaigns: number; plannedTransitions: number; profiles: unknown[] };
        properties: { globalInvariants: unknown[] };
        mutationAdequacy: { mutations: unknown[] };
      };
      const expectedCampaigns =
        PROFILES.length * (CI_SEEDS.shallow.length + CI_SEEDS.medium.length + CI_SEEDS.deep.length);
      expect(receipt.campaigns.plannedCampaigns, "receipt campaign count is stale").to.equal(expectedCampaigns);
      expect(AGG.campaigns, "the executed matrix does not match the receipt").to.equal(expectedCampaigns);
      expect(receipt.campaigns.plannedTransitions, "receipt transition count is stale").to.equal(AGG.transitions);
      expect(receipt.campaigns.profiles.length).to.equal(PROFILES.length);
      expect(receipt.properties.globalInvariants.length).to.equal(GLOBAL_INVARIANTS.length);
      expect(receipt.mutationAdequacy.mutations.length).to.equal(MUTATIONS.length);
    });

    it("prints the campaign summary", function () {
      const summary = {
        campaigns: AGG.campaigns,
        transitionsExercised: AGG.transitions,
        successfulTransitions: AGG.successful,
        globalInvariantsChecked: GLOBAL_INVARIANTS.length,
        outcomesObserved: AGG.outcomes,
        actionCoverage: AGG.actions,
        topReverts: Object.fromEntries(
          Object.entries(AGG.reverts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 12),
        ),
        positiveControls: AGG.controlsPassed + "/" + AGG.controlsAttempted,
        knownDefectHits: AGG.knownDefectHits,
        violations: AGG.violations.length,
      };
      console.log("\n  STATEFUL CAMPAIGN SUMMARY\n" + JSON.stringify(summary, null, 2).replace(/^/gm, "  "));
      expect(AGG.violations).to.deep.equal([]);
    });
  });
});
