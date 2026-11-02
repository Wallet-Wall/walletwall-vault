/**
 * EXPERIMENTAL PROTOTYPE — THE STATEFUL AUTHORITY CAMPAIGN, ON THE GENERATION-2 CANDIDATE.
 *
 * Generation 2 does not inherit Generation 1's assurance record by declaration, so this runs the same
 * fixed seeds and depths as test/StatefulAuthorityFuzz.test.ts against the candidate: every Generation-1
 * profile with its adversary intact, plus thirteen profiles that put the ERC-20 state under direct
 * pressure. Generation 1's own campaign is untouched and still runs on Generation 1.
 *
 * Deterministic in its decisions: see the header of generation-2/stateful/campaign.ts for what that rests on. Not exhaustive, not formal
 * verification and not an audit: see "whatThisDoesNotProve" in GEN2_STATEFUL_AUTHORITY_EVIDENCE.json.
 */
import { expect } from "chai";
import { ACTION_KINDS_G2 } from "../stateful/actions.js";
import {
  CI_SEEDS_G2,
  DEPTHS_G2,
  G2_SEAMS,
  LIFECYCLE_SEAMS,
  runCampaignG2,
  type CampaignResultG2,
} from "../stateful/campaign.js";
import { G2_PROFILES, INHERITED_PROFILE_COUNT } from "../stateful/profiles.js";
import { DECLARED_CUTS } from "../../stateful/model.js";
import { SUSTAINED_DEFECTS } from "../../stateful/defects.js";
import {
  canonicalRunValue,
  readRunRecord,
  writeRunSection,
  writingRunRecord,
  type CampaignRunRecord,
} from "../run-record.js";
import { PROFILES } from "../../stateful/profiles.js";

/** Refuse-only by design: a success here is the violation, so they are the one exemption from "succeeded". */
const MUST_NEVER_SUCCEED = new Set(["RELAY_TAMPER", "CROSS_ASSET_REPLAY"]);

export interface Gen2CampaignAggregate {
  campaigns: number;
  transitions: number;
  successful: number;
  outcomes: Record<string, number>;
  actions: Record<string, number>;
  actionsThatSucceeded: Set<string>;
  reverts: Record<string, number>;
  seams: Record<string, number>;
  lifecycle: Record<string, number>;
  controlsPassed: number;
  controlsAttempted: number;
  knownDefectHits: Record<string, number>;
  violations: { profile: string; seed: number; depth: number; property: string; step: number; detail: string }[];
}

const AGG: Gen2CampaignAggregate = {
  campaigns: 0,
  transitions: 0,
  successful: 0,
  outcomes: {},
  actions: {},
  actionsThatSucceeded: new Set(),
  reverts: {},
  seams: {},
  lifecycle: {},
  controlsPassed: 0,
  controlsAttempted: 0,
  knownDefectHits: {},
  violations: [],
};

function absorb(r: CampaignResultG2): void {
  AGG.campaigns++;
  AGG.transitions += r.transitionsExercised;
  AGG.successful += r.successfulTransitions;
  AGG.controlsPassed += r.positiveControlsPassed;
  AGG.controlsAttempted += r.positiveControlsAttempted;
  for (const [k, v] of Object.entries(r.outcomeCounts)) AGG.outcomes[k] = (AGG.outcomes[k] ?? 0) + v;
  for (const [k, v] of Object.entries(r.actionCoverage)) AGG.actions[k] = (AGG.actions[k] ?? 0) + v;
  for (const [k, v] of Object.entries(r.revertCounts)) AGG.reverts[k] = (AGG.reverts[k] ?? 0) + v;
  for (const [k, v] of Object.entries(r.seams)) AGG.seams[k] = (AGG.seams[k] ?? 0) + v;
  for (const [k, v] of Object.entries(r.lifecycle)) AGG.lifecycle[k] = (AGG.lifecycle[k] ?? 0) + v;
  for (const k of r.actionsThatSucceeded) AGG.actionsThatSucceeded.add(k);
  for (const v of r.violations) AGG.violations.push({ profile: r.profile, seed: r.seed, depth: r.depth, ...v });
  for (const k of r.knownDefectHits) AGG.knownDefectHits[k.defect] = (AGG.knownDefectHits[k.defect] ?? 0) + 1;
}

/** The failure message is the replay instruction: a violation nobody can reproduce is an anecdote. */
function describeFailure(r: CampaignResultG2): string {
  const lines = ["", "GENERATION-2 STATEFUL VIOLATION", `  profile=${r.profile} seed=${r.seed} depth=${r.depth}`, ""];
  for (const v of r.violations) lines.push(`    [${v.property}] step ${v.step}: ${v.detail}`);
  const firstBad = Math.max(r.violations[0]?.step ?? 0, 0);
  lines.push("", "  TRAIL around the first violation:");
  for (const s of r.steps.slice(Math.max(0, firstBad - 8), firstBad + 2)) {
    lines.push(
      `    ${s.step}. ${s.kind} by ${s.caller}${s.ok ? " OK" : " REVERT:" + s.revert}${s.outcomes.length ? " outcomes=" + s.outcomes.join("+") : ""}`,
    );
  }
  lines.push(
    "",
    "  REPRODUCE: npx hardhat --config prototype/vnext-kernel/hardhat.config.ts test prototype/vnext-kernel/generation-2/test/Gen2StatefulCampaign.test.ts",
    "",
  );
  return lines.join("\n");
}

describe("Generation-2 candidate — STATEFUL ADVERSARIAL AUTHORITY CAMPAIGN", function () {
  this.timeout(1_200_000);

  it("runs every Generation-1 profile, in Generation 1's order, before its own", function () {
    expect(INHERITED_PROFILE_COUNT).to.equal(PROFILES.length);
    expect(G2_PROFILES.slice(0, INHERITED_PROFILE_COUNT).map((p) => p.name)).to.deep.equal(PROFILES.map((p) => p.name));
    expect(new Set(G2_PROFILES.map((p) => p.name)).size, "profile names must be unique").to.equal(G2_PROFILES.length);
  });

  for (const tier of ["shallow", "medium", "deep"] as const) {
    describe(`tier: ${tier} (depth ${DEPTHS_G2[tier]})`, function () {
      for (const profile of G2_PROFILES) {
        for (const seed of CI_SEEDS_G2[tier]) {
          it(`${profile.name} @ seed ${seed}`, async function () {
            const r = await runCampaignG2(profile.name, seed, DEPTHS_G2[tier], `g2-${tier}-${profile.name}-${seed}`);
            absorb(r);
            expect(r.violations, describeFailure(r)).to.deep.equal([]);
          });
        }
      }
    });
  }

  // ANTI-VACUITY. Without these, a campaign in which everything reverted would pass every property above.
  describe("campaign adequacy — the results above mean something only if these hold", function () {
    it("every positive control passed in every campaign", function () {
      expect(AGG.controlsAttempted).to.be.greaterThan(0);
      expect(
        AGG.controlsPassed,
        "a fully-authorised honest sequence failed, so every safety result above is vacuous",
      ).to.equal(AGG.controlsAttempted);
    });

    it("every generated action kind succeeded somewhere, except the two whose success would be the violation", function () {
      const never = ACTION_KINDS_G2.filter((k) => !AGG.actionsThatSucceeded.has(k) && !MUST_NEVER_SUCCEED.has(k));
      expect(
        never,
        "these actions NEVER succeeded, so the campaign never reached their seam: " + never.join(", "),
      ).to.deep.equal([]);
      for (const k of MUST_NEVER_SUCCEED) {
        expect(AGG.actions[k] ?? 0, k + " was never attempted").to.be.greaterThan(0);
        expect(AGG.actionsThatSucceeded.has(k), k + " SUCCEEDED").to.equal(false);
      }
    });

    it("every protected OUTCOME was actually reached", function () {
      const never = Object.keys(DECLARED_CUTS).filter((o) => (AGG.outcomes[o] ?? 0) === 0);
      expect(never, "these protected outcomes NEVER occurred: " + never.join(", ")).to.deep.equal([]);
    });

    it("every Generation-2 seam was actually reached", function () {
      console.log("\n  GENERATION-2 SEAMS REACHED\n" + JSON.stringify(AGG.seams, null, 2).replace(/^/gm, "  "));
      const never = G2_SEAMS.filter((s) => (AGG.seams[s] ?? 0) === 0);
      expect(
        never,
        "these seams were NEVER reached, so the properties about them were never exercised: " + never.join(", "),
      ).to.deep.equal([]);
    });

    it("every recovery-lifecycle seam Generation 1 requires was reached here too", function () {
      const never = LIFECYCLE_SEAMS.filter((s) => (AGG.lifecycle[s] ?? 0) === 0);
      expect(never, "never reached on the candidate: " + never.join(", ")).to.deep.equal([]);
    });

    it("attacks reached the authority seams rather than failing on shape", function () {
      const authorityRejections =
        (AGG.reverts.BadSignature ?? 0) +
        (AGG.reverts.QuorumNotMet ?? 0) +
        (AGG.reverts.NotOrdered ?? 0) +
        (AGG.reverts.BadRoster ?? 0);
      expect(authorityRejections, "attacks never reached an authority gate").to.be.greaterThan(100);
      const harness = Object.entries(AGG.reverts).filter(
        ([k]) => k.startsWith("HARNESS_ENCODE") || k.startsWith("LEVER:") || k.startsWith("UNDECODED_ERROR"),
      );
      expect(harness, "the harness itself failed: " + JSON.stringify(harness)).to.deep.equal([]);
    });

    it("every sustained defect with a campaign property still reproduces on the candidate", function () {
      // Not a suppression list: a listed defect that stops surfacing means a fix landed or coverage was lost.
      const missing = SUSTAINED_DEFECTS.filter((d) => d.property !== null && (AGG.knownDefectHits[d.id] ?? 0) === 0);
      expect(
        missing.map((d) => d.id),
        "did not reproduce on the candidate",
      ).to.deep.equal([]);
    });

    it("prints the campaign summary", function () {
      const summary = {
        campaigns: AGG.campaigns,
        transitions: AGG.transitions,
        successful: AGG.successful,
        outcomes: AGG.outcomes,
        actions: AGG.actions,
        reverts: Object.fromEntries(Object.entries(AGG.reverts).sort((a, b) => b[1] - a[1])),
        positiveControls: `${AGG.controlsPassed}/${AGG.controlsAttempted}`,
        knownDefectHits: AGG.knownDefectHits,
        lifecycle: AGG.lifecycle,
        violations: AGG.violations.length,
      };
      console.log("\n  GENERATION-2 CAMPAIGN SUMMARY\n" + JSON.stringify(summary, null, 2).replace(/^/gm, "  "));
      expect(AGG.violations).to.deep.equal([]);
    });

    it("the outcome is the committed record, exactly: same profile, seed, depth and label, same decisions", function () {
      const run: CampaignRunRecord = {
        campaigns: AGG.campaigns,
        transitions: AGG.transitions,
        successful: AGG.successful,
        violations: AGG.violations.length,
        positiveControls: `${AGG.controlsPassed}/${AGG.controlsAttempted}`,
        outcomes: AGG.outcomes,
        actions: AGG.actions,
        reverts: AGG.reverts,
        seams: AGG.seams,
        lifecycle: AGG.lifecycle,
        knownDefectHits: AGG.knownDefectHits,
      };
      if (writingRunRecord()) writeRunSection({ campaign: run });
      expect(canonicalRunValue(run), "regenerate with G2_WRITE_RUN_RECORD=1 and review the diff").to.deep.equal(
        readRunRecord().campaign,
      );
    });
  });
});
