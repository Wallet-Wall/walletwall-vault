/**
 * EXPERIMENTAL PROTOTYPE — MUTATION ADEQUACY FOR THE STATEFUL CAMPAIGN.
 *
 * PROVES THE PROPERTIES HAVE TEETH.
 *
 * "The campaign found nothing" is worth exactly nothing until you know the
 * campaign COULD have found something. Each mutation below compiles a real,
 * deliberately WEAKENED kernel in memory, deploys it, and points the SAME
 * campaign machinery at it. A mutation the campaign does not kill is a hole in
 * the properties and is reported as a SURVIVOR — never quietly dropped.
 *
 * Nine of the sixteen reintroduce a defect that was ACTUALLY REPRODUCED against
 * an earlier revision of this kernel (AUTHORITY.md section 0: A1, A2, B, D, F),
 * so the score is not synthetic. It is a regression proof that the historical
 * bypass classes are still caught — now by COMPOSITION over arbitrary histories
 * rather than by a hand-written attack aimed at the known spot.
 *
 * NOTHING HERE WRITES TO contracts/. Mutants exist only in memory, compiled by
 * the same PINNED solc the reproducibility check uses, and the real
 * prototype/vnext-kernel/artifacts/ and cache are never touched.
 */
import { expect } from "chai";
import { MUTATIONS, buildMutant, type DeployableMutant } from "../stateful/mutants.js";
import { runCampaign } from "../stateful/campaign.js";

/** Seeds tried per mutation, in order, until one catches it. Fixed — never random. */
const MUTATION_SEEDS = [11, 29, 47, 83, 131, 197, 251, 307] as const;
const MUTATION_DEPTH = 90;

export type MutationVerdict = "KILLED" | "SURVIVED" | "INCONCLUSIVE";

export interface MutationOutcome {
  id: string;
  verdict: MutationVerdict;
  expectedProperty: string;
  killedBy: { profile: string; seed: number; property: string; step: number } | null;
  minimalSequence: string[] | null;
  successfulTransitions: number;
  note: string;
}

const RESULTS: MutationOutcome[] = [];

describe("vNext kernel — STATEFUL MUTATION ADEQUACY", function () {
  this.timeout(1_800_000);

  /**
   * Every mutant is compiled UP FRONT, before any network interaction.
   * `execFileSync` blocks the event loop, and doing that while an in-process EVM
   * request is in flight is how a harness deadlocks; compiling first keeps the
   * two phases disjoint.
   */
  const compiled = new Map<string, DeployableMutant>();
  const compileFailures: { id: string; errors: string[] }[] = [];

  before(function () {
    for (const m of MUTATIONS) {
      let built;
      try {
        built = buildMutant(m);
      } catch (e) {
        // replaceWithinFunction throws when the target snippet is not found
        // EXACTLY once. That is deliberate: a mutation that silently became a
        // no-op would score as a survivor and be read as a gap in the campaign,
        // when the real fault is a stale snippet in this catalogue.
        compileFailures.push({ id: m.id, errors: [e instanceof Error ? e.message : String(e)] });
        continue;
      }
      if (built.ok) compiled.set(m.id, built.kernel);
      else compileFailures.push({ id: m.id, errors: built.errors });
    }
  });

  it("every mutation in the catalogue applies and compiles", function () {
    expect(
      compileFailures,
      "a mutation failed to apply or compile — its snippet is stale against the current kernel, " +
        "so it would have been scored as a SURVIVOR while testing nothing:\n" +
        JSON.stringify(compileFailures, null, 2),
    ).to.deep.equal([]);
    expect(compiled.size).to.equal(MUTATIONS.length);
  });

  for (const m of MUTATIONS) {
    it("kills " + m.id, async function () {
      const kernel = compiled.get(m.id);
      expect(kernel, "mutant " + m.id + " did not compile").to.not.equal(undefined);

      let killedBy: MutationOutcome["killedBy"] = null;
      let minimal: string[] | null = null;
      let bestSuccessful = 0;

      outer: for (const profile of m.profiles) {
        for (const seed of MUTATION_SEEDS) {
          const r = await runCampaign(profile, seed, MUTATION_DEPTH, "mut-" + m.id + "-" + profile + "-" + seed, {
            implOverride: kernel,
          });
          bestSuccessful = Math.max(bestSuccessful, r.successfulTransitions);
          const hit = r.violations.find((v) => v.property === m.expectedProperty) ?? r.violations[0];
          if (hit) {
            killedBy = { profile, seed, property: hit.property, step: hit.step };
            minimal = (r.minimalSequence ?? []).map(
              (a) => a.kind + " by " + a.actorName + " " + JSON.stringify(a.params),
            );
            break outer;
          }
        }
      }

      // THE VACUITY GUARD. A mutant that cannot even transact would "die" for
      // the wrong reason, and a mutant that dies while doing nothing proves
      // nothing about the properties.
      const reachedKernel = bestSuccessful > 0;
      const verdict: MutationVerdict = killedBy ? "KILLED" : reachedKernel ? "SURVIVED" : "INCONCLUSIVE";

      RESULTS.push({
        id: m.id,
        verdict,
        expectedProperty: m.expectedProperty,
        killedBy,
        minimalSequence: minimal,
        successfulTransitions: bestSuccessful,
        note: m.rationale,
      });

      expect(
        reachedKernel,
        "INCONCLUSIVE: mutant " + m.id + " never completed a single successful transition, so its " +
          "campaign proves nothing — the mutant is broken, not caught.",
      ).to.equal(true);

      expect(
        verdict,
        "SURVIVOR: " + m.id + " was NOT detected by any stateful property across profiles [" +
          m.profiles.join(", ") + "] and seeds [" + MUTATION_SEEDS.join(", ") + "].\n" +
          "  expected property : " + m.expectedProperty + "\n" +
          "  why it matters    : " + m.rationale + "\n" +
          "  An unexplained survivor is a STOP condition: the campaign does not cover this class.",
      ).to.equal("KILLED");
    });
  }

  it("prints the mutation kill matrix", function () {
    const rows = RESULTS.map(
      (r) =>
        "  " +
        r.verdict.padEnd(13) +
        r.id.padEnd(42) +
        (r.killedBy
          ? "by " + r.killedBy.property + " (" + r.killedBy.profile + " seed " + r.killedBy.seed + ", step " + r.killedBy.step + ")"
          : "NOT CAUGHT"),
    );
    console.log(
      "\n  STATEFUL MUTATION KILL MATRIX (" +
        RESULTS.filter((r) => r.verdict === "KILLED").length +
        "/" +
        RESULTS.length +
        " killed)\n" +
        rows.join("\n"),
    );
    const survivors = RESULTS.filter((r) => r.verdict !== "KILLED");
    expect(survivors, "unexplained survivors: " + JSON.stringify(survivors, null, 2)).to.deep.equal([]);
  });

  /**
   * KILL ATTRIBUTION, asserted rather than merely printed — for the SD-1 mutant.
   *
   * The harness PREFERS a violation matching `expectedProperty` but falls back to
   * `violations[0]`, so "KILLED" alone does not say a mutant died for the reason
   * its author claimed. That is tolerable for a catalogue of historical
   * regressions, and M13 already dies by `P-CUT/CONTAINMENT` rather than its
   * declared `P-CUT/GUARDIAN_TRANSITION` — a PRE-EXISTING mismatch this lane
   * deliberately does not touch.
   *
   * It is NOT tolerable for the mutant that is this change's own adequacy
   * evidence. M17 reintroduces SD-1; if it died by some unrelated property, the
   * claim "the assurance machinery detects a reintroduced SD-1" would be false
   * while the suite stayed green. So this one is pinned.
   */
  it("the SD-1 mutant is killed BY THE PROPERTY THAT COVERS IT, not by an unrelated violation", function () {
    const m17 = RESULTS.find((r) => r.id === "M17-floor-shape-mutable-again");
    expect(m17, "M17 must be in the catalogue — it is this change's adequacy evidence").to.not.equal(undefined);
    expect(m17!.verdict).to.equal("KILLED");
    expect(
      m17!.killedBy?.property,
      "M17 must die by G-FLOOR-NO-DOWNGRADE. A kill by any other property would mean the campaign " +
        "noticed something else about the weakened kernel, and would say nothing about whether the " +
        "reintroduced SD-1 defect itself is detected.",
    ).to.equal("G-FLOOR-NO-DOWNGRADE");
    expect(m17!.killedBy?.property).to.equal(m17!.expectedProperty);
  });

  /**
   * The same pin for the SD-3 / SD-4 mutants, for the same reason: they are this
   * change's adequacy evidence, so "KILLED" alone is not enough — each must die
   * by the property that encodes the invariant it removes.
   *
   * M19/M20 dying by `G-PQ-COMMITMENT-SATISFIABLE` is ALSO the proof that
   * de-listing SD-3 from `KNOWN_DEFECT_PROPERTIES` mattered. While the defect
   * stood, that property's violations were filtered out of `violations` and
   * merely counted, so both mutants reported SURVIVED for a bookkeeping reason
   * rather than a coverage one. That was observed firsthand before the ledger
   * moved, and it is why the ledger update is part of the fix rather than
   * paperwork that follows it.
   */
  it("the SD-3 mutants are each killed BY THE PROPERTY THAT ENCODES THEIR INVARIANT", function () {
    const expected: Record<string, string> = {
      "M19-declaration-not-exhibited": "G-PQ-COMMITMENT-SATISFIABLE",
      "M20-declaration-unbound-from-the-commitment": "G-PQ-COMMITMENT-SATISFIABLE",
    };
    for (const [id, property] of Object.entries(expected)) {
      const r = RESULTS.find((x) => x.id === id);
      expect(r, id + " must be in the catalogue").to.not.equal(undefined);
      expect(r!.verdict, id + " must be killed").to.equal("KILLED");
      expect(
        r!.killedBy?.property,
        id + " must die by " + property + ". A kill by any other property would mean the campaign " +
          "noticed something else about the weakened kernel and says nothing about the invariant removed.",
      ).to.equal(property);
      expect(r!.killedBy?.property).to.equal(r!.expectedProperty);
    }
  });
});

export { RESULTS as MUTATION_RESULTS };
