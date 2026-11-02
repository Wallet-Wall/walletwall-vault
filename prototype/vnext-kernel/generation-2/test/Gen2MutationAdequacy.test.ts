/**
 * EXPERIMENTAL PROTOTYPE — MUTATION ADEQUACY FOR THE GENERATION-2 CAMPAIGN.
 *
 * "The campaign found nothing" is worth nothing until it is shown the campaign COULD have found something.
 * The Generation-2 catalogue runs with strict attribution, and Generation 1's whole catalogue runs against
 * the candidate as well: its bypass classes must stay caught on a kernel that spends an ERC-20.
 *
 * Nothing here writes to contracts/ or generation-2/contracts/: mutants exist in memory only.
 */
import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";

import { GEN2_CONTRACTS, GEN2_FACTORY, GEN2_KERNEL, compileGen2 } from "../compile.js";
import type { CompiledUnit } from "../../erc20-spend-plane/compile.js";
import {
  MUTATION_DEPTH_G2,
  MUTATION_SEEDS_G2,
  POSITIVE_CONTROL_LABELS,
  runCampaignG2,
  type CampaignResultG2,
} from "../stateful/campaign.js";
import { GEN1_CATALOGUE_EXTRA_PROFILES, GEN1_CATALOGUE_NOT_APPLICABLE, G2_MUTATIONS } from "../stateful/mutants.js";
import { G2_PROPERTIES } from "../stateful/invariants.js";
import {
  canonicalRunValue,
  readRunRecord,
  writeRunSection,
  writingRunRecord,
  type MutationRunRow,
} from "../run-record.js";
import { G2_PROFILES } from "../stateful/profiles.js";
import { MUTATIONS } from "../../stateful/mutants.js";

const KERNEL_FILE = "VaultKernelGen2Prototype.sol";
const FACTORY_FILE = "VaultKernelGen2FactoryPrototype.sol";

export type MutationVerdict = "KILLED" | "SURVIVED" | "INCONCLUSIVE";

export interface G2MutationOutcome {
  id: string;
  verdict: MutationVerdict;
  expectedProperty: string;
  killedBy: { profile: string; seed: number; property: string; step: number } | null;
  live: boolean;
  bestSuccessful: number;
  campaigns: number;
}

const G2_RESULTS: G2MutationOutcome[] = [];
const GEN1_RESULTS: G2MutationOutcome[] = [];

interface Built {
  kernel: CompiledUnit;
  factory?: CompiledUnit;
}

describe("Generation-2 candidate — MUTATION ADEQUACY", function () {
  this.timeout(1_800_000);

  const kernelSource = fs.readFileSync(path.join(GEN2_CONTRACTS, KERNEL_FILE), "utf8");
  const factorySource = fs.readFileSync(path.join(GEN2_CONTRACTS, FACTORY_FILE), "utf8");
  const built = new Map<string, Built>();
  const failures: { id: string; error: string }[] = [];

  // Compiled up front: execFileSync blocks the event loop, and doing that with an in-process EVM request in flight deadlocks.
  before(function () {
    for (const m of G2_MUTATIONS) {
      try {
        const overrides: Record<string, string> = { [KERNEL_FILE]: m.apply(kernelSource) };
        if (m.applyFactory) overrides[FACTORY_FILE] = m.applyFactory(factorySource);
        const units = compileGen2({
          overrides,
          only: m.applyFactory ? [GEN2_KERNEL, GEN2_FACTORY] : [GEN2_KERNEL],
        }).units;
        built.set(m.id, {
          kernel: units.get(GEN2_KERNEL)!,
          factory: m.applyFactory ? units.get(GEN2_FACTORY)! : undefined,
        });
      } catch (e) {
        failures.push({ id: m.id, error: e instanceof Error ? e.message : String(e) });
      }
    }
    for (const m of MUTATIONS) {
      if (GEN1_CATALOGUE_NOT_APPLICABLE[m.id] !== undefined) continue;
      try {
        const units = compileGen2({ overrides: { [KERNEL_FILE]: m.apply(kernelSource) }, only: [GEN2_KERNEL] }).units;
        built.set(m.id, { kernel: units.get(GEN2_KERNEL)! });
      } catch (e) {
        failures.push({ id: m.id, error: e instanceof Error ? e.message : String(e) });
      }
    }
  });

  it("every mutation in both catalogues applies and compiles", function () {
    expect(
      failures,
      "a stale anchor would score as a survivor while testing nothing:\n" + JSON.stringify(failures, null, 2),
    ).to.deep.equal([]);
    expect(built.size).to.equal(
      G2_MUTATIONS.length + MUTATIONS.length - Object.keys(GEN1_CATALOGUE_NOT_APPLICABLE).length,
    );
  });

  it("every profile a mutant names exists", function () {
    const names = new Set(G2_PROFILES.map((p) => p.name));
    for (const m of [...G2_MUTATIONS, ...MUTATIONS])
      for (const p of m.profiles) expect(names.has(p), `${m.id} names ${p}`).to.equal(true);
  });

  /**
   * A KILL COUNTS ONLY AGAINST A CLEAN BASELINE. The catalogue's seeds are not the required matrix's, so the same
   * profile, seed, depth and label are also run on the REAL candidate: a violation there is a defect in the candidate
   * and not a kill, and it fails the suite rather than scoring for the mutant.
   */
  async function hunt(
    id: string,
    profiles: readonly string[],
    options: { factory?: CompiledUnit; signingDomainVault?: string; signedSpendRecipient?: string },
    kernel: CompiledUnit,
    stop: (r: CampaignResultG2) => { property: string; step: number } | null,
    live: (r: CampaignResultG2) => boolean,
  ): Promise<Omit<G2MutationOutcome, "id" | "expectedProperty">> {
    let killedBy: G2MutationOutcome["killedBy"] = null;
    let isLive = false;
    let bestSuccessful = 0;
    let campaigns = 0;
    outer: for (const profile of profiles) {
      for (const seed of MUTATION_SEEDS_G2) {
        const r = await runCampaignG2(profile, seed, MUTATION_DEPTH_G2, `mut-${id}-${profile}-${seed}`, {
          implOverride: kernel,
          factoryOverride: options.factory,
          signingDomainVault: options.signingDomainVault,
          signedSpendRecipient: options.signedSpendRecipient,
        });
        campaigns++;
        bestSuccessful = Math.max(bestSuccessful, r.successfulTransitions);
        const liveHere = live(r);
        isLive = isLive || liveHere;
        const hit = stop(r);
        if (hit && liveHere) {
          const baseline = await runCampaignG2(profile, seed, MUTATION_DEPTH_G2, `mut-${id}-${profile}-${seed}`);
          expect(
            baseline.violations,
            `${id}: the REAL candidate violates at ${profile} seed ${seed}, so this is a defect and not a kill`,
          ).to.deep.equal([]);
          killedBy = { profile, seed, property: hit.property, step: hit.step };
          break outer;
        }
      }
    }
    return {
      verdict: killedBy ? "KILLED" : isLive ? "SURVIVED" : "INCONCLUSIVE",
      killedBy,
      live: isLive,
      bestSuccessful,
      campaigns,
    };
  }

  describe("the Generation-2 catalogue: live, and killed by the named property", function () {
    for (const m of G2_MUTATIONS) {
      it(`kills ${m.id} by ${m.expectedProperty}`, async function () {
        const b = built.get(m.id);
        expect(b, `${m.id} did not compile`).to.not.equal(undefined);
        const outcome = await hunt(
          m.id,
          m.profiles,
          {
            factory: b!.factory,
            signingDomainVault: m.signingDomainVault,
            signedSpendRecipient: m.signedSpendRecipient,
          },
          b!.kernel,
          (r) => {
            const hit = r.violations.find((v) => v.property === m.expectedProperty);
            const others = (m.alsoExpected ?? []).every((p) => r.violations.some((v) => v.property === p));
            return hit && others ? { property: hit.property, step: hit.step } : null;
          },
          (r) => r.controlsPassedLabels.includes(m.liveControl),
        );
        G2_RESULTS.push({ id: m.id, expectedProperty: m.expectedProperty, ...outcome });
        expect(outcome.verdict, `${m.id}: ${JSON.stringify(outcome)}\n  why it matters: ${m.rationale}`).to.equal(
          "KILLED",
        );
      });
    }
  });

  describe("Generation 1's catalogue, on the candidate", function () {
    for (const m of MUTATIONS) {
      if (GEN1_CATALOGUE_NOT_APPLICABLE[m.id] !== undefined) continue;
      it(`kills ${m.id}`, async function () {
        const b = built.get(m.id);
        expect(b, `${m.id} did not compile`).to.not.equal(undefined);
        const outcome = await hunt(
          m.id,
          [...m.profiles, ...(GEN1_CATALOGUE_EXTRA_PROFILES[m.id] ?? [])],
          {},
          b!.kernel,
          (r) => {
            const hit = r.violations.find((v) => v.property === m.expectedProperty) ?? r.violations[0];
            return hit ? { property: hit.property, step: hit.step } : null;
          },
          (r) => r.successfulTransitions > 0,
        );
        GEN1_RESULTS.push({ id: m.id, expectedProperty: m.expectedProperty, ...outcome });
        expect(outcome.verdict, `${m.id}: ${JSON.stringify(outcome)}\n  why it matters: ${m.rationale}`).to.equal(
          "KILLED",
        );
      });
    }
  });

  // Mocha runs a suite's own tests before its nested suites, so the results live in a suite placed after both catalogues.
  describe("the results", function () {
    it("the live controls the catalogue names are real ones", function () {
      const labels = new Set<string>(Object.values(POSITIVE_CONTROL_LABELS));
      for (const m of G2_MUTATIONS) expect(labels.has(m.liveControl), m.id).to.equal(true);
    });

    it("prints the kill matrix, and every mutant in both catalogues was killed", function () {
      const row = (r: G2MutationOutcome): string =>
        `  ${r.verdict.padEnd(13)}${r.id.padEnd(50)}${r.killedBy ? `by ${r.killedBy.property} (${r.killedBy.profile} seed ${r.killedBy.seed}, step ${r.killedBy.step}; ${r.campaigns} campaign(s))` : "NOT CAUGHT"}`;
      const score = (rs: G2MutationOutcome[]): string =>
        `${rs.filter((r) => r.verdict === "KILLED").length}/${rs.length}`;
      console.log(`\n  GENERATION-2 CATALOGUE (${score(G2_RESULTS)} killed)\n${G2_RESULTS.map(row).join("\n")}`);
      console.log(
        `\n  GENERATION-1 CATALOGUE ON THE CANDIDATE (${score(GEN1_RESULTS)} killed)\n${GEN1_RESULTS.map(row).join("\n")}`,
      );
      expect(G2_RESULTS.length).to.equal(G2_MUTATIONS.length);
      expect(GEN1_RESULTS.length).to.equal(MUTATIONS.length - Object.keys(GEN1_CATALOGUE_NOT_APPLICABLE).length);
      expect(G2_RESULTS.filter((r) => r.verdict !== "KILLED")).to.deep.equal([]);
      expect(GEN1_RESULTS.filter((r) => r.verdict !== "KILLED")).to.deep.equal([]);
    });

    it("every Generation-2 property has a mutant that dies by it", function () {
      const named = new Set(G2_MUTATIONS.flatMap((m) => [m.expectedProperty, ...(m.alsoExpected ?? [])]));
      expect(G2_PROPERTIES.map((p) => p.name).filter((p) => !named.has(p))).to.deep.equal([]);
    });

    it("the outcome is the committed record, mutant for mutant", function () {
      const row = (r: G2MutationOutcome): MutationRunRow => ({
        id: r.id,
        verdict: r.verdict,
        property: r.killedBy?.property ?? null,
        profile: r.killedBy?.profile ?? null,
        seed: r.killedBy?.seed ?? null,
        step: r.killedBy?.step ?? null,
        campaigns: r.campaigns,
      });
      if (writingRunRecord())
        writeRunSection({ generation2Catalogue: G2_RESULTS.map(row), generation1Catalogue: GEN1_RESULTS.map(row) });
      const recorded = readRunRecord();
      expect(
        canonicalRunValue(G2_RESULTS.map(row)),
        "regenerate with G2_WRITE_RUN_RECORD=1 and review the diff",
      ).to.deep.equal(recorded.generation2Catalogue);
      expect(
        canonicalRunValue(GEN1_RESULTS.map(row)),
        "regenerate with G2_WRITE_RUN_RECORD=1 and review the diff",
      ).to.deep.equal(recorded.generation1Catalogue);
    });

    it("the Generation-1 containment mutants die by the independent rolling oracle, never by the kernel-reported counter", function () {
      for (const id of [
        "M14-containment-budget-removed",
        "M23-tumbling-reset-restored",
        "M24-tracks-only-the-most-recent-start",
      ]) {
        expect(GEN1_RESULTS.find((r) => r.id === id)?.killedBy?.property, id).to.equal("G-CONTAINMENT-ROLLING-BUDGET");
      }
    });
  });
});
