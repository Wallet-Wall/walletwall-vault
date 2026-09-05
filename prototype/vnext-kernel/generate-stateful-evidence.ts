/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * Generates STATEFUL_AUTHORITY_EVIDENCE.json: a deterministic receipt for the
 * stateful adversarial authority campaign.
 *
 * SEPARATE FROM THE OTHER TWO RECEIPTS ON PURPOSE. SCANNER_EVIDENCE.json records
 * what a static analyser saw; AUTHORITY_CENSUS.json records whether every
 * privileged path is classified and routed to its intended gate. Neither says
 * anything about COMPOSITION over time, and folding this into either would let a
 * reader take one artifact's coverage for another's.
 *
 * WHAT IT DOES NOT PROVE is a first-class field of the receipt, not a footnote.
 *
 * Run: npx tsx prototype/vnext-kernel/generate-stateful-evidence.ts
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

import { PROFILES } from "./stateful/profiles.js";
import { MUTATIONS, UNMUTATED_CLAUSES } from "./stateful/mutants.js";
import { REMEDIATED_DEFECTS, SUSTAINED_DEFECTS } from "./stateful/defects.js";
import { GLOBAL_INVARIANTS, REJECTED_INVARIANTS } from "./stateful/invariants.js";
import { DECLARED_CUTS, DOCUMENTED } from "./stateful/model.js";

const ROOT = path.join("prototype", "vnext-kernel");
const OUT = path.join(ROOT, "STATEFUL_AUTHORITY_EVIDENCE.json");

const git = (args: string[]): string => execFileSync("git", args, { encoding: "utf8" }).trim();
const sha256OfFile = (p: string): string => "sha256:" + createHash("sha256").update(fs.readFileSync(p)).digest("hex");

/**
 * The campaign matrix, mirrored from StatefulAuthorityFuzz.test.ts. Kept in sync
 * by a test assertion there rather than by hope: the suite fails if this receipt
 * and the executed matrix disagree.
 */
const CI_SEEDS = {
  shallow: [1, 2, 3, 5, 8, 13, 21, 34],
  medium: [101, 211, 331, 457],
  deep: [90210, 133742],
} as const;
const DEPTHS = { shallow: 25, medium: 65, deep: 150 } as const;
const MUTATION_SEEDS = [11, 29, 47, 83, 131, 197, 251, 307];
const MUTATION_DEPTH = 90;

function main(): void {
  const head = git(["rev-parse", "HEAD"]);
  const tree = git(["rev-parse", "HEAD^{tree}"]);

  const plannedCampaigns =
    PROFILES.length * (CI_SEEDS.shallow.length + CI_SEEDS.medium.length + CI_SEEDS.deep.length);
  const plannedTransitions =
    PROFILES.length *
    (CI_SEEDS.shallow.length * DEPTHS.shallow +
      CI_SEEDS.medium.length * DEPTHS.medium +
      CI_SEEDS.deep.length * DEPTHS.deep);

  /**
   * MEASUREMENTS.json exposes TOP-LEVEL `kernel` / `factory` objects. An earlier
   * revision of this generator read `measurements.contracts[]` — the shape
   * `measure.ts` PRINTS, not the shape the committed file has — so
   * `kernelRuntimeBytes` and `kernelRuntimeHash` were permanently null and the
   * receipt silently published "unknown" as if it were a measurement. It was
   * harmless while this lane changed zero bytes of Solidity; it stopped being
   * harmless the moment one did.
   */
  const measurements = JSON.parse(fs.readFileSync(path.join(ROOT, "MEASUREMENTS.json"), "utf8")) as {
    kernel?: { runtimeBytes: number; runtimeSha256: string };
    sd1Remediation?: { beforeRuntime: number; afterRuntime: number; totalDelta: number };
    sd3Remediation?: { beforeRuntime: number; afterRuntime: number; totalDelta: number };
    sd67Remediation?: { beforeRuntime: number; afterRuntime: number; totalDelta: number };
    w2RecoveryLifecycle?: { beforeRuntime: number; afterRuntime: number; totalDelta: number };
  };
  const kernel = measurements.kernel;
  // The LATEST remediation is what this receipt describes; earlier ones are
  // history and are recorded in their own MEASUREMENTS.json blocks. W2 (K-9
  // mechanism B + recovery lifecycle) is the latest; it is preferred here so
  // that the receipt regenerated at the commit carrying W2 reports W2's delta
  // rather than SD-6/7's.
  const sd1 =
    measurements.w2RecoveryLifecycle ??
    measurements.sd67Remediation ??
    measurements.sd3Remediation ??
    measurements.sd1Remediation;

  const receipt = {
    schema: "vnext-kernel-stateful-authority-evidence.v1",
    head,
    tree,

    lane: {
      question:
        "Can individually-valid, individually-correctly-gated transitions be COMPOSED OVER TIME into an outcome below its declared authority cut?",
      distinctFrom: {
        "vNext Kernel / Slither":
          "asks whether the IMPLEMENTATION PATTERNS look unsafe. Static. Says nothing about histories.",
        "vNext Kernel / Authority Completeness":
          "asks whether every privileged external path is CLASSIFIED and routed to its intended authority mechanism. Per-function. Says nothing about sequences.",
      },
      reasoningModel: "STATE + ACTION + AUTHORITY -> NEXT STATE (not FUNCTION -> EXPECTED GATE)",
    },

    framework: {
      engine: "purpose-built deterministic command-sequence generator (prototype/vnext-kernel/stateful/)",
      prng: "mulberry32, seeded; no Math.random, no clock, no environment input anywhere in the lane",
      whyNotFastCheck:
        "fast-check is not a repository dependency, and adding it would make an assurance-only lane a production package.json / package-lock.json change and drag it through the dependency-freeze and lockfile guard chain. The generator needed here is ~100 lines and shrinking is a list-level delta-debug over recorded actions.",
      shrinking: "truncate-at-first-violation, then single-action delta-debug from a restored EVM snapshot",
      determinism: "a campaign is a pure function of (profile, seed, depth); every failure replays from its seed",
    },

    compiler: { solcVersion: "0.8.24", evmVersion: "cancun", optimizer: { enabled: true, runs: 200 } },

    actorModel: {
      roots: ["CRED_ECDSA", "CRED_PQ", "GUARDIAN_0", "GUARDIAN_1", "GUARDIAN_2"],
      principalRule:
        "A guardian principal is an ADDRESS. Roots are counted by DISTINCT ADDRESS, never by roster seat, so the oracle does not inherit the kernel's ascending-roster assumption.",
      secondFactor:
        "EcdsaBackedVerifier — an INDEPENDENT ECDSA keypair standing in for a PQ scheme. 'The attacker does not hold the second root' is therefore a real cryptographic fact in this harness, and says nothing about ML-DSA.",
      byzantineDegradation:
        "An ALWAYS-TRUE verifier authenticates nobody, so the model stops counting the PQ factor as a root while one is installed — the same statement AUTHORITY.md makes.",
      outOfScope:
        "H-31: several distinct addresses behind ONE off-chain custodian. This lane counts on-chain principals and invents no identity system to pretend otherwise.",
    },

    declaredCuts: Object.fromEntries(
      Object.entries(DECLARED_CUTS).map(([k, v]) => [k, { cut: v, source: DOCUMENTED[k as keyof typeof DOCUMENTED] }]),
    ),

    campaigns: {
      profiles: PROFILES.map((p) => ({
        name: p.name,
        description: p.description,
        actors: p.actors.map((a) => a.name),
        verifierAtGenesis: p.verifier ?? "honest",
        ecdsaOnlyFloor: p.ecdsaOnlyFloor ?? false,
      })),
      fixedSeeds: CI_SEEDS,
      depths: DEPTHS,
      plannedCampaigns,
      plannedTransitions,
      randomnessInRequiredCI: "NONE — the required check runs exactly the fixed seeds above",
    },

    properties: {
      authorityCut: {
        id: "P-CUT/<OUTCOME>",
        statement:
          "If a protected OUTCOME occurred, the roots that AUTHORISED it must satisfy at least one declared authority path IN FULL. Outcomes are detected by STATE DIFF, never by which function was called.",
        attribution:
          "Permissionless finalisers (executeRecovery, egress, retire) and replays of calls that never consumed their authorization are charged to the roots that authorised the pre-committed decision, not to whoever paid the gas.",
      },
      recoveryEvidence: {
        id: "P-MODEL",
        statement:
          "R1/R2/R3 — the harness records for itself whether a recovery it created was CANCELLED, SUPERSEDED or CONSUMED, and whether the approving constituency has since changed. A success against such evidence is a violation regardless of what the kernel believes.",
      },
      incomingPossession: {
        id: "P-INCOMING-POSSESSION",
        statement:
          "R4 — a call that deliberately proved possession of the OUTGOING factors instead of the incoming ones must never succeed.",
      },
      planeSubtractive: {
        id: "P-PLANE-SUBTRACTIVE",
        statement: "A policy plane may only REFUSE. With the denying plane installed, no spend may move value.",
      },
      atomicity: {
        id: "P-ATOMICITY",
        statement: "A REVERTED action must leave kernel state byte-identical. Reverts are total.",
      },
      vacuity: {
        id: "P-VACUITY",
        statement:
          "Every campaign additionally runs fully-honest, fully-authorised actions on a restored fixture and requires them to succeed. Without this, a campaign in which everything reverted would pass every safety property while proving nothing.",
      },
      globalInvariants: GLOBAL_INVARIANTS.map((i) => ({ name: i.name, source: i.source })),
      rejectedInvariants: REJECTED_INVARIANTS,
    },

    mutationAdequacy: {
      seeds: MUTATION_SEEDS,
      depth: MUTATION_DEPTH,
      mechanism:
        "Each mutation compiles a real, deliberately weakened kernel IN MEMORY with the pinned solc and deploys it, then points the SAME campaign machinery at it. Nothing is written to contracts/ or to the real artifacts.",
      vacuityGuard:
        "A mutant that never completes a successful transition is reported INCONCLUSIVE, never KILLED — a mutant that dies while doing nothing proves nothing.",
      mutations: MUTATIONS.map((m) => ({
        id: m.id,
        expectedProperty: m.expectedProperty,
        profiles: m.profiles,
        rationale: m.rationale,
      })),
      historicalRegressionClasses: [
        "A1 — rotateCredential gated on the ECDSA conjunct alone (M2)",
        "A2 — setVerifier gated on the ECDSA conjunct alone (M3)",
        "B  — a roster in which one PRINCIPAL holds two seats (M9), and quorum counting by index rather than principal (M13)",
        "D  — possession proven against the OUTGOING credential (M7)",
        "F  — a policy plane whose refusal is not honoured (M11)",
      ],
      /**
       * Clauses of the kernel that this catalogue does NOT cover, published so a
       * reader cannot mistake the kill matrix for total coverage. A disclosure
       * that lives only in a source comment is not a disclosure.
       */
      unmutatedClauses: UNMUTATED_CLAUSES,
    },

    sustainedDefects: SUSTAINED_DEFECTS.map((d) => ({
      id: d.id,
      title: d.title,
      classification: d.classification,
      rootsRequired: d.rootsRequired,
      contradicts: d.contradicts,
      rootCause: d.rootCause,
      notAnEscalationBecause: d.notAnEscalationBecause,
      minimalFixSketch: d.minimalFixSketch,
      reproducedBy: d.reproducedBy ?? "prototype/vnext-kernel/test/StatefulSustainedDefects.test.ts",
    })),

    solidityChanged: {
      bytes: sd1?.totalDelta ?? 0,
      note:
        sd1 === undefined
          ? "This lane changes ZERO bytes of Solidity. Every sustained defect is RECORDED and REPRODUCED; remediation is a separate, minimal change."
          : "The figure is read from MEASUREMENTS.json rather than hard-coded, so a receipt can no longer claim zero bytes on a commit that changed Solidity. Which defects are closed and which stand is carried by the `remediated` and `sustainedDefects` arrays in this same receipt, not by prose here.",
      beforeRuntimeBytes: sd1?.beforeRuntime ?? null,
      kernelRuntimeBytes: kernel?.runtimeBytes ?? null,
      kernelRuntimeHash: kernel?.runtimeSha256 ?? null,
    },
    remediated: REMEDIATED_DEFECTS.map((r) => ({
      id: r.id,
      verdict: "DEFECT_REMEDIATED",
      sustainedAt: r.sustainedAt,
      remediatedOn: r.remediatedOn,
      invariant: r.invariant,
      sourceDelta: r.sourceDelta,
      rejectedAlternatives: r.rejectedAlternatives,
      invertedReproduction: r.invertedReproduction,
      residual: r.residual,
    })),

    whatThisDoesNotProve: [
      "NOT EXHAUSTIVE. A bounded, seeded campaign over a bounded action vocabulary. Any sequence outside the generated distribution is untested.",
      "NOT FORMAL VERIFICATION. Deterministic seeded campaigns are still testing. No state space is proven covered, and 'no violation found' is not 'no violation exists'.",
      "NOT AN AUDIT. No third party has reviewed this code.",
      "NO CRYPTOGRAPHIC CLAIM. The second factor is an independent ECDSA keypair standing in for a PQ scheme. Nothing here says anything about ML-DSA.",
      "DOES NOT PROVE GUARDIAN INDEPENDENCE (H-31). Distinct on-chain addresses may still be one off-chain custodian.",
      "DOES NOT SUPERSEDE the Slither lane or the authority-completeness lane. It answers a different question and is evidence for neither.",
      "MUTATION SCORE IS ADEQUACY, NOT COVERAGE. Killing every mutation in a hand-written catalogue shows the properties detect THOSE classes; it does not enumerate the classes that are missing.",
      "THE GENERATOR'S DISTRIBUTION IS TUNED. Several profiles deliberately bias timing and parameter choices so a seam is reachable at all. Biasing a distribution is not filtering a sequence, but it does mean coverage is uneven by construction.",
    ],

    knownGaps: [
      "Cross-chain and cross-vault replay is covered only by the domain separator's construction, not by a second deployed chain.",
      "A verifier that loses its code between recovery initiation and execution is not reachable in this harness: post-Cancun SELFDESTRUCT only clears code in the same transaction as creation, so G-VERIFIER-HAS-CODE is asserted rather than adversarially exercised.",
      "The ERC-1271 guardian mocks (reverting, gas-burning, huge-returndata, wrong-answer) are exercised by the existing prototype suite, not by this campaign: the generated rosters are EOA seats only.",
      "guardianThreshold is a free parameter a k-quorum may lower to 1, permanently moving the guardian cut. The campaign models this faithfully (cuts are computed from the LIVE threshold) and does not treat it as a defect, because AUTHORITY.md assigns setGuardians to the guardian quorum. It is recorded here as an OBSERVATION worth an explicit row in the published table.",
    ],
  };

  fs.writeFileSync(OUT, JSON.stringify(receipt, null, 2) + "\n");
  console.log("Wrote " + OUT);
  console.log("  head            " + head);
  console.log("  profiles        " + PROFILES.length);
  console.log("  planned         " + plannedCampaigns + " campaigns / " + plannedTransitions + " transitions");
  console.log("  invariants      " + GLOBAL_INVARIANTS.length + " global (+ " + REJECTED_INVARIANTS.length + " rejected, recorded)");
  console.log("  mutations       " + MUTATIONS.length);
  console.log("  sustained       " + SUSTAINED_DEFECTS.length + " defects still open");
  console.log("  remediated      " + REMEDIATED_DEFECTS.length + " defect(s), " + (sd1?.totalDelta ?? 0) + " Solidity bytes changed");
  console.log("  digest          " + sha256OfFile(OUT));
}

main();
