/**
 * EXPERIMENTAL PROTOTYPE ADMISSION TOOLING — NOT PRODUCTION.
 *
 * Generates the Generation-2 receipts. THE TWO-COMMIT PROTOCOL: commit the code, then run this with
 * `--subject <that commit>` on a clean checkout of it, and commit what it writes. A receipt names the commit it
 * is ABOUT, never the commit that contains it, and this generator refuses to run if any measured input differs
 * from the subject by a single byte, so a receipt cannot describe a tree nobody committed. Nothing here reads the
 * clock or the machine: two runs on one subject produce byte-identical files.
 *
 * Run: npx tsx prototype/vnext-kernel/generation-2/generate-evidence.ts --subject <40-hex>
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { sha256Hex } from "../erc20-spend-plane/compile.js";
import { GLOBAL_INVARIANTS, REJECTED_INVARIANTS } from "../stateful/invariants.js";
import { DECLARED_CUTS, DOCUMENTED } from "../stateful/model.js";
import { MUTATIONS } from "../stateful/mutants.js";
import { REMEDIATED_DEFECTS, SUSTAINED_DEFECTS } from "../stateful/defects.js";
import {
  DISCLOSED_NARROWINGS,
  HAZARD_COVERAGE,
  MATRIX,
  OWNER_DECISIONS,
  RESIDUALS,
  deriveAdmissionVerdict,
} from "./admission-matrix.js";
import { CENSUS_PATH, runGen2Census } from "./authority/census.js";
import { GEN2_ROOT } from "./compile.js";
import { candidateIdentity } from "./identity.js";
import { executionProblems, readRunRecord } from "./run-record.js";
import { ADJUDICATIONS, SCANNER_RUN_PATH, type ScannerRun } from "./scanner.js";
import {
  CI_SEEDS_G2,
  DEPTHS_G2,
  G2_SEAMS,
  LIFECYCLE_SEAMS,
  MUTATION_DEPTH_G2,
  MUTATION_SEEDS_G2,
} from "./stateful/campaign.js";
import { ACTION_KINDS_G2 } from "./stateful/actions.js";
import { G2_PROPERTIES } from "./stateful/invariants.js";
import { GEN1_CATALOGUE_EXTRA_PROFILES, GEN1_CATALOGUE_NOT_APPLICABLE, G2_MUTATIONS } from "./stateful/mutants.js";
import { G2_PROFILES, INHERITED_PROFILE_COUNT } from "./stateful/profiles.js";

export const ROOT = "prototype/vnext-kernel";
export const ADMISSION_EVIDENCE_PATH = `${ROOT}/GEN2_ADMISSION_EVIDENCE.json`;
export const STATEFUL_EVIDENCE_PATH = `${ROOT}/GEN2_STATEFUL_AUTHORITY_EVIDENCE.json`;
export const SCANNER_EVIDENCE_PATH = `${ROOT}/GEN2_SCANNER_EVIDENCE.json`;
export const CRITERIA_PATH = `${GEN2_ROOT}/ADMISSION_CRITERIA.json`;
export const GAS_RECORD_PATH = `${GEN2_ROOT}/GEN2_GAS_RECORD.json`;

/** Everything a receipt's currency rests on, as paths whose LF-normalised bytes must equal the subject's. */
export function measuredInputs(): string[] {
  const walk = (dir: string): string[] =>
    fs
      .readdirSync(dir, { withFileTypes: true })
      .flatMap((e) =>
        e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name).split(path.sep).join("/")],
      );
  return [...walk(GEN2_ROOT)].filter((p) => !p.endsWith(".md")).sort();
}

const lf = (s: string): string => s.split("\r\n").join("\n");
export const inputDigests = (): Record<string, string> =>
  Object.fromEntries(measuredInputs().map((p) => [p, sha256Hex(lf(fs.readFileSync(p, "utf8")))]));

export const planned = (): { campaigns: number; transitions: number } => {
  const tiers = ["shallow", "medium", "deep"] as const;
  const perProfileCampaigns = tiers.reduce((n, t) => n + CI_SEEDS_G2[t].length, 0);
  const perProfileTransitions = tiers.reduce((n, t) => n + CI_SEEDS_G2[t].length * DEPTHS_G2[t], 0);
  return {
    campaigns: G2_PROFILES.length * perProfileCampaigns,
    transitions: G2_PROFILES.length * perProfileTransitions,
  };
};

/**
 * THE EVIDENCE ROOT: one digest binding the candidate's identity, every measured input and the three other
 * receipts, as sorted `path:sha256` lines, so a reader can check the set with one comparison and a change to any
 * member moves it. A receipt's own subject is inside what is hashed, so a regenerated receipt moves it too.
 */
export function evidenceRoot(
  identity: unknown,
  digests: Readonly<Record<string, string>>,
  receiptPaths: readonly string[],
): { root: string; members: Record<string, string> } {
  const members: Record<string, string> = { identity: sha256Hex(JSON.stringify(identity)), ...digests };
  for (const p of receiptPaths) members[p] = sha256Hex(lf(fs.readFileSync(p, "utf8")));
  const lines = Object.keys(members)
    .sort()
    .map((k) => `${k}:${members[k]}`);
  return { root: sha256Hex(lines.join("\n")), members };
}

export const SIDE_RECEIPTS = [CENSUS_PATH, STATEFUL_EVIDENCE_PATH, SCANNER_EVIDENCE_PATH] as const;

export const WARNING =
  "EXPERIMENTAL PROTOTYPE. NOT AUDITED. NOT PRODUCTION. NO DEPLOYMENT. Admission of a kernel candidate approves no asset, no network and no real value.";

function resolveSubject(sha: string): { head: string; tree: string } {
  if (!/^[0-9a-f]{40}$/.test(sha)) throw new Error("--subject must be a 40-hex commit");
  const git = (...args: string[]): string => execFileSync("git", args, { encoding: "utf8" }).trim();
  const tree = git("rev-parse", `${sha}^{tree}`);
  for (const p of measuredInputs()) {
    const atSubject = lf(
      execFileSync("git", ["show", `${sha}:${p}`], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 }),
    );
    if (atSubject !== lf(fs.readFileSync(p, "utf8")))
      throw new Error(`${p} differs from the subject ${sha}: commit it first, then regenerate.`);
  }
  return { head: sha, tree };
}

function main(): void {
  const i = process.argv.indexOf("--subject");
  if (i < 0 || !process.argv[i + 1])
    throw new Error("usage: generate-evidence.ts --subject <40-hex commit that carries the code>");
  const subject = resolveSubject(process.argv[i + 1]!);
  const digests = inputDigests();

  const write = (file: string, value: unknown): void => fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");

  // ---- the census ----
  const census = runGen2Census();
  if (census.derivedVerdict.verdict !== "NO_NEW_PRIVILEGED_PRINCIPAL")
    throw new Error("the census does not support admission: " + census.derivedVerdict.reasons.join("; "));
  write(CENSUS_PATH, { _WARNING: WARNING, evidenceSubject: subject, ...census });

  // ---- the stateful campaign: its plan, and what the committed record says happened ----
  const { campaigns, transitions } = planned();
  const ran = readRunRecord();
  write(STATEFUL_EVIDENCE_PATH, {
    schema: "vnext-kernel-gen2-stateful-authority-evidence.v1",
    _WARNING: WARNING,
    evidenceSubject: subject,
    question:
      "Can individually-valid transitions be composed over time, on the Generation-2 candidate with ERC-20 state in the history, into an outcome below its declared authority cut?",
    notInherited:
      "Generation 1's receipt covers Generation 1. This campaign ran on the candidate: same seeds and depths, same global invariants imported unchanged, same cut model.",
    framework:
      "generation-2/stateful/, reusing stateful/'s PRNG, cut model, defect ledger, global invariants and quorum shapes by import. A campaign is a pure function of (profile, seed, depth).",
    oracle:
      "Asymmetric: IF a protected outcome occurred, by state diff, THEN the roots that authorised it satisfy a declared path. Asset properties read the token's own ledger, never the kernel's view of it. No refusal is judged mid-history: the two liveness properties are judged at the end of a history.",
    declaredCuts: Object.fromEntries(
      Object.entries(DECLARED_CUTS).map(([k, v]) => [k, { cut: v, source: DOCUMENTED[k as keyof typeof DOCUMENTED] }]),
    ),
    actions: [...ACTION_KINDS_G2],
    campaigns: {
      inheritedProfiles: INHERITED_PROFILE_COUNT,
      erc20Profiles: G2_PROFILES.length - INHERITED_PROFILE_COUNT,
      profiles: G2_PROFILES.map((p) => ({
        name: p.name,
        description: p.description,
        actors: p.actors.map((a) => a.name),
        ecdsaOnlyFloor: p.ecdsaOnlyFloor ?? false,
        realRoot: p.realRoot ?? false,
        sibling: p.sibling ?? false,
        tokenModes: p.tokenModes ?? ["VANILLA"],
      })),
      fixedSeeds: CI_SEEDS_G2,
      depths: DEPTHS_G2,
      plannedCampaigns: campaigns,
      plannedTransitions: transitions,
    },
    executed: ran.campaign,
    properties: {
      asset: G2_PROPERTIES,
      inherited: ["P-CUT/<OUTCOME>", "P-MODEL", "P-INCOMING-POSSESSION", "P-PLANE-SUBTRACTIVE", "P-VACUITY"],
      globalInvariants: GLOBAL_INVARIANTS.map((g) => ({ name: g.name, source: g.source })),
      rejectedInvariants: REJECTED_INVARIANTS,
    },
    antiVacuity: {
      seams: [...G2_SEAMS],
      lifecycleSeams: [...LIFECYCLE_SEAMS],
      rule: "generation-2/test/Gen2StatefulCampaign.test.ts requires every positive control to pass, every action to succeed (bar the two whose success is itself the violation), every outcome and every seam to be reached, and every sustained defect with a property to keep firing.",
    },
    mutationAdequacy: {
      seeds: MUTATION_SEEDS_G2,
      depth: MUTATION_DEPTH_G2,
      attribution:
        "Generation-2 catalogue: killed only by the named property, on a mutant whose named positive control still passed, with the same profile, seed and depth clean on the real candidate. Otherwise INCONCLUSIVE or SURVIVED. Generation-1 catalogue: killed by any property, as in Generation 1, against the same clean baseline.",
      results: { generation2: ran.generation2Catalogue, generation1OnTheCandidate: ran.generation1Catalogue },
      generation2: G2_MUTATIONS.map((m) => ({
        id: m.id,
        expectedProperty: m.expectedProperty,
        liveControl: m.liveControl,
        profiles: m.profiles,
        rationale: m.rationale,
      })),
      generation1OnTheCandidate: MUTATIONS.map((m) => ({
        id: m.id,
        expectedProperty: m.expectedProperty,
        profiles: [...m.profiles, ...(GEN1_CATALOGUE_EXTRA_PROFILES[m.id] ?? [])],
        applicable: GEN1_CATALOGUE_NOT_APPLICABLE[m.id] === undefined,
      })),
    },
    sustainedDefects: SUSTAINED_DEFECTS.map((d) => ({
      id: d.id,
      property: d.property,
      classification: d.classification,
    })),
    conditionallyRemediated: REMEDIATED_DEFECTS.filter((d) => d.condition !== undefined).map((d) => ({
      id: d.id,
      condition: d.condition,
    })),
    whatThisDoesNotProve: [
      "NOT EXHAUSTIVE. A bounded, seeded campaign over a bounded action vocabulary.",
      "NOT FORMAL VERIFICATION. 'No violation found' is not 'no violation exists'.",
      "NOT AN AUDIT. No third party has reviewed this code.",
      "NOT A TOKEN CLAIM. The admitted asset is a local mock throughout. The token zoo is a set of behaviours, not a model of any real token.",
      "NO CRYPTOGRAPHIC CLAIM. Under the fixture the second factor is an independent ECDSA key standing in for a PQ scheme.",
      "MUTATION SCORE IS ADEQUACY, NOT COVERAGE. It shows these properties detect these classes.",
    ],
    harnessSelfChecks: [
      {
        name: "P-ATOMICITY",
        note: "A reverted call cannot change storage by the EVM's own rule, so this checks the harness's snapshot and digest, never a kernel. It is not evidence for any row.",
      },
    ],
    knownGaps: [
      "The generator nests no credential, roster or recovery act in a token hook: test/Gen2Reentrancy.test.ts exercises those deterministically.",
      "The campaign's destination is a fixed stub, so a destination losing its code is exercised deterministically, in test/Gen2Migration.test.ts.",
      "Generated rosters are EOA seats; ERC-1271 guardian faults are exercised by test/Gen2KernelRows.test.ts.",
      "Cross-chain replay is covered by the domain separator's construction, not by a second deployed chain.",
      "The campaign's token zoo reaches one asset at a time; multi-asset vaults do not exist in this kernel.",
    ],
  });

  // ---- the scanner ----
  const run = JSON.parse(fs.readFileSync(SCANNER_RUN_PATH, "utf8")) as ScannerRun;
  write(SCANNER_EVIDENCE_PATH, {
    schema: "vnext-kernel-gen2-scanner-evidence.v1",
    _WARNING: WARNING,
    evidenceSubject: subject,
    slither: {
      tool: run.tool,
      semanticConfigSha256: run.semanticConfigSha256,
      analyzedSources: run.analyzedSources,
      rawResults: run.rawResults,
      dependencyOnlyResults: run.dependencyOnlyResults,
      distinctOwnFindings: run.distinctOwnFindings.length,
      canonicalAllFindingsSha256: run.canonicalAllFindingsSha256,
      severity: run.severity,
      findings: run.distinctOwnFindings.map((r) => ({
        semanticId: r.semanticId,
        check: r.check,
        impact: r.impact,
        confidence: r.confidence,
        key: r.key,
        sourceLocation: r.sourceLocation,
        verdict: r.classification,
        ...(ADJUDICATIONS[r.key] && r.classification === "PASS_WITH_DECLARED_EXCEPTION"
          ? {
              rationale: ADJUDICATIONS[r.key]!.rationale,
              whyStaticAnalysisCannotResolve: ADJUDICATIONS[r.key]!.whyStaticAnalysisCannotResolve,
              dynamicProperty: ADJUDICATIONS[r.key]!.dynamicProperty,
              mutant: ADJUDICATIONS[r.key]!.mutant,
            }
          : {}),
      })),
    },
    codeql: {
      status: "NOT_RUN_LOCALLY",
      why: "CodeQL ships no Solidity extractor, so it cannot analyse the candidate at any commit: this is a permanent limit of the tool, not a gap in this run. It analyses this lane's TypeScript tooling in CI at publication. It is not installed on the machine this lane ran on.",
    },
    authorityScanner: {
      tool: "authority/check.ts, unchanged, driven through an in-memory rename",
      receipt: "GEN2_AUTHORITY_CENSUS.json",
    },
    prohibitedPatterns: {
      tool: "test/Gen2Scanner.test.ts: opcode sweep of the runtime, and AST and source patterns",
      receipt: "this suite; it has no separate file",
    },
    ciBoundary:
      "The repository's Slither CI job targets prototype/vnext-kernel/contracts only. Adding this tree to it is a workflow edit the App cannot push: an owner act at publication. Until then this receipt is a reproducible local run, recorded as such.",
    doesNotEstablish: [
      "That the candidate is free of defects Slither's detectors cannot express.",
      "Anything about a real token: the zoo is a fixture.",
    ],
  });

  // ---- the admission record ----
  const criteria = JSON.parse(fs.readFileSync(CRITERIA_PATH, "utf8")) as {
    criteria: {
      id: string;
      concern: string;
      statement: string;
      tier: string;
      measuredVariantA: string;
      measuredReason: string;
      source: string;
    }[];
  };
  const rows = criteria.criteria.map((c) => ({
    ...c,
    measuredOnCandidate: MATRIX[c.id]!.classification,
    note: MATRIX[c.id]!.note,
    evidence: MATRIX[c.id]!.evidence,
    residuals: MATRIX[c.id]!.residuals ?? [],
    admissionDelta: MATRIX[c.id]!.admissionDelta ?? null,
    blockedOnDecision: MATRIX[c.id]!.blockedOnDecision ?? null,
    whyTheT0Holds: MATRIX[c.id]!.whyTheT0Holds ?? null,
  }));
  const gas = JSON.parse(fs.readFileSync(GAS_RECORD_PATH, "utf8")) as { gas: Record<string, number> };
  const counts: Record<string, number> = {};
  for (const r of rows) counts[r.measuredOnCandidate] = (counts[r.measuredOnCandidate] ?? 0) + 1;
  const problems = executionProblems(ran);
  const verdict = deriveAdmissionVerdict(Object.values(MATRIX), OWNER_DECISIONS, problems);
  const identity = candidateIdentity();
  const root = evidenceRoot(identity, digests, SIDE_RECEIPTS);
  write(ADMISSION_EVIDENCE_PATH, {
    schema: "vnext-kernel-gen2-admission-evidence.v1",
    _WARNING: WARNING,
    evidenceSubject: subject,
    subjectInputs: digests,
    verdict,
    executionProblems: problems,
    separately: { PRODUCTION_BASE_USDC: "NOT_ADMITTED", MAINNET_REAL_FUNDS: "NOT_APPROVED" },
    neutralGates: [
      "LEGAL_REVIEW_REQUIRED",
      "SANCTIONS_CONTROL_REVIEW_REQUIRED",
      "PAYMENTS_PROVIDER_APPROVAL_REQUIRED_IF_APPLICABLE",
    ],
    evidenceRoot: root.root,
    identity,
    gas: gas.gas,
    matrixSummary: counts,
    matrix: rows,
    residuals: RESIDUALS,
    disclosedNarrowings: DISCLOSED_NARROWINGS,
    hazardCoverage: HAZARD_COVERAGE,
    ownerDecisions: OWNER_DECISIONS,
  });

  console.log(`subject ${subject.head}`);
  console.log(`verdict ${verdict}`);
  console.log(`matrix  ${JSON.stringify(counts)}`);
  console.log(`inputs  ${Object.keys(digests).length} files digested`);
  console.log(`root    ${root.root}`);
  console.log(
    `wrote   ${[CENSUS_PATH, STATEFUL_EVIDENCE_PATH, SCANNER_EVIDENCE_PATH, ADMISSION_EVIDENCE_PATH].join(", ")}`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]).endsWith("generate-evidence.ts")) main();
