/**
 * EXPERIMENTAL PROTOTYPE ADMISSION TOOLING — NOT PRODUCTION.
 *
 * THE SCANNER BOUNDARY FOR THE CANDIDATE ITSELF. No Generation-1 scanner result is carried: Slither ran on
 * generation-2/contracts at the pinned commit, and every own-code finding is adjudicated here firsthand and
 * joined by semantic identity (scanner-finding-identity.ts), so a finding that merely moves keeps its verdict
 * and a new one fails test/Gen2Scanner.test.ts for want of a row.
 *
 * Every finding on the candidate's kernel or factory is PASS_WITH_DECLARED_EXCEPTION and must say why static
 * analysis cannot resolve it, which dynamic property covers it, and which mutant shows that property has teeth.
 * The token zoo is a test fixture analysed only because it shares the tree, and its adversarial behaviour is the
 * point of it, so its rows are classified apart and carry no such duty.
 */
import fs from "node:fs";
import path from "node:path";

import { canonicalAllFindingsSha256 } from "../scanner-canonical-digest.js";
import { indexFindings, isOwnFinding, semanticId, type SlitherFinding } from "../scanner-finding-identity.js";
import { PINNED_SEMANTIC_CONFIG, scannerSemanticConfigSha256 } from "../scanner-input-scope.js";
import { GEN2_CONTRACTS } from "./compile.js";
import { sourceSha256 } from "./identity.js";

export const SCANNER_RUN_PATH = "prototype/vnext-kernel/generation-2/scanner-run.json";

export type ScannerClassification = "PASS_WITH_DECLARED_EXCEPTION" | "TEST_FIXTURE_BY_DESIGN";

export interface Adjudication {
  classification: ScannerClassification;
  rationale: string;
  /** Required on every PASS_WITH_DECLARED_EXCEPTION. */
  whyStaticAnalysisCannotResolve?: string;
  dynamicProperty?: string;
  mutant?: string;
}

const REENTRANCY_RATIONALE =
  "The kernel emits after an external call by design: the nonce is consumed before the plane and the token run, the balance is snapshotted after the plane and read again after the token, and every nested call clears its own authority. The event order carries no authority.";

/**
 * Keyed by `check|Contract.function(args)`: readable, and stable across a line move. The semantic id is joined
 * in the run record below, so a reader can go from a finding's identity to the reason it is accepted.
 */
export const ADJUDICATIONS: Readonly<Record<string, Adjudication>> = {
  "arbitrary-send-eth|VaultKernelGen2Prototype.egress(address)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "The recipient is migration.destinationVault, written once by bindMigration under guardian quorum AND credential. Permissionless because a caller has no discretion over it.",
    whyStaticAnalysisCannotResolve:
      "Slither sees a value transfer to a storage-derived address reachable by anyone; that the address was fixed by a k+1 authorisation in an earlier transaction is a fact about histories.",
    dynamicProperty: "P-EGRESS-RECIPIENT",
    mutant: "M-G2-9-migration-caller-chooses-recipient",
  },
  "low-level-calls|VaultKernelGen2Prototype.execute(address,uint256,uint256,uint64,bytes,bytes,bytes)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "The new effect surface: one fixed selector on the code-bound asset. A low-level call is required, because the observed delta is the settlement rule and the token's boolean is deliberately not read: a typed call would revert on a token that returns nothing.",
    whyStaticAnalysisCannotResolve:
      "Whether the call settled is a property of the token's ledger, which no static analysis of the kernel can read.",
    dynamicProperty: "P-SETTLEMENT-EXACT",
    mutant: "M-G2-4-boolean-trust",
  },
  "low-level-calls|VaultKernelGen2Prototype.egress(address)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "Two calls: a value transfer to the bound destination, and a fixed-selector transfer on a caller-named holding. The caller names which class leaves, and neither where it goes nor how much.",
    whyStaticAnalysisCannotResolve:
      "An arbitrary address is called, and only the composition with the binding's fixed recipient and the independent per-asset retry makes that safe.",
    dynamicProperty: "P-EXIT-REACHABLE",
    mutant: "M-G2-8-migration-caller-chooses-token",
  },
  "low-level-calls|VaultKernelGen2Prototype._balanceOf(address)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "A read-only fixed-selector staticcall, strict since this lane: a failed query or a short return refuses, so a failure can never read as an observed zero (F-SETTLE).",
    whyStaticAnalysisCannotResolve: "Whether a query's answer is true is the token's behaviour.",
    dynamicProperty: "P-SETTLEMENT-EXACT",
    mutant: "M-G2-12-lenient-balance-read",
  },
  "reentrancy-events|VaultKernelGen2Prototype.execute(address,uint256,uint256,uint64,bytes,bytes,bytes)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: REENTRANCY_RATIONALE,
    whyStaticAnalysisCannotResolve:
      "Slither reports the ordering; serial equivalence of what a hook can do is a claim about all histories.",
    dynamicProperty: "P-NONCE-SPENT-BEFORE-TOKEN-RUNS",
    mutant: "M-G2-6-nonce-after-token-call",
  },
  "reentrancy-events|VaultKernelGen2Prototype.egress(address)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      REENTRANCY_RATIONALE +
      " Egress holds no nonce and needs none: it has no discretion to replay, and a nested egress can only move holdings to the same destination (test/Gen2Reentrancy.test.ts).",
    whyStaticAnalysisCannotResolve: "As above.",
    dynamicProperty: "P-EGRESS-RECIPIENT",
    mutant: "M-G2-9-migration-caller-chooses-recipient",
  },
  "reentrancy-events|VaultKernelGen2FactoryPrototype.deployVault(bytes32,VaultKernelGen2Prototype.GenesisConfig,bytes)":
    {
      classification: "PASS_WITH_DECLARED_EXCEPTION",
      rationale:
        "The event follows a call into a clone this same transaction created, delegating to an implementation the factory fixed at construction. There is no third party in the call.",
      whyStaticAnalysisCannotResolve:
        "Slither does not know the callee was created one statement earlier from an immutable implementation.",
      dynamicProperty: "P-ASSET-CODE-IDENTITY",
      mutant: "M-G2-2-asset-outside-the-identity",
    },
  "timestamp|VaultKernelGen2Prototype.egress(address)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "This lane's admission delta: `block.timestamp < b.boundAt + BIND_DELAY`. The comparison IS I-MIGRATION-SUBORDINATE-TO-RECOVERY. Seven days dwarfs any producer's timestamp slack.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read; only the invariant says this one is meant.",
    dynamicProperty: "P-MIGRATION-TIME",
    mutant: "M-G2-11-egress-delay-removed",
  },
  "timestamp|VaultKernelGen2Prototype.retire()": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "Compares against the same bound. retire gates nothing a binding has not already opened; it freezes authority and egress stays open.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "P-MIGRATION-TIME",
    mutant: "M-G2-11-egress-delay-removed",
  },
  "timestamp|VaultKernelGen2Prototype.enterContainment(VaultKernelGen2Prototype.QuorumProof,uint256,uint64)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "This comparison IS I-CONTAINMENT-BUDGET, stated on wall-clock time, at day scale.",
    whyStaticAnalysisCannotResolve: "The bound is a claim over rolling windows of a history.",
    dynamicProperty: "G-CONTAINMENT-ROLLING-BUDGET",
    mutant: "M14-containment-budget-removed",
  },
  "timestamp|VaultKernelGen2Prototype.executeRecovery(VaultKernelGen2Prototype.CredentialChange)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "The half-open recovery window: 7 days to mature, 14 to expire. Day scale.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "P-MODEL",
    mutant: "M6-cancel-does-not-invalidate",
  },
  "timestamp|VaultKernelGen2Prototype._requireIncomingPossession(bytes32,address,bytes32,address,VaultKernelGen2Prototype.CredentialChange)":
    {
      classification: "PASS_WITH_DECLARED_EXCEPTION",
      rationale:
        "A detector artefact: this function reads no clock. The flagged comparisons are its signature and key checks, reached through a caller's timing guard.",
      whyStaticAnalysisCannotResolve: "Taint from the caller reaches it.",
      dynamicProperty: "P-INCOMING-POSSESSION",
      mutant: "M7-pop-checks-outgoing-key",
    },
  "timestamp|VaultKernelGen2Prototype._containedWithin(uint64,uint64,uint64)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "Pure interval arithmetic behind a view. No authority reads it.",
    whyStaticAnalysisCannotResolve: "Taint from the view's clock argument.",
    dynamicProperty: "G-CONTAINMENT-ROLLING-BUDGET",
    mutant: "M24-tracks-only-the-most-recent-start",
  },
  "timestamp|VaultKernelGen2Prototype._recoveryIsLive()": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "This IS I-RECOVERY-EFFECTIVE-LIVENESS.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "P-MODEL",
    mutant: "M5-recovery-replay-enabled",
  },
  "timestamp|VaultKernelGen2Prototype._effectiveState()": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "Containment self-expires on the wall clock with no principal acting, at a 3-day scale.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "G-EFFECTIVE-STATE-DERIVATION",
    mutant: "M15-effective-state-ignores-expiry",
  },
  "timestamp|VaultKernelGen2Prototype._consume(uint8,uint256,uint64)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "A signer's own deadline. Slack favours nobody but the signer who chose it.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "P-NO-REPLAY",
    mutant: "M-G2-13-spend-nonce-not-consumed",
  },
  "timestamp|VaultKernelGen2Prototype.cancelRecovery(uint256,uint64,bytes)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "Its only clock read is the liveness gate above.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "P-MODEL",
    mutant: "M6-cancel-does-not-invalidate",
  },
  "timestamp|VaultKernelGen2Prototype.containmentUsedInWindow()": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "A view reporting clock-derived accounting. Nothing reads it for authority, and the oracle deliberately does not trust it.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "G-CONTAINMENT-ROLLING-BUDGET",
    mutant: "M24-tracks-only-the-most-recent-start",
  },
  "timestamp|VaultKernelGen2Prototype.containmentWindowStart()": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "A view reporting the rolling origin. Nothing reads it for authority.",
    whyStaticAnalysisCannotResolve: "The detector flags every clock read.",
    dynamicProperty: "G-CONTAINMENT-ROLLING-BUDGET",
    mutant: "M14-containment-budget-removed",
  },
  "assembly|VaultKernelGen2Prototype._admittedAsset()": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "One mload of the third args field at a fixed offset, memory-safe: reading bytes 28..48 of the clone's own code.",
    whyStaticAnalysisCannotResolve:
      "The detector reports all assembly; that the offset is right is proven by reading the deployed code byte for byte.",
    dynamicProperty: "P-ASSET-CODE-IDENTITY",
    mutant: "M-G2-2-asset-outside-the-identity",
  },
  "assembly|VaultKernelGen2Prototype._attests(bytes32,address,bool,bytes)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "A bounded-gas, bounded-returndata STATICCALL Solidity's high-level syntax cannot express, for I-GUARDIAN-FAULT-ISOLATION.",
    whyStaticAnalysisCannotResolve: "Fault isolation is a property under hostile callees.",
    dynamicProperty: "P-CUT/GUARDIAN_TRANSITION",
    mutant: "M13-quorum-counts-indices-not-principals",
  },
  "incorrect-equality|VaultKernelGen2Prototype.containmentUsedInWindow()": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "`containedUntil == 0` is the no-episode sentinel of a word written once per episode from a block timestamp.",
    whyStaticAnalysisCannotResolve: "The detector flags every strict equality on a clock-derived word.",
    dynamicProperty: "G-CONTAINMENT-ROLLING-BUDGET",
    mutant: "M24-tracks-only-the-most-recent-start",
  },
  "incorrect-equality|VaultKernelGen2Prototype._containedWithin(uint64,uint64,uint64)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "`start == 0` is the same sentinel.",
    whyStaticAnalysisCannotResolve: "As above.",
    dynamicProperty: "G-CONTAINMENT-ROLLING-BUDGET",
    mutant: "M24-tracks-only-the-most-recent-start",
  },
  "missing-zero-check|VaultKernelGen2Prototype.setPolicy(address,uint256,uint64,bytes,bytes,bytes).policy": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "address(0) is the documented way back to the kernel floor, never to 'no restriction'.",
    whyStaticAnalysisCannotResolve: "The detector cannot know zero is a meaningful value here.",
    dynamicProperty: "P-PLANE-SUBTRACTIVE",
    mutant: "M11-plane-denial-ignored",
  },
  "uninitialized-local|VaultKernelGen2Prototype._requireQuorum(bytes32,VaultKernelGen2Prototype.QuorumProof).counted": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "A uint256 local Solidity zero-initialises. A counter starting at zero is what is meant.",
    whyStaticAnalysisCannotResolve:
      "A style detector with no security content here; the quorum it counts is what the property watches.",
    dynamicProperty: "P-CUT/GUARDIAN_TRANSITION",
    mutant: "M13-quorum-counts-indices-not-principals",
  },
  "uninitialized-local|VaultKernelGen2Prototype.egress(address).moved": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale: "Zero until assigned, and zero is the truth when nothing moved. A zero-balance egress publishes a zero.",
    whyStaticAnalysisCannotResolve: "Style detector.",
    dynamicProperty: "P-EGRESS-RECIPIENT",
    mutant: "M-G2-9-migration-caller-chooses-recipient",
  },
  "unused-return|VaultKernelGen2Prototype._attests(bytes32,address,bool,bytes)": {
    classification: "PASS_WITH_DECLARED_EXCEPTION",
    rationale:
      "Destructures ECDSA.tryRecover's three values and uses recovered and err. The third is the error's detail, which adds nothing to a refusal.",
    whyStaticAnalysisCannotResolve: "The detector flags the ignored member.",
    dynamicProperty: "P-CUT/GUARDIAN_TRANSITION",
    mutant: "M9-duplicate-guardian-principal",
  },
};

const FIXTURE_RATIONALE =
  "Gen2TokenZoo.sol is a test fixture, never measured and never part of the candidate's identity. Adversarial behaviour is what it is for.";

function signatureOf(f: SlitherFinding): string {
  const first = (f.description ?? "")
    .split("\n")[0]!
    .replace(/\([^()]*prototype[^()]*\)/g, "")
    .trim();
  const match = /([A-Za-z0-9_]+\.[A-Za-z0-9_]+\([^)]*(?:\([^)]*\))?[^)]*\)(?:\.[A-Za-z0-9_]+)?)/.exec(first);
  return match ? match[1]! : first;
}

export const adjudicationKey = (f: SlitherFinding): string => `${f.check}|${signatureOf(f)}`;

export function isFixtureFinding(f: SlitherFinding): boolean {
  return f.elements.every((e) => (e.source_mapping?.filename_relative ?? "").endsWith("Gen2TokenZoo.sol"));
}

export interface ScannerRunRow {
  semanticId: string;
  check: string;
  impact: string;
  confidence: string;
  key: string;
  sourceLocation: string[];
  narrow: string | null;
  broad: string | null;
  classification: ScannerClassification;
}

export interface ScannerRun {
  schema: string;
  note: string;
  tool: {
    slitherCommit: string;
    slitherVersion: string;
    crypticCompile: string;
    solc: string;
    target: string;
    flags: string;
  };
  semanticConfigSha256: string;
  analyzedSources: { path: string; sha256: string }[];
  rawResults: number;
  ownRawResults: number;
  dependencyOnlyResults: number;
  canonicalAllFindingsSha256: string;
  distinctOwnFindings: ScannerRunRow[];
  kernelAndFactoryFindings: number;
  fixtureFindings: number;
  severity: Record<string, number>;
}

export const SCANNER_TARGET = "prototype/vnext-kernel/generation-2/contracts";
const SOURCES = [
  "VaultKernelGen2Prototype.sol",
  "VaultKernelGen2FactoryPrototype.sol",
  "interfaces/IKernelPlanes.sol",
  "Gen2TokenZoo.sol",
];

export const analyzedSources = (): { path: string; sha256: string }[] =>
  SOURCES.map((rel) => ({ path: `${SCANNER_TARGET}/${rel}`, sha256: sourceSha256(path.join(GEN2_CONTRACTS, rel)) }));

/** Reduces a raw Slither run to what a finding means: no machine path, no line-dependent identity, no raw bytes. */
export function reduceRun(rawJson: string): ScannerRun {
  const raw = JSON.parse(rawJson) as { success: boolean; results: { detectors: SlitherFinding[] } };
  if (!raw.success) throw new Error("the Slither run did not succeed");
  const findings = raw.results.detectors;
  const own = findings.filter(isOwnFinding);
  const read = (rel: string): string[] => fs.readFileSync(rel, "utf8").split("\n");
  const index = indexFindings(own, read);
  if (index.ambiguities.length > 0)
    throw new Error("two findings share a semantic id: " + JSON.stringify(index.ambiguities));

  const seen = new Map<string, SlitherFinding>();
  for (const f of own) seen.set(semanticId(f), f);
  const rows: ScannerRunRow[] = [...seen.entries()].map(([id, f]) => {
    const row = index.byId.get(id)!;
    const fixture = isFixtureFinding(f);
    const key = adjudicationKey(f);
    const adjudication = ADJUDICATIONS[key];
    if (!fixture && adjudication === undefined)
      throw new Error(`no adjudication for ${key}. Read the finding before adding one.`);
    return {
      semanticId: id,
      check: f.check,
      impact: f.impact,
      confidence: f.confidence,
      key,
      sourceLocation: [...new Set(row.lineSpans)].sort(),
      narrow: row.narrow ?? null,
      broad: row.broad ?? null,
      classification: fixture ? "TEST_FIXTURE_BY_DESIGN" : adjudication!.classification,
    };
  });
  rows.sort((a, b) => a.semanticId.localeCompare(b.semanticId));

  const severity: Record<string, number> = {};
  for (const r of rows) severity[r.impact] = (severity[r.impact] ?? 0) + 1;
  return {
    schema: "vnext-kernel-gen2-scanner-run.v1",
    note:
      "The reduction of one Slither run on generation-2/contracts. The raw file embeds absolute paths and is deliberately not committed: canonicalAllFindingsSha256 is what a re-run compares. " +
      FIXTURE_RATIONALE,
    tool: {
      slitherCommit: PINNED_SEMANTIC_CONFIG.slitherCommit,
      slitherVersion: "0.11.5",
      crypticCompile: PINNED_SEMANTIC_CONFIG.crypticCompile,
      solc: PINNED_SEMANTIC_CONFIG.solc,
      target: SCANNER_TARGET,
      flags: `--compile-force-framework solc --solc-remaps "@openzeppelin/=node_modules/@openzeppelin/" --solc-args "--evm-version cancun --optimize --optimize-runs 200" --exclude-dependencies --no-fail-pedantic`,
    },
    semanticConfigSha256: scannerSemanticConfigSha256({ ...PINNED_SEMANTIC_CONFIG, target: SCANNER_TARGET }),
    analyzedSources: analyzedSources(),
    rawResults: findings.length,
    ownRawResults: own.length,
    dependencyOnlyResults: findings.length - own.length,
    canonicalAllFindingsSha256: canonicalAllFindingsSha256(findings),
    distinctOwnFindings: rows,
    kernelAndFactoryFindings: rows.filter((r) => r.classification !== "TEST_FIXTURE_BY_DESIGN").length,
    fixtureFindings: rows.filter((r) => r.classification === "TEST_FIXTURE_BY_DESIGN").length,
    severity,
  };
}

if (process.argv[1]?.endsWith("scanner.ts")) {
  const rawPath = process.argv[2];
  if (!rawPath) throw new Error("usage: tsx generation-2/scanner.ts <raw slither json>");
  const run = reduceRun(fs.readFileSync(rawPath, "utf8"));
  fs.writeFileSync(SCANNER_RUN_PATH, JSON.stringify(run, null, 2) + "\n");
  console.log(
    `Wrote ${SCANNER_RUN_PATH}: ${run.rawResults} raw, ${run.distinctOwnFindings.length} distinct own (${run.kernelAndFactoryFindings} candidate, ${run.fixtureFindings} fixture)`,
  );
}
