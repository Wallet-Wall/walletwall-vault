/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * WORKFLOW / CONFIG EQUIVALENCE — fail-closed.
 *
 * `scanner-input-scope.ts` hashes `PINNED_SEMANTIC_CONFIG` into
 * `scannerSemanticConfigSha256`, which licenses carrying a scanner result from one commit to
 * another. That constant was TRANSCRIBED from `.github/workflows/vnext-kernel-assurance.yml`, so
 * the two could drift: someone bumps `solc-version` in the workflow, the constant stays put, the
 * digest does not move, and a receipt keeps claiming currency across a change that alters every
 * result. The digest would be attesting to a configuration nothing runs.
 *
 * WHY A VERIFIER RATHER THAN ONE SHARED SOURCE. Deriving the digest by parsing YAML at generation
 * time would remove the duplication but make the digest depend on a parser and on formatting, and
 * `js-yaml` is only a transitive dependency here (v5, with an API that has since changed twice).
 * A literal constant plus an independent equivalence check keeps the digest stable and byte-simple
 * while still making drift IMPOSSIBLE TO MISS -- and, unlike a shared source, it fails loudly when
 * a field it does not understand appears.
 *
 * EXTRACTION IS ANCHORED AND FAIL-CLOSED. Every field below is located by an explicit pattern; a
 * field that cannot be located throws rather than defaulting, because a silently-absent anchor is
 * exactly how a verifier turns into a rubber stamp.
 *
 * THE ONE FIELD THE WORKFLOW CANNOT EXPRESS, AND HOW IT IS PINNED ANYWAY. The workflow pins the
 * ACTION and, through it, `slither-version` and `solc-version`. It cannot name `crytic-compile`:
 * that comes from the pinned Slither commit's own constraint, `crytic-compile<0.5.0,>=0.4.1` -- a
 * RANGE. It decides how sources are compiled and named, so a different resolution can change
 * results.
 *
 * An earlier revision merely DOCUMENTED that gap in `WORKFLOW_UNPINNED` and called the observed
 * 0.4.2 "bound by the observed resolution". That was not a pin: nothing stopped the next install
 * resolving 0.4.3. The gap is now closed rather than described -- the action's `slither-plugins`
 * input runs `pip3 install -r` in the SAME venv after Slither, so `scanner-requirements.txt`
 * forces the exact version and fails the step if it cannot be satisfied.
 * `assertScannerRequirementsPinned` checks that file against the hashed config and
 * `assertWorkflowUsesRequirements` checks the workflow actually hands it over; without the second,
 * the pin could sit in the repository uninstalled.
 */
import fs from "node:fs";
import { PINNED_SEMANTIC_CONFIG, type ScannerSemanticConfig } from "./scanner-input-scope.js";

export const WORKFLOW_PATH = ".github/workflows/vnext-kernel-assurance.yml";

export const REQUIREMENTS_PATH = "prototype/vnext-kernel/scanner-requirements.txt";

/**
 * Semantic-config fields the workflow does NOT pin.
 *
 * NOW EMPTY, and that is the point. `crypticCompile` used to live here with a paragraph
 * explaining why it could not be pinned: the action installs Slither from a pinned commit and
 * crytic-compile is resolved from that commit's own constraint, `crytic-compile<0.5.0,>=0.4.1`.
 * A RANGE. Documenting the gap did not close it -- the observed 0.4.2 was a resolution, not a pin,
 * and a later resolution to 0.4.3 would have changed how sources are compiled and named with
 * nothing to object.
 *
 * The action's `slither-plugins` input runs `pip3 install -r <file>` in the SAME venv AFTER
 * Slither is installed, so `scanner-requirements.txt` forces the exact version and fails the step
 * if it cannot be satisfied. An entry may only be added back here with a reason that survives the
 * question this one did not: "what stops it changing?"
 */
export const WORKFLOW_UNPINNED: Readonly<Record<string, string>> = Object.freeze({});

export interface WorkflowScannerConfig {
  action: string;
  slitherCommit: string;
  solcVersion: string;
  target: string;
  compileFramework: string;
  remaps: string[];
  evmVersion: string;
  optimizerEnabled: boolean;
  optimizerRuns: number;
  dependencyPolicy: string;
  failOn: string;
  emitsJson: boolean;
  emitsSarif: boolean;
}

function must(text: string, re: RegExp, what: string): RegExpMatchArray {
  const m = text.match(re);
  if (!m) {
    throw new Error(
      `${WORKFLOW_PATH}: could not locate ${what}. The workflow/config equivalence verifier is ` +
        `fail-closed: an anchor it cannot find is treated as drift, never as agreement.`,
    );
  }
  return m;
}

/**
 * Removes full-line YAML comments before extraction.
 *
 * NOT COSMETIC. This workflow documents itself heavily, and the prose QUOTES the very flags being
 * extracted -- `# WHY --compile-force-framework solc, not hardhat:` and
 * "`fail-on: none` matches production's slither.yml". Matching against the raw text captured
 * `"solc,"` and ``"none`"`` from those comments instead of the real values, which meant the
 * verifier was comparing PROSE to the hashed config: someone could change the actual argument and
 * leave the comment alone, and the check would still agree. A verifier that reads documentation
 * instead of configuration is worse than none, because it reports agreement it never established.
 */
function stripYamlComments(text: string): string {
  return text
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
}

/** Extracts the scanner-semantic configuration actually expressed by the workflow. */
export function readWorkflowScannerConfig(path: string = WORKFLOW_PATH): WorkflowScannerConfig {
  const text = stripYamlComments(fs.readFileSync(path, "utf8"));
  const action = must(text, /uses:\s*(crytic\/slither-action@[0-9a-f]{40})/, "the pinned slither-action")[1];
  const slitherCommit = must(text, /slither-version:\s*([0-9a-f]{40})/, "slither-version")[1];
  const solcVersion = must(text, /solc-version:\s*"([^"]+)"/, "solc-version")[1];
  const target = must(text, /^\s*target:\s*(\S+)\s*$/m, "the Slither target path")[1];
  const compileFramework = must(text, /--compile-force-framework\s+(\S+)/, "--compile-force-framework")[1];
  const remap = must(text, /--solc-remaps\s+"([^"]+)"/, "--solc-remaps")[1];
  const solcArgs = must(text, /--solc-args\s+"([^"]+)"/, "--solc-args")[1];
  const evmVersion = must(solcArgs, /--evm-version\s+(\S+)/, "--evm-version inside --solc-args")[1];
  const optimizerRuns = Number(must(solcArgs, /--optimize-runs\s+(\d+)/, "--optimize-runs inside --solc-args")[1]);
  const failOn = must(text, /fail-on:\s*(\S+)/, "fail-on")[1];
  if (!/--exclude-dependencies/.test(text)) {
    throw new Error(`${WORKFLOW_PATH}: --exclude-dependencies is absent; the dependency policy no longer matches the hashed config.`);
  }
  return {
    action,
    slitherCommit,
    solcVersion,
    target,
    compileFramework,
    remaps: [remap],
    evmVersion,
    optimizerEnabled: /--optimize(\s|$)/.test(solcArgs),
    optimizerRuns,
    dependencyPolicy: "--exclude-dependencies",
    failOn,
    emitsJson: /--json\s+\S+/.test(text),
    emitsSarif: /sarif:\s*\S+/.test(text),
  };
}

export interface EquivalenceResult {
  equal: boolean;
  differences: string[];
  checked: string[];
}

/**
 * Compares the workflow against the hashed constant, field by field.
 *
 * `solcVersion` is compared on the part before `+`: the workflow names a solc-select version
 * ("0.8.24") while the constant records the full compiler identity the run reported
 * ("0.8.24+commit.e11b9ed9"). The commit suffix is not something the workflow can express, so
 * requiring equality there would be a permanent false failure.
 */
export function compareWorkflowToPinnedConfig(
  workflow: WorkflowScannerConfig,
  pinned: ScannerSemanticConfig = PINNED_SEMANTIC_CONFIG,
): EquivalenceResult {
  const differences: string[] = [];
  const checked: string[] = [];
  const cmp = (field: string, fromWorkflow: unknown, fromPinned: unknown) => {
    checked.push(field);
    if (JSON.stringify(fromWorkflow) !== JSON.stringify(fromPinned)) {
      differences.push(`${field}: workflow ${JSON.stringify(fromWorkflow)} != PINNED_SEMANTIC_CONFIG ${JSON.stringify(fromPinned)}`);
    }
  };
  cmp("slitherCommit", workflow.slitherCommit, pinned.slitherCommit);
  cmp("solc", workflow.solcVersion, pinned.solc.split("+")[0]);
  cmp("evmVersion", workflow.evmVersion, pinned.evmVersion);
  cmp("optimizer.enabled", workflow.optimizerEnabled, pinned.optimizer.enabled);
  cmp("optimizer.runs", workflow.optimizerRuns, pinned.optimizer.runs);
  cmp("remaps", workflow.remaps, pinned.remaps);
  cmp("target", workflow.target, pinned.target);
  cmp("compileFramework", workflow.compileFramework, pinned.compileFramework);
  cmp("dependencyPolicy", workflow.dependencyPolicy, pinned.dependencyPolicy);
  return { equal: differences.length === 0, differences, checked };
}

/** Throws unless the workflow and the hashed config agree on every comparable field. */
export function assertWorkflowMatchesPinnedConfig(path: string = WORKFLOW_PATH): EquivalenceResult {
  const result = compareWorkflowToPinnedConfig(readWorkflowScannerConfig(path));
  if (!result.equal) {
    throw new Error(
      `the Slither invocation in ${path} no longer matches PINNED_SEMANTIC_CONFIG, so ` +
        `scannerSemanticConfigSha256 attests to a configuration nothing runs:\n  ` +
        result.differences.join("\n  "),
    );
  }
  return result;
}

/** Parses a pip requirements file into exact `name==version` pins, ignoring comments and blanks. */
export function readPinnedRequirements(path: string = REQUIREMENTS_PATH): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of fs.readFileSync(path, "utf8").split("\n")) {
    const line = raw.split("#")[0].trim();
    if (!line) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)==([A-Za-z0-9._-]+)$/);
    if (!m) {
      throw new Error(
        `${path}: "${line}" is not an EXACT pin. Only `+"`name==version`"+` is accepted here; a range ` +
          `is what left crytic-compile unpinned in the first place.`,
      );
    }
    out.set(m[1].toLowerCase(), m[2]);
  }
  return out;
}

/**
 * The requirements file must pin exactly the versions the hashed config claims.
 *
 * Fail-closed in both directions: a version that differs is drift, and a dependency the hashed
 * config names but the file does not pin is an unclosed gap rather than an omission.
 */
export function assertScannerRequirementsPinned(
  path: string = REQUIREMENTS_PATH,
  pinned: ScannerSemanticConfig = PINNED_SEMANTIC_CONFIG,
): Map<string, string> {
  const reqs = readPinnedRequirements(path);
  const actual = reqs.get("crytic-compile");
  if (!actual) {
    throw new Error(`${path}: crytic-compile is not pinned. It is part of the hashed scanner config and the workflow cannot express it.`);
  }
  if (actual !== pinned.crypticCompile) {
    throw new Error(
      `${path} pins crytic-compile==${actual} but PINNED_SEMANTIC_CONFIG hashes ${pinned.crypticCompile}; ` +
        `scannerSemanticConfigSha256 would attest to a compiler front-end nothing installs`,
    );
  }
  return reqs;
}

/** The workflow must actually hand that requirements file to the action. */
export function assertWorkflowUsesRequirements(path: string = WORKFLOW_PATH): void {
  const text = stripYamlComments(fs.readFileSync(path, "utf8"));
  const m = text.match(/slither-plugins:\s*(\S+)/);
  if (!m) {
    throw new Error(
      `${path}: slither-plugins is not set, so ${REQUIREMENTS_PATH} is never installed and ` +
        `crytic-compile falls back to range resolution`,
    );
  }
  if (m[1] !== REQUIREMENTS_PATH) {
    throw new Error(`${path}: slither-plugins points at ${m[1]}, not ${REQUIREMENTS_PATH}`);
  }
}

/**
 * The workflow must keep emitting BOTH outputs from the one execution, and must not start gating
 * on detector severity. Neither value is part of the semantic digest -- they cannot change the
 * result set -- but both are load-bearing for the gate that consumes the results.
 */
export function assertWorkflowOutputContract(path: string = WORKFLOW_PATH): void {
  const w = readWorkflowScannerConfig(path);
  if (!w.emitsSarif) throw new Error(`${path}: the SARIF output is gone; scanner findings would stop reaching GitHub.`);
  if (!w.emitsJson) {
    throw new Error(
      `${path}: --json is gone. SARIF carries only each result's primary location, so the element ` +
        `chain a finding's semantic identity is built from cannot be recovered from it and the ` +
        `triage gate has no input.`,
    );
  }
  if (w.failOn !== "none") {
    throw new Error(
      `${path}: fail-on is "${w.failOn}", not "none". This lane's security claim is the firsthand ` +
        `triage, not a scanner's confidence-weighted severity; gating here would manufacture the ` +
        `"scanner-green implies safe" signal the workflow comment exists to avoid.`,
    );
  }
}
