/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * THE SCANNER-INPUT SCOPE: what must be byte-equal for two commits to share a scanner result.
 *
 * WHY NOT `MEASUREMENTS.json.sourceDigests`. That block is the MEASURED scope — the contracts
 * `measure.ts` weighs and `reproduce.ts` rebuilds. It lists three project files and omits
 * `PrototypeMocks.sol`, because the mocks are never deployed or measured. But Slither DOES analyze
 * the mocks: 12 of the 33 distinct own-code findings live in them. Reusing `sourceDigests` as the
 * scanner scope would silently under-cover by exactly the file with the most findings, which is
 * the "one artifact's coverage taken for another's" error the receipts are separated to avoid.
 *
 * WHY NOT COUNTS OR ANCESTRY. Between a46bc50c and aaa21d09 the raw count (217), the own count
 * (54) and the distinct count (33) are all equal, and a46bc50c is an ancestor of aaa21d09 — and
 * yet 21 of 33 findings moved and one function's body changed. Equal counts and ancestry are
 * both TRUE and both WORTHLESS as a currency licence. Only byte equality of the inputs licenses
 * carrying a scanner result from one commit to another.
 *
 * THE THREE BOUND DIGESTS:
 *
 *   contractsTree               git's own Merkle oid for prototype/vnext-kernel/contracts. One
 *                               40-hex value covering every analyzed .sol including the mocks and
 *                               the interfaces, with no list to keep in sync.
 *   externalImportClosureSha256 the transitive import closure reached through the remap, hashed
 *                               as sorted `path:sha256` lines. Derived by walking imports from the
 *                               project sources, never hand-listed.
 *   scannerSemanticConfigSha256 everything about the invocation that can change the RESULT SET.
 *
 * OUTPUT-ONLY FLAGS ARE EXCLUDED FROM THE CONFIG DIGEST. `--sarif <path>` and `--json <path>`
 * choose where results are written, not what they are; `--no-fail-pedantic` chooses an exit code.
 * Hashing a path would also make the digest machine-dependent, which is the same defect as
 * hashing Slither's `filename_absolute`.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const CONTRACTS_PATH = "prototype/vnext-kernel/contracts";
export const OZ_PACKAGE = "node_modules/@openzeppelin/contracts";
export const REMAP_PREFIX = "@openzeppelin/contracts/";

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest("hex");

export interface ScannerSemanticConfig {
  slitherCommit: string;
  crypticCompile: string;
  solc: string;
  evmVersion: string;
  optimizer: { enabled: boolean; runs: number };
  remaps: string[];
  target: string;
  compileFramework: string;
  dependencyPolicy: string;
}

/**
 * The pinned configuration, mirrored from `.github/workflows/vnext-kernel-assurance.yml`.
 *
 * Kept as data rather than parsed out of the workflow on purpose: a parser would silently agree
 * with whatever the workflow says, including a value someone changed by accident. A literal here
 * DISAGREES when the workflow drifts, and the workflow-shape guard is what catches that.
 */
export const PINNED_SEMANTIC_CONFIG: ScannerSemanticConfig = {
  slitherCommit: "ff1bf3ff4a5ebdfa63e4b83cb4885f682624daad",
  crypticCompile: "0.4.2",
  solc: "0.8.24+commit.e11b9ed9",
  evmVersion: "cancun",
  optimizer: { enabled: true, runs: 200 },
  remaps: ["@openzeppelin/=node_modules/@openzeppelin/"],
  target: CONTRACTS_PATH,
  compileFramework: "solc",
  dependencyPolicy: "--exclude-dependencies",
};

/** Flags deliberately NOT hashed, recorded so the exclusion is auditable rather than implicit. */
export const OUTPUT_ONLY_FLAGS = ["--sarif", "--json", "--no-fail-pedantic"] as const;

export function scannerSemanticConfigSha256(cfg: ScannerSemanticConfig = PINNED_SEMANTIC_CONFIG): string {
  return sha256(JSON.stringify(cfg));
}

export type GitRunner = (args: string[]) => string;
export const realGit: GitRunner = (args) =>
  execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

/** git's Merkle oid for the analyzed contracts directory at `rev`. Throws when `rev` is unresolvable. */
export function contractsTree(rev: string, git: GitRunner = realGit): string {
  return git(["rev-parse", `${rev}:${CONTRACTS_PATH}`]);
}

/**
 * Walks imports from the project sources through the remap and returns the transitive closure of
 * external files, as repo-relative paths, sorted.
 */
export function externalImportClosure(rootDir: string): string[] {
  const projectDir = path.join(rootDir, CONTRACTS_PATH);
  const ozDir = path.join(rootDir, OZ_PACKAGE);
  const seen = new Set<string>();

  const readImports = (text: string): string[] =>
    [...text.matchAll(/import\s*(?:\{[^}]*\}\s*from\s*)?["']([^"']+)["']/g)].map((m) => m[1]);

  const walkExternal = (rel: string): void => {
    if (seen.has(rel)) return;
    seen.add(rel);
    const abs = path.join(ozDir, rel);
    if (!fs.existsSync(abs)) throw new Error(`scanner input closure: missing external source ${rel}`);
    for (const spec of readImports(fs.readFileSync(abs, "utf8"))) {
      if (spec.startsWith(REMAP_PREFIX)) walkExternal(spec.slice(REMAP_PREFIX.length));
      else if (spec.startsWith(".")) walkExternal(path.posix.normalize(path.posix.join(path.posix.dirname(rel), spec)));
    }
  };

  const walkProject = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walkProject(p);
      else if (entry.name.endsWith(".sol")) {
        for (const spec of readImports(fs.readFileSync(p, "utf8"))) {
          if (spec.startsWith(REMAP_PREFIX)) walkExternal(spec.slice(REMAP_PREFIX.length));
        }
      }
    }
  };

  walkProject(projectDir);
  return [...seen].sort();
}

export function externalImportClosureSha256(rootDir: string, ozVersion: string): string {
  const ozDir = path.join(rootDir, OZ_PACKAGE);
  const lines = externalImportClosure(rootDir).map(
    (rel) => `npm/@openzeppelin/contracts@${ozVersion}/${rel}:${sha256(fs.readFileSync(path.join(ozDir, rel)))}`,
  );
  return sha256(lines.join("\n"));
}

export function installedOzVersion(rootDir: string): string {
  const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, OZ_PACKAGE, "package.json"), "utf8"));
  return pkg.version as string;
}

/** The `@openzeppelin/contracts` pin recorded in the lockfile at `rev` — the bytes CI will install. */
export function lockedOzPin(rev: string, git: GitRunner = realGit): { version: string; integrity: string } {
  const lock = JSON.parse(git(["show", `${rev}:package-lock.json`]));
  const entry = lock.packages?.[OZ_PACKAGE];
  if (!entry) throw new Error(`scanner input scope: ${OZ_PACKAGE} absent from package-lock.json at ${rev}`);
  return { version: entry.version, integrity: entry.integrity };
}

export interface ScannerInputScope {
  contractsTree: string;
  externalImportClosureSha256: string;
  scannerSemanticConfigSha256: string;
  openzeppelin: { version: string; integrity: string };
}

export function scopeAt(rev: string, rootDir: string, git: GitRunner = realGit): ScannerInputScope {
  const pin = lockedOzPin(rev, git);
  return {
    contractsTree: contractsTree(rev, git),
    externalImportClosureSha256: externalImportClosureSha256(rootDir, pin.version),
    scannerSemanticConfigSha256: scannerSemanticConfigSha256(),
    openzeppelin: pin,
  };
}

export interface ScopeComparison {
  equal: boolean;
  differences: string[];
}

/**
 * FAIL-CLOSED comparison. Every field must be equal; a missing field is a difference, never a pass.
 */
export function compareScopes(a: ScannerInputScope, b: ScannerInputScope): ScopeComparison {
  const differences: string[] = [];
  const cmp = (name: string, x: unknown, y: unknown) => {
    if (JSON.stringify(x) !== JSON.stringify(y)) differences.push(`${name}: ${JSON.stringify(x)} != ${JSON.stringify(y)}`);
  };
  cmp("contractsTree", a.contractsTree, b.contractsTree);
  cmp("externalImportClosureSha256", a.externalImportClosureSha256, b.externalImportClosureSha256);
  cmp("scannerSemanticConfigSha256", a.scannerSemanticConfigSha256, b.scannerSemanticConfigSha256);
  cmp("openzeppelin", a.openzeppelin, b.openzeppelin);
  return { equal: differences.length === 0, differences };
}

/**
 * Licences a receipt generated at `generationRev` to describe `sourceRev`.
 *
 * The ONLY admissible licence. Equal finding counts, equal raw hashes and ancestry are all
 * explicitly insufficient and are not consulted here.
 */
export function assertScopeEquality(
  sourceRev: string,
  generationRev: string,
  rootDir: string,
  git: GitRunner = realGit,
): ScannerInputScope {
  const source = scopeAt(sourceRev, rootDir, git);
  const generation = scopeAt(generationRev, rootDir, git);
  const { equal, differences } = compareScopes(source, generation);
  if (!equal) {
    throw new Error(
      `scanner-input scope differs between source subject ${sourceRev} and generation subject ${generationRev}; ` +
        `a receipt may not claim currency across this gap:\n  ${differences.join("\n  ")}`,
    );
  }
  return source;
}
