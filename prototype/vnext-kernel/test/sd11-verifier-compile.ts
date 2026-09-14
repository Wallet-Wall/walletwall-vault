/**
 * EXPERIMENTAL PROTOTYPE ASSURANCE TOOLING — NOT PRODUCTION.
 *
 * LANE SD-11: an in-memory Solidity compiler for VERIFIER fixtures, plus the
 * REAL production verifier sources read from `contracts/`.
 *
 * WHY THIS EXISTS AND WHY IT WRITES NOTHING
 * -----------------------------------------
 * SD-11A and SD-11B are questions about VERIFIERS, and answering them needs
 * verifier contracts the prototype's own `contracts/` directory does not
 * contain. Adding them there would be the wrong instrument twice over:
 *
 *   1. `prototype/vnext-kernel/contracts` is the SCANNER INPUT SCOPE. Its git
 *      tree oid is one of the three digests that license carrying a Slither
 *      result from one commit to another (`scanner-input-scope.ts`). Adding a
 *      single file moves `contractsTree`, which invalidates the committed
 *      `SCANNER_EVIDENCE.json` and demands a fresh pinned Slither run before CI
 *      can be green again — an enormous blast radius for a diagnostic fixture.
 *   2. The measured surface (`measure.ts`, `reproduce.ts`) and the mutation
 *      catalogue both enumerate that directory. A fixture there would have to be
 *      explained to every one of them.
 *
 * So this module does what `stateful/mutants.ts` and
 * `authority/mutation-harness.ts` already do for MUTATED KERNELS — drives the
 * PINNED solc binary directly through `--standard-json` and returns deployable
 * artifacts — and never writes to `contracts/`, to `artifacts/` or to `cache/`.
 *
 * THE PRODUCTION SOURCES ARE READ, NEVER COPIED
 * ---------------------------------------------
 * `productionSource()` reads `contracts/verifiers/*.sol` from disk at their real
 * repo-relative paths and hands them to solc under those same keys, so the
 * relative import `../IPQCVerifier.sol` resolves to the real
 * `contracts/IPQCVerifier.sol` through `--base-path .`. The bytes deployed in a
 * reproduction are therefore compiled from THE ACTUAL REPOSITORY ARTIFACT, not
 * from a paraphrase of it that could flatter the finding. A port would have been
 * open to exactly the objection SD5-A1R had to accept once already: that the
 * measurement was of the harness rather than of the system.
 *
 * THIS IS A READ-ONLY CROSS-BOUNDARY MEASUREMENT, and the coupling it creates is
 * deliberate: if a production verifier's source changes, a reproduction built on
 * it should CHANGE ITS ANSWER rather than keep publishing a stale one. The tests
 * that use this module therefore assert the structural facts they depend on
 * (which contracts exist, which mutator functions their ABIs do and do not
 * expose) rather than assuming them.
 *
 * NO `setCode` ANYWHERE. Everything here produces CREATION bytecode, deployed by
 * an ordinary transaction. `setCode` proves REPRESENTABILITY under an interface
 * and never DEPLOYMENT REACHABILITY — the correction SD5-A1R accepted and this
 * lane inherits.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SOLC_VERSION = "0.8.24";

// Duplicated from stateful/mutants.ts and authority/mutation-harness.ts for the
// reason those two already duplicate each other: each must stay runnable without
// importing another module's CLI-oriented main().
function compilerCachePlatform(): string {
  switch (os.platform()) {
    case "win32":
      return "windows-amd64";
    case "linux":
      return os.arch() === "arm64" ? "linux-arm64" : "linux-amd64";
    case "darwin":
      return "macosx-amd64";
    default:
      throw new Error("no native solc cache layout known for platform " + os.platform() + "/" + os.arch());
  }
}

function hardhatCacheRoot(): string {
  const home = os.homedir();
  switch (os.platform()) {
    case "win32":
      return path.join(process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local"), "hardhat-nodejs", "Cache");
    case "darwin":
      return path.join(home, "Library", "Caches", "hardhat-nodejs");
    case "linux":
      return path.join(process.env.XDG_CACHE_HOME ?? path.join(home, ".cache"), "hardhat-nodejs");
    default:
      throw new Error("no known hardhat cache directory convention for platform " + os.platform());
  }
}

function solcPath(): string {
  const base = path.join(hardhatCacheRoot(), "compilers-v3", compilerCachePlatform());
  const hit = fs.readdirSync(base).find((f) => f.includes(SOLC_VERSION));
  if (hit === undefined) throw new Error("pinned solc " + SOLC_VERSION + " not found in " + base);
  return path.join(base, hit);
}

export interface Deployable {
  readonly abi: unknown[];
  readonly bytecode: string;
  /** The compiler's deployedBytecode, for immutable-range reasoning. NOT an identity claim. */
  readonly deployedBytecode: string;
}

/** Reads a production contract at its real repo-relative path, so solc resolves its imports on disk. */
export function productionSource(repoRelativePath: string): { key: string; content: string } {
  const content = fs.readFileSync(repoRelativePath, "utf8");
  return { key: repoRelativePath.split(path.sep).join("/"), content };
}

/**
 * Compiles `sources` with the settings PINNED IDENTICAL to the prototype's own
 * hardhat config (0.8.24, cancun, optimizer on / 200 runs, viaIR off), so a
 * fixture and the kernel it is admitted into are built by the same compiler
 * under the same settings.
 */
export function compileSources(sources: Readonly<Record<string, string>>): Map<string, Deployable> {
  const input = {
    language: "Solidity",
    sources: Object.fromEntries(Object.entries(sources).map(([k, content]) => [k, { content }])),
    settings: {
      evmVersion: "cancun",
      optimizer: { enabled: true, runs: 200 },
      remappings: ["@openzeppelin/=node_modules/@openzeppelin/"],
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } },
    },
  };

  const raw = execFileSync(solcPath(), ["--standard-json", "--base-path", ".", "--include-path", "node_modules"], {
    input: JSON.stringify(input),
    maxBuffer: 256 * 1024 * 1024,
  }).toString();

  const parsed = JSON.parse(raw) as {
    errors?: { severity: string; formattedMessage: string }[];
    contracts?: Record<
      string,
      Record<string, { abi: unknown[]; evm: { bytecode: { object: string }; deployedBytecode: { object: string } } }>
    >;
  };

  const fatal = (parsed.errors ?? []).filter((e) => e.severity === "error").map((e) => e.formattedMessage);
  if (fatal.length > 0) throw new Error("SD-11 fixture compilation failed:\n" + fatal.join("\n"));

  const out = new Map<string, Deployable>();
  for (const [file, units] of Object.entries(parsed.contracts ?? {})) {
    for (const [name, unit] of Object.entries(units)) {
      // Last writer wins only if a name repeats across files; the callers below
      // use unique contract names, and `has()` is asserted by the suite.
      out.set(name, {
        abi: unit.abi,
        bytecode: "0x" + unit.evm.bytecode.object,
        deployedBytecode: "0x" + unit.evm.deployedBytecode.object,
      });
      out.set(file + ":" + name, {
        abi: unit.abi,
        bytecode: "0x" + unit.evm.bytecode.object,
        deployedBytecode: "0x" + unit.evm.deployedBytecode.object,
      });
    }
  }
  return out;
}
