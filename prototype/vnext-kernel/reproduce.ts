/**
 * EXPERIMENTAL PROTOTYPE — deterministic rebuild + storage layout + selectors.
 *
 * Drives the PINNED solc binary directly from the sources on disk, so the
 * prototype can be rebuilt independently of Hardhat and byte-compared. It also
 * requests `storageLayout`, which the Hardhat build does not emit.
 *
 * Run:  npx tsx prototype/vnext-kernel/reproduce.ts
 *       npx tsx prototype/vnext-kernel/reproduce.ts --json
 *
 * Never run against a coverage-instrumented tree.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SOLC_VERSION = "0.8.24";
const SOLC_LONG = "0.8.24+commit.e11b9ed9";
const SETTINGS = {
  evmVersion: "cancun",
  optimizer: { enabled: true, runs: 200 },
  viaIR: false,
} as const;

const ROOT = path.join("prototype", "vnext-kernel");
const SRC = path.join(ROOT, "contracts");

/**
 * Hardhat's own compiler-cache platform directory name (mirrors
 * CompilerPlatform in hardhat/src/internal/builtin-plugins/solidity/
 * build-system/compiler/downloader.ts, which this script deliberately does
 * not import -- it drives solc independently of Hardhat's build system, see
 * this file's header comment). Only the OS/arch combinations Hardhat itself
 * resolves to a native (non-WASM) binary are handled; anything else throws
 * rather than guessing a cache layout this script has not verified.
 */
function compilerCachePlatform(): string {
  switch (os.platform()) {
    case "win32":
      return "windows-amd64";
    case "linux":
      return os.arch() === "arm64" ? "linux-arm64" : "linux-amd64";
    case "darwin":
      return "macosx-amd64";
    default:
      throw new Error(`no native solc cache layout known for platform ${os.platform()}/${os.arch()}`);
  }
}

/**
 * Hardhat's global cache root, "<name>-nodejs" under the OS cache
 * convention (mirrors the `env-paths` package's `cache` entry for
 * name="hardhat", the same package @nomicfoundation/hardhat-utils'
 * getCacheDir() resolves through -- reimplemented here, synchronously and
 * without a new dependency, rather than importing that async helper from a
 * package this project does not itself depend on directly).
 */
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
      throw new Error(`no known hardhat cache directory convention for platform ${os.platform()}`);
  }
}

function solcPath(): string {
  const base = path.join(hardhatCacheRoot(), "compilers-v3", compilerCachePlatform());
  // The cached binary has no extension on Linux/macOS and a .exe extension
  // on Windows; list.json (the only other file in this directory) never
  // contains the version string, so matching on SOLC_VERSION alone is
  // sufficient without also requiring a specific extension.
  const hit = fs.readdirSync(base).find((f) => f.includes(SOLC_VERSION));
  if (hit === undefined) throw new Error(`pinned solc ${SOLC_VERSION} not found in ${base}`);
  return path.join(base, hit);
}

export interface Repro {
  readonly solcVersion: string;
  readonly solcLongVersion: string;
  readonly settings: typeof SETTINGS;
  readonly sourceDigests: Record<string, string>;
  readonly contracts: Record<
    string,
    {
      runtimeBytes: number;
      initcodeBytes: number;
      runtimeSha256: string;
      immutableSlots: number;
      selectors: Record<string, string>;
      storage: { slot: string; offset: number; label: string; type: string; bytes: string }[];
    }
  >;
}

const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

export function build(): Repro {
  const solc = solcPath();
  const input = {
    language: "Solidity",
    sources: sourcesWithRemappedImports(),
    settings: {
      evmVersion: SETTINGS.evmVersion,
      optimizer: SETTINGS.optimizer,
      remappings: REMAPPINGS,
      outputSelection: {
        "*": {
          "*": [
            "abi",
            "evm.bytecode.object",
            "evm.deployedBytecode.object",
            "evm.deployedBytecode.immutableReferences",
            "evm.methodIdentifiers",
            "storageLayout",
          ],
        },
      },
    },
  };
  const out = JSON.parse(
    execFileSync(solc, ["--standard-json"], { input: JSON.stringify(input), maxBuffer: 256 * 1024 * 1024 }).toString(),
  );
  const fatal = (out.errors ?? []).filter((e: { severity: string }) => e.severity === "error");
  if (fatal.length > 0) throw new Error(fatal.map((e: { formattedMessage: string }) => e.formattedMessage).join("\n"));

  const contracts: Repro["contracts"] = {};
  for (const [file, names] of Object.entries(out.contracts as Record<string, Record<string, unknown>>)) {
    for (const [name, c] of Object.entries(names)) {
      if (name !== "VaultKernelPrototype" && name !== "VaultKernelFactoryPrototype") continue;
      const cc = c as {
        evm: {
          bytecode: { object: string };
          deployedBytecode: { object: string; immutableReferences?: Record<string, unknown> };
          methodIdentifiers: Record<string, string>;
        };
        storageLayout: {
          storage: { slot: string; offset: number; label: string; type: string }[];
          types: Record<string, { numberOfBytes: string; label: string }>;
        };
      };
      void file;
      contracts[name] = {
        runtimeBytes: cc.evm.deployedBytecode.object.length / 2,
        initcodeBytes: cc.evm.bytecode.object.length / 2,
        runtimeSha256: sha(Buffer.from(cc.evm.deployedBytecode.object, "hex")),
        immutableSlots: Object.keys(cc.evm.deployedBytecode.immutableReferences ?? {}).length,
        selectors: cc.evm.methodIdentifiers,
        storage: (cc.storageLayout?.storage ?? []).map((s) => ({
          slot: s.slot,
          offset: s.offset,
          label: s.label,
          type: cc.storageLayout.types[s.type]?.label ?? s.type,
          bytes: cc.storageLayout.types[s.type]?.numberOfBytes ?? "?",
        })),
      };
    }
  }

  const sourceDigests: Record<string, string> = {};
  for (const [k, v] of Object.entries(sourcesWithRemappedImports())) sourceDigests[k] = sha(v.content);

  return { solcVersion: SOLC_VERSION, solcLongVersion: SOLC_LONG, settings: SETTINGS, sourceDigests, contracts };
}

/**
 * Resolve the prototype's own sources plus every OpenZeppelin file they reach,
 * reading everything from disk so the compile does not depend on Hardhat at
 * runtime — only on the same inputs Hardhat was given.
 *
 * THE SOURCE KEYS AND THE REMAPPING ARE PART OF THE OUTPUT. solc hashes the
 * metadata JSON — which contains the source keys — into a CBOR blob appended to
 * the runtime code. A different key set produces the same LENGTH and a DIFFERENT
 * HASH. This tripped during authoring: a "reproducible build" that reproduces
 * the byte count but not the bytes is not one, and the discrepancy is the whole
 * reason the check exists. Hardhat 3 names project files `project/<path>` and
 * npm files `npm/<pkg>@<version>/<path>`, with a remapping between them.
 */
export const OZ_VERSION = "5.6.1";
export const REMAPPINGS = [`project/:@openzeppelin/contracts/=npm/@openzeppelin/contracts@${OZ_VERSION}/`];

function sourcesWithRemappedImports(): Record<string, { content: string }> {
  const sources: Record<string, { content: string }> = {};
  const seen = new Set<string>();
  const posix = (p: string) => p.split(path.sep).join("/");

  // A relative import inside an npm-keyed file must resolve against that file's
  // NPM KEY, not against its location on disk — otherwise `../Strings.sol` from
  // an OpenZeppelin file lands back in `project/` and solc cannot find it.
  const visit = (key: string, diskPath: string): void => {
    if (seen.has(key)) return;
    seen.add(key);
    const content = fs.readFileSync(diskPath, "utf8");
    sources[key] = { content };
    for (const m of content.matchAll(/import\s+(?:\{[^}]*\}\s+from\s+)?"([^"]+)"/g)) {
      const spec = m[1];
      if (spec.startsWith("@openzeppelin/contracts/")) {
        const rel = spec.slice("@openzeppelin/contracts/".length);
        visit(`npm/@openzeppelin/contracts@${OZ_VERSION}/${rel}`, path.join("node_modules", spec));
        continue;
      }
      const childKey = path.posix.normalize(path.posix.join(path.posix.dirname(key), spec));
      const childDisk = path.normalize(path.join(path.dirname(diskPath), spec));
      visit(childKey, childDisk);
    }
  };

  visit(`project/${posix(SRC)}/VaultKernelPrototype.sol`, path.join(SRC, "VaultKernelPrototype.sol"));
  visit(`project/${posix(SRC)}/VaultKernelFactoryPrototype.sol`, path.join(SRC, "VaultKernelFactoryPrototype.sol"));
  return sources;
}

function main(): void {
  const a = build();
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(a, null, 2));
    return;
  }
  console.log(
    `solc ${a.solcLongVersion}  evm=${a.settings.evmVersion}  optimizer=${a.settings.optimizer.enabled}/${a.settings.optimizer.runs}  viaIR=${a.settings.viaIR}`,
  );
  for (const [name, c] of Object.entries(a.contracts)) {
    console.log(`\n== ${name}`);
    console.log(
      `   runtime ${c.runtimeBytes}  initcode ${c.initcodeBytes}  immutableSlots ${c.immutableSlots}  selectors ${Object.keys(c.selectors).length}`,
    );
    console.log(`   runtime sha256 ${c.runtimeSha256}`);
    if (c.storage.length > 0) {
      console.log("   storage:");
      for (const s of c.storage) {
        console.log(
          `     slot ${String(s.slot).padStart(2)} off ${String(s.offset).padStart(2)}  ${s.label.padEnd(26)} ${s.type} (${s.bytes}B)`,
        );
      }
      console.log(`   distinct slots: ${new Set(c.storage.map((s) => s.slot)).size}`);
    }
  }
}

main();
