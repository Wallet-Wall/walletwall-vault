/**
 * GEN2-PQ-CONFORMANCE-1 — compile the VENDORED ML-DSA-65 verifier closure with the pinned solc binary.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION.
 *
 * The vendored files are byte-identical to ZKNoxHQ/ETHDILITHIUM at 4c370bb5 (SOURCE_PINS.json), so they
 * keep their upstream import specifiers (`sstore2/SSTORE2.sol`, `InterfaceVerifier/IVerifier.sol`). They
 * are compiled here in memory through solc's standard JSON, with the source-unit names and remappings the
 * vendor's Foundry layout would produce (`src/...`, `lib/sstore2/contracts/...`,
 * `lib/InterfaceVerifier/src/...`) and the vendor's `foundry.toml [profile.default]` settings:
 * solc 0.8.30, evm osaka, via-IR, optimizer runs 1,000,000. Nothing is written to disk.
 *
 * The solc binary is the one Hardhat downloaded for `hardhat.config.ts` of this spike, located the way
 * `prototype/vnext-kernel/erc20-spend-plane/compile.ts` locates its pinned compiler, so the harness and the
 * vendored closure are compiled by the same bytes.
 *
 * What this does NOT establish: equality with a build made by the vendor's own `forge build`. No ML-DSA-65
 * deployment or artefact was published by the vendor to compare against; `forge` itself could not be
 * installed in this environment (TOOLCHAIN.md). The reproducibility claim recorded in `results/build.json` is
 * therefore: the same pinned binary and settings produce the same bytes on every run, here and in a fresh
 * checkout, and the runtime minus its CBOR metadata tail does not depend on source-unit naming.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const SPIKE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const VENDOR_DIR = path.join(SPIKE_DIR, "vendor");
export const ZKNOX_DIR = path.join(VENDOR_DIR, "zknox-ethdilithium-4c370bb5");

export const SOLC_VERSION = "0.8.30";
export const VENDOR_PIN = {
  repository: "ZKNoxHQ/ETHDILITHIUM",
  branch: "mldsa-65",
  commit: "4c370bb5ff90d98e1ce8fb96f867126f0fbb9046",
  foundryProfile: "default",
} as const;

/** The vendor's settings (foundry.toml [profile.default] at 4c370bb5). */
export const COMPILE_SETTINGS = {
  evmVersion: "osaka",
  viaIR: true,
  optimizer: { enabled: true, runs: 1_000_000 },
  remappings: ["sstore2/=lib/sstore2/contracts/", "InterfaceVerifier/=lib/InterfaceVerifier/src/"],
} as const;

/** Source-unit name (as the vendor's Foundry project would name it) -> vendored file. */
export const SOURCE_UNITS: Readonly<Record<string, string>> = {
  "src/ZKNOX_dilithium65.sol": "zknox-ethdilithium-4c370bb5/src/ZKNOX_dilithium65.sol",
  "src/ZKNOX_dilithium65_core_packed.sol": "zknox-ethdilithium-4c370bb5/src/ZKNOX_dilithium65_core_packed.sol",
  "src/ZKNOX_dilithium_core_packed.sol": "zknox-ethdilithium-4c370bb5/src/ZKNOX_dilithium_core_packed.sol",
  "src/ZKNOX_dilithium_utils.sol": "zknox-ethdilithium-4c370bb5/src/ZKNOX_dilithium_utils.sol",
  "src/ZKNOX_NTT_dilithium_mont.sol": "zknox-ethdilithium-4c370bb5/src/ZKNOX_NTT_dilithium_mont.sol",
  "src/ZKNOX_shake_fast.sol": "zknox-ethdilithium-4c370bb5/src/ZKNOX_shake_fast.sol",
  "lib/sstore2/contracts/SSTORE2.sol": "sstore2-0a28fe61/contracts/SSTORE2.sol",
  "lib/sstore2/contracts/utils/Bytecode.sol": "sstore2-0a28fe61/contracts/utils/Bytecode.sol",
  "lib/InterfaceVerifier/src/IVerifier.sol": "interface-verifier-5ec0596c/src/IVerifier.sol",
};

export const VERIFIER_CONTRACT = "ZKNOX_dilithium65";
export const VERIFIER_SOURCE_UNIT = "src/ZKNOX_dilithium65.sol";

export const sha256Hex = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");

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

/** The pinned solc binary Hardhat cached for this spike's config. */
export function solcPath(): string {
  const base = path.join(hardhatCacheRoot(), "compilers-v3", compilerCachePlatform());
  const hit = fs.readdirSync(base).find((f) => f.includes(SOLC_VERSION) && !f.endsWith(".json"));
  if (hit === undefined) {
    throw new Error(
      `pinned solc ${SOLC_VERSION} not found in ${base} -- run \`npx hardhat --config prototype/vnext-kernel/pq-verifier-spike/hardhat.config.ts compile\` once so Hardhat caches it`,
    );
  }
  return path.join(base, hit);
}

/** `solc --version`'s Version line, e.g. `0.8.30+commit.73712a01.Windows.msvc` (the platform suffix is the host's). */
export function solcVersionString(): string {
  const out = execFileSync(solcPath(), ["--version"], { encoding: "utf8" });
  const m = out.match(/Version:\s*(\S+)/);
  if (!m) throw new Error(`unexpected solc --version output: ${out.slice(0, 200)}`);
  return m[1]!;
}

/** `{ version: "0.8.30", commit: "73712a01" }` from the version line, platform-independent. */
export function solcVersionParts(v: string = solcVersionString()): { version: string; commit: string } {
  const m = v.match(/^(\d+\.\d+\.\d+)\+commit\.([0-9a-f]+)/);
  if (!m) throw new Error(`unexpected solc version string: ${v}`);
  return { version: m[1]!, commit: m[2]! };
}

export interface CompiledVerifier {
  readonly contract: string;
  readonly sourceUnit: string;
  readonly abi: unknown[];
  /** 0x-prefixed creation bytecode (no constructor arguments). */
  readonly bytecode: string;
  /** 0x-prefixed runtime bytecode as emitted by solc: the immutable slot holds zeros. */
  readonly deployedBytecode: string;
  readonly immutableReferences: Record<string, { start: number; length: number }[]>;
  /** signature -> 4-byte selector (hex, no 0x). */
  readonly methodIdentifiers: Record<string, string>;
  /** solc's metadata JSON for the contract, verbatim. */
  readonly metadata: string;
  readonly solcVersion: string;
  readonly settings: typeof COMPILE_SETTINGS & { metadata?: { bytecodeHash: "ipfs" | "none" } };
  readonly sourceSha256: Record<string, string>;
}

export interface CompileOptions {
  /** `none` drops the CBOR metadata hash from the bytecode (a second build, for the naming-independence check). */
  readonly bytecodeHash?: "ipfs" | "none";
  /** Replace the source-unit names (e.g. with the repository paths) to show the runtime sans metadata is unchanged. */
  readonly sourceUnitNames?: Readonly<Record<string, string>>;
}

export function vendoredSources(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [unit, rel] of Object.entries(SOURCE_UNITS))
    out[unit] = fs.readFileSync(path.join(VENDOR_DIR, rel), "utf8");
  return out;
}

const cache = new Map<string, CompiledVerifier>();

export function compileVendoredVerifier(options: CompileOptions = {}): CompiledVerifier {
  const key = JSON.stringify(options);
  const hit = cache.get(key);
  if (hit) return hit;

  const rename = (unit: string): string => options.sourceUnitNames?.[unit] ?? unit;
  const sources = vendoredSources();
  const renamedSources: Record<string, { content: string }> = {};
  for (const [unit, content] of Object.entries(sources)) renamedSources[rename(unit)] = { content };
  const remappings = options.sourceUnitNames
    ? COMPILE_SETTINGS.remappings.map((r) => {
        const [prefix, target] = r.split("=") as [string, string];
        // a renamed layout moves lib/<x>/ to wherever the caller put it; derive the new target from one of its units
        const sample = Object.keys(SOURCE_UNITS).find((u) => u.startsWith(target));
        if (!sample) return r;
        const renamed = rename(sample);
        return `${prefix}=${renamed.slice(0, renamed.length - (sample.length - target.length))}`;
      })
    : [...COMPILE_SETTINGS.remappings];

  const settings = {
    evmVersion: COMPILE_SETTINGS.evmVersion,
    viaIR: COMPILE_SETTINGS.viaIR,
    optimizer: { ...COMPILE_SETTINGS.optimizer },
    remappings,
    ...(options.bytecodeHash ? { metadata: { bytecodeHash: options.bytecodeHash } } : {}),
    outputSelection: {
      "*": {
        "*": [
          "abi",
          "evm.bytecode.object",
          "evm.deployedBytecode.object",
          "evm.deployedBytecode.immutableReferences",
          "evm.methodIdentifiers",
          "metadata",
        ],
      },
    },
  };
  const input = { language: "Solidity", sources: renamedSources, settings };
  const raw = execFileSync(solcPath(), ["--standard-json"], {
    input: JSON.stringify(input),
    maxBuffer: 512 * 1024 * 1024,
  }).toString();
  const parsed = JSON.parse(raw) as {
    errors?: { severity: string; formattedMessage: string }[];
    contracts?: Record<
      string,
      Record<
        string,
        {
          abi: unknown[];
          metadata: string;
          evm: {
            bytecode: { object: string };
            deployedBytecode: {
              object: string;
              immutableReferences?: Record<string, { start: number; length: number }[]>;
            };
            methodIdentifiers: Record<string, string>;
          };
        }
      >
    >;
  };
  const fatal = (parsed.errors ?? []).filter((e) => e.severity === "error").map((e) => e.formattedMessage);
  if (fatal.length > 0) throw new Error("vendored verifier compilation failed:\n" + fatal.join("\n"));
  const unit = rename(VERIFIER_SOURCE_UNIT);
  const c = parsed.contracts?.[unit]?.[VERIFIER_CONTRACT];
  if (!c) throw new Error(`compiler output has no ${VERIFIER_CONTRACT} in ${unit}`);
  const result: CompiledVerifier = {
    contract: VERIFIER_CONTRACT,
    sourceUnit: unit,
    abi: c.abi,
    bytecode: "0x" + c.evm.bytecode.object,
    deployedBytecode: "0x" + c.evm.deployedBytecode.object,
    immutableReferences: c.evm.deployedBytecode.immutableReferences ?? {},
    methodIdentifiers: c.evm.methodIdentifiers,
    metadata: c.metadata,
    solcVersion: solcVersionString(),
    settings: {
      ...COMPILE_SETTINGS,
      remappings: remappings as unknown as typeof COMPILE_SETTINGS.remappings,
      ...(options.bytecodeHash ? { metadata: { bytecodeHash: options.bytecodeHash } } : {}),
    },
    sourceSha256: Object.fromEntries(Object.entries(sources).map(([u, s]) => [u, sha256Hex(s)])),
  };
  cache.set(key, result);
  return result;
}

/** Split a runtime into (code, cbor metadata tail): the last two bytes give the CBOR length (solc convention). */
export function splitCborTail(runtimeHex: string): { code: string; cbor: string; cborLength: number } {
  const hex = runtimeHex.replace(/^0x/, "");
  const len = parseInt(hex.slice(-4), 16);
  const cut = hex.length - 4 - len * 2;
  return { code: "0x" + hex.slice(0, cut), cbor: "0x" + hex.slice(cut), cborLength: len };
}

export const byteLength = (hex: string): number => hex.replace(/^0x/, "").length / 2;
