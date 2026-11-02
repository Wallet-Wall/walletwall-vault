/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT TOOLING — NOT PRODUCTION.
 *
 * Compiles and measures the admitted-asset ERC-20 spend-plane CANDIDATES
 * (`erc20-spend-plane/contracts/`) with the PINNED solc binary, under settings
 * identical to `prototype/vnext-kernel/hardhat.config.ts`, and never writes to
 * `prototype/vnext-kernel/contracts/`, `artifacts/` or `cache/`.
 *
 * WHY THE CANDIDATES LIVE OUTSIDE `contracts/`. That directory is the evidence
 * subject of two guards: `test/EvidenceSubjectProvenance.test.ts` compares its git
 * tree oid between the declared subject and the publishing commit, and
 * `scanner-input-scope.ts` licenses `SCANNER_EVIDENCE.json` on the same oid. One
 * added file there would turn both red until every receipt is regenerated under a
 * fresh pinned Slither run — a publication lane's work, not a measurement's. The
 * SD-11 lane met the same constraint with `test/sd11-verifier-compile.ts`: drive
 * solc directly through `--standard-json`, return deployable artifacts, write
 * nothing. This module does the same for a whole candidate generation, and adds
 * the measurement the lane exists to produce.
 *
 * THE MEASUREMENT METHOD IS THE REPOSITORY'S OWN. `reproduce.ts` establishes that
 * the pinned solc, driven from the sources on disk, reproduces the Hardhat
 * artifact byte-for-byte in LENGTH, and in HASH once the source keys match. This
 * module uses that same compiler and those same settings; its positive control
 * (`compileGen1Baseline`) compiles the Generation-1 kernel through this exact path
 * and the suite asserts the result equals `MEASUREMENTS.json kernel.runtimeBytes`
 * and the Hardhat artifact's executable prefix byte-for-byte. The runtime HASH is
 * not compared across methods: solc hashes the source KEYS into the CBOR metadata
 * tail, and this module keys sources by repository path where Hardhat keys them
 * `project/...`, so only the 53-byte tail differs — which `executablePrefix`
 * makes measurable rather than asserted.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const SOLC_VERSION = "0.8.24";
export const SOLC_LONG_VERSION = "0.8.24+commit.e11b9ed9";

export const PLANE_ROOT = "prototype/vnext-kernel/erc20-spend-plane";
export const PLANE_CONTRACTS = `${PLANE_ROOT}/contracts`;
export const GEN1_CONTRACTS = "prototype/vnext-kernel/contracts";
export const MEASUREMENTS_JSON = "prototype/vnext-kernel/MEASUREMENTS.json";
export const PLANE_RECORD_JSON = `${PLANE_ROOT}/ERC20_SPEND_PLANE_MEASUREMENTS.json`;

/** Every source of the candidate generation, relative to PLANE_CONTRACTS. */
export const PLANE_SOURCES = [
  "VaultKernelErc20Prototype.sol",
  "VaultKernelErc20NullVerifierPrototype.sol",
  "VaultKernelErc20FactoryPrototype.sol",
  "Erc20PlaneMocks.sol",
  "interfaces/IKernelPlanes.sol",
] as const;

export const VARIANT_A = "VaultKernelErc20Prototype";
export const VARIANT_B = "VaultKernelErc20NullVerifierPrototype";
export const PLANE_FACTORY = "VaultKernelErc20FactoryPrototype";
export const GEN1_KERNEL = "VaultKernelPrototype";
export const GEN1_FACTORY = "VaultKernelFactoryPrototype";

/** WalletWall size vocabulary (architecture section 19.0), identical to measure.ts. */
export const NETWORK_RUNTIME_LIMIT = 24_576;
export const NETWORK_INITCODE_LIMIT = 49_152;
export const WALLETWALL_PORTABILITY_BUDGET = 24_576;
export const WALLETWALL_INTERNAL_RESERVE = 2_600;
export const TARGET_KERNEL_CEILING = WALLETWALL_PORTABILITY_BUDGET - WALLETWALL_INTERNAL_RESERVE;
/**
 * Architecture section 19.2, "STOP CONDITION": "If the kernel lands below 600 bytes
 * of headroom: redesign or externalize. Do not weaken the gate." The custody
 * adjudication (section 7.6) reads that headroom against TARGET_KERNEL_CEILING,
 * the stricter of the two readings, and so does this module.
 */
export const STOP_CONDITION_HEADROOM = 600;

/** The immutable-args layout the Generation-2 factory writes. */
export const CLONE_ARGS_BYTES = 8 + 20 + 20;
/** EIP-1167 clone template (45 bytes) plus the args appended after it. */
export const CLONE_TEMPLATE_BYTES = 45;

const COMPILE_SETTINGS = {
  evmVersion: "cancun",
  optimizer: { enabled: true, runs: 200 },
  remappings: ["@openzeppelin/=node_modules/@openzeppelin/"],
} as const;

// Duplicated from reproduce.ts, authority/mutation-harness.ts and
// test/sd11-verifier-compile.ts for the reason each of those already gives: this
// module must stay runnable standalone, by the CLI and by the suite, without
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

export function solcPath(): string {
  const base = path.join(hardhatCacheRoot(), "compilers-v3", compilerCachePlatform());
  const hit = fs.readdirSync(base).find((f) => f.includes(SOLC_VERSION));
  if (hit === undefined) {
    throw new Error(
      `pinned solc ${SOLC_VERSION} not found in ${base} -- run \`npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile\` once so Hardhat caches it`,
    );
  }
  return path.join(base, hit);
}

export const sha256Hex = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");

export interface StorageEntry {
  readonly slot: string;
  readonly offset: number;
  readonly label: string;
  readonly type: string;
  readonly bytes: string;
}

export interface CompiledUnit {
  readonly name: string;
  readonly sourceKey: string;
  readonly abi: unknown[];
  /** 0x-prefixed creation bytecode. */
  readonly bytecode: string;
  /** 0x-prefixed runtime bytecode as the compiler emits it (immutable placeholders zeroed). */
  readonly deployedBytecode: string;
  readonly immutableReferences: Record<string, unknown>;
  /** canonical signature -> 4-byte selector (hex, no prefix). */
  readonly methodIdentifiers: Record<string, string>;
  readonly storage: StorageEntry[];
}

export interface Compiled {
  readonly units: Map<string, CompiledUnit>;
  /** sourceKey -> content actually handed to solc (after any renames). */
  readonly sources: Record<string, string>;
  /** sourceKey -> { ast }, present only when `ast: true` was requested. */
  readonly asts?: Record<string, { ast: unknown }>;
}

export interface CompileOptions {
  /**
   * Textual renames applied to EVERY source before compilation, oldName -> newName.
   * Used by the authority-census suite to compile the candidates under the
   * Generation-1 contract names so `authority/check.ts` can be run on them
   * unchanged. In memory only; nothing on disk is renamed.
   */
  readonly renames?: Readonly<Record<string, string>>;
  /** Also request each source unit's AST (for the authority checker). */
  readonly ast?: boolean;
  /**
   * Replacement source text per file (relative to PLANE_CONTRACTS), for the mutation suite: a
   * weakened candidate compiled from an in-memory copy. Files not listed are read from disk; the
   * tracked files are never written.
   */
  readonly overrides?: Readonly<Record<string, string>>;
}

interface SolcOutput {
  errors?: { severity: string; formattedMessage: string }[];
  sources?: Record<string, { ast: unknown }>;
  contracts?: Record<
    string,
    Record<
      string,
      {
        abi: unknown[];
        evm: {
          bytecode: { object: string };
          deployedBytecode: { object: string; immutableReferences?: Record<string, unknown> };
          methodIdentifiers: Record<string, string>;
        };
        storageLayout?: {
          storage: { slot: string; offset: number; label: string; type: string }[];
          types: Record<string, { numberOfBytes: string; label: string }> | null;
        };
      }
    >
  >;
}

function runSolc(sources: Record<string, string>, ast: boolean): SolcOutput {
  const outputSelection: Record<string, Record<string, string[]>> = {
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
  };
  if (ast) outputSelection["*"][""] = ["ast"];
  const input = {
    language: "Solidity",
    sources: Object.fromEntries(Object.entries(sources).map(([k, content]) => [k, { content }])),
    settings: { ...COMPILE_SETTINGS, outputSelection },
  };
  const raw = execFileSync(solcPath(), ["--standard-json", "--base-path", ".", "--include-path", "node_modules"], {
    input: JSON.stringify(input),
    maxBuffer: 512 * 1024 * 1024,
  }).toString();
  const parsed = JSON.parse(raw) as SolcOutput;
  const fatal = (parsed.errors ?? []).filter((e) => e.severity === "error").map((e) => e.formattedMessage);
  if (fatal.length > 0) throw new Error("ERC-20 spend-plane compilation failed:\n" + fatal.join("\n"));
  return parsed;
}

function collectUnits(parsed: SolcOutput, wanted?: ReadonlySet<string>): Map<string, CompiledUnit> {
  const units = new Map<string, CompiledUnit>();
  for (const [sourceKey, byName] of Object.entries(parsed.contracts ?? {})) {
    for (const [name, c] of Object.entries(byName)) {
      if (wanted !== undefined && !wanted.has(name)) continue;
      if (units.has(name)) throw new Error(`contract name "${name}" is defined in more than one source unit`);
      const types = c.storageLayout?.types ?? {};
      units.set(name, {
        name,
        sourceKey,
        abi: c.abi,
        bytecode: "0x" + c.evm.bytecode.object,
        deployedBytecode: "0x" + c.evm.deployedBytecode.object,
        immutableReferences: c.evm.deployedBytecode.immutableReferences ?? {},
        methodIdentifiers: c.evm.methodIdentifiers,
        storage: (c.storageLayout?.storage ?? []).map((s) => ({
          slot: s.slot,
          offset: s.offset,
          label: s.label,
          type: types?.[s.type]?.label ?? s.type,
          bytes: types?.[s.type]?.numberOfBytes ?? "?",
        })),
      });
    }
  }
  return units;
}

const posix = (p: string): string => p.split(path.sep).join("/");

function applyRenames(content: string, renames?: Readonly<Record<string, string>>): string {
  if (!renames) return content;
  let out = content;
  for (const [from, to] of Object.entries(renames)) out = out.split(from).join(to);
  return out;
}

/**
 * Reads the candidate sources from disk, keyed by repository-relative path so relative imports
 * resolve on disk. A rename is applied to the KEYS as well as the contents: the file names carry
 * the contract names, so the factory's `import "./VaultKernelErc20Prototype.sol"` must keep
 * resolving to the (renamed, inline) unit rather than to a file that does not exist.
 */
export function planeSources(
  renames?: Readonly<Record<string, string>>,
  overrides?: Readonly<Record<string, string>>,
): Record<string, string> {
  const sources: Record<string, string> = {};
  for (const rel of PLANE_SOURCES) {
    const key = applyRenames(posix(path.join(PLANE_CONTRACTS, rel)), renames);
    const content = overrides?.[rel] ?? fs.readFileSync(path.join(PLANE_CONTRACTS, rel), "utf8");
    sources[key] = applyRenames(content, renames);
  }
  return sources;
}

/** Compiles the whole candidate generation (both kernels, the factory, the mocks and the interface copy). */
export function compilePlane(options: CompileOptions = {}): Compiled {
  const sources = planeSources(options.renames, options.overrides);
  const parsed = runSolc(sources, options.ast === true);
  // Only project units are kept: the OpenZeppelin libraries solc also compiles are not candidates.
  const projectKeys = new Set(Object.keys(sources));
  const units = new Map<string, CompiledUnit>();
  for (const [name, unit] of collectUnits(parsed)) {
    if (projectKeys.has(unit.sourceKey)) units.set(name, unit);
  }
  return { units, sources, asts: options.ast ? parsed.sources : undefined };
}

/**
 * THE POSITIVE CONTROL for the measurement method: the Generation-1 kernel and
 * factory compiled through this module's exact path. The suite asserts the kernel
 * measures `MEASUREMENTS.json kernel.runtimeBytes` and that its executable prefix
 * equals the Hardhat artifact's.
 */
export function compileGen1Baseline(): Compiled {
  const sources: Record<string, string> = {};
  for (const rel of ["VaultKernelPrototype.sol", "VaultKernelFactoryPrototype.sol", "interfaces/IKernelPlanes.sol"]) {
    const key = posix(path.join(GEN1_CONTRACTS, rel));
    sources[key] = fs.readFileSync(path.join(GEN1_CONTRACTS, rel), "utf8");
  }
  const parsed = runSolc(sources, false);
  const projectKeys = new Set(Object.keys(sources));
  const units = new Map<string, CompiledUnit>();
  for (const [name, unit] of collectUnits(parsed)) {
    if (projectKeys.has(unit.sourceKey)) units.set(name, unit);
  }
  return { units, sources };
}

export const byteLength = (hex: string): number => (hex.length - 2) / 2;

/**
 * Splits runtime code at its CBOR metadata tail: the last two bytes encode the
 * tail's length. Everything before the tail is the EXECUTABLE PREFIX, which is what
 * a byte-identity claim across two compilation paths can compare — the tail hashes
 * the source keys and so differs between Hardhat (`project/...`) and this module.
 */
export function executablePrefix(deployedBytecode: string): { prefix: string; metadataTailBytes: number } {
  const hex = deployedBytecode.startsWith("0x") ? deployedBytecode.slice(2) : deployedBytecode;
  const cborLength = parseInt(hex.slice(-4), 16);
  const tailBytes = cborLength + 2;
  return { prefix: "0x" + hex.slice(0, hex.length - tailBytes * 2), metadataTailBytes: tailBytes };
}

export const isStateChanging = (fragment: { type?: string; stateMutability?: string }): boolean =>
  fragment.type === "function" && (fragment.stateMutability === "nonpayable" || fragment.stateMutability === "payable");

export interface UnitMeasurement {
  readonly contract: string;
  readonly runtimeBytes: number;
  readonly initcodeBytes: number;
  readonly immutableSlots: number;
  readonly selectors: number;
  readonly stateChangingSelectors: number;
  readonly runtimeSha256: string;
  readonly executablePrefixSha256: string;
  readonly metadataTailBytes: number;
  readonly storageEntries: number;
  readonly storageSlots: number;
}

export function measureUnit(unit: CompiledUnit): UnitMeasurement {
  const { prefix, metadataTailBytes } = executablePrefix(unit.deployedBytecode);
  const fragments = unit.abi as { type?: string; stateMutability?: string }[];
  return {
    contract: unit.name,
    runtimeBytes: byteLength(unit.deployedBytecode),
    initcodeBytes: byteLength(unit.bytecode),
    immutableSlots: Object.keys(unit.immutableReferences).length,
    selectors: fragments.filter((f) => f.type === "function").length,
    stateChangingSelectors: fragments.filter(isStateChanging).length,
    runtimeSha256: sha256Hex(Buffer.from(unit.deployedBytecode.slice(2), "hex")),
    executablePrefixSha256: sha256Hex(Buffer.from(prefix.slice(2), "hex")),
    metadataTailBytes,
    storageEntries: unit.storage.length,
    storageSlots: new Set(unit.storage.map((s) => s.slot)).size,
  };
}

export interface KernelHeadroom {
  readonly deltaVsGen1Kernel: number;
  readonly headroomVsTargetCeiling: number;
  readonly headroomVsPortabilityBudget: number;
  readonly headroomVsNetworkRuntimeLimit: number;
  readonly initcodeHeadroomVsNetworkLimit: number;
  /** headroomVsTargetCeiling >= STOP_CONDITION_HEADROOM, the stricter reading of architecture 19.2. */
  readonly stopConditionHeadroomRemaining: number;
  readonly stopCondition: "CLEAR" | "BREACHED";
  readonly verdict: "TARGET PASS" | "ARCHITECTURE PRESSURE" | "CURRENT PORTABILITY FAIL";
}

export function verdictFor(runtime: number): KernelHeadroom["verdict"] {
  if (runtime <= TARGET_KERNEL_CEILING) return "TARGET PASS";
  if (runtime <= WALLETWALL_PORTABILITY_BUDGET) return "ARCHITECTURE PRESSURE";
  return "CURRENT PORTABILITY FAIL";
}

export function kernelHeadroom(runtime: number, initcode: number, gen1Runtime: number): KernelHeadroom {
  const headroomVsTargetCeiling = TARGET_KERNEL_CEILING - runtime;
  return {
    deltaVsGen1Kernel: runtime - gen1Runtime,
    headroomVsTargetCeiling,
    headroomVsPortabilityBudget: WALLETWALL_PORTABILITY_BUDGET - runtime,
    headroomVsNetworkRuntimeLimit: NETWORK_RUNTIME_LIMIT - runtime,
    initcodeHeadroomVsNetworkLimit: NETWORK_INITCODE_LIMIT - initcode,
    stopConditionHeadroomRemaining: headroomVsTargetCeiling - STOP_CONDITION_HEADROOM,
    stopCondition: headroomVsTargetCeiling >= STOP_CONDITION_HEADROOM ? "CLEAR" : "BREACHED",
    verdict: verdictFor(runtime),
  };
}

export interface Gen1Declared {
  readonly kernelRuntimeBytes: number;
  readonly kernelInitcodeBytes: number;
  readonly kernelRuntimeSha256: string;
  readonly factoryRuntimeBytes: number;
  readonly factoryInitcodeBytes: number;
  readonly factoryImmutableSlots: number;
}

/** The Generation-1 figures as MEASUREMENTS.json declares them -- the baseline every delta below is against. */
export function gen1Declared(): Gen1Declared {
  const m = JSON.parse(fs.readFileSync(MEASUREMENTS_JSON, "utf8")) as {
    kernel: { runtimeBytes: number; initcodeBytes: number; runtimeSha256: string };
    factory: { runtimeBytes: number; initcodeBytes: number; immutableSlots: number };
  };
  return {
    kernelRuntimeBytes: m.kernel.runtimeBytes,
    kernelInitcodeBytes: m.kernel.initcodeBytes,
    kernelRuntimeSha256: m.kernel.runtimeSha256,
    factoryRuntimeBytes: m.factory.runtimeBytes,
    factoryInitcodeBytes: m.factory.initcodeBytes,
    factoryImmutableSlots: m.factory.immutableSlots,
  };
}

export interface VariantMeasurement extends UnitMeasurement, KernelHeadroom {
  readonly description: string;
}

export interface PlaneBytesRecord {
  readonly measuredBy: string;
  readonly build: {
    readonly solc: string;
    readonly evmVersion: string;
    readonly optimizer: { enabled: boolean; runs: number };
    readonly viaIR: false;
  };
  readonly limits: {
    readonly NETWORK_RUNTIME_LIMIT: number;
    readonly NETWORK_INITCODE_LIMIT: number;
    readonly WALLETWALL_PORTABILITY_BUDGET: number;
    readonly WALLETWALL_INTERNAL_RESERVE: number;
    readonly TARGET_KERNEL_CEILING: number;
    readonly STOP_CONDITION_HEADROOM: number;
  };
  readonly baseline: {
    readonly source: string;
    readonly kernel: UnitMeasurement & { declaredRuntimeBytes: number; declaredRuntimeSha256: string };
    readonly factory: UnitMeasurement & { declaredRuntimeBytes: number };
    readonly cloneRuntimeBytes: number;
  };
  readonly variants: {
    readonly A: VariantMeasurement;
    readonly B: VariantMeasurement;
    readonly variantDeltaBytesBMinusA: number;
  };
  readonly factory: UnitMeasurement & { deltaVsGen1Factory: number; initcodeDeltaVsGen1Factory: number };
  readonly clone: { readonly runtimeBytes: number; readonly argsBytes: number; readonly argsLayout: string };
  readonly abi: {
    readonly stateChangingSelectorsIdenticalToGen1: boolean;
    readonly addedSelectors: string[];
    readonly removedSelectors: string[];
    readonly executeSignature: string;
  };
  readonly storage: {
    readonly identicalToGen1: boolean;
    readonly entries: number;
    readonly slots: number;
  };
  readonly interfaceCopyByteIdenticalToGen1: boolean;
  readonly sourceSha256: Record<string, string>;
}

function selectorSet(unit: CompiledUnit, stateChangingOnly: boolean): Map<string, string> {
  const out = new Map<string, string>();
  const fragments = unit.abi as {
    type?: string;
    name?: string;
    stateMutability?: string;
    inputs?: { type: string }[];
  }[];
  for (const [signature, selector] of Object.entries(unit.methodIdentifiers)) {
    if (stateChangingOnly) {
      const name = signature.slice(0, signature.indexOf("("));
      const frag = fragments.find((f) => f.type === "function" && f.name === name && canonicalOf(f) === signature);
      if (!frag || !isStateChanging(frag)) continue;
    }
    out.set(selector, signature);
  }
  return out;
}

function canonicalOf(f: { name?: string; inputs?: { type: string; components?: unknown[] }[] }): string {
  const typeOf = (i: { type: string; components?: { type: string; components?: unknown[] }[] }): string => {
    if (i.type.startsWith("tuple")) {
      const inner = (i.components ?? []).map((c) => typeOf(c as never)).join(",");
      return `(${inner})${i.type.slice("tuple".length)}`;
    }
    return i.type;
  };
  return `${f.name}(${(f.inputs ?? []).map((i) => typeOf(i as never)).join(",")})`;
}

/**
 * Storage identity by slot, offset, type and size. A struct's type LABEL is qualified by the
 * contract that declares it (`struct VaultKernelPrototype.SecurityFloor`), so the kernel's own
 * name is masked before comparing — the layout, not the contract name, is what must be identical.
 */
const storageFingerprint = (unit: CompiledUnit): string =>
  JSON.stringify(
    unit.storage.map((s) => [
      s.slot,
      s.offset,
      s.type.split(/VaultKernel[A-Za-z0-9]*Prototype[.]/).join("Kernel."),
      s.bytes,
    ]),
  );

/** The compile-derived half of the record. Gas is measured by the suite and carried separately. */
export function measurePlane(
  compiled: Compiled = compilePlane(),
  gen1: Compiled = compileGen1Baseline(),
): PlaneBytesRecord {
  const need = (c: Compiled, name: string): CompiledUnit => {
    const u = c.units.get(name);
    if (!u) throw new Error(`compiled output has no contract named ${name}`);
    return u;
  };
  const a = need(compiled, VARIANT_A);
  const b = need(compiled, VARIANT_B);
  const factory = need(compiled, PLANE_FACTORY);
  const gen1Kernel = need(gen1, GEN1_KERNEL);
  const gen1Factory = need(gen1, GEN1_FACTORY);
  const declared = gen1Declared();

  const ma = measureUnit(a);
  const mb = measureUnit(b);
  const mf = measureUnit(factory);
  const mg = measureUnit(gen1Kernel);
  const mgf = measureUnit(gen1Factory);

  const gen1Selectors = selectorSet(gen1Kernel, false);
  const aSelectors = selectorSet(a, false);
  const added = [...aSelectors.entries()]
    .filter(([sel]) => !gen1Selectors.has(sel))
    .map(([, sig]) => sig)
    .sort();
  const removed = [...gen1Selectors.entries()]
    .filter(([sel]) => !aSelectors.has(sel))
    .map(([, sig]) => sig)
    .sort();
  const gen1StateChanging = [...selectorSet(gen1Kernel, true).keys()].sort();
  const aStateChanging = [...selectorSet(a, true).keys()].sort();
  const bStateChanging = [...selectorSet(b, true).keys()].sort();
  const stateChangingIdentical =
    JSON.stringify(gen1StateChanging) === JSON.stringify(aStateChanging) &&
    JSON.stringify(gen1StateChanging) === JSON.stringify(bStateChanging);

  const executeSignature = Object.keys(a.methodIdentifiers).find((s) => s.startsWith("execute(")) ?? "(none)";

  const interfaceGen1 = fs.readFileSync(path.join(GEN1_CONTRACTS, "interfaces/IKernelPlanes.sol"));
  const interfacePlane = fs.readFileSync(path.join(PLANE_CONTRACTS, "interfaces/IKernelPlanes.sol"));

  const sourceSha256: Record<string, string> = {};
  for (const [key, content] of Object.entries(compiled.sources)) sourceSha256[key] = sha256Hex(content);

  return {
    measuredBy:
      "prototype/vnext-kernel/erc20-spend-plane/compile.ts -- pinned solc " +
      SOLC_LONG_VERSION +
      " via --standard-json, settings identical to prototype/vnext-kernel/hardhat.config.ts; positive control = the Generation-1 kernel compiled through the same path",
    build: { solc: SOLC_LONG_VERSION, evmVersion: "cancun", optimizer: { enabled: true, runs: 200 }, viaIR: false },
    limits: {
      NETWORK_RUNTIME_LIMIT,
      NETWORK_INITCODE_LIMIT,
      WALLETWALL_PORTABILITY_BUDGET,
      WALLETWALL_INTERNAL_RESERVE,
      TARGET_KERNEL_CEILING,
      STOP_CONDITION_HEADROOM,
    },
    baseline: {
      source:
        "prototype/vnext-kernel/MEASUREMENTS.json kernel/factory (Generation 1), re-measured here through the same compiler path",
      kernel: {
        ...mg,
        declaredRuntimeBytes: declared.kernelRuntimeBytes,
        declaredRuntimeSha256: declared.kernelRuntimeSha256,
      },
      factory: { ...mgf, declaredRuntimeBytes: declared.factoryRuntimeBytes },
      cloneRuntimeBytes: CLONE_TEMPLATE_BYTES + 8 + 20,
    },
    variants: {
      A: {
        description:
          "admitted-asset ERC-20 spend plane; genesis KEEPS the admissible-verifier requirement when requirePq == false",
        ...ma,
        ...kernelHeadroom(ma.runtimeBytes, ma.initcodeBytes, declared.kernelRuntimeBytes),
      },
      B: {
        description:
          "as A, and genesis ACCEPTS a null verifier (address(0)) when requirePq == false; setVerifier and initiateRecovery still refuse null",
        ...mb,
        ...kernelHeadroom(mb.runtimeBytes, mb.initcodeBytes, declared.kernelRuntimeBytes),
      },
      variantDeltaBytesBMinusA: mb.runtimeBytes - ma.runtimeBytes,
    },
    factory: {
      ...mf,
      deltaVsGen1Factory: mf.runtimeBytes - declared.factoryRuntimeBytes,
      initcodeDeltaVsGen1Factory: mf.initcodeBytes - declared.factoryInitcodeBytes,
    },
    clone: {
      runtimeBytes: CLONE_TEMPLATE_BYTES + CLONE_ARGS_BYTES,
      argsBytes: CLONE_ARGS_BYTES,
      argsLayout: "generation (8) || verifierAuthority (20) || admittedAsset (20)",
    },
    abi: {
      stateChangingSelectorsIdenticalToGen1: stateChangingIdentical,
      addedSelectors: added,
      removedSelectors: removed,
      executeSignature,
    },
    storage: {
      identicalToGen1:
        storageFingerprint(a) === storageFingerprint(gen1Kernel) &&
        storageFingerprint(b) === storageFingerprint(gen1Kernel),
      entries: a.storage.length,
      slots: new Set(a.storage.map((s) => s.slot)).size,
    },
    interfaceCopyByteIdenticalToGen1: interfaceGen1.equals(interfacePlane),
    sourceSha256,
  };
}
