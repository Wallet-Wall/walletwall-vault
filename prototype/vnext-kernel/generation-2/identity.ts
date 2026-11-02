/**
 * EXPERIMENTAL PROTOTYPE ADMISSION TOOLING — NOT PRODUCTION.
 *
 * THE CANDIDATE'S IDENTITY: everything needed to reconstruct it independently, computed from committed
 * source through the pinned compiler. Nothing here reads the clock, the machine or an RPC, so two runs on
 * two checkouts of one tree produce byte-identical output. It deliberately names no deployed address: an
 * admission identity is a statement about bytes, and which factory binds which asset on which network is a
 * deployment fact for a later lane.
 *
 * Line endings are normalised to LF before hashing or compiling the identity's sources, on every platform:
 * a CRLF checkout would otherwise move every metadata hash without moving one instruction.
 */
import fs from "node:fs";
import path from "node:path";

import {
  CLONE_ARGS_BYTES,
  CLONE_TEMPLATE_BYTES,
  NETWORK_INITCODE_LIMIT,
  NETWORK_RUNTIME_LIMIT,
  SOLC_LONG_VERSION,
  STOP_CONDITION_HEADROOM,
  TARGET_KERNEL_CEILING,
  VARIANT_A,
  WALLETWALL_INTERNAL_RESERVE,
  WALLETWALL_PORTABILITY_BUDGET,
  byteLength,
  executablePrefix,
  isStateChanging,
  sha256Hex,
  type CompiledUnit,
} from "../erc20-spend-plane/compile.js";
import {
  CANDIDATE_SOURCES,
  COMPILE_SETTINGS,
  GEN1_CONTRACTS_DIR,
  GEN2_CONTRACTS,
  GEN2_FACTORY,
  GEN2_KERNEL,
  GEN2_ROOT_CONTRACT,
  GEN2_VERIFIER_CLASS,
  GENERATION_2,
  VARIANT_A_SOURCE,
  compileGen2,
} from "./compile.js";
import { compilePlane, compileGen1Baseline, GEN1_KERNEL, PLANE_FACTORY } from "../erc20-spend-plane/compile.js";
import { MANIFEST_PATH } from "./authority/census.js";

export const IDENTITY_SCHEMA = "vnext-kernel-gen2-candidate-identity.v1";

const lf = (text: string): string => text.split("\r\n").join("\n");
export const sourceSha256 = (file: string): string => sha256Hex(lf(fs.readFileSync(file, "utf8")));

const unitIdentity = (u: CompiledUnit): Record<string, unknown> => {
  const { prefix, metadataTailBytes } = executablePrefix(u.deployedBytecode);
  return {
    runtimeBytes: byteLength(u.deployedBytecode),
    initcodeBytes: byteLength(u.bytecode),
    runtimeSha256: sha256Hex(u.deployedBytecode),
    executablePrefixSha256: sha256Hex(prefix),
    initcodeSha256: sha256Hex(u.bytecode),
    metadataTailBytes,
    immutableSlots: Object.keys(u.immutableReferences).length,
  };
};

export interface CandidateMeasurement {
  runtimeBytes: number;
  initcodeBytes: number;
  deltaFromMeasuredVariantA: number;
  initcodeDeltaFromMeasuredVariantA: number;
  deltaFromGeneration1: number;
  headroomToEip170: number;
  headroomToTargetKernelCeiling: number;
  headroomAboveStopLine: number;
  factoryRuntimeBytes: number;
  factoryInitcodeBytes: number;
  cloneRuntimeBytes: number;
  storageEntries: number;
  storageSlots: number;
  selectors: number;
  stateChangingSelectors: number;
}

export interface CandidateIdentity {
  schema: string;
  warning: string;
  sourceTree: { path: string; sha256: string }[];
  verifierClassSource: { path: string; sha256: string };
  authorityManifest: { path: string; sha256: string };
  compiler: { solc: string; evmVersion: string; optimizer: { enabled: boolean; runs: number }; viaIR: boolean };
  kernel: Record<string, unknown>;
  factory: Record<string, unknown>;
  provenanceRoot: Record<string, unknown>;
  verifierClass: Record<string, unknown>;
  clone: { templateBytes: number; argsBytes: number; runtimeBytes: number; shape: string };
  immutableArgsLayout: { field: string; offset: number; bytes: number; boundAt: string }[];
  generationIdentifier: string;
  admittedAssetBindingLocation: string;
  storageLayoutSha256: string;
  selectorSetSha256: string;
  measuredVariantA: {
    source: string;
    sourceSha256: string;
    runtimeBytes: number;
    initcodeBytes: number;
    runtimeSha256: string;
    executablePrefixSha256: string;
  };
  limits: Record<string, number>;
  measurement: CandidateMeasurement;
}

export function candidateIdentity(): CandidateIdentity {
  // Compile from LF-normalised text, so a Windows checkout and a Linux one identify the same bytes.
  const overrides = Object.fromEntries(
    CANDIDATE_SOURCES.map((rel) => [rel, lf(fs.readFileSync(path.join(GEN2_CONTRACTS, rel), "utf8"))]),
  );
  const c = compileGen2({ overrides });
  const get = (name: string): CompiledUnit => {
    const u = c.units.get(name);
    if (!u) throw new Error("no compiled unit " + name);
    return u;
  };
  const kernel = get(GEN2_KERNEL);
  const factory = get(GEN2_FACTORY);
  const plane = compilePlane();
  const variantA = plane.units.get(VARIANT_A)!;
  void plane.units.get(PLANE_FACTORY);
  const gen1 = compileGen1Baseline().units.get(GEN1_KERNEL)!;

  const runtime = byteLength(kernel.deployedBytecode);
  const initcode = byteLength(kernel.bytecode);
  const slots = new Set(kernel.storage.map((s) => s.slot)).size;
  const abi = kernel.abi as { type?: string; name?: string; stateMutability?: string }[];
  const measurement: CandidateMeasurement = {
    runtimeBytes: runtime,
    initcodeBytes: initcode,
    deltaFromMeasuredVariantA: runtime - byteLength(variantA.deployedBytecode),
    initcodeDeltaFromMeasuredVariantA: initcode - byteLength(variantA.bytecode),
    deltaFromGeneration1: runtime - byteLength(gen1.deployedBytecode),
    headroomToEip170: NETWORK_RUNTIME_LIMIT - runtime,
    headroomToTargetKernelCeiling: TARGET_KERNEL_CEILING - runtime,
    headroomAboveStopLine: TARGET_KERNEL_CEILING - runtime - STOP_CONDITION_HEADROOM,
    factoryRuntimeBytes: byteLength(factory.deployedBytecode),
    factoryInitcodeBytes: byteLength(factory.bytecode),
    cloneRuntimeBytes: CLONE_TEMPLATE_BYTES + CLONE_ARGS_BYTES,
    storageEntries: kernel.storage.length,
    storageSlots: slots,
    selectors: Object.keys(kernel.methodIdentifiers).length,
    stateChangingSelectors: abi.filter((f) => f.type === "function" && isStateChanging(f)).length,
  };

  const rootSource = `${GEN1_CONTRACTS_DIR}/ImmutableAttestationVerifierFactoryPrototype.sol`;
  const { prefix: variantPrefix } = executablePrefix(variantA.deployedBytecode);
  return {
    schema: IDENTITY_SCHEMA,
    warning:
      "EXPERIMENTAL PROTOTYPE. NOT AUDITED. NOT PRODUCTION. NO DEPLOYMENT. An admission candidate is not approved for any network or any real value.",
    sourceTree: CANDIDATE_SOURCES.map((rel) => ({
      path: `${GEN2_CONTRACTS}/${rel}`,
      sha256: sourceSha256(path.join(GEN2_CONTRACTS, rel)),
    })),
    verifierClassSource: { path: rootSource, sha256: sourceSha256(rootSource) },
    authorityManifest: { path: MANIFEST_PATH, sha256: sourceSha256(MANIFEST_PATH) },
    compiler: {
      solc: SOLC_LONG_VERSION,
      evmVersion: COMPILE_SETTINGS.evmVersion,
      optimizer: { ...COMPILE_SETTINGS.optimizer },
      viaIR: false,
    },
    kernel: { contract: GEN2_KERNEL, ...unitIdentity(kernel) },
    factory: {
      contract: GEN2_FACTORY,
      ...unitIdentity(factory),
      note: "runtimeSha256 is over the compiler's template, with immutables unlinked: a deployed factory's four immutable words differ by constructor argument.",
    },
    provenanceRoot: { contract: GEN2_ROOT_CONTRACT, ...unitIdentity(get(GEN2_ROOT_CONTRACT)) },
    verifierClass: { contract: GEN2_VERIFIER_CLASS, ...unitIdentity(get(GEN2_VERIFIER_CLASS)) },
    clone: {
      templateBytes: CLONE_TEMPLATE_BYTES,
      argsBytes: CLONE_ARGS_BYTES,
      runtimeBytes: CLONE_TEMPLATE_BYTES + CLONE_ARGS_BYTES,
      shape: "363d3d373d3d3d363d73 || implementation(20) || 5af43d82803e903d91602b57fd5bf3 || args(48)",
    },
    immutableArgsLayout: [
      { field: "generation", offset: 0, bytes: 8, boundAt: "factory constructor argument generation_" },
      { field: "verifierAuthority", offset: 8, bytes: 20, boundAt: "factory constructor argument verifierAuthority_" },
      { field: "admittedAsset", offset: 28, bytes: 20, boundAt: "factory constructor argument admittedAsset_" },
    ],
    generationIdentifier: GENERATION_2.toString(),
    admittedAssetBindingLocation:
      "bytes 28..48 of the clone's immutable args, i.e. runtime bytes 73..93 of the 93-byte clone; read by _admittedAsset through Clones.fetchCloneArgs; no storage word on the kernel or the factory holds it",
    storageLayoutSha256: sha256Hex(JSON.stringify(kernel.storage)),
    selectorSetSha256: sha256Hex(JSON.stringify(Object.entries(kernel.methodIdentifiers).sort())),
    measuredVariantA: {
      source: VARIANT_A_SOURCE,
      sourceSha256: sourceSha256(VARIANT_A_SOURCE),
      runtimeBytes: byteLength(variantA.deployedBytecode),
      initcodeBytes: byteLength(variantA.bytecode),
      runtimeSha256: sha256Hex(variantA.deployedBytecode),
      executablePrefixSha256: sha256Hex(variantPrefix),
    },
    limits: {
      NETWORK_RUNTIME_LIMIT,
      NETWORK_INITCODE_LIMIT,
      WALLETWALL_PORTABILITY_BUDGET,
      WALLETWALL_INTERNAL_RESERVE,
      TARGET_KERNEL_CEILING,
      STOP_CONDITION_HEADROOM,
    },
    measurement,
  };
}
