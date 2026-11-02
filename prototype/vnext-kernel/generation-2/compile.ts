/**
 * EXPERIMENTAL PROTOTYPE ADMISSION TOOLING — NOT PRODUCTION.
 *
 * Compiles the GENERATION-2 ADMISSION CANDIDATE with the pinned solc, under settings identical to
 * prototype/vnext-kernel/hardhat.config.ts, and never writes to contracts/, artifacts/ or cache/.
 *
 * WHY THE CANDIDATE IS NOT UNDER contracts/ OR erc20-spend-plane/. contracts/ is the Generation-1
 * evidence subject (test/EvidenceSubjectProvenance.test.ts), and erc20-spend-plane/ is the record of
 * what PR #237 measured, which this lane must not rewrite: the admission delta is measured AGAINST it.
 * The candidate therefore has its own tree, its own identity and its own receipts.
 *
 * THE VERIFIER PROVENANCE ROOT AND ITS CLASS ARE COMPILED HERE FROM THE GENERATION-1 SOURCES, by
 * repository path, so the candidate's identity manifest pins their hashes through the same compiler
 * path. They are not copied: there is one source of the root class in this repository.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { solcPath, type CompiledUnit } from "../erc20-spend-plane/compile.js";

export const GEN2_ROOT = "prototype/vnext-kernel/generation-2";
export const GEN2_CONTRACTS = `${GEN2_ROOT}/contracts`;
export const GEN1_CONTRACTS_DIR = "prototype/vnext-kernel/contracts";
export const VARIANT_A_SOURCE = "prototype/vnext-kernel/erc20-spend-plane/contracts/VaultKernelErc20Prototype.sol";

export const GEN2_KERNEL = "VaultKernelGen2Prototype";
export const GEN2_FACTORY = "VaultKernelGen2FactoryPrototype";
export const GEN2_ROOT_CONTRACT = "ImmutableAttestationVerifierFactoryPrototype";
export const GEN2_VERIFIER_CLASS = "ImmutableAttestationPQCVerifier";

/** The generation a Generation-2 factory is constructed with, and the first byte-field of every clone's args. */
export const GENERATION_2 = 2n;

/** The candidate proper, relative to GEN2_CONTRACTS. The zoo is a test fixture, deliberately outside the identity. */
export const CANDIDATE_SOURCES = [
  "VaultKernelGen2Prototype.sol",
  "VaultKernelGen2FactoryPrototype.sol",
  "interfaces/IKernelPlanes.sol",
] as const;
export const ZOO_SOURCE = "Gen2TokenZoo.sol";

/** The pinned tuple. A change here is a different build, hence a different identity. */
export const COMPILE_SETTINGS = {
  evmVersion: "cancun",
  optimizer: { enabled: true, runs: 200 },
  remappings: ["@openzeppelin/=node_modules/@openzeppelin/"],
} as const;

interface SolcContract {
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

export interface Gen2Compiled {
  readonly units: Map<string, CompiledUnit>;
  readonly sources: Record<string, string>;
  /** sourceKey -> { ast }, present only when `ast: true` was requested. */
  readonly asts?: Record<string, { ast: unknown }>;
}

export interface Gen2CompileOptions {
  /** Replacement text, keyed by file relative to GEN2_CONTRACTS, for mutants. Never written to disk. */
  readonly overrides?: Readonly<Record<string, string>>;
  /** Extra in-memory sources, keyed by repository path, for fixtures a single suite needs. */
  readonly extraSources?: Readonly<Record<string, string>>;
  /** Exact-once-free textual renames, applied to the content and the key of every candidate source. */
  readonly renames?: Readonly<Record<string, string>>;
  readonly ast?: boolean;
  /** Generate code for these contracts only: the optimizer is most of the cost of a mutant. */
  readonly only?: readonly string[];
}

const posix = (p: string): string => p.split(path.sep).join("/");

function applyRenames(text: string, renames?: Readonly<Record<string, string>>): string {
  if (!renames) return text;
  let out = text;
  for (const [from, to] of Object.entries(renames)) out = out.split(from).join(to);
  return out;
}

/** The candidate, the zoo, the provenance root and its class, in one compilation. */
export function gen2Sources(options: Gen2CompileOptions = {}): Record<string, string> {
  const sources: Record<string, string> = {};
  for (const rel of [...CANDIDATE_SOURCES, ZOO_SOURCE]) {
    const content = options.overrides?.[rel] ?? fs.readFileSync(path.join(GEN2_CONTRACTS, rel), "utf8");
    sources[applyRenames(posix(path.join(GEN2_CONTRACTS, rel)), options.renames)] = applyRenames(
      content,
      options.renames,
    );
  }
  sources[`${GEN1_CONTRACTS_DIR}/ImmutableAttestationVerifierFactoryPrototype.sol`] = fs.readFileSync(
    path.join(GEN1_CONTRACTS_DIR, "ImmutableAttestationVerifierFactoryPrototype.sol"),
    "utf8",
  );
  return { ...sources, ...(options.extraSources ?? {}) };
}

export function compileGen2(options: Gen2CompileOptions = {}): Gen2Compiled {
  const sources = gen2Sources(options);
  const selected = [
    "abi",
    "evm.bytecode.object",
    "evm.deployedBytecode.object",
    "evm.deployedBytecode.immutableReferences",
    "evm.methodIdentifiers",
    "storageLayout",
  ];
  const outputSelection: Record<string, Record<string, string[]>> = {
    "*": options.only ? Object.fromEntries(options.only.map((name) => [name, selected])) : { "*": selected },
  };
  if (options.ast) outputSelection["*"]![""] = ["ast"];
  const input = {
    language: "Solidity",
    sources: Object.fromEntries(Object.entries(sources).map(([k, content]) => [k, { content }])),
    settings: { ...COMPILE_SETTINGS, outputSelection },
  };
  const raw = execFileSync(solcPath(), ["--standard-json", "--base-path", ".", "--include-path", "node_modules"], {
    input: JSON.stringify(input),
    maxBuffer: 512 * 1024 * 1024,
  }).toString();
  const parsed = JSON.parse(raw) as {
    errors?: { severity: string; formattedMessage: string }[];
    sources?: Record<string, { ast: unknown }>;
    contracts?: Record<string, Record<string, SolcContract>>;
  };
  const fatal = (parsed.errors ?? []).filter((e) => e.severity === "error").map((e) => e.formattedMessage);
  if (fatal.length > 0) throw new Error("Generation-2 compilation failed:\n" + fatal.join("\n"));

  const units = new Map<string, CompiledUnit>();
  for (const [sourceKey, byName] of Object.entries(parsed.contracts ?? {})) {
    if (sourceKey.startsWith("@openzeppelin/")) continue;
    for (const [name, c] of Object.entries(byName)) {
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
  return { units, sources, asts: options.ast ? parsed.sources : undefined };
}

let cached: Gen2Compiled | undefined;

/** The candidate, compiled once per process. */
export function gen2(): Gen2Compiled {
  if (!cached) cached = compileGen2();
  return cached;
}

export function gen2Unit(name: string): CompiledUnit {
  const unit = gen2().units.get(name);
  if (!unit) throw new Error(`compiled Generation-2 unit has no contract named ${name}`);
  return unit;
}

/** Applies exact-once textual edits to the candidate kernel and compiles the result in memory. */
export function compileMutatedKernel(mutate: (source: string) => string): CompiledUnit {
  const file = "VaultKernelGen2Prototype.sol";
  const original = fs.readFileSync(path.join(GEN2_CONTRACTS, file), "utf8");
  const mutated = mutate(original);
  if (mutated === original) throw new Error("the mutation changed nothing");
  const unit = compileGen2({ overrides: { [file]: mutated } }).units.get(GEN2_KERNEL);
  if (!unit) throw new Error("the mutated kernel did not compile to " + GEN2_KERNEL);
  return unit;
}
