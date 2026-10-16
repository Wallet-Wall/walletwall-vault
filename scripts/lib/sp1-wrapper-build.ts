/**
 * Records of each build of the ZKMLDSAVerifier wrapper (the SP1 implementation lane; closes SP1-TD2 review residual
 * R2-3; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD2's binding gate judged every registered wrapper against the wrapper compiled from TODAY's tree, so any change
 * to the wrapper's compiled code would turn every earlier registry entry "not genuine" and refuse every binding on
 * that chain. Instead, each build is recorded once, from the compiler's own output, as an immutable file in
 * evidence/zk/sp1/wrapper-builds/, and a deployed wrapper is judged against the build it was deployed from:
 *
 *   - the runtime template exactly as solc emitted it (immutables are zero there), its keccak256, the CBOR metadata
 *     boundary and the immutables' positions, keyed by name (AST ids are per compile job, positions are per build);
 *   - the compiler and settings, and the compilation unit's sources (the import closure) with their sha256;
 *   - the SP1 pins the build enforces, read from the compiler's AST of the constants (and executed by the tests).
 *
 * A deployed runtime matches a build when it has the template's length and equals it byte for byte once the recorded
 * immutable positions are masked — metadata included, so a build from other sources is another build. CI refuses a
 * compiled wrapper that is not the latest recorded build (record it with `npm run sp1:wrapper-build`), and records
 * are append-only (scripts/lib/append-only-history.ts).
 *
 * The pure functions here take their inputs as arguments; the readers that touch the repository are separate and take
 * only the repository root, so no caller can hand an authority check a substituted record set by accident.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { getBytes, isHexString, keccak256 } from "ethers";

import { decodeSolcMetadataBoundary } from "./reproducibility-evidence";

export const WRAPPER_BUILDS_DIR = "evidence/zk/sp1/wrapper-builds";
export const WRAPPER_BUILD_SCHEMA = "walletwall.sp1-wrapper-build.v1";
export const WRAPPER_SOURCE = "contracts/verifiers/ZKMLDSAVerifier.sol";
export const WRAPPER_NAME = "ZKMLDSAVerifier";
export const WRAPPER_ARTIFACT_REL = "artifacts/contracts/verifiers/ZKMLDSAVerifier.sol/ZKMLDSAVerifier.json";
const BUILD_INFO_DIR = "artifacts/build-info";
const PROJECT_PREFIX = "project/";
const ID_PREFIX = "zkmldsa-verifier-b";
/** The constants that pin the SP1 verifier, by record field. */
export const PIN_CONSTANTS = {
  sp1VerifierCodehash: "SP1_VERIFIER_CODEHASH",
  sp1VerifierHash: "SP1_VERIFIER_HASH",
  vkRoot: "SP1_VK_ROOT",
  version: "SP1_VERSION",
} as const;
const COMPARED_FIELDS = ["schema", "contract", "compiler", "sources", "pins", "runtime"] as const;

export interface ImmutableRef {
  start: number;
  length: number;
}

export interface WrapperBuild {
  schema: string;
  id: string;
  sequence: number;
  contract: { source: string; name: string };
  compiler: { solc: string; evmVersion: string; optimizer: { enabled: boolean; runs: number } };
  sources: { path: string; sha256: string }[];
  pins: { sp1VerifierCodehash: string; sp1VerifierHash: string; vkRoot: string; version: string };
  runtime: {
    bytes: number;
    templateKeccak: string;
    metadataRegionStart: number;
    immutableReferences: Record<string, ImmutableRef[]>;
    template: string;
  };
}

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex");
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const isWord = (x: unknown) => typeof x === "string" && /^0x[0-9a-f]{64}$/.test(x);

// ---------------------------------------------------------------------------------------------------------
// Matching a deployed runtime
// ---------------------------------------------------------------------------------------------------------

/** Whether `runtime` is a deployment of `build`: the template, byte for byte, outside the recorded immutables. */
export function matchesBuild(runtime: string, build: WrapperBuild): boolean {
  if (typeof runtime !== "string" || !isHexString(runtime) || runtime === "0x") return false;
  const code = Buffer.from(getBytes(runtime));
  const reference = Buffer.from(getBytes(build.runtime.template));
  if (code.length !== reference.length) return false;
  for (const refs of Object.values(build.runtime.immutableReferences)) {
    for (const { start, length } of refs) {
      code.fill(0, start, start + length);
      reference.fill(0, start, start + length);
    }
  }
  return code.equals(reference);
}

/** The recorded build `runtime` is a deployment of, latest first; null when it is none of them. */
export function buildMatching(runtime: string, builds: readonly WrapperBuild[]): WrapperBuild | null {
  for (let i = builds.length - 1; i >= 0; i--) if (matchesBuild(runtime, builds[i])) return builds[i];
  return null;
}

// ---------------------------------------------------------------------------------------------------------
// Checking records
// ---------------------------------------------------------------------------------------------------------

/** Every way a set of build records (in sequence order) is malformed or inconsistent with itself; empty: valid. */
export function wrapperBuildErrors(builds: readonly WrapperBuild[]): string[] {
  const errors: string[] = [];
  const ids = new Set<string>();
  const templates = new Set<string>();
  builds.forEach((b, i) => {
    const at = `wrapper build ${String(b?.id)}`;
    if (b?.schema !== WRAPPER_BUILD_SCHEMA) errors.push(`${at}: schema must be ${WRAPPER_BUILD_SCHEMA}`);
    if (b?.sequence !== i + 1) errors.push(`${at}: sequence must be ${i + 1} (records are numbered from 1, in order)`);
    if (b?.id !== `${ID_PREFIX}${b?.sequence}`) errors.push(`${at}: id must be ${ID_PREFIX}<sequence>`);
    if (ids.has(b?.id)) errors.push(`${at}: listed twice`);
    ids.add(b?.id);
    if (!same(b?.contract, { source: WRAPPER_SOURCE, name: WRAPPER_NAME })) {
      errors.push(`${at}: contract must be ${WRAPPER_SOURCE}:${WRAPPER_NAME}`);
    }
    const sources = Array.isArray(b?.sources) ? b.sources : [];
    if (sources.length === 0 || !sources.some((s) => s?.path === WRAPPER_SOURCE)) {
      errors.push(`${at}: sources must list the compilation unit, ${WRAPPER_SOURCE} included`);
    }
    for (const s of sources) {
      if (typeof s?.path !== "string" || !/^[0-9a-f]{64}$/.test(String(s?.sha256))) {
        errors.push(`${at}: each source needs a path and a sha256`);
      }
    }
    const p = b?.pins;
    if (!p || !isWord(p.sp1VerifierCodehash) || !isWord(p.sp1VerifierHash) || !isWord(p.vkRoot)) {
      errors.push(`${at}: pins must hold the SP1 verifier code hash, VERIFIER_HASH and VK_ROOT as 32-byte words`);
    }
    if (typeof p?.version !== "string" || p.version.length === 0) errors.push(`${at}: pins.version must be named`);
    const r = b?.runtime;
    if (!r || typeof r.template !== "string" || !isHexString(r.template) || r.template === "0x") {
      errors.push(`${at}: runtime.template must be the compiled runtime`);
      return;
    }
    const length = getBytes(r.template).length;
    if (r.bytes !== length) errors.push(`${at}: runtime.bytes must be the template's length (${length})`);
    if (r.templateKeccak !== keccak256(r.template)) errors.push(`${at}: runtime.templateKeccak is not the template's`);
    if (templates.has(r.templateKeccak)) errors.push(`${at}: the same build is recorded twice`);
    templates.add(r.templateKeccak);
    const boundary = decodeSolcMetadataBoundary(r.template);
    const regionStart = boundary.ok ? boundary.regionStart : undefined;
    if (regionStart === undefined || regionStart !== r.metadataRegionStart) {
      errors.push(`${at}: runtime.metadataRegionStart must be the template's CBOR metadata boundary`);
    }
    for (const [name, refs] of Object.entries(r.immutableReferences ?? {})) {
      for (const ref of refs) {
        const inCode =
          regionStart !== undefined && ref.start >= 0 && ref.length === 32 && ref.start + ref.length <= regionStart;
        if (!inCode) errors.push(`${at}: immutable ${name} must sit in the code, before the metadata`);
      }
    }
  });
  return errors;
}

/** How the current compilation departs from the latest recorded build; empty when it is that build. */
export function compareCurrentBuild(current: WrapperBuild, builds: readonly WrapperBuild[]): string[] {
  if (builds.length === 0) {
    return [`no wrapper build is recorded in ${WRAPPER_BUILDS_DIR}: run npm run sp1:wrapper-build`];
  }
  const latest = builds[builds.length - 1];
  return COMPARED_FIELDS.filter((f) => !same(current[f], latest[f])).map(
    (f) =>
      `the compiled ${WRAPPER_NAME}'s ${f} differ from the latest recorded build ${latest.id}: record the new build ` +
      `with npm run sp1:wrapper-build (a recorded build is never edited)`,
  );
}

/** The record to append for `current`, or null when it already is the latest recorded build. */
export function nextBuildRecord(current: WrapperBuild, builds: readonly WrapperBuild[]): WrapperBuild | null {
  if (compareCurrentBuild(current, builds).length === 0) return null;
  const sequence = builds.length + 1;
  return { ...current, id: `${ID_PREFIX}${sequence}`, sequence };
}

// ---------------------------------------------------------------------------------------------------------
// Reading the compiler's output and the records
// ---------------------------------------------------------------------------------------------------------

export type AstNode = Record<string, any>;

function walk(node: unknown, visit: (n: AstNode) => void): void {
  if (Array.isArray(node)) node.forEach((n) => walk(n, visit));
  else if (node !== null && typeof node === "object") {
    const n = node as AstNode;
    if (typeof n.nodeType === "string") visit(n);
    for (const value of Object.values(n)) if (value !== null && typeof value === "object") walk(value, visit);
  }
}
export { walk as walkAst };

/** The compiled wrapper's ABI and its contract's AST, from the build info its artifact names (compile first). */
export function compiledWrapper(repoRoot = "."): { abi: AstNode[]; contract: AstNode } {
  const artifact = JSON.parse(readFileSync(resolve(repoRoot, WRAPPER_ARTIFACT_REL), "utf8"));
  const output = JSON.parse(
    readFileSync(resolve(repoRoot, BUILD_INFO_DIR, `${String(artifact.buildInfoId)}.output.json`), "utf8"),
  ).output;
  let contract: AstNode | undefined;
  walk(output.sources[`${PROJECT_PREFIX}${WRAPPER_SOURCE}`]?.ast, (n) => {
    if (n.nodeType === "ContractDefinition" && n.name === WRAPPER_NAME) contract = n;
  });
  if (!contract) throw new Error(`no ${WRAPPER_NAME} contract in the build info`);
  return { abi: artifact.abi as AstNode[], contract };
}

function literalValue(name: string, value: AstNode | undefined): string {
  if (value?.nodeType !== "Literal") throw new Error(`${WRAPPER_NAME}.${name} is not a literal constant`);
  if (value.kind === "string") return String(value.value);
  const hex = String(value.value).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(hex)) throw new Error(`${WRAPPER_NAME}.${name} is not a 32-byte literal`);
  return hex;
}

/**
 * The record of the wrapper as compiled now (run `hardhat compile` first), with no id or sequence yet: from the
 * Hardhat artifact and its solc build info, never from a description of the build.
 */
export function buildFromCompilation(repoRoot = "."): WrapperBuild {
  const artifact = JSON.parse(readFileSync(resolve(repoRoot, WRAPPER_ARTIFACT_REL), "utf8"));
  const id = String(artifact.buildInfoId);
  const info = JSON.parse(readFileSync(resolve(repoRoot, BUILD_INFO_DIR, `${id}.json`), "utf8"));
  const output = JSON.parse(readFileSync(resolve(repoRoot, BUILD_INFO_DIR, `${id}.output.json`), "utf8")).output;
  const root = `${PROJECT_PREFIX}${WRAPPER_SOURCE}`;

  // The compilation unit: the wrapper's source and everything it imports, transitively.
  const closure = new Set<string>([root]);
  const queue = [root];
  while (queue.length > 0) {
    const key = queue.pop() as string;
    walk(output.sources[key]?.ast, (n) => {
      if (n.nodeType === "ImportDirective" && !closure.has(n.absolutePath)) {
        closure.add(n.absolutePath);
        queue.push(n.absolutePath);
      }
    });
  }
  const sources = [...closure]
    .map((key) => {
      const content = info.input.sources[key]?.content;
      if (typeof content !== "string") throw new Error(`the build info has no content for ${key}`);
      return { path: key.startsWith(PROJECT_PREFIX) ? key.slice(PROJECT_PREFIX.length) : key, sha256: sha256(content) };
    })
    .sort((a, b) => a.path.localeCompare(b.path));

  // The pins and the immutables' names, from the wrapper contract's AST.
  let contract: AstNode | undefined;
  walk(output.sources[root]?.ast, (n) => {
    if (n.nodeType === "ContractDefinition" && n.name === WRAPPER_NAME) contract = n;
  });
  if (!contract) throw new Error(`no ${WRAPPER_NAME} contract in the build info`);
  const declarations: AstNode[] = contract.nodes.filter((n: AstNode) => n.nodeType === "VariableDeclaration");
  const pinOf = (name: string) => {
    const d = declarations.find((v) => v.name === name && v.constant === true);
    if (!d) throw new Error(`${WRAPPER_NAME} declares no constant ${name}`);
    return literalValue(name, d.value);
  };
  const nameOfId = new Map(declarations.map((d) => [String(d.id), String(d.name)]));
  const immutableReferences: Record<string, ImmutableRef[]> = {};
  for (const [astId, refs] of Object.entries(artifact.immutableReferences ?? {})) {
    const name = nameOfId.get(astId);
    if (name === undefined) throw new Error(`immutable reference ${astId} names no ${WRAPPER_NAME} variable`);
    immutableReferences[name] = (refs as ImmutableRef[])
      .map(({ start, length }) => ({ start, length }))
      .sort((a, b) => a.start - b.start);
  }

  const template = String(artifact.deployedBytecode).toLowerCase();
  const boundary = decodeSolcMetadataBoundary(template);
  const metadataRegionStart = boundary.ok ? boundary.regionStart : undefined;
  if (metadataRegionStart === undefined) {
    throw new Error(`the compiled ${WRAPPER_NAME} runtime has no solc metadata: ${String(boundary.error)}`);
  }
  return {
    schema: WRAPPER_BUILD_SCHEMA,
    id: "",
    sequence: 0,
    contract: { source: WRAPPER_SOURCE, name: WRAPPER_NAME },
    compiler: {
      solc: String(info.solcLongVersion),
      evmVersion: String(info.input.settings.evmVersion),
      optimizer: {
        enabled: info.input.settings.optimizer?.enabled === true,
        runs: Number(info.input.settings.optimizer?.runs),
      },
    },
    sources,
    pins: {
      sp1VerifierCodehash: pinOf(PIN_CONSTANTS.sp1VerifierCodehash),
      sp1VerifierHash: pinOf(PIN_CONSTANTS.sp1VerifierHash),
      vkRoot: pinOf(PIN_CONSTANTS.vkRoot),
      version: pinOf(PIN_CONSTANTS.version),
    },
    runtime: {
      bytes: getBytes(template).length,
      templateKeccak: keccak256(template),
      metadataRegionStart,
      immutableReferences: Object.fromEntries(
        Object.entries(immutableReferences).sort(([a], [b]) => a.localeCompare(b)),
      ),
      template,
    },
  };
}

/** The committed build records, in sequence order; a file must be named after the id it holds. */
export function readWrapperBuilds(repoRoot = "."): WrapperBuild[] {
  const dir = resolve(repoRoot, WRAPPER_BUILDS_DIR);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((file) => {
      const build = JSON.parse(readFileSync(resolve(dir, file), "utf8")) as WrapperBuild;
      if (`${build.id}.json` !== file) throw new Error(`${WRAPPER_BUILDS_DIR}/${file} holds ${String(build.id)}`);
      return build;
    })
    .sort((a, b) => a.sequence - b.sequence);
}

/** The current compilation against the committed records, and the records against themselves. */
export function currentBuildErrors(repoRoot = "."): string[] {
  const builds = readWrapperBuilds(repoRoot);
  return [...wrapperBuildErrors(builds), ...compareCurrentBuild(buildFromCompilation(repoRoot), builds)];
}

/** A record as committed: fixed key order, the long template last, trailing newline. */
export function serializeBuild(build: WrapperBuild): string {
  return `${JSON.stringify(build, null, 2)}\n`;
}
