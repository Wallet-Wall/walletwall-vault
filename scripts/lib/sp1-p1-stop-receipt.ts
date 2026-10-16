/**
 * SP1-P1 assurance receipt: program identity across build environments and SP1 verifier-gateway provenance.
 *
 * The receipt (evidence/zk/sp1-p1/stop-receipt.json) is a pure function of
 *   - two committed observation files (evidence/zk/sp1-p1/observations/*.raw.json): raw measurements taken
 *     outside this repository (SP1 builds in three environments, read-only chain reads, recompilations), and
 *   - bytes of this repository (the zkvm guest/host sources, ZKMLDSAVerifier.sol, the prover runbook).
 * Every verdict in it is DERIVED here from the observations, never hand-typed, and `validateCommittedReceipt`
 * re-derives the whole receipt and refuses drift, stale sources and over-claims.
 *
 * It records a STOP: the lane's hard stop conditions fired (see `stopConditions`). It is not a readiness claim.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const SP1_P1_STOP_RECEIPT_SCHEMA = "walletwall.sp1-p1-stop-receipt.v1";
export const SP1_P1_RECEIPT_ARTIFACT_TYPE = "sp1-p1-assurance-stop-receipt";
/** Fixed instant (the measurement day) so the committed receipt is deterministic. */
export const SP1_P1_RECEIPT_GENERATED_AT = "2026-10-15T00:00:00.000Z";

export const RECEIPT_REL = "evidence/zk/sp1-p1/stop-receipt.json";
export const PROGRAM_IDENTITY_OBSERVATIONS_REL = "evidence/zk/sp1-p1/observations/program-identity.raw.json";
export const VERIFIER_GATEWAY_OBSERVATIONS_REL = "evidence/zk/sp1-p1/observations/verifier-gateway.raw.json";
export const ZK_VERIFIER_SOURCE_REL = "contracts/verifiers/ZKMLDSAVerifier.sol";
export const PROVER_RUNBOOK_REL = "docs/ZK_Prover_Runbook.md";
export const SUBJECT_SOURCE_DIRS = ["zkvm/guest", "zkvm/host"] as const;

export const CLAIM_STATUSES = [
  "ESTABLISHED",
  "PARTIALLY_ESTABLISHED",
  "NOT_ESTABLISHED",
  "NOT_TESTED",
  "OUT_OF_SCOPE",
] as const;
export type ClaimStatus = (typeof CLAIM_STATUSES)[number];

export const CLAIM_KEYS = [
  "WITHDRAWAL_PROGRAM_RELATION",
  "CROSS_ENVIRONMENT_PROGRAM_REPRODUCIBILITY",
  "REAL_SP1_PROOF_GENERATED",
  "REAL_SP1_PROOF_VERIFIED",
  "SP1_VERIFIER_GATEWAY_PROVENANCE",
  "ACVP_WITHDRAWAL_PROGRAM_ISOLATION",
  "CROSS_VAULT_REPLAY_RESISTANCE",
  "CROSS_CHAIN_REPLAY_RESISTANCE",
  "PRODUCTION_READINESS",
  "NIST_CONFORMANCE",
] as const;
export type ClaimKey = (typeof CLAIM_KEYS)[number];

/** The measured lane subject (commit main was at when Phases 0-2 ran). */
export const SUBJECT = {
  repository: "Wallet-Wall/walletwall-vault",
  measuredCommit: "6463caee352beda7a27009d29f1a48b42b063fd8",
  measuredTree: "6fea1db98b3404bb1def8aa5621538a6088efd56",
  zkvmGuestTree: "f61fdc6c8785df742857574c5dbf47aa62283c49",
  zkvmHostTree: "30f72596c430974bf8113892bf41c26dce3629f3",
  sp1Pins: { "sp1-zkvm": "=6.3.1", "sp1-sdk": "=6.3.1", "sp1-build": "=6.3.1" },
  circuitVersion: "v6.1.0",
} as const;

export const WITHDRAWAL = "mldsa65-withdrawal";
export const ACVP = "mldsa65-acvp";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_WORD = `0x${"0".repeat(64)}`;

// ---------------------------------------------------------------------------------------------------------
// Observation types (the committed raw files)
// ---------------------------------------------------------------------------------------------------------

export interface ProgramMeasurement {
  elfSha256: string | null;
  elfBytes: number | null;
  /** null when the procedure produced the ELF only (docker mode) and no vkey was computed from it. */
  vkey: string | null;
}

export interface EnvironmentObservation {
  id: string;
  /** Physical host class; environments sharing it are NOT independent of each other. */
  hostId: string;
  procedure: "repository-host-flow-local" | "vendor-image-host-flow" | "vendor-image-docker-mode";
  description: string;
  os: string | null;
  kernel: string | null;
  measuredAtUtc: string | null;
  image: { reference: string; imageId: string; createdUtc: string; platform: string } | null;
  toolchain: Record<string, string | null>;
  builder: { home: string | null; embeddedCargoHome: string | null };
  sourceManifest: { path: string; sha256: string }[] | null;
  programs: Record<string, ProgramMeasurement>;
  hostBinarySha256: string | null;
}

/** An (ELF -> vkey) result computed outside every build environment, by a different binary. */
export interface VkeyCrossCheck {
  source: string;
  program: string;
  elfSha256: string;
  vkey: string;
}

export interface ProgramIdentityObservations {
  environments: EnvironmentObservation[];
  crossChecks?: { vkeyFromElf?: { tool: string; purpose: string; ranOn: string; results: VkeyCrossCheck[] } };
}

interface RouteObservation {
  selector: string;
  verifier: string;
  frozen: boolean;
  version: string | null;
  verifierHash: string | null;
  verifierCodeBytes: number;
  verifierCodeKeccak: string | null;
}

interface GatewayChainObservation {
  rpc: string;
  chainIdReported: number;
  block: { number: number; hash: string; timestamp: number };
  groth16Gateway: {
    address: string;
    codeBytes: number;
    codeKeccak: string;
    eip1967ImplementationSlot: string;
    eip1967AdminSlot: string;
    owner: string;
    ownerCodeBytes: number;
    ownerCodeKeccak: string | null;
    ownerSafe: {
      singleton: string;
      version: string;
      threshold: number | null;
      owners: string[] | null;
      modules: string[] | string;
      guardSlot: string;
      fallbackHandler: string;
    } | null;
    eventLogSource: string;
    events: { kind: string; block: number; tx: string; selector?: string; verifier?: string }[];
    routes: RouteObservation[];
    upstreamSelectorProbe: {
      probed: number;
      nonEmpty: { selector: string; verifier: string; frozen: boolean; inLogs: boolean }[];
    };
  };
  plonkGateway: { address: string; owner: string; routes: number; liveRoutes: number };
}

export interface VerifierGatewayObservations {
  measuredAtUtc: string;
  chains: Record<string, GatewayChainObservation>;
  attribution: {
    sp1VerifierGroth16V610: {
      address: string;
      sourceCommit: string;
      runtimeEqual: boolean;
      create2: { equalsAddress: boolean; salt: string };
      deployTx: { inputIsSaltPlusInitcode: boolean };
      onchainRuntimeKeccakMainnet: string;
      verifierHash: string;
      [k: string]: unknown;
    };
    groth16Gateway: {
      address: string;
      runtimeEqual: boolean;
      create2: { equalsAddress: boolean; salt: string };
      onchainRuntimeKeccakMainnet: string;
      onchainRuntimeKeccakSepolia: string;
      [k: string]: unknown;
    };
    vkConstantJoin: {
      vkSha256: string;
      comparedConstants: number;
      equal: number;
      mismatches: number;
      [k: string]: unknown;
    };
  };
  sourcify: {
    chainId: number;
    address: string;
    match: string | null;
    runtimeMatch: string | null;
    creationMatch: string | null;
  }[];
  upstream: Record<string, unknown>;
  /** The decisive state reads re-done through an independent RPC provider at the same pinned blocks. */
  secondProvider?: { purpose: string; providers: Record<string, string>; checks: Record<string, unknown>[] };
}

// ---------------------------------------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------------------------------------

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Digest of a per-file sha256 manifest in exactly the byte format the measuring environments produced with
 * `find zkvm -type f | LC_ALL=C sort | xargs sha256sum`, then `sha256sum` of that listing: one line per file,
 * `<hex>␠␠<path>\n`, sorted by path in byte order. Recomputing it here (Node crypto) and comparing it with the
 * environments' coreutils result is a two-implementation agreement on the subject's source identity.
 */
export function sourceManifestDigest(entries: { path: string; sha256: string }[]): string {
  const sorted = [...entries].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return sha256Hex(sorted.map((e) => `${e.sha256}  ${e.path}\n`).join(""));
}

/** Per-file manifest of the tracked zkvm guest/host sources, read from the working tree's exact bytes. */
export function workingTreeSourceManifest(repoRoot = "."): { path: string; sha256: string }[] {
  const listed = execFileSync("git", ["ls-files", "-z", "--", ...SUBJECT_SOURCE_DIRS], { cwd: resolve(repoRoot) })
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  return listed.map((p) => ({ path: p, sha256: sha256Hex(readFileSync(resolve(repoRoot, p))) }));
}

// ---------------------------------------------------------------------------------------------------------
// Program identity verdict
// ---------------------------------------------------------------------------------------------------------

const VENDOR_FAMILY = "vendor-image";
/** The pinned vendor procedure appears in two equivalent forms (host flow in the image, docker-mode replay). */
export function procedureFamily(p: EnvironmentObservation["procedure"]): string {
  return p === "repository-host-flow-local" ? "repository-local" : VENDOR_FAMILY;
}

export interface IdentityGroup {
  elfSha256: string;
  vkeys: string[];
  environments: string[];
  hosts: string[];
  families: string[];
  /** True when an out-of-environment vkey computation covered this ELF (and, being merged into `vkeys`, agreed). */
  vkeyCrossChecked: boolean;
}

export interface ProgramIdentityVerdict {
  program: string;
  groups: IdentityGroup[];
  families: Record<
    string,
    { hosts: string[]; environments: string[]; identities: number; reproducedAcrossIndependentHosts: boolean }
  >;
  contradictions: string[];
  status: ClaimStatus;
  reason: string;
}

function uniq<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}

/**
 * Reproducibility of one program's identity across environments. Independence is by `hostId` only: two
 * environments on one host (two target dirs, two containers, two procedures) never count as independent.
 *   ESTABLISHED            one identity everywhere, observed on >= 2 independent hosts
 *   PARTIALLY_ESTABLISHED  some procedure family reproduces one identity on >= 2 independent hosts, but the
 *                          observations as a whole contain more than one identity (an unresolved conflict)
 *   NOT_ESTABLISHED        otherwise, or when an ELF hash maps to two vkeys (contradiction)
 */
export function deriveProgramIdentityVerdict(
  envs: EnvironmentObservation[],
  program: string,
  crossChecks: VkeyCrossCheck[] = [],
): ProgramIdentityVerdict {
  const contradictions: string[] = [];
  const byElf = new Map<string, IdentityGroup>();
  for (const e of envs) {
    const m = e.programs[program];
    if (!m || !m.elfSha256) {
      contradictions.push(`${e.id}: no ${program} ELF hash`);
      continue;
    }
    const g = byElf.get(m.elfSha256) ?? {
      elfSha256: m.elfSha256,
      vkeys: [],
      environments: [],
      hosts: [],
      families: [],
      vkeyCrossChecked: false,
    };
    if (m.vkey) g.vkeys = uniq([...g.vkeys, m.vkey]);
    g.environments.push(e.id);
    g.hosts = uniq([...g.hosts, e.hostId]);
    g.families = uniq([...g.families, procedureFamily(e.procedure)]);
    byElf.set(m.elfSha256, g);
  }
  // Out-of-environment (ELF -> vkey) results join the group of their ELF as further vkey evidence, so a
  // disagreement surfaces as "maps to 2 vkeys" below; a cross-check of an ELF no environment produced is itself
  // a contradiction (it cannot be evidence about these builds).
  for (const x of crossChecks.filter((c) => c.program === program)) {
    const g = byElf.get(x.elfSha256);
    if (!g) {
      contradictions.push(`cross-check ${x.source} names ${program} ELF ${x.elfSha256} that no environment produced`);
      continue;
    }
    g.vkeys = uniq([...g.vkeys, x.vkey]);
    g.vkeyCrossChecked = true;
  }
  const groups = [...byElf.values()];
  for (const g of groups) {
    if (g.vkeys.length > 1) contradictions.push(`${program} ELF ${g.elfSha256} maps to ${g.vkeys.length} vkeys`);
  }
  const vkeyOwners = new Map<string, string[]>();
  for (const g of groups) for (const v of g.vkeys) vkeyOwners.set(v, [...(vkeyOwners.get(v) ?? []), g.elfSha256]);
  for (const [v, elfs] of vkeyOwners)
    if (elfs.length > 1) contradictions.push(`${program} vkey ${v} claimed by ${elfs.length} ELFs`);

  const families: ProgramIdentityVerdict["families"] = {};
  for (const e of envs) {
    const f = procedureFamily(e.procedure);
    const entry = families[f] ?? {
      hosts: [],
      environments: [],
      identities: 0,
      reproducedAcrossIndependentHosts: false,
    };
    entry.hosts = uniq([...entry.hosts, e.hostId]);
    entry.environments.push(e.id);
    families[f] = entry;
  }
  for (const [f, entry] of Object.entries(families)) {
    entry.identities = groups.filter((g) => g.families.includes(f)).length;
    entry.reproducedAcrossIndependentHosts = entry.identities === 1 && entry.hosts.length >= 2;
  }

  const allHosts = uniq(envs.map((e) => e.hostId));
  let status: ClaimStatus;
  let reason: string;
  if (contradictions.length > 0) {
    status = "NOT_ESTABLISHED";
    reason = `contradictory observations: ${contradictions.join("; ")}`;
  } else if (groups.length === 1 && allHosts.length >= 2) {
    status = "ESTABLISHED";
    reason = `one ${program} identity on ${allHosts.length} independent hosts`;
  } else if (Object.values(families).some((f) => f.reproducedAcrossIndependentHosts)) {
    const fam = Object.entries(families)
      .filter(([, f]) => f.reproducedAcrossIndependentHosts)
      .map(([k]) => k);
    status = "PARTIALLY_ESTABLISHED";
    reason = `procedure family ${fam.join(", ")} reproduces one ${program} identity on >= 2 independent hosts, but the observations hold ${groups.length} distinct identities (unresolved identity conflict; no canonical designation)`;
  } else {
    status = "NOT_ESTABLISHED";
    reason = `no procedure reproduced one ${program} identity on two independent hosts (${groups.length} identities over hosts ${allHosts.join(", ")})`;
  }
  return { program, groups, families, contradictions, status, reason };
}

/** The withdrawal and ACVP programs never share an ELF or a vkey, in any environment or across environments. */
export function deriveProgramIsolation(envs: EnvironmentObservation[]): { holds: boolean; violations: string[] } {
  const violations: string[] = [];
  const wElfs = new Set<string>();
  const wVkeys = new Set<string>();
  const aElfs = new Set<string>();
  const aVkeys = new Set<string>();
  for (const e of envs) {
    const w = e.programs[WITHDRAWAL];
    const a = e.programs[ACVP];
    if (!w || !a || !w.elfSha256 || !a.elfSha256) {
      violations.push(`${e.id}: both programs must be measured`);
      continue;
    }
    if (w.elfSha256 === a.elfSha256) violations.push(`${e.id}: withdrawal and ACVP ELFs are identical`);
    if (w.vkey && a.vkey && w.vkey === a.vkey) violations.push(`${e.id}: withdrawal and ACVP vkeys are identical`);
    wElfs.add(w.elfSha256);
    aElfs.add(a.elfSha256);
    if (w.vkey) wVkeys.add(w.vkey);
    if (a.vkey) aVkeys.add(a.vkey);
  }
  for (const x of wElfs)
    if (aElfs.has(x)) violations.push(`ELF ${x} is a withdrawal ELF in one environment and an ACVP ELF in another`);
  for (const x of wVkeys)
    if (aVkeys.has(x)) violations.push(`vkey ${x} is a withdrawal vkey in one environment and an ACVP vkey in another`);
  return { holds: violations.length === 0, violations };
}

// ---------------------------------------------------------------------------------------------------------
// Gateway verdict
// ---------------------------------------------------------------------------------------------------------

export interface GatewayChainSummary {
  chainId: string;
  block: number;
  gateway: string;
  codeKeccak: string;
  proxySlotsSet: boolean;
  owner: string;
  ownerKind: string;
  ownerCanAddRoutes: boolean;
  liveRoutes: { selector: string; verifier: string; version: string | null }[];
  frozenRoutes: { selector: string; verifier: string; version: string | null }[];
  routeEnumerationAgrees: boolean;
}

export interface GatewayVerdict {
  intendedTarget: string;
  chains: GatewayChainSummary[];
  bytesAttributed: { gateway: boolean; sp1VerifierGroth16V610: boolean; vkConstantsJoined: boolean };
  /** Every measured chain re-read through a second RPC provider, every compared fact equal. */
  stateReadsCorroborated: boolean;
  ownerMutable: boolean;
  status: ClaimStatus;
  reason: string;
}

/** True only when a second provider re-read every measured chain and every compared fact matched. */
export function stateReadsCorroborated(obs: VerifierGatewayObservations): boolean {
  const checks = obs.secondProvider?.checks ?? [];
  return Object.keys(obs.chains).every((cid) => {
    const c = checks.find((x) => String(x.chainId) === cid);
    if (!c) return false;
    const flags = Object.entries(c).filter(([k]) => k.endsWith("Same"));
    return flags.length >= 5 && flags.every(([, v]) => v === true);
  });
}

export function ownerKind(gw: GatewayChainObservation["groth16Gateway"]): string {
  if (gw.owner.toLowerCase() === ZERO_ADDRESS) return "none";
  if (gw.ownerCodeBytes === 0) return "EOA (single key)";
  const s = gw.ownerSafe;
  if (s && s.threshold !== null && Array.isArray(s.owners)) {
    const modules = Array.isArray(s.modules) ? s.modules.length : "unknown";
    return `Safe ${s.version} ${s.threshold}-of-${s.owners.length} (modules: ${modules}, guard: ${s.guardSlot === ZERO_WORD ? "none" : "set"})`;
  }
  return "contract (unclassified)";
}

/**
 * Provenance of the gateway a ZKMLDSAVerifier is directed to trust. Byte attribution alone is not enough:
 * if any measured deployment has an owner, that owner can add routes (widening the accepting relation for
 * every program vkey) or freeze them, outside WalletWall's trust model, so the claim is NOT_ESTABLISHED.
 */
export function deriveGatewayVerdict(obs: VerifierGatewayObservations, intendedTarget: string): GatewayVerdict {
  const chains: GatewayChainSummary[] = Object.entries(obs.chains).map(([chainId, c]) => {
    const gw = c.groth16Gateway;
    const fromLogs = uniq(gw.events.filter((e) => e.selector).map((e) => e.selector as string)).sort();
    const routeSelectors = gw.routes.map((r) => r.selector).sort();
    const probeMissing = gw.upstreamSelectorProbe.nonEmpty.filter((p) => !routeSelectors.includes(p.selector));
    return {
      chainId,
      block: c.block.number,
      gateway: gw.address,
      codeKeccak: gw.codeKeccak,
      proxySlotsSet: gw.eip1967ImplementationSlot !== ZERO_WORD || gw.eip1967AdminSlot !== ZERO_WORD,
      owner: gw.owner,
      ownerKind: ownerKind(gw),
      ownerCanAddRoutes: gw.owner.toLowerCase() !== ZERO_ADDRESS,
      liveRoutes: gw.routes
        .filter((r) => !r.frozen)
        .map((r) => ({ selector: r.selector, verifier: r.verifier, version: r.version })),
      frozenRoutes: gw.routes
        .filter((r) => r.frozen)
        .map((r) => ({ selector: r.selector, verifier: r.verifier, version: r.version })),
      routeEnumerationAgrees: JSON.stringify(fromLogs) === JSON.stringify(routeSelectors) && probeMissing.length === 0,
    };
  });
  const a = obs.attribution;
  const exact = (addr: string) =>
    obs.sourcify.some(
      (s) => s.chainId === 1 && s.address.toLowerCase() === addr.toLowerCase() && s.match === "exact_match",
    );
  const bytesAttributed = {
    gateway: a.groth16Gateway.runtimeEqual && a.groth16Gateway.create2.equalsAddress && exact(a.groth16Gateway.address),
    sp1VerifierGroth16V610:
      a.sp1VerifierGroth16V610.runtimeEqual &&
      a.sp1VerifierGroth16V610.create2.equalsAddress &&
      a.sp1VerifierGroth16V610.deployTx.inputIsSaltPlusInitcode &&
      exact(a.sp1VerifierGroth16V610.address),
    vkConstantsJoined:
      a.vkConstantJoin.mismatches === 0 &&
      a.vkConstantJoin.equal === a.vkConstantJoin.comparedConstants &&
      a.vkConstantJoin.comparedConstants > 0 &&
      a.vkConstantJoin.vkSha256.toLowerCase() === a.sp1VerifierGroth16V610.verifierHash.toLowerCase(),
  };
  const ownerMutable = chains.some((c) => c.ownerCanAddRoutes || c.proxySlotsSet);
  const enumerationOk = chains.every((c) => c.routeEnumerationAgrees);
  const corroborated = stateReadsCorroborated(obs);
  let status: ClaimStatus;
  let reason: string;
  if (ownerMutable) {
    status = "NOT_ESTABLISHED";
    reason = `the gateway's accepting relation is owner-mutable on ${chains
      .filter((c) => c.ownerCanAddRoutes)
      .map((c) => `chain ${c.chainId} (${c.ownerKind})`)
      .join(
        " and ",
      )}: addRoute widens it for every program vkey and freezeRoute removes it, with no WalletWall action; byte attribution does not change that`;
  } else if (!(bytesAttributed.gateway && enumerationOk && corroborated)) {
    status = "NOT_ESTABLISHED";
    reason = "gateway bytes, route table or state reads not independently attributed";
  } else {
    status = "ESTABLISHED";
    reason = "ownerless, non-proxy gateway whose bytes and routes are independently attributed";
  }
  return {
    intendedTarget,
    chains,
    bytesAttributed,
    stateReadsCorroborated: corroborated,
    ownerMutable,
    status,
    reason,
  };
}

// ---------------------------------------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------------------------------------

export interface Claim {
  status: ClaimStatus;
  basis: string;
}

export interface Sp1P1StopReceipt {
  schema: string;
  artifactType: string;
  lane: string;
  verdict: "STOP_DESIGN_ISSUE";
  generatedAt: string;
  subject: typeof SUBJECT & { sourceManifestSha256: string };
  repositoryBindings: {
    sourceFiles: { path: string; sha256: string }[];
    zkMldsaVerifierSha256: string;
    proverRunbookDirectsToGateway: boolean;
  };
  observations: { path: string; sha256: string }[];
  programIdentity: {
    environments: {
      id: string;
      hostId: string;
      procedure: string;
      embeddedCargoHome: string | null;
      image: string | null;
      withdrawal: ProgramMeasurement;
      acvp: ProgramMeasurement;
    }[];
    withdrawal: ProgramIdentityVerdict;
    acvp: ProgramIdentityVerdict;
    isolation: { holds: boolean; violations: string[] };
    vkeyCrossCheck: { tool: string; purpose: string; ranOn: string; results: number } | null;
    mismatchCause: string;
  };
  verifierGateway: GatewayVerdict & { authoritySurface: string[] };
  proof: null;
  findings: { id: string; severity: string; summary: string }[];
  stopConditions: { condition: string; phase: string; triggered: boolean; evidence: string }[];
  claims: Record<ClaimKey, Claim>;
  notAttempted: string[];
  unresolved: string[];
  independentAuthorities: { authority: string; establishes: string }[];
}

export interface ReceiptInputs {
  identity: ProgramIdentityObservations;
  gateway: VerifierGatewayObservations;
  observationFiles: { path: string; sha256: string }[];
  sourceFiles: { path: string; sha256: string }[];
  zkMldsaVerifierSha256: string;
  proverRunbookDirectsToGateway: boolean;
}

const INTENDED_TARGET =
  "docs/ZK_Prover_Runbook.md §4: SP1_VERIFIER_ADDRESS = the canonical SP1 Groth16 verifier gateway (SP1VerifierGateway 0x397A5f7f3dBd538f23DE225B51f532c34448dA9B)";

export function buildReceipt(inp: ReceiptInputs): Sp1P1StopReceipt {
  const envs = inp.identity.environments;
  const xc = inp.identity.crossChecks?.vkeyFromElf;
  const withdrawal = deriveProgramIdentityVerdict(envs, WITHDRAWAL, xc?.results ?? []);
  const acvp = deriveProgramIdentityVerdict(envs, ACVP, xc?.results ?? []);
  const isolation = deriveProgramIsolation(envs);
  const gateway = deriveGatewayVerdict(inp.gateway, INTENDED_TARGET);
  const homes = uniq(envs.map((e) => e.builder.embeddedCargoHome).filter((h): h is string => !!h));
  const twoIdentities = withdrawal.groups.length > 1;
  const sameHostOnly = !Object.values(withdrawal.families).some((f) => f.reproducedAcrossIndependentHosts);

  const claims: Record<ClaimKey, Claim> = {
    WITHDRAWAL_PROGRAM_RELATION: {
      status: "PARTIALLY_ESTABLISHED",
      basis:
        "Source-level relation only: the native relation tests (zkvm/relation-tests, 3+2+14) pass on the subject sources; it is not bound to a canonical ELF/vkey (identity unresolved) and no proof of it exists.",
    },
    CROSS_ENVIRONMENT_PROGRAM_REPRODUCIBILITY: { status: withdrawal.status, basis: withdrawal.reason },
    REAL_SP1_PROOF_GENERATED: {
      status: "NOT_ESTABLISHED",
      basis:
        "Not attempted: proof generation was stopped by the owner after the Phase 2 trust-root STOP (no circuit-artifact download, no prover run).",
    },
    REAL_SP1_PROOF_VERIFIED: {
      status: "NOT_ESTABLISHED",
      basis:
        "Not attempted: no real proof exists; no verifier (gateway, direct or mock) was exercised with one in this lane.",
    },
    SP1_VERIFIER_GATEWAY_PROVENANCE: { status: gateway.status, basis: gateway.reason },
    ACVP_WITHDRAWAL_PROGRAM_ISOLATION: isolation.holds
      ? {
          status: "PARTIALLY_ESTABLISHED",
          basis:
            "Distinct withdrawal and ACVP ELFs and vkeys in every measured environment and across environments, plus the native program-isolation tests; routing an ACVP proof into the withdrawal verifier was NOT_TESTED (no real proofs).",
        }
      : { status: "NOT_ESTABLISHED", basis: `isolation violations: ${isolation.violations.join("; ")}` },
    CROSS_VAULT_REPLAY_RESISTANCE: {
      status: "NOT_TESTED",
      basis:
        "Construction present (EIP-712 verifyingContract in the vault digest; verifier_address in the journal checked against address(this)); not executed with a real proof in this lane.",
    },
    CROSS_CHAIN_REPLAY_RESISTANCE: {
      status: "NOT_TESTED",
      basis:
        "Construction present (EIP-712 chainId; journal chain_id) but not executed with a real proof; finding F-1: ZKMLDSAVerifier compares uint64(block.chainid), so its own chain binding holds only below 2^64.",
    },
    PRODUCTION_READINESS: {
      status: "NOT_ESTABLISHED",
      basis: "Unaudited research prototype; no real proof; gateway trust root unresolved; no deployment authorized.",
    },
    NIST_CONFORMANCE: {
      status: "NOT_ESTABLISHED",
      basis: "Only the six-vector ACVP subset exists; this lane produced no conformance evidence.",
    },
  };

  const authoritySurface = [
    "Who: the gateway owner (Ownable). Measured owner per chain is listed in `chains[].owner` / `ownerKind`.",
    "addRoute(verifier): registers a new verifier under bytes4(VERIFIER_HASH); takes effect immediately for every caller and every program vkey (the proof's first 4 bytes select the route), so it can only widen the accepting relation.",
    "freezeRoute(selector): permanently disables a route; proofs for it revert (a liveness lever over every ZKMLDSAVerifier pinned to the gateway).",
    "Cannot: replace or remove an existing route's verifier, unfreeze a route, or upgrade the gateway's own code (no proxy, EIP-1967 slots empty).",
    "Accepting relation today = union of the live routes on that chain; the prover, not WalletWall, chooses the route.",
    "WalletWall control over the above: none. ZKMLDSAVerifier pins only the gateway address; the vault's own pqVerifier rotation is timelocked but does not observe gateway route changes.",
  ];

  const stopConditions = [
    {
      condition: "two clean environments produce different withdrawal vkeys",
      phase: "1",
      triggered: twoIdentities,
      evidence: withdrawal.groups
        .map((g) => `${g.elfSha256.slice(0, 12)}… ${g.vkeys.join("/") || "(vkey n/a)"} [${g.environments.join(",")}]`)
        .join(" vs "),
    },
    {
      condition: "program identity depends on unpinned mutable external state",
      phase: "1",
      triggered: homes.length > 1 && twoIdentities,
      evidence: `embedded $CARGO_HOME prefixes differ across procedures: ${homes.join(" vs ")}`,
    },
    {
      condition: "the actual verifier gateway cannot be independently attributed",
      phase: "2",
      triggered: !gateway.bytesAttributed.gateway,
      evidence: `gateway bytes attributed: ${gateway.bytesAttributed.gateway}`,
    },
    {
      condition: "the gateway is mutable in a way the current trust model does not account for",
      phase: "2",
      triggered: gateway.ownerMutable,
      evidence: gateway.chains
        .map(
          (c) =>
            `chain ${c.chainId}: owner ${c.owner} (${c.ownerKind}), live routes ${c.liveRoutes.map((r) => `${r.selector}=${r.version}`).join("+")}`,
        )
        .join("; "),
    },
  ];

  return {
    schema: SP1_P1_STOP_RECEIPT_SCHEMA,
    artifactType: SP1_P1_RECEIPT_ARTIFACT_TYPE,
    lane: "SP1-P1 real proof + verifier gateway provenance closure",
    verdict: "STOP_DESIGN_ISSUE",
    generatedAt: SP1_P1_RECEIPT_GENERATED_AT,
    subject: { ...SUBJECT, sourceManifestSha256: sourceManifestDigest(inp.sourceFiles) },
    repositoryBindings: {
      sourceFiles: [...inp.sourceFiles].sort((x, y) => Buffer.compare(Buffer.from(x.path), Buffer.from(y.path))),
      zkMldsaVerifierSha256: inp.zkMldsaVerifierSha256,
      proverRunbookDirectsToGateway: inp.proverRunbookDirectsToGateway,
    },
    observations: inp.observationFiles,
    programIdentity: {
      environments: envs.map((e) => ({
        id: e.id,
        hostId: e.hostId,
        procedure: e.procedure,
        embeddedCargoHome: e.builder.embeddedCargoHome,
        image: e.image?.reference ?? null,
        withdrawal: e.programs[WITHDRAWAL],
        acvp: e.programs[ACVP],
      })),
      withdrawal,
      acvp,
      isolation,
      vkeyCrossCheck: xc ? { tool: xc.tool, purpose: xc.purpose, ranOn: xc.ranOn, results: xc.results.length } : null,
      mismatchCause:
        "Same sources and succinct toolchain (rustc 1.94.0-dev, LLVM 21.1.8); each ELF embeds the same 10 crate-registry source paths in panic Location strings, differing only in the builder's $CARGO_HOME prefix (sp1-build 6.3.1 passes no remap/trim-paths flag). The repository's local build is therefore bound to the builder's home directory.",
    },
    verifierGateway: { ...gateway, authoritySurface },
    proof: null,
    findings: [
      {
        id: "F-1",
        severity: "low (construction)",
        summary:
          "ZKMLDSAVerifier.verify compares committedChainId != uint64(block.chainid): the cast truncates, so the verifier's own chain binding holds only for chain IDs below 2^64. The vault's EIP-712 domain still carries the full chainid.",
      },
      {
        id: "F-2",
        severity: "informational",
        summary:
          "The journal's sigHash is never checked on chain. Not a defect (the signature is not an on-chain input; any valid ML-DSA signature over the digest authorizes), but it is not a binding.",
      },
      {
        id: "F-3",
        severity: "design (trust model)",
        summary:
          "docs/ZK_Verifier_Production.md calls the SP1 verifier address an immutable trust root, and the runbook directs it at the owner-mutable gateway: address immutability is not relation immutability.",
      },
      {
        id: "F-4",
        severity: "design (testnet)",
        summary:
          "On Sepolia the gateway owner is a single EOA and a release-candidate route (v4.0.0-rc.3, frozen on mainnet) is still live next to v6.1.0.",
      },
    ],
    stopConditions,
    claims,
    notAttempted: [
      "Phase 3 real proof (owner: no 6.21 GB circuit download, no Docker/WSL change)",
      "Phase 4 EVM verification through any verifier",
      "Phase 5 adversarial negative matrix with a real proof",
      "Phase 6 replay tests with a real proof",
      "Phase 8 mutation campaign against proof-path code (the receipt validator itself is mutation-tested)",
    ],
    unresolved: [
      sameHostOnly
        ? "Program identity: no procedure has been reproduced on a second independent host."
        : "Program identity: the repository's default local build and the pinned vendor procedure yield different withdrawal identities; neither is designated canonical (owner decision).",
      "Gateway trust model: whether WalletWall binds to an immutable verifier, a WalletWall-governed gateway, or accounts for Succinct gateway mutability is a design decision for a follow-up lane.",
      "The prover's S3 circuit artifacts (v6.1.0-groth16) are joined to the on-chain verifying key only by a real proof that verifies; none exists.",
      "sp1-contracts tags are lightweight (unsigned); provenance rests on byte equality, not on a signed release.",
      "Every vkey here (mldsa65-host in each environment, and the cargo-prove cross-check) comes from the same upstream sp1-prover implementation: binary-level, not algorithm-level, independence.",
    ],
    independentAuthorities: [
      {
        authority: "succinctlabs/sp1-contracts git (tags v6.0.0/v6.1.0/v6.1.1)",
        establishes: "verifier and gateway source; deployments JSON; upstream incident history",
      },
      {
        authority: "Official solc 0.8.20 (binaries.soliditylang.org, sha256-checked against list.json)",
        establishes: "recompiled runtime and initcode bytes",
      },
      {
        authority: "Ethereum mainnet + Sepolia state (public RPC, pinned block numbers/hashes)",
        establishes: "runtime code hashes, owners, Safe configuration, routes, deploy transactions",
      },
      {
        authority: "CREATE2 derivation (EIP-1014) over recompiled initcode",
        establishes: "address <-> initcode commitment for the gateway and the v6.1.0 verifier",
      },
      {
        authority: "Sourcify v2 API",
        establishes: "independent exact match (runtime + creation) of the mainnet gateway and v6.1.0 verifier",
      },
      {
        authority: "Blockscout logs API",
        establishes:
          "complete RouteAdded/RouteFrozen/OwnershipTransferred history, cross-checked by direct routes() probes of every upstream selector",
      },
      {
        authority: "crates.io sp1-verifier 6.3.1 groth16_vk.bin decoded by arkworks",
        establishes: "the verifying key the Solidity constants must equal; its sha256 equals VERIFIER_HASH",
      },
      {
        authority: "Vendor image ghcr.io/succinctlabs/sp1@sha256:0942a27d… and a GitHub-hosted runner",
        establishes: "program identity outside the developer workstation",
      },
      {
        authority: "Succinct's released cargo-prove binary (sp1up 8252c29), run outside every build environment",
        establishes: "each recorded ELF's sha256 and vkey recomputed from the ELF file itself, not by mldsa65-host",
      },
      {
        authority: "A second, independent RPC provider (dRPC) at the same pinned blocks",
        establishes:
          "the decisive chain state (block hashes, gateway code, owner, Safe threshold, every route) a second time",
      },
    ],
  };
}

// ---------------------------------------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------------------------------------

const TOP_KEYS = [
  "schema",
  "artifactType",
  "lane",
  "verdict",
  "generatedAt",
  "subject",
  "repositoryBindings",
  "observations",
  "programIdentity",
  "verifierGateway",
  "proof",
  "findings",
  "stopConditions",
  "claims",
  "notAttempted",
  "unresolved",
  "independentAuthorities",
];

/**
 * Over-claim and shape checks that hold for ANY receipt of this schema, independent of the generator. A
 * receipt that is internally consistent with its observations can still fail here: these are the lane's
 * non-negotiable rules, not derivations.
 */
export function validateReceiptRules(value: unknown): string[] {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value)) return ["receipt must be an object"];
  const r = value as Record<string, unknown>;
  for (const k of Object.keys(r)) if (!TOP_KEYS.includes(k)) errors.push(`unknown top-level key ${k}`);
  for (const k of TOP_KEYS) if (!(k in r)) errors.push(`missing top-level key ${k}`);
  if (r.schema !== SP1_P1_STOP_RECEIPT_SCHEMA) errors.push(`schema must be ${SP1_P1_STOP_RECEIPT_SCHEMA}`);
  if (r.artifactType !== SP1_P1_RECEIPT_ARTIFACT_TYPE)
    errors.push(`artifactType must be ${SP1_P1_RECEIPT_ARTIFACT_TYPE}`);

  const claims = r.claims as Record<string, Claim> | undefined;
  if (!claims || typeof claims !== "object") return [...errors, "claims must be an object"];
  for (const k of Object.keys(claims))
    if (!(CLAIM_KEYS as readonly string[]).includes(k)) errors.push(`unknown claim ${k}`);
  for (const k of CLAIM_KEYS) {
    const c = claims[k];
    if (!c) {
      errors.push(`missing claim ${k}`);
      continue;
    }
    if (!(CLAIM_STATUSES as readonly string[]).includes(c.status))
      errors.push(`claim ${k} has invalid status ${String(c.status)}`);
    if (typeof c.basis !== "string" || c.basis.trim().length < 20) errors.push(`claim ${k} needs a basis`);
  }
  const st = (k: ClaimKey) => claims[k]?.status;

  if (st("PRODUCTION_READINESS") !== "NOT_ESTABLISHED") errors.push("PRODUCTION_READINESS must stay NOT_ESTABLISHED");
  if (st("NIST_CONFORMANCE") === "ESTABLISHED" || st("NIST_CONFORMANCE") === "PARTIALLY_ESTABLISHED")
    errors.push("NIST_CONFORMANCE cannot be claimed from this lane");
  if (r.proof === null) {
    if (st("REAL_SP1_PROOF_GENERATED") !== "NOT_ESTABLISHED") errors.push("REAL_SP1_PROOF_GENERATED requires a proof");
    if (st("REAL_SP1_PROOF_VERIFIED") !== "NOT_ESTABLISHED") errors.push("REAL_SP1_PROOF_VERIFIED requires a proof");
    for (const k of ["CROSS_VAULT_REPLAY_RESISTANCE", "CROSS_CHAIN_REPLAY_RESISTANCE"] as const)
      if (st(k) === "ESTABLISHED" || st(k) === "PARTIALLY_ESTABLISHED")
        errors.push(`${k} cannot be claimed without an executed real-proof test`);
  } else {
    errors.push("this receipt schema records no proof; a proof requires a new schema");
  }

  const gw = r.verifierGateway as Partial<GatewayVerdict> | undefined;
  if (!gw || !Array.isArray(gw.chains)) errors.push("verifierGateway.chains must be an array");
  else if (gw.chains.some((c) => c.ownerCanAddRoutes) && st("SP1_VERIFIER_GATEWAY_PROVENANCE") === "ESTABLISHED")
    errors.push("SP1_VERIFIER_GATEWAY_PROVENANCE cannot be ESTABLISHED while a measured gateway has an owner");

  const pi = r.programIdentity as { withdrawal?: ProgramIdentityVerdict } | undefined;
  if (!pi?.withdrawal) errors.push("programIdentity.withdrawal missing");
  else if (st("CROSS_ENVIRONMENT_PROGRAM_REPRODUCIBILITY") !== pi.withdrawal.status)
    errors.push("CROSS_ENVIRONMENT_PROGRAM_REPRODUCIBILITY must equal the derived withdrawal identity verdict");

  const stops = r.stopConditions as { triggered: boolean }[] | undefined;
  if (!Array.isArray(stops)) errors.push("stopConditions must be an array");
  else if (stops.some((s) => s.triggered) && r.verdict !== "STOP_DESIGN_ISSUE")
    errors.push("a triggered stop condition requires verdict STOP_DESIGN_ISSUE");
  return errors;
}

/**
 * The receipt's inputs: the committed observations (always the working tree's: they must never change) and the
 * repository bytes it binds — from the working tree while the receipt is live, or from git at `at` (a commit)
 * once it is superseded and validated as a historical record.
 */
export function readObservationInputs(repoRoot = ".", at?: string): ReceiptInputs {
  const read = (rel: string) => readFileSync(resolve(repoRoot, rel));
  const bound = (rel: string) => (at === undefined ? read(rel) : gitBytes(repoRoot, at, rel));
  const idBytes = read(PROGRAM_IDENTITY_OBSERVATIONS_REL);
  const gwBytes = read(VERIFIER_GATEWAY_OBSERVATIONS_REL);
  const runbook = bound(PROVER_RUNBOOK_REL).toString("utf8");
  return {
    identity: JSON.parse(idBytes.toString("utf8")) as ProgramIdentityObservations,
    gateway: JSON.parse(gwBytes.toString("utf8")) as VerifierGatewayObservations,
    observationFiles: [
      { path: PROGRAM_IDENTITY_OBSERVATIONS_REL, sha256: sha256Hex(idBytes) },
      { path: VERIFIER_GATEWAY_OBSERVATIONS_REL, sha256: sha256Hex(gwBytes) },
    ],
    sourceFiles: at === undefined ? workingTreeSourceManifest(repoRoot) : commitSourceManifest(repoRoot, at),
    zkMldsaVerifierSha256: sha256Hex(bound(ZK_VERIFIER_SOURCE_REL)),
    proverRunbookDirectsToGateway: /canonical SP1 Groth16\s+verifier gateway/.test(runbook),
  };
}

// ---------------------------------------------------------------------------------------------------------
// Supersession (SP1-TD1 finding TD1-N4)
// ---------------------------------------------------------------------------------------------------------
//
// This receipt records a STOP, and its validator binds the files the lanes after it had to change
// (ZKMLDSAVerifier.sol, the runbook). Restamping it to new bytes would erase what it proved. Once the questions it
// stopped on were decided (SP1-TD1) and the next lane changed a bound file (SP1-TD2 added the verifier halt to
// ZKMLDSAVerifier.sol), the receipt is marked superseded instead: its exact bytes are pinned, and every binding is
// re-checked at the commit where it was last live, read from git. The receipt itself is never rewritten.

export const SUPERSESSION_REL = "evidence/zk/sp1-p1/supersession.json";
export const SUPERSESSION_SCHEMA = "walletwall.sp1-p1-supersession.v1";
export const SUPERSESSION_FINDING = "TD1-N4";

export interface Supersession {
  schema: string;
  receipt: string;
  /** sha256 of the committed receipt bytes: the record is pinned, not restamped. */
  receiptSha256: string;
  /** A commit at which the receipt was live: its bindings hold there against the tree, read from git. */
  historicalSubject: string;
  finding: string;
  /** The records that supersede it, in order; the first is the decision that answered the STOP. */
  supersededBy: { lane: string; record: string; reason: string }[];
}

function git(repoRoot: string, args: string[]): Buffer {
  return execFileSync("git", args, {
    cwd: resolve(repoRoot),
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

/** A file's bytes at `commit`, read from git. */
export function gitBytes(repoRoot: string, commit: string, rel: string): Buffer {
  return git(repoRoot, ["show", `${commit}:${rel}`]);
}

/** Per-file manifest of the zkvm guest/host sources at `commit`, in `workingTreeSourceManifest`'s path order. */
export function commitSourceManifest(repoRoot: string, commit: string): { path: string; sha256: string }[] {
  const listed = git(repoRoot, ["ls-tree", "-r", "-z", "--name-only", commit, "--", ...SUBJECT_SOURCE_DIRS])
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  return listed.map((p) => ({ path: p, sha256: sha256Hex(gitBytes(repoRoot, commit, p)) }));
}

/** The supersession record, or null while the receipt is live. */
export function readSupersession(repoRoot = "."): unknown {
  let text: string;
  try {
    text = readFileSync(resolve(repoRoot, SUPERSESSION_REL), "utf8");
  } catch {
    return null;
  }
  return JSON.parse(text) as unknown;
}

/** Errors in a supersession record, checked against the committed receipt bytes and the repository's history. */
export function validateSupersession(value: unknown, receiptBytes: Buffer, repoRoot = "."): string[] {
  const errors: string[] = [];
  const s = value as Partial<Supersession> | null;
  if (s === null || typeof s !== "object") return ["the supersession record is not an object"];
  if (s.schema !== SUPERSESSION_SCHEMA) errors.push(`supersession schema must be ${SUPERSESSION_SCHEMA}`);
  if (s.receipt !== RECEIPT_REL) errors.push(`supersession must name ${RECEIPT_REL}`);
  if (s.finding !== SUPERSESSION_FINDING) errors.push(`supersession must cite ${SUPERSESSION_FINDING}`);
  if (s.receiptSha256 !== sha256Hex(receiptBytes)) {
    errors.push(
      "the committed receipt is not the bytes the supersession pinned (a superseded receipt is never restamped)",
    );
  }
  const commit =
    typeof s.historicalSubject === "string" && /^[0-9a-f]{40}$/.test(s.historicalSubject) ? s.historicalSubject : null;
  if (commit === null) {
    errors.push("historicalSubject must be a full commit id");
  } else {
    let then: Buffer | null = null;
    try {
      then = gitBytes(repoRoot, commit, RECEIPT_REL);
    } catch {
      then = null;
    }
    if (then === null) errors.push(`the receipt is not in the repository at ${commit} (or the commit is unavailable)`);
    else if (!then.equals(receiptBytes)) errors.push(`the receipt at ${commit} is not the committed receipt`);
  }
  if (!Array.isArray(s.supersededBy) || s.supersededBy.length === 0) {
    errors.push("supersededBy must name at least one superseding record");
  } else {
    if (s.supersededBy[0]?.lane !== "SP1-TD1")
      errors.push("the first superseding record is SP1-TD1, which decided the STOP");
    for (const r of s.supersededBy) {
      if (typeof r?.lane !== "string" || typeof r.reason !== "string" || r.reason.length === 0) {
        errors.push("each superseding record has a lane and a reason");
      }
      if (typeof r?.record !== "string" || !existsSync(resolve(repoRoot, r.record))) {
        errors.push(`superseding record ${String(r?.record)} does not exist`);
      }
    }
  }
  return errors;
}

/** The inputs the committed receipt is validated against: the working tree, or its historical subject once superseded. */
export function receiptInputsInRepo(repoRoot = "."): ReceiptInputs {
  const s = readSupersession(repoRoot) as Partial<Supersession> | null;
  return readObservationInputs(repoRoot, s === null ? undefined : s.historicalSubject);
}

/** The full check of the committed receipt in this repository: live against the working tree, or as superseded. */
export function validateCommittedReceiptInRepo(
  repoRoot = ".",
  supersession: unknown = readSupersession(repoRoot),
): string[] {
  const receiptBytes = readFileSync(resolve(repoRoot, RECEIPT_REL));
  const committed = JSON.parse(receiptBytes.toString("utf8")) as unknown;
  if (supersession === null) return validateCommittedReceipt(committed, readObservationInputs(repoRoot));
  const errors = validateSupersession(supersession, receiptBytes, repoRoot);
  if (errors.length > 0) return errors;
  return validateCommittedReceipt(
    committed,
    readObservationInputs(repoRoot, (supersession as Supersession).historicalSubject),
  );
}

/**
 * Inputs a receipt may be generated from: refuses (rather than rebinding) when the subject sources on disk
 * no longer match what every measuring environment recorded, or when observations are incomplete.
 */
export function checkInputsFresh(inp: ReceiptInputs): string[] {
  const errors: string[] = [];
  const onDisk = sourceManifestDigest(inp.sourceFiles);
  const measured = inp.identity.environments.filter((e) => e.sourceManifest);
  if (measured.length === 0) errors.push("no environment recorded a source manifest");
  for (const e of measured) {
    const d = sourceManifestDigest(e.sourceManifest as { path: string; sha256: string }[]);
    if (d !== onDisk)
      errors.push(
        `stale: zkvm guest/host sources on disk (${onDisk}) differ from what environment ${e.id} built (${d}); re-measure`,
      );
  }
  if (!inp.proverRunbookDirectsToGateway)
    errors.push(
      "premise changed: docs/ZK_Prover_Runbook.md no longer directs SP1_VERIFIER_ADDRESS at the canonical gateway; re-adjudicate Phase 2",
    );
  const ids = inp.identity.environments.map((e) => e.id);
  if (uniq(ids).length !== ids.length) errors.push("duplicate environment ids");
  return errors;
}

/** Full check of a committed receipt against its observations and the repository bytes on disk. */
export function validateCommittedReceipt(committed: unknown, inp: ReceiptInputs): string[] {
  const errors = [...validateReceiptRules(committed), ...checkInputsFresh(inp)];
  const c = committed as Partial<Sp1P1StopReceipt>;
  if (JSON.stringify(c.observations) !== JSON.stringify(inp.observationFiles))
    errors.push("observation files changed since the receipt was generated (sha256 mismatch)");
  if (c.repositoryBindings?.zkMldsaVerifierSha256 !== inp.zkMldsaVerifierSha256)
    errors.push("contracts/verifiers/ZKMLDSAVerifier.sol changed since the receipt was generated; re-adjudicate");
  if (JSON.stringify(committed) !== JSON.stringify(buildReceipt(inp)))
    errors.push("committed receipt has drifted from the generator; run `npm run sp1-p1:receipt`");
  return errors;
}
