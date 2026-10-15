/**
 * SP1-TD1 decision receipt: which verifier WalletWall trusts for SP1 withdrawal proofs, and which build
 * procedure defines PROGRAM_VKEY.
 *
 * The receipt (evidence/zk/sp1-td1/decision-receipt.json) is a pure function of
 *   - evidence/zk/sp1-td1/decision-inputs.json: the options under evaluation, the procedure candidates, and
 *     `probeFacts` — outcomes test/Sp1Td1TrustTargetProbes.test.ts re-executes against the exact mainnet
 *     verifier and gateway bytes (the suite fails when an execution and a recorded fact disagree);
 *   - the TD1 raw observations (evidence/zk/sp1-td1/observations/*.raw.json): chain state on four chains via
 *     two providers each, CREATE2-authenticated deployment bytecode, the vendor image's content digests, a
 *     route-event timeline, an upstream proof fixture, and a local build probe;
 *   - the SP1-P1 observations and receipt (evidence/zk/sp1-p1/), referenced by hash, never rewritten; and
 *   - the zkvm guest/host sources in the working tree (the designation's subject).
 * Every decision, authority row, designation and claim status is DERIVED here; `validateCommittedDecisionReceipt`
 * re-derives the whole receipt and refuses drift, stale subjects and over-claims, and `validateDecisionRules`
 * rejects the over-claims on its own (a hand-edited receipt cannot pass by being self-consistent).
 *
 * Authorization and liveness are kept apart throughout: a lever that can make a previously REJECTED proof
 * accepted is an authorization lever ("widen"); one that can only make a previously ACCEPTED proof rejected is
 * a liveness lever ("disable"). They are never summed into one score.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  ACVP,
  PROGRAM_IDENTITY_OBSERVATIONS_REL,
  RECEIPT_REL as SP1P1_RECEIPT_REL,
  VERIFIER_GATEWAY_OBSERVATIONS_REL,
  WITHDRAWAL,
  sha256Hex,
  sourceManifestDigest,
  workingTreeSourceManifest,
  type EnvironmentObservation,
  type ProgramIdentityObservations,
  type VerifierGatewayObservations,
} from "./sp1-p1-stop-receipt";

export const TD1_RECEIPT_SCHEMA = "walletwall.sp1-td1-decision-receipt.v1";
export const TD1_RECEIPT_ARTIFACT_TYPE = "sp1-td1-trust-target-program-identity-decision";
/** Fixed so the receipt is a deterministic function of its inputs. */
export const TD1_RECEIPT_GENERATED_AT = "2026-10-15T00:00:00.000Z";
export const TD1_INPUTS_REL = "evidence/zk/sp1-td1/decision-inputs.json";
export const TD1_RECEIPT_REL = "evidence/zk/sp1-td1/decision-receipt.json";
export const TD1_OBSERVATIONS = {
  chainState: "evidence/zk/sp1-td1/observations/chain-state.raw.json",
  deploymentBytecode: "evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json",
  localRemapBuild: "evidence/zk/sp1-td1/observations/local-remap-build.raw.json",
  routeTimeline: "evidence/zk/sp1-td1/observations/route-timeline.raw.json",
  upstreamProofFixture: "evidence/zk/sp1-td1/observations/upstream-proof-fixture.raw.json",
  vendorImage: "evidence/zk/sp1-td1/observations/vendor-image.raw.json",
} as const;

export const TRUST_TARGET_DECISIONS = [
  "DIRECT_IMMUTABLE_VERIFIER",
  "SELECTOR_PINNED_GATEWAY",
  "WALLETWALL_GOVERNED_GATEWAY",
  "UPSTREAM_GATEWAY_OWNER_ACCEPTED",
  "UNRESOLVED",
] as const;
export type TrustTargetDecision = (typeof TRUST_TARGET_DECISIONS)[number];

export const PROGRAM_IDENTITY_DECISIONS = [
  "PINNED_VENDOR_BUILD",
  "REPRODUCIBLE_REPO_BUILD",
  "OTHER_ESTABLISHED_PROCEDURE",
  "UNRESOLVED",
] as const;
export type ProgramIdentityDecision = (typeof PROGRAM_IDENTITY_DECISIONS)[number];

export const CLAIM_STATUSES = ["ESTABLISHED", "PARTIALLY_ESTABLISHED", "NOT_ESTABLISHED", "NOT_TESTED"] as const;
export type ClaimStatus = (typeof CLAIM_STATUSES)[number];
export const TD1_CLAIM_KEYS = [
  "TRUST_TARGET_CODE_IDENTITY",
  "DIRECT_AND_GATEWAY_VERIFICATION_EQUIVALENT",
  "UNPINNED_GATEWAY_OWNER_CAN_WIDEN",
  "DECIDED_TARGET_HAS_NO_EXTERNAL_LEVER",
  "CANONICAL_PROGRAM_IDENTITY",
  "PROGRAM_VKEY_DESIGNATED",
  "IDENTITY_REPRODUCED_OUTSIDE_VENDOR_IMAGE",
  "VKEY_DERIVATION_ALGORITHM_INDEPENDENT",
  "GATEWAY_ROUTE_HISTORY_COMPLETE",
  "REAL_SP1_PROOF_GENERATED",
  "REAL_SP1_PROOF_VERIFIED",
  "PRODUCTION_READINESS",
] as const;
export type Td1ClaimKey = (typeof TD1_CLAIM_KEYS)[number];

/** Pins that, together with write-once routes, take the gateway owner's addRoute out of the accepted path. */
export const FULL_GATEWAY_PINS = ["selector", "routeVerifier", "gatewayCode", "verifierCode"] as const;
/** Levers that can only stop verification; they must never be read as widening it. */
export const LIVENESS_LEVERS = ["freezeRoute", "gatewayAdminFreezeRoute"] as const;
/** Levers that can make a previously rejected proof accepted. */
export const AUTHORIZATION_LEVERS = [
  "addRoute",
  "addRoute (route squat)",
  "gatewayAdminAddRoute",
  "pqVerifierRotation",
  "unestablished verifier code",
] as const;
const GOVERNED_PRINCIPAL = "WalletWall vault owner (timelocked pqVerifier rotation)";
const ZERO_WORD = `0x${"0".repeat(64)}`;

// ---------------------------------------------------------------------------------------------------------
// Inputs and observation types
// ---------------------------------------------------------------------------------------------------------

export interface FileRef {
  path: string;
  sha256: string;
}

export interface OptionInput {
  id: string;
  decisionValue: Exclude<TrustTargetDecision, "UNRESOLVED">;
  label: string;
  path: string[];
  components: ("sp1Verifier" | "upstreamGateway" | "walletwallGateway")[];
  pins: string[];
  probeFactsKey: string;
  newAttackSurface: string;
  operationalComplexity: string;
}

export interface ProbeFacts {
  bytes: { gatewayRuntimeEqualsMainnet: boolean; v610RuntimeEqualsMainnet: boolean; v600RuntimeEqualsMainnet: boolean };
  semantics: {
    gatewayForwardsConsumerTupleUnchanged: boolean;
    realProofAcceptedDirect: boolean;
    realProofAcceptedViaGateway: boolean;
    tamperedProofRejectedDirectAndViaGateway: boolean;
    v610PreCheckRevertDataIdenticalDirectAndViaGateway: boolean;
    unroutedSelectorRejectedDirectAndViaGateway: boolean;
  };
  verifierRuntime: { v610ForbiddenOpcodes: string[]; gatewayHasSstore: boolean };
  D_upstreamGatewayUnpinned: {
    ownerAddRouteWidensAcceptedRelation: boolean;
    ownerAddRouteDrainsPqOnlyVault: boolean;
    ownerFreezeRejectsValidProof: boolean;
    freezeAcceptsNoPreviouslyRejectedInput: boolean;
    ownerCanReplaceExistingRoute: boolean;
    nonOwnerCanAddRoute: boolean;
  };
  C_walletwallGateway: {
    adminAddRouteWidensAcceptedRelation: boolean;
    adminWidensWithoutDelay: boolean;
    vaultVerifierRotationDelaySeconds: number;
  };
  B0_selectorOnlyPin: { routeSquatOnUnroutedChainAccepted: boolean };
  B_selectorRouteCodePinned: {
    squattedRouteRejectedAtConstruction: boolean;
    realProofAcceptedThroughPin: boolean;
    otherSelectorRouteRejected: boolean;
    pinnedRouteReplaceable: boolean;
    ownerFreezeRejectsValidProof: boolean;
  };
  A_directCodePinned: {
    acceptsCanonicalCode: boolean;
    acceptsSameCodeAtAnotherAddress: boolean;
    rejectsGateway: boolean;
    rejectsOtherVerifierVersion: boolean;
    rejectsAcceptAllVerifier: boolean;
    unmodifiedConsumerRejectsForgedRouteProof: boolean;
    noPrincipalCanAlterAcceptedRelation: boolean;
  };
}

export interface FindingInput {
  id: string;
  source: string;
  title: string;
  disposition: string;
  practicalImpact: string;
  securityImpact: string;
  repairBeforeRealProof: boolean;
  guestOrVkeyChange: boolean;
  plan: string;
}

export interface DecisionInputs {
  schema: string;
  lane: string;
  subject: {
    repository: string;
    baseCommit: string;
    baseTree: string;
    mergedPredecessor: Record<string, unknown>;
    zkvmGuestTree: string;
    zkvmHostTree: string;
  };
  evidence: {
    sp1p1Receipt: FileRef;
    sp1p1Observations: FileRef[];
    td1Observations: FileRef[];
    canonicalProcedureScripts: (FileRef & { sourceCommit: string; sourcePath: string })[];
    probeSuite: string;
  };
  trustTargetSelection: { version: string; verifier: string; selector: string; requiredChains: string[] };
  options: OptionInput[];
  probeFacts: ProbeFacts;
  programIdentitySelection: {
    minimumIndependentHosts: number;
    candidates: { decisionValue: Exclude<ProgramIdentityDecision, "UNRESOLVED">; family: string; role: string }[];
    canonicalProcedure: {
      id: string;
      image: string;
      platform: string;
      entrypoint: string;
      driver: string;
      commands: string[];
      environment: Record<string, string>;
      target: string;
      features: string[];
      sp1: Record<string, string>;
      forbidden: string[];
    };
  };
  offChainLivenessDependencies: string[];
  findings: FindingInput[];
  implementationPlan: string[];
}

interface ChainVerifierRead {
  address: string;
  codeBytes: number;
  codeKeccak: string | null;
  VERIFIER_HASH?: string | null;
  VK_ROOT?: string | null;
  VERSION?: string | null;
}

interface ChainRouteRead {
  selector: string;
  verifier: string;
  frozen: boolean;
  verifierCodeKeccak: string | null;
  version: string | null;
}

export interface ChainStateObservation {
  measuredAtUtc: string;
  selectorUniverse: { count: number; selectors: string[]; headAtClone: string };
  chains: Record<
    string,
    {
      providers: string[];
      block: { number: number; hash: string; timestamp: number };
      chainIdReported: number;
      deterministicDeployer: { address: string; codeBytes: number; codeKeccak: string | null };
      verifiers: Record<string, ChainVerifierRead>;
      gateway: {
        address: string;
        codeBytes: number;
        codeKeccak: string | null;
        eip1967ImplementationSlot: string;
        eip1967AdminSlot: string;
        owner: string | null;
        ownerCodeBytes: number | null;
        ownerSafe: {
          version: string | null;
          threshold: number | null;
          owners: string[] | null;
          modules: string[] | null;
          guardSlot: string;
        } | null;
        routes: ChainRouteRead[];
      };
      secondProvider: {
        url: string;
        chainIdSame: boolean;
        blockHashSame: boolean;
        deterministicDeployerSame: boolean;
        verifiersSame: boolean;
        gatewayCodeSame: boolean;
        ownerSame: boolean;
        ownerSafeSame: boolean;
        routesSame: boolean;
        routesChecked: number;
      };
    }
  >;
  sepoliaV500FrozenFlip: {
    selector: string;
    firstFrozenBlock: number;
    routeFrozenLogs: { block: number; tx: string; selector: string; verifier: string }[];
    indexerCorroboration: { tx: string; routeFrozenLogsInTx: number }[];
  };
}

export interface DeploymentRecord {
  chainId: number;
  tx: string;
  toIsDeterministicDeployer: boolean;
  receiptStatus: number;
  transactionOnBothProviders: boolean;
  inputSameOnBothProviders: boolean;
  salt: string;
  initcodeKeccak: string;
  create2Derived: string;
  equalsAddress: boolean;
  initcode: string;
}

export interface DeploymentBytecodeObservation {
  create2Deployer: string;
  deployments: Record<string, DeploymentRecord>;
}

export interface LocalRemapObservation {
  preregistration: { sha256: string };
  host: { hostId: string };
  builds: {
    id: "P-local" | "P-remap";
    procedure: string;
    freshWorkDir: boolean;
    freshTargetDir: boolean;
    sourceManifest: { path: string; sha256: string }[];
    programs: Record<string, { elfSha256: string; elfBytes: number; vkey: string }>;
    embeddedRegistryPaths: string[];
  }[];
}

export interface RouteTimelineObservation {
  upstreamAdvisory: {
    id: string;
    published: string;
    severity: string;
    affected: string;
    patched: string;
    onChainVerifierImpactStated: boolean;
  };
  events: {
    chainId: number;
    block: number;
    event: string;
    selector: string;
    version: string;
    timestamp: number;
    utc: string;
    providersAgree: boolean;
    providersRead: number;
  }[];
}

export interface UpstreamFixtureObservation {
  tags: Record<string, { type: string; commit: string; signatureBlockPresent?: boolean; signatureVerified?: boolean }>;
  fixture: {
    programVKey: string;
    publicValues: string;
    proofBytes: string;
    fileSha256: string;
    verifierUnderTest: string;
  };
  templateComparison: { nonConstantLinesSameMultiset: boolean; nonConstantLinesSameOrder: boolean };
}

export interface VendorImageObservation {
  pinnedIndex: {
    reference: string;
    bodySha256: string;
    manifests: { digest: string; platform: { os: string; architecture: string } }[];
  };
  linuxAmd64Manifest: { digest: string; bodySha256: string; config: { digest: string } };
  mutableTag: { tag: string; resolvesToDigest: string | null };
}

export interface DecisionContext {
  inputs: DecisionInputs;
  chain: ChainStateObservation;
  deployments: DeploymentBytecodeObservation;
  remap: LocalRemapObservation;
  timeline: RouteTimelineObservation;
  fixture: UpstreamFixtureObservation;
  image: VendorImageObservation;
  sp1p1Identity: ProgramIdentityObservations;
  sp1p1Gateway: VerifierGatewayObservations;
  sp1p1Receipt: { subject: { circuitVersion: string; sourceManifestSha256: string; sp1Pins: Record<string, string> } };
  /** sha256 of every evidence file as it is on disk now. */
  fileHashes: Record<string, string>;
  workingTreeManifest: { path: string; sha256: string }[];
}

// ---------------------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------------------

const uniq = <T>(xs: T[]): T[] => [...new Set(xs)];
const lower = (s: string | null | undefined) => (s ?? "").toLowerCase();
const sameAddress = (a: string | null | undefined, b: string | null | undefined) => !!a && !!b && lower(a) === lower(b);

function ownerKind(g: ChainStateObservation["chains"][string]["gateway"]): string {
  if (!g.owner) return "none";
  if ((g.ownerCodeBytes ?? 0) === 0) return "EOA (single key)";
  const s = g.ownerSafe;
  if (s && s.threshold !== null && s.owners) {
    const guard = s.guardSlot === ZERO_WORD ? "no guard" : "guard set";
    return `Safe ${s.version ?? "?"} ${s.threshold}-of-${s.owners.length} (${(s.modules ?? []).length} modules, ${guard})`;
  }
  return "contract (not a recognised Safe)";
}

// ---------------------------------------------------------------------------------------------------------
// Trust target code identity
// ---------------------------------------------------------------------------------------------------------

export interface TrustTargetIdentity {
  version: string;
  verifier: string;
  selector: string;
  codeKeccak: string | null;
  verifierHash: string | null;
  vkRoot: string | null;
  chains: { chainId: string; block: number; codeKeccak: string | null; providersAgree: boolean }[];
  create2: { tx: string; salt: string; initcodeKeccak: string; derived: string; authenticated: boolean };
  sp1p1Attribution: { ownCompileEqualsChain: boolean; vkConstantsJoined: boolean; sourcifyExactMainnet: boolean };
  runtime: { forbiddenOpcodes: string[]; probeBytesEqualMainnet: boolean };
  circuitVersionMatchesSubject: boolean;
  established: boolean;
  failures: string[];
}

export function deriveTrustTargetIdentity(ctx: DecisionContext): TrustTargetIdentity {
  const sel = ctx.inputs.trustTargetSelection;
  const failures: string[] = [];
  const chains = sel.requiredChains.map((id) => {
    const c = ctx.chain.chains[id];
    if (!c) {
      failures.push(`chain ${id}: not measured`);
      return { chainId: id, block: 0, codeKeccak: null, providersAgree: false };
    }
    const v = c.verifiers[sel.version];
    const sp = c.secondProvider;
    const providersAgree = sp.chainIdSame && sp.blockHashSame && sp.verifiersSame;
    if (!providersAgree) failures.push(`chain ${id}: the second provider does not corroborate the verifier read`);
    if (!v || !sameAddress(v.address, sel.verifier))
      failures.push(`chain ${id}: ${sel.version} not read at ${sel.verifier}`);
    if (!v?.codeKeccak) failures.push(`chain ${id}: no code at ${sel.verifier}`);
    if (v?.VERSION !== sel.version)
      failures.push(`chain ${id}: VERSION() is ${String(v?.VERSION)}, not ${sel.version}`);
    if (lower(v?.VERIFIER_HASH).slice(0, 10) !== lower(sel.selector))
      failures.push(`chain ${id}: VERIFIER_HASH does not start with ${sel.selector}`);
    return { chainId: id, block: c.block.number, codeKeccak: v?.codeKeccak ?? null, providersAgree };
  });
  const codes = uniq(chains.map((c) => c.codeKeccak));
  if (codes.length !== 1) failures.push(`the verifier's runtime code differs across chains (${codes.join(", ")})`);
  const reads = sel.requiredChains.map((id) => ctx.chain.chains[id]?.verifiers[sel.version]).filter(Boolean);
  const hashes = uniq(reads.map((v) => lower(v!.VERIFIER_HASH)));
  const roots = uniq(reads.map((v) => lower(v!.VK_ROOT)));
  if (hashes.length !== 1) failures.push("VERIFIER_HASH differs across chains");
  if (roots.length !== 1) failures.push("VK_ROOT differs across chains");

  const d = ctx.deployments.deployments[sel.version];
  const authenticated =
    !!d &&
    d.equalsAddress &&
    d.toIsDeterministicDeployer &&
    d.receiptStatus === 1 &&
    d.inputSameOnBothProviders &&
    sameAddress(d.create2Derived, sel.verifier);
  if (!authenticated) failures.push("the verifier's initcode is not CREATE2-authenticated against its address");

  const a = ctx.sp1p1Gateway.attribution;
  const ownCompileEqualsChain =
    a.sp1VerifierGroth16V610.runtimeEqual === true &&
    a.sp1VerifierGroth16V610.create2.equalsAddress === true &&
    sameAddress(a.sp1VerifierGroth16V610.address, sel.verifier) &&
    lower(a.sp1VerifierGroth16V610.onchainRuntimeKeccakMainnet) === lower(codes[0]);
  const vkConstantsJoined =
    a.vkConstantJoin.mismatches === 0 &&
    a.vkConstantJoin.equal === a.vkConstantJoin.comparedConstants &&
    a.vkConstantJoin.comparedConstants > 0 &&
    lower(a.vkConstantJoin.vkSha256) === lower(hashes[0]);
  const sourcifyExactMainnet = ctx.sp1p1Gateway.sourcify.some(
    (s) => s.chainId === 1 && sameAddress(s.address, sel.verifier) && s.match === "exact_match",
  );
  if (!ownCompileEqualsChain) failures.push("SP1-P1's own compile of the tagged source does not equal the chain bytes");
  if (!vkConstantsJoined) failures.push("the verifying-key constants are not joined to the published vk artifact");
  if (!sourcifyExactMainnet) failures.push("no Sourcify exact match for the verifier on mainnet");

  const forbidden = ctx.inputs.probeFacts.verifierRuntime.v610ForbiddenOpcodes;
  const probeBytesEqualMainnet = ctx.inputs.probeFacts.bytes.v610RuntimeEqualsMainnet === true;
  if (forbidden.length > 0)
    failures.push(`the verifier runtime has reachable ${forbidden.join("/")}: it is not immutable`);
  if (!probeBytesEqualMainnet) failures.push("the probe suite did not run the mainnet verifier bytes");
  const circuitVersionMatchesSubject = ctx.sp1p1Receipt.subject.circuitVersion === sel.version;
  if (!circuitVersionMatchesSubject)
    failures.push(`the subject's SP1 circuit (${ctx.sp1p1Receipt.subject.circuitVersion}) is not the target version`);

  return {
    version: sel.version,
    verifier: sel.verifier,
    selector: sel.selector,
    codeKeccak: codes.length === 1 ? codes[0] : null,
    verifierHash: hashes.length === 1 ? hashes[0] : null,
    vkRoot: roots.length === 1 ? roots[0] : null,
    chains,
    create2: {
      tx: d?.tx ?? "",
      salt: d?.salt ?? "",
      initcodeKeccak: d?.initcodeKeccak ?? "",
      derived: d?.create2Derived ?? "",
      authenticated,
    },
    sp1p1Attribution: { ownCompileEqualsChain, vkConstantsJoined, sourcifyExactMainnet },
    runtime: { forbiddenOpcodes: [...forbidden], probeBytesEqualMainnet },
    circuitVersionMatchesSubject,
    established: failures.length === 0,
    failures,
  };
}

// ---------------------------------------------------------------------------------------------------------
// Gateway posture per chain
// ---------------------------------------------------------------------------------------------------------

export interface GatewayChainPosture {
  chainId: string;
  block: number;
  gateway: string;
  codeKeccak: string | null;
  proxySlotsSet: boolean;
  owner: string | null;
  ownerKind: string;
  ownerSafeSigners: string[];
  liveRoutes: { selector: string; version: string | null }[];
  frozenRoutes: { selector: string; version: string | null }[];
  targetRoutedLive: boolean;
  extraLiveRoutes: { selector: string; version: string | null }[];
  stateCorroborated: boolean;
}

export interface GatewayPosture {
  chains: GatewayChainPosture[];
  selectorsProbed: number;
  sameCodeOnEveryChain: boolean;
  routeHistoryIndexerGap: {
    chainId: string;
    tx: string;
    selector: string;
    missingFromSp1P1History: boolean;
    indexerHasLog: boolean;
  } | null;
}

export function deriveGatewayPosture(ctx: DecisionContext): GatewayPosture {
  const sel = ctx.inputs.trustTargetSelection;
  const chains = Object.keys(ctx.chain.chains)
    .sort()
    .map((id): GatewayChainPosture => {
      const c = ctx.chain.chains[id];
      const g = c.gateway;
      const live = g.routes.filter((r) => !r.frozen).map((r) => ({ selector: r.selector, version: r.version }));
      const frozen = g.routes.filter((r) => r.frozen).map((r) => ({ selector: r.selector, version: r.version }));
      const target = g.routes.find((r) => lower(r.selector) === lower(sel.selector));
      const sp = c.secondProvider;
      return {
        chainId: id,
        block: c.block.number,
        gateway: g.address,
        codeKeccak: g.codeKeccak,
        proxySlotsSet: g.eip1967ImplementationSlot !== ZERO_WORD || g.eip1967AdminSlot !== ZERO_WORD,
        owner: g.owner,
        ownerKind: ownerKind(g),
        ownerSafeSigners: g.ownerSafe?.owners ?? [],
        liveRoutes: live,
        frozenRoutes: frozen,
        targetRoutedLive: !!target && !target.frozen && sameAddress(target.verifier, sel.verifier),
        extraLiveRoutes: live.filter((r) => lower(r.selector) !== lower(sel.selector)),
        stateCorroborated:
          sp.chainIdSame && sp.blockHashSame && sp.gatewayCodeSame && sp.ownerSame && sp.ownerSafeSame && sp.routesSame,
      };
    });
  const flip = ctx.chain.sepoliaV500FrozenFlip;
  const sp1p1Sepolia = (ctx.sp1p1Gateway.chains["11155111"]?.groth16Gateway.events ?? []).map((e) => lower(e.tx));
  const log = flip?.routeFrozenLogs?.[0];
  const gap = log
    ? {
        chainId: "11155111",
        tx: log.tx,
        selector: log.selector,
        missingFromSp1P1History: !sp1p1Sepolia.includes(lower(log.tx)),
        indexerHasLog:
          (flip.indexerCorroboration.find((x) => lower(x.tx) === lower(log.tx))?.routeFrozenLogsInTx ?? 0) > 0,
      }
    : null;
  return {
    chains,
    selectorsProbed: ctx.chain.selectorUniverse.count,
    sameCodeOnEveryChain: uniq(chains.map((c) => c.codeKeccak)).length === 1,
    routeHistoryIndexerGap: gap,
  };
}

// ---------------------------------------------------------------------------------------------------------
// Option authority (the matrix)
// ---------------------------------------------------------------------------------------------------------

export interface Lever {
  principal: string;
  lever: string;
  scope: "authorization" | "liveness";
  chains: string[];
  delaySeconds: number;
  governed: boolean;
}

export interface OptionAuthority {
  id: string;
  decisionValue: Exclude<TrustTargetDecision, "UNRESOLVED">;
  label: string;
  path: string[];
  pins: string[];
  verifierCodeMutable: boolean;
  gatewayCodeMutable: boolean | null;
  routeRegistry: boolean;
  proxyOrAdmin: string;
  acceptedRelationMutableOutsideTimelock: boolean;
  widen: Lever[];
  disable: Lever[];
  upstreamGovernanceDependency: "authorization" | "liveness" | "none";
  walletwallGovernanceDependency: string;
  requiresRedeployToUpgrade: boolean;
  trustRootIndependentlyReproducible: boolean;
  crossChainIdentity: string;
  authorizationCut: string;
  livenessCut: string;
  newAttackSurface: string;
  operationalComplexity: string;
  viable: boolean;
  rejectedBecause: string | null;
}

function gatewayOwnerLevers(posture: GatewayPosture, lever: string, scope: Lever["scope"]): Lever[] {
  const byOwner = new Map<string, { kind: string; chains: string[] }>();
  for (const c of posture.chains) {
    if (!c.owner) continue;
    const key = `${c.owner} (${c.ownerKind})`;
    const e = byOwner.get(key) ?? { kind: c.ownerKind, chains: [] };
    e.chains.push(c.chainId);
    byOwner.set(key, e);
  }
  return [...byOwner.entries()].map(([principal, e]) => ({
    principal: `upstream gateway owner ${principal}`,
    lever,
    scope,
    chains: e.chains,
    delaySeconds: 0,
    governed: false,
  }));
}

export function deriveOptionAuthority(
  option: OptionInput,
  ctx: DecisionContext,
  identity: TrustTargetIdentity,
  posture: GatewayPosture,
): OptionAuthority {
  const f = ctx.inputs.probeFacts;
  const measuredChains = posture.chains.map((c) => c.chainId);
  const widen: Lever[] = [
    {
      principal: GOVERNED_PRINCIPAL,
      lever: "pqVerifierRotation",
      scope: "authorization",
      chains: ["every chain WalletWall deploys to"],
      delaySeconds: f.C_walletwallGateway.vaultVerifierRotationDelaySeconds,
      governed: true,
    },
  ];
  const disable: Lever[] = [];
  const has = (c: OptionInput["components"][number]) => option.components.includes(c);
  const pinned = (p: string) => option.pins.includes(p);
  const fullyPinned = FULL_GATEWAY_PINS.every((p) => pinned(p));

  if (has("upstreamGateway")) {
    // Routes are write-once, so a full pin (selector + the route's verifier + both code hashes) leaves no one a
    // way to change which code a pinned proof reaches. That rests on three executed facts, not on the pin list.
    const routePinHolds =
      fullyPinned &&
      f.B_selectorRouteCodePinned.pinnedRouteReplaceable === false &&
      f.B_selectorRouteCodePinned.otherSelectorRouteRejected === true &&
      f.B_selectorRouteCodePinned.squattedRouteRejectedAtConstruction === true;
    // Who can add a route on an unpinned or selector-only path: the owner, or anyone if addRoute were ungated.
    const adder = f.D_upstreamGatewayUnpinned.nonOwnerCanAddRoute ? "anyone (addRoute not owner-gated)" : null;
    if (!routePinHolds) {
      if (pinned("selector")) {
        // A selector pin alone: a verifier can still be registered under the pinned selector on any chain
        // where it is not yet routed, and nothing in the option checks that at deployment.
        if (f.B0_selectorOnlyPin.routeSquatOnUnroutedChainAccepted)
          widen.push({
            principal: `${adder ?? "upstream gateway owner"} on any chain where the pinned selector is not yet routed`,
            lever: "addRoute (route squat)",
            scope: "authorization",
            chains: [
              ...posture.chains.filter((c) => !c.targetRoutedLive).map((c) => c.chainId),
              "any chain not measured here",
            ],
            delaySeconds: 0,
            governed: false,
          });
      } else {
        if (f.D_upstreamGatewayUnpinned.ownerAddRouteWidensAcceptedRelation)
          widen.push(...gatewayOwnerLevers(posture, "addRoute", "authorization"));
        if (adder)
          widen.push({
            principal: adder,
            lever: "addRoute",
            scope: "authorization",
            chains: measuredChains,
            delaySeconds: 0,
            governed: false,
          });
      }
    }
    const freezeStops = fullyPinned
      ? f.B_selectorRouteCodePinned.ownerFreezeRejectsValidProof
      : f.D_upstreamGatewayUnpinned.ownerFreezeRejectsValidProof;
    if (freezeStops) disable.push(...gatewayOwnerLevers(posture, "freezeRoute", "liveness"));
  }
  if (has("walletwallGateway")) {
    if (f.C_walletwallGateway.adminAddRouteWidensAcceptedRelation)
      widen.push({
        principal: "WalletWall gateway admin",
        lever: "gatewayAdminAddRoute",
        scope: "authorization",
        chains: ["every chain the WalletWall gateway is deployed to"],
        delaySeconds: f.C_walletwallGateway.adminWidensWithoutDelay
          ? 0
          : f.C_walletwallGateway.vaultVerifierRotationDelaySeconds,
        governed: false,
      });
    disable.push({
      principal: "WalletWall gateway admin",
      lever: "gatewayAdminFreezeRoute",
      scope: "liveness",
      chains: ["every chain the WalletWall gateway is deployed to"],
      delaySeconds: 0,
      governed: false,
    });
  }
  // deriveTrustTargetIdentity already fails on any reachable state- or code-changing opcode.
  const verifierCodeMutable =
    !identity.established || f.A_directCodePinned.noPrincipalCanAlterAcceptedRelation !== true;
  if (has("sp1Verifier") && verifierCodeMutable)
    widen.push({
      principal: "unknown (verifier code identity not established)",
      lever: "unestablished verifier code",
      scope: "authorization",
      chains: measuredChains,
      delaySeconds: 0,
      governed: false,
    });

  const routeRegistry = has("upstreamGateway") || has("walletwallGateway");
  const gatewayCodeMutable = has("upstreamGateway")
    ? posture.chains.some((c) => c.proxySlotsSet) || !posture.sameCodeOnEveryChain
    : has("walletwallGateway")
      ? false
      : null;
  const externalWiden = widen.filter((l) => !l.governed);
  const externalDisable = disable.filter((l) => !l.governed);
  const upstream = (ls: Lever[]) => ls.some((l) => l.principal.startsWith("upstream gateway owner"));
  const upstreamGovernanceDependency = upstream(externalWiden)
    ? "authorization"
    : upstream(externalDisable)
      ? "liveness"
      : "none";
  const acceptedRelationMutableOutsideTimelock = externalWiden.length > 0;
  const requiresRedeployToUpgrade = !(routeRegistry && !pinned("selector"));
  const trustRootIndependentlyReproducible =
    identity.established &&
    !acceptedRelationMutableOutsideTimelock &&
    (!has("upstreamGateway") || f.bytes.gatewayRuntimeEqualsMainnet);

  const extraLive = posture.chains.filter((c) => c.extraLiveRoutes.length > 0);
  const ownerKinds = uniq(posture.chains.map((c) => `${c.chainId}: ${c.ownerKind}`));
  const crossChainIdentity = routeRegistry
    ? `per-chain owner and route table (${ownerKinds.join("; ")})` +
      (extraLive.length > 0
        ? `; extra live routes on ${extraLive.map((c) => `${c.chainId} (${c.extraLiveRoutes.map((r) => r.version).join(", ")})`).join(", ")}`
        : "")
    : identity.codeKeccak
      ? `one runtime code hash ${identity.codeKeccak} on every measured chain (${identity.chains.map((c) => c.chainId).join(", ")})`
      : "code identity not established";

  const cut = (ls: Lever[]) =>
    ls.length === 0
      ? "none"
      : uniq(ls.map((l) => `${l.principal} via ${l.lever} (delay ${l.delaySeconds}s)`)).join("; ");
  const authorizationCut =
    externalWiden.length === 0
      ? `only ${GOVERNED_PRINCIPAL}, after ${f.C_walletwallGateway.vaultVerifierRotationDelaySeconds}s`
      : `ANY ONE OF: ${cut(externalWiden)}`;
  const livenessCut = cut(externalDisable);

  let rejectedBecause: string | null = null;
  if (!identity.established) rejectedBecause = "the verifier's code identity is not established";
  else if (acceptedRelationMutableOutsideTimelock)
    rejectedBecause = `a principal outside WalletWall's timelocked rotation can widen the accepted relation: ${cut(externalWiden)}`;
  const proxyOrAdmin = has("upstreamGateway")
    ? "upstream Ownable owner (no proxy)"
    : has("walletwallGateway")
      ? "WalletWall Ownable admin (no proxy)"
      : "none";

  return {
    id: option.id,
    decisionValue: option.decisionValue,
    label: option.label,
    path: option.path,
    pins: option.pins,
    verifierCodeMutable,
    gatewayCodeMutable,
    routeRegistry,
    proxyOrAdmin,
    acceptedRelationMutableOutsideTimelock,
    widen,
    disable,
    upstreamGovernanceDependency,
    walletwallGovernanceDependency: has("walletwallGateway")
      ? "timelocked pqVerifier rotation AND an instant gateway admin"
      : "timelocked pqVerifier rotation only",
    requiresRedeployToUpgrade,
    trustRootIndependentlyReproducible,
    crossChainIdentity,
    authorizationCut,
    livenessCut,
    newAttackSurface: option.newAttackSurface,
    operationalComplexity: option.operationalComplexity,
    viable: rejectedBecause === null,
    rejectedBecause,
  };
}

/**
 * The decision rule, in order: (1) only options whose accepted relation no principal outside WalletWall's
 * timelocked rotation can widen are viable; (2) among those, fewer distinct external liveness principals
 * win (authority minimisation); (3) then fewer components in the accepted path. No viable option: UNRESOLVED.
 */
export function decideTrustTarget(options: OptionAuthority[]): {
  decision: TrustTargetDecision;
  optionId: string | null;
} {
  const viable = options.filter((o) => o.viable);
  if (viable.length === 0) return { decision: "UNRESOLVED", optionId: null };
  const external = (o: OptionAuthority) => uniq(o.disable.filter((l) => !l.governed).map((l) => l.principal)).length;
  const ranked = [...viable].sort((a, b) => external(a) - external(b) || a.path.length - b.path.length);
  return { decision: ranked[0].decisionValue, optionId: ranked[0].id };
}

// ---------------------------------------------------------------------------------------------------------
// Program identity
// ---------------------------------------------------------------------------------------------------------

interface IdentityEnvironment {
  id: string;
  hostId: string;
  family: string;
  image: string | null;
  platform: string | null;
  embeddedCargoHome: string | null;
  manifestDigest: string | null;
  withdrawal: { elfSha256: string | null; elfBytes: number | null; vkey: string | null };
  acvp: { elfSha256: string | null; vkey: string | null };
}

export interface FamilyVerdict {
  family: string;
  environments: string[];
  hosts: string[];
  withdrawalElfs: string[];
  withdrawalVkeys: string[];
  embeddedCargoHomes: string[];
  imagesDigestPinned: boolean;
  manifestsFresh: boolean;
  reproducedOnIndependentHosts: boolean;
}

export interface ProgramIdentityVerdict {
  environments: IdentityEnvironment[];
  families: FamilyVerdict[];
  contradictions: string[];
  vendorImage: {
    reference: string;
    indexDigestVerified: boolean;
    linuxAmd64Manifest: string | null;
    config: string | null;
    mutableTagCurrentlyResolvesToPin: boolean;
  };
  canonicalProcedureScriptsPreserved: boolean;
  candidates: {
    decisionValue: ProgramIdentityDecision;
    family: string;
    role: string;
    established: boolean;
    reason: string;
  }[];
  decision: ProgramIdentityDecision;
}

function familyOfSp1P1(e: EnvironmentObservation): string {
  return e.procedure === "repository-host-flow-local" ? "repository-local" : "vendor-image";
}

export function identityEnvironments(ctx: DecisionContext): IdentityEnvironment[] {
  const fromSp1P1 = ctx.sp1p1Identity.environments.map((e): IdentityEnvironment => ({
    id: e.id,
    hostId: e.hostId,
    family: familyOfSp1P1(e),
    image: e.image?.reference ?? null,
    platform: e.image?.platform ?? null,
    embeddedCargoHome: e.builder.embeddedCargoHome,
    manifestDigest: e.sourceManifest ? sourceManifestDigest(e.sourceManifest) : null,
    withdrawal: {
      elfSha256: e.programs[WITHDRAWAL]?.elfSha256 ?? null,
      elfBytes: e.programs[WITHDRAWAL]?.elfBytes ?? null,
      vkey: e.programs[WITHDRAWAL]?.vkey ?? null,
    },
    acvp: { elfSha256: e.programs[ACVP]?.elfSha256 ?? null, vkey: e.programs[ACVP]?.vkey ?? null },
  }));
  const cargoHomeOf = (paths: string[]) => {
    const m = uniq(paths.map((p) => (p.match(/^(.*\/\.cargo)\/registry\//) ?? [])[1]).filter(Boolean));
    return m.length === 1 ? (m[0] as string) : null;
  };
  const fromTd1 = ctx.remap.builds.map((b): IdentityEnvironment => ({
    id: `TD1-${b.id}`,
    hostId: ctx.remap.host.hostId,
    family: b.id === "P-remap" ? "repository-local-remapped" : "repository-local",
    image: null,
    platform: null,
    embeddedCargoHome: cargoHomeOf(b.embeddedRegistryPaths),
    manifestDigest: sourceManifestDigest(b.sourceManifest),
    withdrawal: {
      elfSha256: b.programs[WITHDRAWAL]?.elfSha256 ?? null,
      elfBytes: b.programs[WITHDRAWAL]?.elfBytes ?? null,
      vkey: b.programs[WITHDRAWAL]?.vkey ?? null,
    },
    acvp: { elfSha256: b.programs[ACVP]?.elfSha256 ?? null, vkey: b.programs[ACVP]?.vkey ?? null },
  }));
  return [...fromSp1P1, ...fromTd1];
}

export function deriveProgramIdentity(ctx: DecisionContext): ProgramIdentityVerdict {
  const sel = ctx.inputs.programIdentitySelection;
  const envs = identityEnvironments(ctx);
  const onDisk = sourceManifestDigest(ctx.workingTreeManifest);
  const img = ctx.image;
  const pinnedDigest = (img.pinnedIndex.reference.split("@")[1] ?? "").toLowerCase();
  const amd64 = img.pinnedIndex.manifests.find(
    (m) => m.platform?.os === "linux" && m.platform?.architecture === "amd64",
  );
  const indexDigestVerified =
    pinnedDigest.startsWith("sha256:") &&
    lower(img.pinnedIndex.bodySha256) === pinnedDigest &&
    lower(sel.canonicalProcedure.image) === lower(img.pinnedIndex.reference) &&
    !!amd64 &&
    lower(amd64.digest) === lower(img.linuxAmd64Manifest.digest) &&
    lower(img.linuxAmd64Manifest.bodySha256) === lower(img.linuxAmd64Manifest.digest);

  const families = uniq(envs.map((e) => e.family)).map((family): FamilyVerdict => {
    const fe = envs.filter((e) => e.family === family);
    const hosts = uniq(fe.map((e) => e.hostId));
    const elfs = uniq(fe.map((e) => e.withdrawal.elfSha256).filter((x): x is string => !!x));
    const vkeys = uniq(
      fe
        .map((e) => e.withdrawal.vkey)
        .filter((x): x is string => !!x)
        .map(lower),
    );
    const withImage = fe.filter((e) => e.image !== null);
    const imagesDigestPinned =
      withImage.length > 0 &&
      withImage.every(
        (e) => lower(e.image) === lower(img.pinnedIndex.reference) && e.platform === sel.canonicalProcedure.platform,
      );
    const manifests = fe.map((e) => e.manifestDigest).filter((x): x is string => !!x);
    const manifestsFresh = manifests.length > 0 && manifests.every((m) => m === onDisk);
    return {
      family,
      environments: fe.map((e) => e.id),
      hosts,
      withdrawalElfs: elfs,
      withdrawalVkeys: vkeys,
      embeddedCargoHomes: uniq(fe.map((e) => e.embeddedCargoHome ?? "unknown")),
      imagesDigestPinned,
      manifestsFresh,
      reproducedOnIndependentHosts:
        hosts.length >= sel.minimumIndependentHosts && elfs.length === 1 && vkeys.length === 1,
    };
  });

  // Contradictions: one ELF with two vkeys anywhere (builds or the cargo-prove cross-check), or a split family.
  const contradictions: string[] = [];
  const pairs = [
    ...envs
      .filter((e) => e.withdrawal.elfSha256 && e.withdrawal.vkey)
      .map((e) => [e.withdrawal.elfSha256!, lower(e.withdrawal.vkey), e.id]),
    ...(ctx.sp1p1Identity.crossChecks?.vkeyFromElf?.results ?? [])
      .filter((r) => r.program === WITHDRAWAL)
      .map((r) => [r.elfSha256, lower(r.vkey), `cross-check:${r.source}`]),
  ];
  for (const elf of uniq(pairs.map((p) => p[0]))) {
    const vks = uniq(pairs.filter((p) => p[0] === elf).map((p) => p[1]));
    if (vks.length > 1) contradictions.push(`ELF ${elf} maps to ${vks.length} vkeys (${vks.join(", ")})`);
  }
  for (const fam of families)
    if (fam.withdrawalElfs.length > 1 && fam.family !== "repository-local")
      contradictions.push(`family ${fam.family} produced ${fam.withdrawalElfs.length} withdrawal ELFs`);

  const scripts = ctx.inputs.evidence.canonicalProcedureScripts;
  const canonicalProcedureScriptsPreserved =
    scripts.length > 0 &&
    scripts.every((s) => ctx.fileHashes[s.path] === s.sha256) &&
    scripts.some((s) => s.path === sel.canonicalProcedure.entrypoint) &&
    scripts.some((s) => s.path === sel.canonicalProcedure.driver);
  const pinsMatch = Object.entries(ctx.sp1p1Receipt.subject.sp1Pins).every(
    ([k, v]) => sel.canonicalProcedure.sp1[k] === v && /^=\d+\.\d+\.\d+$/.test(v),
  );
  const circuitMatches = sel.canonicalProcedure.sp1.circuitVersion === ctx.sp1p1Receipt.subject.circuitVersion;

  const fam = (name: string) => families.find((f) => f.family === name);
  const candidates = sel.candidates.map((c) => {
    const f = fam(c.family);
    let established = false;
    let reason: string;
    if (!f) reason = `no observation of family ${c.family}`;
    else if (c.role.startsWith("cross-check")) {
      reason = "pre-registered as a cross-check only; never the canonical definition";
    } else if (!f.reproducedOnIndependentHosts) {
      reason = f.embeddedCargoHomes.some((h) => h.startsWith("/home/"))
        ? `one identity per builder: the ELF embeds the builder's own CARGO_HOME (${f.embeddedCargoHomes.join(", ")}), observed on ${f.hosts.length} host(s)`
        : `not one identity on >= ${sel.minimumIndependentHosts} independent hosts`;
    } else if (c.decisionValue === "PINNED_VENDOR_BUILD" && !(f.imagesDigestPinned && indexDigestVerified)) {
      reason = "the vendor image is not pinned by a verified content digest";
    } else if (!f.manifestsFresh) {
      reason = "the measured subject differs from the zkvm sources on disk";
    } else if (!canonicalProcedureScriptsPreserved) {
      reason = "the exact procedure scripts are not preserved with matching hashes";
    } else if (!pinsMatch || !circuitMatches) {
      reason = "the procedure's SP1 pins or circuit version disagree with the subject";
    } else if (contradictions.length > 0) {
      reason = `contradicting identity evidence: ${contradictions.join("; ")}`;
    } else {
      established = true;
      reason = `one ELF and vkey on ${f.hosts.length} independent hosts (${f.hosts.join(", ")}), digest-pinned, fresh subject`;
    }
    return {
      decisionValue: c.decisionValue as ProgramIdentityDecision,
      family: c.family,
      role: c.role,
      established,
      reason,
    };
  });
  // A cross-check candidate is never established above, so the first established candidate is canonical.
  const chosen = candidates.find((c) => c.established);
  return {
    environments: envs,
    families,
    contradictions,
    vendorImage: {
      reference: img.pinnedIndex.reference,
      indexDigestVerified,
      linuxAmd64Manifest: amd64?.digest ?? null,
      config: img.linuxAmd64Manifest.config?.digest ?? null,
      mutableTagCurrentlyResolvesToPin: lower(img.mutableTag.resolvesToDigest) === pinnedDigest,
    },
    canonicalProcedureScriptsPreserved,
    candidates,
    decision: chosen ? chosen.decisionValue : "UNRESOLVED",
  };
}

export interface VkeyDesignation {
  status: "DESIGNATED" | "NOT_DESIGNATED";
  program: string;
  procedure: string | null;
  image: string | null;
  subjectManifestSha256: string;
  zkvmGuestTree: string;
  zkvmHostTree: string;
  sp1: Record<string, string>;
  elfSha256: string | null;
  elfBytes: number | null;
  vkey: string | null;
  independentHosts: string[];
  environments: string[];
  crossCheck: { tool: string | null; agreeing: number; conflicting: number };
  reproducedOutsideVendorImage: boolean;
  doNotPin: { program: string; elfSha256: string | null; vkey: string | null }[];
  reason: string;
}

export function deriveDesignation(ctx: DecisionContext, pid: ProgramIdentityVerdict): VkeyDesignation {
  const sel = ctx.inputs.programIdentitySelection;
  const chosen = pid.candidates.find((c) => c.decisionValue === pid.decision);
  const fam = chosen ? pid.families.find((f) => f.family === chosen.family) : undefined;
  const envs = fam ? pid.environments.filter((e) => fam.environments.includes(e.id)) : [];
  const elfSha256 = fam?.withdrawalElfs.length === 1 ? fam.withdrawalElfs[0] : null;
  const vkey = fam?.withdrawalVkeys.length === 1 ? fam.withdrawalVkeys[0] : null;
  const elfBytes = uniq(envs.map((e) => e.withdrawal.elfBytes)).length === 1 ? envs[0].withdrawal.elfBytes : null;
  const xc = ctx.sp1p1Identity.crossChecks?.vkeyFromElf;
  const results = (xc?.results ?? []).filter((r) => r.program === WITHDRAWAL && r.elfSha256 === elfSha256);
  const agreeing = results.filter((r) => lower(r.vkey) === vkey).length;
  const conflicting = results.filter((r) => lower(r.vkey) !== vkey).length;
  const remapped = pid.environments.find((e) => e.family === "repository-local-remapped");
  const reproducedOutsideVendorImage =
    !!remapped &&
    remapped.withdrawal.elfSha256 === elfSha256 &&
    lower(remapped.withdrawal.vkey) === vkey &&
    elfSha256 !== null;
  const acvpElfs = uniq(envs.map((e) => e.acvp.elfSha256));
  const acvpVkeys = uniq(
    envs
      .map((e) => e.acvp.vkey)
      .filter((x): x is string => !!x)
      .map(lower),
  );
  // A resolved decision implies one ELF and one vkey in the chosen family, and a conflicting cross-check is a
  // contradiction that already unresolves it; what is left to require here is the outside link itself.
  let reason = "designated";
  let ok = pid.decision !== "UNRESOLVED";
  if (!ok) reason = "no established canonical procedure";
  else if (agreeing < 1) {
    ok = false;
    reason = `the vkey is not linked to the canonical ELF by an outside cross-check (agreeing ${agreeing}, conflicting ${conflicting})`;
  }
  return {
    status: ok ? "DESIGNATED" : "NOT_DESIGNATED",
    program: WITHDRAWAL,
    procedure: ok ? sel.canonicalProcedure.id : null,
    image: ok ? sel.canonicalProcedure.image : null,
    subjectManifestSha256: sourceManifestDigest(ctx.workingTreeManifest),
    zkvmGuestTree: ctx.inputs.subject.zkvmGuestTree,
    zkvmHostTree: ctx.inputs.subject.zkvmHostTree,
    sp1: sel.canonicalProcedure.sp1,
    elfSha256: ok ? elfSha256 : null,
    elfBytes: ok ? elfBytes : null,
    vkey: ok ? vkey : null,
    independentHosts: fam?.hosts ?? [],
    environments: fam?.environments ?? [],
    crossCheck: { tool: xc?.tool ?? null, agreeing, conflicting },
    reproducedOutsideVendorImage,
    doNotPin: [
      {
        program: ACVP,
        elfSha256: acvpElfs.length === 1 ? acvpElfs[0] : null,
        vkey: acvpVkeys.length === 1 ? acvpVkeys[0] : null,
      },
    ],
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

export interface Td1DecisionReceipt {
  schema: string;
  artifactType: string;
  lane: string;
  verdict: "DESIGN_DECIDED" | "PARTIAL_DECISION" | "STOP_NO_DESIGN_JUSTIFIED";
  generatedAt: string;
  subject: DecisionInputs["subject"] & { zkvmSourceManifestSha256: string };
  evidence: { files: FileRef[]; probeSuite: string };
  trustTarget: TrustTargetIdentity;
  gatewayPosture: GatewayPosture;
  options: OptionAuthority[];
  programIdentity: ProgramIdentityVerdict;
  upstreamTimeline: {
    advisory: RouteTimelineObservation["upstreamAdvisory"];
    advisedVersionRouteFrozenUtc: string | null;
    daysFromAdvisoryToFreeze: number | null;
  };
  decisions: {
    SP1_TRUST_TARGET_DECISION: TrustTargetDecision;
    SP1_TRUST_TARGET_OPTION: string | null;
    PROGRAM_IDENTITY_DECISION: ProgramIdentityDecision;
    AUTHORIZATION_AUTHORITY_DELTA: { baseline: string; removed: Lever[]; added: Lever[]; retained: Lever[] };
    LIVENESS_DEPENDENCY: { onChainExternal: Lever[]; removedVersusBaseline: Lever[]; offChain: string[] };
    UPGRADE_MODEL: "EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION" | "MUTABLE_ROUTING" | "UNRESOLVED";
    CROSS_CHAIN_MODEL: "CODE_HASH_PINNED_SAME_IDENTITY_ON_EVERY_CHAIN" | "PER_CHAIN_ROUTE_TABLE" | "UNRESOLVED";
    PROGRAM_VKEY_DESIGNATION: VkeyDesignation;
    IMPLEMENTATION_REQUIRED: { required: boolean; plan: string[] };
    REAL_PROOF_LANE_UNBLOCKED: { value: boolean; basis: string[]; preconditions: string[] };
  };
  claims: Record<Td1ClaimKey, Claim>;
  findings: FindingInput[];
  offChainLivenessDependencies: string[];
}

const TOP_KEYS = [
  "schema",
  "artifactType",
  "lane",
  "verdict",
  "generatedAt",
  "subject",
  "evidence",
  "trustTarget",
  "gatewayPosture",
  "options",
  "programIdentity",
  "upstreamTimeline",
  "decisions",
  "claims",
  "findings",
  "offChainLivenessDependencies",
];

const REAL_PROOF_PRECONDITIONS = [
  "the owner approves the v6.1.0 Groth16 circuit download (an owner gate, not a trust gate)",
  "the proof is generated for the designated ELF: its sha256 is checked against the designation before proving (a default local build embeds the builder's CARGO_HOME and yields a different program)",
  "verification targets the designated trust target only: the CREATE2-authenticated v6.1.0 bytes (in a local EVM) or a chain deployment checked by EXTCODEHASH, never a gateway route",
];

function sameLever(a: Lever, b: Lever) {
  return a.principal === b.principal && a.lever === b.lever;
}

export function buildDecisionReceipt(ctx: DecisionContext): Td1DecisionReceipt {
  const identity = deriveTrustTargetIdentity(ctx);
  const posture = deriveGatewayPosture(ctx);
  const options = ctx.inputs.options.map((o) => deriveOptionAuthority(o, ctx, identity, posture));
  const target = decideTrustTarget(options);
  const pid = deriveProgramIdentity(ctx);
  const designation = deriveDesignation(ctx, pid);
  const decided = options.find((o) => o.id === target.optionId) ?? null;
  const baseline = options.find((o) => o.decisionValue === "UPSTREAM_GATEWAY_OWNER_ACCEPTED");
  const ext = (ls: Lever[] | undefined) => (ls ?? []).filter((l) => !l.governed);

  const advisoryFreeze = ctx.timeline.events.find(
    (e) => e.chainId === 1 && e.event === "RouteFrozen" && e.version === "v6.0.0" && e.providersAgree,
  );
  const advisoryTs = Date.parse(`${ctx.timeline.upstreamAdvisory.published}T00:00:00Z`) / 1000;
  const lag = advisoryFreeze ? Math.floor((advisoryFreeze.timestamp - advisoryTs) / 86400) : null;

  const trustResolved = target.decision !== "UNRESOLVED";
  const programResolved = pid.decision !== "UNRESOLVED";
  // A decided option is viable, and viability requires an established code identity (which includes the circuit
  // check) and no external authorization lever; a DESIGNATED vkey implies a resolved program identity. The
  // receipt-level rules re-check each of these independently.
  const unblockBasis: string[] = [];
  if (decided)
    unblockBasis.push(`trust target ${target.decision} (option ${decided.id}) with established code identity`);
  if (designation.status === "DESIGNATED")
    unblockBasis.push(`PROGRAM_VKEY designated by ${pid.decision} (${designation.vkey})`);
  if (identity.circuitVersionMatchesSubject)
    unblockBasis.push(`circuit ${identity.version} matches the subject's SP1 pins`);
  const unblocked = !!decided && designation.status === "DESIGNATED";

  const st = (ok: boolean): ClaimStatus => (ok ? "ESTABLISHED" : "NOT_ESTABLISHED");
  const f = ctx.inputs.probeFacts;
  const equivalence =
    f.semantics.gatewayForwardsConsumerTupleUnchanged &&
    f.semantics.realProofAcceptedDirect &&
    f.semantics.realProofAcceptedViaGateway &&
    f.semantics.tamperedProofRejectedDirectAndViaGateway &&
    f.semantics.v610PreCheckRevertDataIdenticalDirectAndViaGateway &&
    f.semantics.unroutedSelectorRejectedDirectAndViaGateway &&
    ctx.fixture.templateComparison.nonConstantLinesSameMultiset;
  const gap = posture.routeHistoryIndexerGap;
  const claims: Record<Td1ClaimKey, Claim> = {
    TRUST_TARGET_CODE_IDENTITY: {
      status: st(identity.established),
      basis: identity.established
        ? `runtime ${identity.codeKeccak} on ${identity.chains.length} chains (two providers each), CREATE2-authenticated initcode, SP1-P1 own compile + Sourcify + VK join, no reachable state/code-changing opcode`
        : `not established: ${identity.failures.join("; ")}`,
    },
    DIRECT_AND_GATEWAY_VERIFICATION_EQUIVALENT: {
      status: st(equivalence),
      basis:
        "the gateway forwards the consumer's tuple unchanged; a real upstream v6 proof verifies directly and through it, tampering is rejected identically, v6.1.0 pre-checks revert identically; the v6.0.0 and v6.1.0 wrappers share every non-constant statement",
    },
    UNPINNED_GATEWAY_OWNER_CAN_WIDEN: {
      status: st(
        f.D_upstreamGatewayUnpinned.ownerAddRouteWidensAcceptedRelation &&
          f.D_upstreamGatewayUnpinned.ownerAddRouteDrainsPqOnlyVault,
      ),
      basis:
        "executed on the mainnet gateway bytes: after one addRoute by the owner, a forged journal drains a PqOnly WalletWallVault through the unmodified ZKMLDSAVerifier",
    },
    DECIDED_TARGET_HAS_NO_EXTERNAL_LEVER: {
      status: st(!!decided && ext(decided.widen).length === 0 && ext(decided.disable).length === 0),
      basis: decided
        ? `option ${decided.id}: external authorization levers ${ext(decided.widen).length}, external liveness levers ${ext(decided.disable).length}`
        : "no option decided",
    },
    CANONICAL_PROGRAM_IDENTITY: {
      status: st(programResolved),
      basis: pid.candidates.map((c) => `${c.decisionValue}: ${c.reason}`).join(" | "),
    },
    PROGRAM_VKEY_DESIGNATED: {
      status: st(designation.status === "DESIGNATED"),
      basis:
        designation.status === "DESIGNATED"
          ? `${designation.vkey} for ELF ${designation.elfSha256} (${designation.elfBytes} B) on ${designation.independentHosts.length} hosts; cargo-prove cross-check ${designation.crossCheck.agreeing} agreeing, ${designation.crossCheck.conflicting} conflicting`
          : designation.reason,
    },
    IDENTITY_REPRODUCED_OUTSIDE_VENDOR_IMAGE: {
      status: st(designation.reproducedOutsideVendorImage),
      basis:
        "a WSL build with a separately installed sp1up toolchain and only the vendor-supported --remap-path-prefix flag reproduced the designated ELF and vkey byte for byte (pre-registered; cross-check role only)",
    },
    VKEY_DERIVATION_ALGORITHM_INDEPENDENT: {
      status: "NOT_ESTABLISHED",
      basis:
        "every vkey here comes from Succinct's sp1-prover (mldsa65-host and two cargo-prove runs): binary- and machine-level independence only; a real proof verifying on the pinned verifier is the next join",
    },
    GATEWAY_ROUTE_HISTORY_COMPLETE: {
      status: "NOT_ESTABLISHED",
      basis: gap
        ? `the Sepolia RouteFrozen ${gap.selector} in tx ${gap.tx} is ${gap.missingFromSp1P1History ? "absent from" : "present in"} the SP1-P1 indexer history and the indexer ${gap.indexerHasLog ? "has" : "lacks"} its log; enumerating a mutable route table is not needed under a code-pinned target`
        : "not assessed",
    },
    REAL_SP1_PROOF_GENERATED: {
      status: "NOT_ESTABLISHED",
      basis: "out of scope for TD1: no circuit download, no prover run",
    },
    REAL_SP1_PROOF_VERIFIED: {
      status: "NOT_ESTABLISHED",
      basis:
        "no WalletWall proof exists; the only real proof exercised is upstream's v6 fixture, as a control for the verifier template",
    },
    PRODUCTION_READINESS: {
      status: "NOT_ESTABLISHED",
      basis: "design lane; unaudited prototype; implementation, real proof and audit outstanding",
    },
  };

  return {
    schema: TD1_RECEIPT_SCHEMA,
    artifactType: TD1_RECEIPT_ARTIFACT_TYPE,
    lane: ctx.inputs.lane,
    verdict:
      trustResolved && programResolved
        ? "DESIGN_DECIDED"
        : !trustResolved && !programResolved
          ? "STOP_NO_DESIGN_JUSTIFIED"
          : "PARTIAL_DECISION",
    generatedAt: TD1_RECEIPT_GENERATED_AT,
    subject: { ...ctx.inputs.subject, zkvmSourceManifestSha256: sourceManifestDigest(ctx.workingTreeManifest) },
    evidence: { files: evidenceFiles(ctx.inputs), probeSuite: ctx.inputs.evidence.probeSuite },
    trustTarget: identity,
    gatewayPosture: posture,
    options,
    programIdentity: pid,
    upstreamTimeline: {
      advisory: ctx.timeline.upstreamAdvisory,
      advisedVersionRouteFrozenUtc: advisoryFreeze?.utc ?? null,
      daysFromAdvisoryToFreeze: lag,
    },
    decisions: {
      SP1_TRUST_TARGET_DECISION: target.decision,
      SP1_TRUST_TARGET_OPTION: target.optionId,
      PROGRAM_IDENTITY_DECISION: pid.decision,
      AUTHORIZATION_AUTHORITY_DELTA: {
        baseline: baseline ? `option ${baseline.id} (${baseline.label})` : "none",
        removed: ext(baseline?.widen).filter((l) => !ext(decided?.widen).some((d) => sameLever(d, l))),
        added: ext(decided?.widen).filter((l) => !ext(baseline?.widen).some((b) => sameLever(b, l))),
        retained: (decided?.widen ?? []).filter((l) => l.governed),
      },
      LIVENESS_DEPENDENCY: {
        onChainExternal: ext(decided?.disable),
        removedVersusBaseline: ext(baseline?.disable).filter(
          (l) => !ext(decided?.disable).some((d) => sameLever(d, l)),
        ),
        offChain: ctx.inputs.offChainLivenessDependencies,
      },
      UPGRADE_MODEL: !decided
        ? "UNRESOLVED"
        : decided.requiresRedeployToUpgrade
          ? "EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION"
          : "MUTABLE_ROUTING",
      CROSS_CHAIN_MODEL: !decided
        ? "UNRESOLVED"
        : decided.routeRegistry
          ? "PER_CHAIN_ROUTE_TABLE"
          : identity.established
            ? "CODE_HASH_PINNED_SAME_IDENTITY_ON_EVERY_CHAIN"
            : "UNRESOLVED",
      PROGRAM_VKEY_DESIGNATION: designation,
      IMPLEMENTATION_REQUIRED: { required: true, plan: ctx.inputs.implementationPlan },
      REAL_PROOF_LANE_UNBLOCKED: { value: unblocked, basis: unblockBasis, preconditions: REAL_PROOF_PRECONDITIONS },
    },
    claims,
    findings: ctx.inputs.findings,
    offChainLivenessDependencies: ctx.inputs.offChainLivenessDependencies,
  };
}

function evidenceFiles(inputs: DecisionInputs): FileRef[] {
  return [
    inputs.evidence.sp1p1Receipt,
    ...inputs.evidence.sp1p1Observations,
    ...inputs.evidence.td1Observations,
    ...inputs.evidence.canonicalProcedureScripts.map(({ path, sha256 }) => ({ path, sha256 })),
  ];
}

// ---------------------------------------------------------------------------------------------------------
// Rules: what no receipt may claim, checked on the receipt alone
// ---------------------------------------------------------------------------------------------------------

export function validateDecisionRules(value: unknown): string[] {
  const errors: string[] = [];
  if (typeof value !== "object" || value === null || Array.isArray(value)) return ["receipt must be an object"];
  const r = value as Partial<Td1DecisionReceipt> & Record<string, unknown>;
  for (const k of Object.keys(r)) if (!TOP_KEYS.includes(k)) errors.push(`unknown top-level key ${k}`);
  for (const k of TOP_KEYS) if (!(k in r)) errors.push(`missing top-level key ${k}`);
  if (r.schema !== TD1_RECEIPT_SCHEMA) errors.push(`schema must be ${TD1_RECEIPT_SCHEMA}`);
  if (r.artifactType !== TD1_RECEIPT_ARTIFACT_TYPE) errors.push(`artifactType must be ${TD1_RECEIPT_ARTIFACT_TYPE}`);
  const d = r.decisions;
  const options = r.options;
  const tt = r.trustTarget;
  if (!d || !Array.isArray(options) || !tt) return [...errors, "decisions, options and trustTarget are required"];

  if (!(TRUST_TARGET_DECISIONS as readonly string[]).includes(d.SP1_TRUST_TARGET_DECISION))
    errors.push(`invalid SP1_TRUST_TARGET_DECISION ${String(d.SP1_TRUST_TARGET_DECISION)}`);
  if (!(PROGRAM_IDENTITY_DECISIONS as readonly string[]).includes(d.PROGRAM_IDENTITY_DECISION))
    errors.push(`invalid PROGRAM_IDENTITY_DECISION ${String(d.PROGRAM_IDENTITY_DECISION)}`);

  // Authorization and liveness are never conflated.
  for (const o of options) {
    for (const l of o.widen ?? []) {
      if (l.scope !== "authorization")
        errors.push(`option ${o.id}: widen lever ${l.lever} is not scoped authorization`);
      if ((LIVENESS_LEVERS as readonly string[]).includes(l.lever))
        errors.push(`option ${o.id}: ${l.lever} can only stop verification; it is not an authorization lever`);
    }
    for (const l of o.disable ?? []) {
      if (l.scope !== "liveness") errors.push(`option ${o.id}: disable lever ${l.lever} is not scoped liveness`);
      if ((AUTHORIZATION_LEVERS as readonly string[]).includes(l.lever))
        errors.push(`option ${o.id}: ${l.lever} widens the accepted relation; it cannot be classified liveness-only`);
    }
    if (o.routeRegistry !== (o.path ?? []).some((p) => /gateway/i.test(p)))
      errors.push(`option ${o.id}: routeRegistry disagrees with its accepted path`);
    const external = (o.widen ?? []).filter((l) => !l.governed).length;
    if (o.acceptedRelationMutableOutsideTimelock !== external > 0)
      errors.push(`option ${o.id}: acceptedRelationMutableOutsideTimelock disagrees with its authorization levers`);
    // A route registry the consumer does not fully pin is a mutable accepted relation.
    const fullyPinned = FULL_GATEWAY_PINS.every((p) => (o.pins ?? []).includes(p));
    if (o.routeRegistry && !fullyPinned && !o.acceptedRelationMutableOutsideTimelock)
      errors.push(`option ${o.id}: an owner-mutable route registry cannot be classified immutable`);
    if (o.routeRegistry && !fullyPinned && o.viable)
      errors.push(`option ${o.id}: an unpinned route registry cannot be viable`);
    if (o.viable && o.acceptedRelationMutableOutsideTimelock)
      errors.push(`option ${o.id}: an option with an external authorization lever cannot be viable`);
    if (o.viable !== (o.rejectedBecause === null)) errors.push(`option ${o.id}: viable and rejectedBecause disagree`);
  }

  const decided = options.find((o) => o.id === d.SP1_TRUST_TARGET_OPTION);
  if (d.SP1_TRUST_TARGET_DECISION === "UNRESOLVED") {
    if (d.SP1_TRUST_TARGET_OPTION !== null) errors.push("an UNRESOLVED trust target names no option");
  } else {
    if (!decided) errors.push("the trust-target decision names no evaluated option");
    else {
      if (decided.decisionValue !== d.SP1_TRUST_TARGET_DECISION)
        errors.push("the decided option's value differs from the decision");
      if (!decided.viable) errors.push(`the decided option ${decided.id} is not viable`);
      if (decided.acceptedRelationMutableOutsideTimelock)
        errors.push(`the decided option ${decided.id} leaves an external authorization lever`);
      const better = options.filter(
        (o) =>
          o.viable && o.disable.filter((l) => !l.governed).length < decided.disable.filter((l) => !l.governed).length,
      );
      if (better.length > 0)
        errors.push(
          `a viable option with fewer external liveness levers exists (${better.map((o) => o.id).join(", ")})`,
        );
    }
    if (!tt.established) errors.push("a trust target cannot be decided while its code identity is not established");
    if (d.SP1_TRUST_TARGET_DECISION === "DIRECT_IMMUTABLE_VERIFIER") {
      if (tt.runtime.forbiddenOpcodes.length > 0)
        errors.push("a direct immutable target cannot have reachable state- or code-changing opcodes");
      if (!tt.create2.authenticated) errors.push("a direct immutable target needs CREATE2-authenticated initcode");
      if (uniq(tt.chains.map((c) => c.codeKeccak)).length !== 1)
        errors.push("a direct immutable target needs one code hash on every chain");
      if (decided && decided.verifierCodeMutable)
        errors.push("a direct immutable target cannot have mutable verifier code");
    }
  }

  const dz = d.PROGRAM_VKEY_DESIGNATION;
  const pid = r.programIdentity;
  if (!dz || !pid) errors.push("PROGRAM_VKEY_DESIGNATION and programIdentity are required");
  else {
    if (d.PROGRAM_IDENTITY_DECISION !== "UNRESOLVED") {
      const cand = pid.candidates.find((c) => c.decisionValue === d.PROGRAM_IDENTITY_DECISION);
      if (!cand || !cand.established) errors.push("the program-identity decision names no established candidate");
      if (cand && cand.role.startsWith("cross-check"))
        errors.push("a cross-check procedure cannot define PROGRAM_VKEY");
      const fam = cand ? pid.families.find((f) => f.family === cand.family) : undefined;
      if (!fam || !fam.reproducedOnIndependentHosts)
        errors.push("a canonical program identity needs one identity on independent hosts");
      if (fam && fam.hosts.length < 2) errors.push("one-host reproducibility cannot define PROGRAM_VKEY");
      if (pid.contradictions.length > 0)
        errors.push("a canonical program identity cannot carry contradicting evidence");
      if (d.PROGRAM_IDENTITY_DECISION === "PINNED_VENDOR_BUILD") {
        if (!pid.vendorImage.indexDigestVerified)
          errors.push("the vendor build must be pinned by a verified image digest");
        if (!(dz.image ?? "").includes("@sha256:"))
          errors.push("the designation must reference the image by digest, never by tag");
      }
      if (dz.status !== "DESIGNATED") errors.push("a resolved program identity must designate PROGRAM_VKEY");
    } else if (dz.status === "DESIGNATED")
      errors.push("PROGRAM_VKEY cannot be designated while program identity is UNRESOLVED");
    if (dz.status === "DESIGNATED") {
      if (!dz.elfSha256 || !dz.vkey) errors.push("a designation needs the canonical ELF and its vkey");
      if (dz.crossCheck.agreeing < 1)
        errors.push("the designated vkey is not linked to the canonical ELF by an outside cross-check");
      if (dz.crossCheck.conflicting > 0)
        errors.push("an outside cross-check computed another vkey for the canonical ELF");
      const chosenFam = pid.families.find(
        (f) => f.family === pid.candidates.find((c) => c.decisionValue === d.PROGRAM_IDENTITY_DECISION)?.family,
      );
      if (chosenFam && (chosenFam.withdrawalElfs[0] !== dz.elfSha256 || chosenFam.withdrawalVkeys[0] !== dz.vkey))
        errors.push("the designated ELF/vkey is not the canonical family's identity");
      for (const f of pid.families)
        if (
          f.family !== chosenFam?.family &&
          f.withdrawalVkeys.includes(dz.vkey ?? "") &&
          f.family === "repository-local"
        )
          errors.push("the designated vkey is a builder-dependent local identity");
      if ((dz.doNotPin ?? []).some((x) => x.vkey === dz.vkey))
        errors.push("the designated vkey is a program a verifier must never pin");
    }
  }

  const unblock = d.REAL_PROOF_LANE_UNBLOCKED;
  if (unblock?.value === true) {
    if (d.SP1_TRUST_TARGET_DECISION === "UNRESOLVED")
      errors.push("the real-proof lane cannot be unblocked with an UNRESOLVED trust target");
    if (
      d.SP1_TRUST_TARGET_DECISION === "UPSTREAM_GATEWAY_OWNER_ACCEPTED" ||
      d.SP1_TRUST_TARGET_DECISION === "WALLETWALL_GOVERNED_GATEWAY"
    )
      errors.push("the real-proof lane cannot be unblocked on a mutable trust target");
    if (d.PROGRAM_IDENTITY_DECISION === "UNRESOLVED")
      errors.push("the real-proof lane cannot be unblocked without a canonical program identity");
    if (dz?.status !== "DESIGNATED")
      errors.push("the real-proof lane cannot be unblocked without a designated PROGRAM_VKEY");
    if (!tt.established)
      errors.push("the real-proof lane cannot be unblocked before the trust target's code identity is established");
    if (!tt.circuitVersionMatchesSubject)
      errors.push("the real-proof lane needs the target circuit to match the subject's SP1 version");
  }

  const claims = r.claims as Record<string, Claim> | undefined;
  if (!claims) errors.push("claims are required");
  else {
    for (const k of TD1_CLAIM_KEYS) {
      const c = claims[k];
      if (!c) errors.push(`missing claim ${k}`);
      else if (!(CLAIM_STATUSES as readonly string[]).includes(c.status)) errors.push(`claim ${k} has invalid status`);
    }
    for (const k of Object.keys(claims))
      if (!(TD1_CLAIM_KEYS as readonly string[]).includes(k)) errors.push(`unknown claim ${k}`);
    for (const k of [
      "REAL_SP1_PROOF_GENERATED",
      "REAL_SP1_PROOF_VERIFIED",
      "PRODUCTION_READINESS",
      "VKEY_DERIVATION_ALGORITHM_INDEPENDENT",
    ])
      if (claims[k]?.status !== "NOT_ESTABLISHED") errors.push(`${k} cannot be claimed by a design lane`);
    if (claims.TRUST_TARGET_CODE_IDENTITY?.status === "ESTABLISHED" && !tt.established)
      errors.push("TRUST_TARGET_CODE_IDENTITY cannot be ESTABLISHED without the evidence");
    if (claims.PROGRAM_VKEY_DESIGNATED?.status === "ESTABLISHED" && dz?.status !== "DESIGNATED")
      errors.push("PROGRAM_VKEY_DESIGNATED cannot be ESTABLISHED without a designation");
    if (claims.CANONICAL_PROGRAM_IDENTITY?.status === "ESTABLISHED" && d.PROGRAM_IDENTITY_DECISION === "UNRESOLVED")
      errors.push("CANONICAL_PROGRAM_IDENTITY cannot be ESTABLISHED while the decision is UNRESOLVED");
  }
  return errors;
}

// ---------------------------------------------------------------------------------------------------------
// Reading, freshness and the committed-receipt check
// ---------------------------------------------------------------------------------------------------------

export function readDecisionContext(repoRoot = "."): DecisionContext {
  const bytes = (rel: string) => readFileSync(resolve(repoRoot, rel));
  const json = <T>(rel: string) => JSON.parse(bytes(rel).toString("utf8")) as T;
  const inputs = json<DecisionInputs>(TD1_INPUTS_REL);
  const fileHashes: Record<string, string> = {};
  for (const f of evidenceFiles(inputs)) {
    try {
      fileHashes[f.path] = sha256Hex(bytes(f.path));
    } catch {
      fileHashes[f.path] = "missing";
    }
  }
  return {
    inputs,
    chain: json<ChainStateObservation>(TD1_OBSERVATIONS.chainState),
    deployments: json<DeploymentBytecodeObservation>(TD1_OBSERVATIONS.deploymentBytecode),
    remap: json<LocalRemapObservation>(TD1_OBSERVATIONS.localRemapBuild),
    timeline: json<RouteTimelineObservation>(TD1_OBSERVATIONS.routeTimeline),
    fixture: json<UpstreamFixtureObservation>(TD1_OBSERVATIONS.upstreamProofFixture),
    image: json<VendorImageObservation>(TD1_OBSERVATIONS.vendorImage),
    sp1p1Identity: json<ProgramIdentityObservations>(PROGRAM_IDENTITY_OBSERVATIONS_REL),
    sp1p1Gateway: json<VerifierGatewayObservations>(VERIFIER_GATEWAY_OBSERVATIONS_REL),
    sp1p1Receipt: json(SP1P1_RECEIPT_REL),
    fileHashes,
    workingTreeManifest: workingTreeSourceManifest(repoRoot),
  };
}

/** Refuses (rather than rebinding) when evidence bytes or the zkvm subject on disk moved. */
export function checkContextFresh(ctx: DecisionContext): string[] {
  const errors: string[] = [];
  for (const f of evidenceFiles(ctx.inputs))
    if (ctx.fileHashes[f.path] !== f.sha256)
      errors.push(`stale: ${f.path} on disk (${ctx.fileHashes[f.path]}) is not the recorded ${f.sha256}`);
  const onDisk = sourceManifestDigest(ctx.workingTreeManifest);
  if (onDisk !== ctx.sp1p1Receipt.subject.sourceManifestSha256)
    errors.push(
      `stale: the zkvm guest/host sources (${onDisk}) are not the subject the designation was measured on (${ctx.sp1p1Receipt.subject.sourceManifestSha256}); a guest change needs a new designation`,
    );
  const listed = ctx.inputs.evidence.td1Observations.map((o) => o.path).sort();
  const expected = Object.values(TD1_OBSERVATIONS).slice().sort();
  if (JSON.stringify(listed) !== JSON.stringify(expected))
    errors.push("decision inputs must list exactly the TD1 observation files");
  return errors;
}

export function validateCommittedDecisionReceipt(committed: unknown, ctx: DecisionContext): string[] {
  const errors = [...validateDecisionRules(committed), ...checkContextFresh(ctx)];
  if (JSON.stringify(committed) !== JSON.stringify(buildDecisionReceipt(ctx)))
    errors.push("committed decision receipt has drifted from the generator; run `npm run sp1-td1:receipt`");
  return errors;
}
