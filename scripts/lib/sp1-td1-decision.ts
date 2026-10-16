/**
 * SP1-TD1 decision receipt: which verifier WalletWall trusts for SP1 withdrawal proofs, and which build
 * procedure defines PROGRAM_VKEY.
 *
 * The receipt (evidence/zk/sp1-td1/decision-receipt.json) is a pure function of
 *   - evidence/zk/sp1-td1/decision-inputs.json: the options under evaluation, the procedure candidates, the
 *     open owner decisions, and `probeFacts` — outcomes test/Sp1Td1TrustTargetProbes.test.ts re-executes against
 *     the exact mainnet verifier and gateway bytes (the suite fails when an execution and a recorded fact
 *     disagree, and when an option's pins or components differ from the probe contracts that ran for it);
 *   - the TD1 raw observations (evidence/zk/sp1-td1/observations/*.raw.json): chain state on four chains via
 *     two providers each, CREATE2-authenticated deployment bytecode, per-chain execution verdicts, a real v6.1.0
 *     proof from mainnet, the vendor image's content digests, a route-event timeline, an upstream proof fixture,
 *     and a local build probe (whose committed inputs are bound to the hashes it recorded);
 *   - the SP1-P1 observations and receipt (evidence/zk/sp1-p1/), referenced by hash, never rewritten; and
 *   - the zkvm guest/host sources, in the working tree and as the trees HEAD records (the designation's subject).
 * Every decision, authority row, designation and claim status is DERIVED here; `validateCommittedDecisionReceipt`
 * re-derives the whole receipt and refuses drift, stale subjects and over-claims. `validateDecisionRules` checks,
 * on the receipt alone, the invariants a hand edit could break in the decisions, option viability, lever classes
 * (scope, protective freezes), the models, the owner decision, the real-proof preconditions and the claims it
 * names. It cannot re-run a probe: a self-consistent edit of derived facts (an option's pins, the equivalence and
 * widening claims, the authority delta) is caught only by re-derivation, and the findings and the plan are authored
 * inputs, reviewed rather than derived.
 *
 * Authorization and liveness are kept apart throughout: a lever that can make a previously REJECTED proof
 * accepted is an authorization lever ("widen"); one that can only make a previously ACCEPTED proof rejected is
 * a liveness lever ("disable"). They are never summed into one score. A liveness lever is also marked when it
 * would protect against a defect in the verifier itself (a freeze stops forged proofs too); that trade-off is
 * the owner's decision, recorded open or decided, never netted against authorization.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AbiCoder, Interface, concat, getBytes, hexlify } from "ethers";

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
  chainExecution: "evidence/zk/sp1-td1/observations/chain-execution.raw.json",
  chainState: "evidence/zk/sp1-td1/observations/chain-state.raw.json",
  deploymentBytecode: "evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json",
  localRemapBuild: "evidence/zk/sp1-td1/observations/local-remap-build.raw.json",
  mainnetV610Proof: "evidence/zk/sp1-td1/observations/mainnet-v610-proof.raw.json",
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
  "PINNED_VERIFYING_KEY_REAL_PROOF",
  "DIRECT_AND_GATEWAY_VERIFICATION_EQUIVALENT",
  "UNPINNED_GATEWAY_OWNER_CAN_WIDEN",
  "DECIDED_TARGET_HAS_NO_EXTERNAL_LEVER",
  "CANONICAL_PROGRAM_IDENTITY",
  "PROGRAM_VKEY_DESIGNATED",
  "IDENTITY_REPRODUCED_OUTSIDE_VENDOR_IMAGE",
  "VKEY_DERIVATION_ALGORITHM_INDEPENDENT",
  "GATEWAY_ROUTE_HISTORY_COMPLETE",
  "DEFECT_RESPONSE_PATH",
  "REAL_SP1_PROOF_GENERATED",
  "REAL_SP1_PROOF_VERIFIED",
  "PRODUCTION_READINESS",
] as const;
export type Td1ClaimKey = (typeof TD1_CLAIM_KEYS)[number];

/** CROSS_CHAIN_MODEL values: a code hash is necessary but not sufficient, so the direct model carries a per-chain check. */
export const CROSS_CHAIN_MODELS = [
  "CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK",
  "PER_CHAIN_ROUTE_TABLE",
  "UNRESOLVED",
] as const;
/**
 * What every chain must answer, set here rather than read from the observation (which must not grade itself): a real
 * proof verifies, its tampered copy does not, and the odd-word canary does not (it verifies wherever the pairing
 * precompile is missing), on the v6.1.0 bytes and on the v6.0.0 template.
 */
export const REQUIRED_CHAIN_VERDICTS: Record<string, string> = {
  v610RealProof: "success",
  v610TamperedPublicValues: "revert ProofInvalid",
  v610OddWordCanary: "revert ProofInvalid",
  v600RealProof: "success",
  v600TamperedPublicValues: "revert ProofInvalid",
};
/**
 * Beneath every option: each chain's own governance (its precompile semantics; on an L2, its upgrade keys) can change
 * what any deployed code accepts. No pin can see it and no option avoids it, so it does not separate the options; it
 * is stated wherever a claim says "no external principal" (TD1-N8).
 */
export const INHERITED_BY_EVERY_OPTION =
  "each chain's own governance (precompile semantics; on an L2, its upgrade keys) — inherited by every option, invisible to any pin; the per-chain execution check must be repeated after a chain changes its precompiles (TD1-N8)";
/** The defect response the owner decided (2026-10-15), and the only mechanism it admits. */
export const DECIDED_DEFECT_RESPONSE = "WALLETWALL_DETECT_AND_FAIL_CLOSED";
export const LOCAL_ONE_WAY_VERIFIER_HALT = "LOCAL_ONE_WAY_VERIFIER_HALT";
export const NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION = "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION";
/** The owner's amendment (2026-10-15): until every consumer can recover, recovery is claimed only where the halt applies. */
export const NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE =
  "NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE";
/** A widening capability given to a principal that already exists is new authority all the same. */
export const NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL =
  "NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL";
/** The common halt, frozen for TD2 beside the recovery gate of each consumer the halt cannot reach yet. */
export const TD2_COMMON_VERIFIER_HALT = "TD2-COMMON-VERIFIER-HALT";
/** The owner's name for the multisig vault's recovery gate, and the consumer it is for (TD1-N11). */
export const TD2_MULTISIG_ROTATION = "TD2-MULTISIG-ROTATION";
const MULTISIG_VAULT = "WalletWallMultiSigVault";
/** What the common halt must prove in TD2: the owner's three, and what the review added (exclusion, identity, transfer). */
export const COMMON_HALT_PROOFS = [
  "VALID_VERIFICATION_WHILE_ACTIVE",
  "FAILS_CLOSED_AFTER_HALT_THROUGH_EVERY_CONSUMER_IN_SCOPE",
  "HALT_PRINCIPAL_CANNOT_MAKE_AN_INVALID_PROOF_VALID",
  "HALT_PRINCIPAL_CANNOT_ROTATE_EVEN_AFTER_AN_OWNERSHIP_TRANSFER",
  "HALTED_IDENTITY_REFUSED_AS_A_RECOVERY_TARGET",
  "EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER",
];
/** What a consumer's recovery gate must prove before the halt may reach that consumer. */
export const RECOVERY_GATE_PROOFS = [
  "HALTED_THEN_ROTATED_WITHDRAWAL_SUCCEEDS",
  "MALICIOUS_REPLACEMENT_BLOCKED_OUTSIDE_DELAYED_PATH",
  "HALT_PRINCIPAL_CANNOT_ROTATE_EVEN_AFTER_AN_OWNERSHIP_TRANSFER",
  "HALTED_IDENTITY_REFUSED_AS_A_ROTATION_TARGET",
];
/** A gate's stop condition, structured: on an unacceptable cut it stops and returns to design, never weakens the halt. */
export const GATE_STOP_CONDITION = {
  when: "UNACCEPTABLE_AUTHORIZATION_CUT",
  then: "STOP_AND_RETURN_TO_DESIGN",
  never: "WEAKEN_THE_ONE_WAY_HALT",
};
/** Recovery is to an independently established identity: a fresh deployment of the halted one is not. */
export const RECOVERY_IDENTITY = "INDEPENDENTLY_ESTABLISHED_NEVER_THE_HALTED_ONE";
/** Until its gate, a consumer kept outside the halt is bound to no part of the SP1 path (another interim is the owner's). */
export const EXCLUDED_INTERIM = "NOT_BOUND_TO_THE_SP1_PATH";
/** The principals the amendment accounts for, in order. */
const ACCOUNTING_KEYS = ["haltPrincipal", "vaultOwnerToday", "multisigOwnerToday", "proposedMultisigRotation"];
/** What the vault owner holds with respect to verification: the retained rotation and a reversible pause. */
const VAULT_OWNER_CAPABILITIES = ["PQ_VERIFIER_ROTATION", "pause", "unpause"];
/** The routes by which a consumer leaves a halted wrapper; anything else is no route. */
const RECOVERING_ROUTES = ["OWN_TIMELOCKED_ROTATION", "ITS_CONSUMERS_TIMELOCKED_ROTATION"];
/** Powers that would change what verifies. A halt principal holds none of them; holding one is authority. */
export const WIDENING_POWERS = [
  "WIDEN_ACCEPTED_RELATION",
  "ADD_ROUTE",
  "CHANGE_SP1_VERIFIER",
  "CHANGE_PROGRAM_VKEY",
  "SELECT_VERIFIER",
  "BYPASS_VERIFICATION",
  // After its delay, a rotation can point a consumer at any verifier, an accept-all one included.
  "PQ_VERIFIER_ROTATION",
];
/** The onlyOwner functions the multisig vault's owner may hold while it is accounted liveness-only. */
const LIVENESS_OWNER_FUNCTIONS = ["pause", "unpause"];
/** The only reachable environment read the pinned runtime may make (its self-call's code check). */
const ALLOWED_RUNTIME_READS = ["EXTCODESIZE"];
/** Precompiles a Groth16 BN254 verifier may call at a constant address: modexp, ecAdd, ecMul, pairing. */
const ALLOWED_CONSTANT_CALL_TARGETS = ["0x05", "0x06", "0x07", "0x08"];

/** Pins that, together with write-once routes, take the gateway owner's addRoute out of the accepted path. */
export const FULL_GATEWAY_PINS = ["selector", "routeVerifier", "gatewayCode", "verifierCode"] as const;
/** Pins that make an upstream freeze bit the pinned verifier's own route (so freezing it protects). */
export const FREEZE_COUPLING_PINS = ["selector", "routeVerifier", "gatewayCode"] as const;
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
/** The first v6.1.0 build's selector (wrong VERIFIER_HASH/VK_ROOT): routed on Sepolia, then frozen. */
const BROKEN_V610_SELECTOR = "0x2b4aeaf7";
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
  components: ("sp1Verifier" | "upstreamGateway" | "walletwallGateway" | "upstreamFreezeBit")[];
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
    realV610ProofAcceptedDirect: boolean;
    realV610ProofAcceptedViaGateway: boolean;
    realV610TamperedRejectedDirectAndViaGateway: boolean;
    /** The canary's positive control: refused by the pinned code, accepted by it once the pairing call is empty. */
    oddWordCanaryRefusedByPinnedCode: boolean;
    oddWordCanaryAcceptedWithoutPairingPrecompile: boolean;
  };
  verifierRuntime: {
    v610ForbiddenOpcodes: string[];
    gatewayHasSstore: boolean;
    v610ReachableEnvironmentReads: Record<string, number>;
    v610StaticcallSites: { constantPrecompile: number; computedTarget: number };
    v610ConstantStaticcallTargets: string[];
    v610MetadataIsSolcCbor: boolean;
  };
  /** Every contract that verifies through an IPQCVerifier, and how each can replace its verifier (source scan). */
  verifierConsumers: {
    pqVerifierConsumers: string[];
    consumersWithTimelockedRotation: string[];
    consumersFollowingTheirConsumer: string[];
    consumersWithFixedVerifier: string[];
    /** The contracts the policy bridge can read a verifier from (they declare policyControlEpoch): it recovers with them. */
    bridgeCredentialSources: string[];
    /** The onlyOwner functions WalletWallMultiSigVault declares: its owner's powers beyond handing over ownership. */
    multisigOwnerOnlyFunctions: string[];
    /** Each rotating consumer's PQ_VERIFIER_UPDATE_DELAY, in seconds. */
    rotationDelaySeconds: Record<string, number>;
  };
  AF_directFreezeCoupled: {
    squattedRouteRejectedAtConstruction: boolean;
    realProofAcceptedThroughCoupling: boolean;
    upstreamFreezeFailsClosed: boolean;
    otherSelectorRouteGrantsNothing: boolean;
  };
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
    canonicalProcedureScripts: (FileRef & { sourceCommit: string | null; sourcePath: string; provenance?: string })[];
    /** Committed measurement inputs, each bound (RFC 6901 pointer) to the hash an observation recorded for it. */
    measurementFiles: (FileRef & { boundTo: { observation: string; pointer: string } })[];
    measurementScriptsNotCommitted: { reason: string; scripts: string[] };
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
  ownerDecisions: OwnerDecisionInput[];
}

/** A trade-off the evidence frames but cannot settle: open until the owner decides, then recorded as decided. */
export interface OwnerDecisionInput {
  id: string;
  question: string;
  /** Each choice names the evaluated options that realize it. */
  choices: { id: string; options: string[]; description: string }[];
  recommendation: string;
  rationale: string;
  requiredBeforeRealValue: boolean;
  /** Only the owner settles it; a lane records the owner's decision, never its own. */
  status: "OWNER_DECISION_REQUIRED" | "DECIDED";
  decision?: string;
  mechanism?: string;
  decidedBy?: string;
  decidedOn?: string;
  haltDesign?: HaltDesign;
  /** Amendments to the decision, each attributed: the owner's words, not the lane's. */
  amendments?: { id: string; by: string; on: string; summary: string }[];
  /** The owner's amendment: the halt principal, the vault owners, and the rotation proposed for the multisig vault. */
  authorityAccounting?: AuthorityAccounting;
  /** What TD1 freezes for TD2 to build; TD1 builds none of it. */
  td2Requirements?: Td2Requirement[];
}

/**
 * The owner's refinement of WALLETWALL_DETECT_AND_FAIL_CLOSED: a local circuit breaker at the verifier wrapper,
 * ACTIVE -> HALTED only, held by a principal that can do nothing but halt. Frozen here; built in TD2.
 */
export interface HaltDesign {
  location: string;
  states: string[];
  initialState: string;
  transitions: { from: string; to: string; trigger: string }[];
  haltPrincipal: { id: string; powers: string[]; selection: string };
  wrapperIdentity: { sp1Verifier: string; programVKey: string };
  /** What recovery may rotate to: an independently established identity, never a fresh deployment of the halted one. */
  recoveryIdentity: string;
  /**
   * Where the halt applies: only to consumers that can leave a halted wrapper. A consumer that cannot stays off any
   * haltable wrapper until its own TD2 gate gives it a delayed verifier rotation (TD1-N11), bound meanwhile to no part
   * of the SP1 path.
   */
  haltScope: { applies: string[]; excludedUntilRecoverable: { consumer: string; gate: string; interim: string }[] };
  detectionSignals: string[];
  detectionSignalsControlState: boolean;
  recovery: string;
  td2Tests: string[];
}

/** One principal's power over verification, accounted on its own: what it holds, and whether that can widen. */
export interface AccountedAuthority {
  principal: string;
  capabilities: string[];
  scope: "authorization" | "liveness";
  widensAuthorization: boolean;
  classification?: string;
  status?: string;
  requires?: string[];
  note?: string;
}

export interface AuthorityAccounting {
  haltPrincipal: AccountedAuthority;
  /** The WalletWallVault and StablecoinVaultSimulator owner, whose timelocked rotation the decision retains. */
  vaultOwnerToday: AccountedAuthority;
  multisigOwnerToday: AccountedAuthority;
  proposedMultisigRotation: AccountedAuthority;
}

/**
 * A requirement TD1 freezes for TD2. A consumer's recovery gate names its consumer and carries its delayed rotation's
 * invariants; the owner's items are kept as given, and what review added is recorded apart.
 */
export interface Td2Requirement {
  id: string;
  status: string;
  summary: string;
  consumer?: string;
  excludedConsumersRefusedAHaltableWrapper?: string[];
  items?: string[];
  reviewAdditions?: string[];
  invariants?: {
    minimumDelaySeconds: number;
    instantReplacement: boolean;
    invokableByHaltPrincipal: boolean;
    targetMustPassEvidenceGates: boolean;
    oldWrapperUnhalt: boolean;
  };
  executableProofs?: string[];
  stopCondition?: { when: string; then: string; never: string; text: string };
}

/** How one consumer leaves a halted wrapper, and whether the halt applies to it yet. */
export interface ConsumerRecovery {
  consumer: string;
  /** Its own timelocked pqVerifier rotation, the rotation of the consumers it follows (the policy bridge), or none. */
  route: "OWN_TIMELOCKED_ROTATION" | "ITS_CONSUMERS_TIMELOCKED_ROTATION" | "NONE";
  /** Its own rotation's delay (OWN_TIMELOCKED_ROTATION only). */
  rotationDelaySeconds: number | null;
  halt: "APPLIED" | "EXCLUDED_UNTIL_RECOVERABLE" | "UNSCOPED";
  gate: string | null;
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

/** eth_call verdicts of the deployed verifier template on each chain, through two providers. */
export interface ChainExecutionObservation {
  proofSource: { observation: string; transaction: string };
  /** The exact calldata sent to every provider on every chain. */
  calls: Record<string, { to: string; data: string; dataSha256: string }>;
  chains: Record<string, { block: number; providersAgree: boolean; verdicts: Record<string, string> }>;
}

/** A real v6.1.0 proof taken from a successful mainnet call into the pinned verifier. */
export interface MainnetProofObservation {
  source: { chainId: number; transaction: string; transactionOnBothProviders: boolean; receiptStatus: number | null };
  call: { programVKey: string; publicValues: string; proofBytes: string };
  decoded: { proofSelector: string; exitCode: string; vkRoot: string };
}

export interface DecisionContext {
  inputs: DecisionInputs;
  chainExec: ChainExecutionObservation;
  mainnetProof: MainnetProofObservation;
  /** `git rev-parse HEAD:zkvm/guest` / `HEAD:zkvm/host` of the checkout being validated (null: unreadable). */
  gitTrees: { guest: string | null; host: string | null };
  /** For each measurement file, the hash its bound observation recorded (null: the pointer resolves to nothing). */
  boundHashes: Record<string, string | null>;
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
  runtime: {
    forbiddenOpcodes: string[];
    probeBytesEqualMainnet: boolean;
    reachableEnvironmentReads: Record<string, number>;
    constantCallTargets: string[];
    computedCallTargets: number;
    metadataIsSolcCbor: boolean;
  };
  /** Same code is the same relation only if each chain's precompiles give the same verdicts. */
  chainExecution: { chainId: string; block: number; providersAgree: boolean; verdictsAsExpected: boolean }[];
  /** The calls behind those verdicts are the ones this receipt names (rebuilt and compared byte for byte). */
  chainCallsBound: boolean;
  /** The canary is shown to pass where the pairing precompile is missing, and to fail on the pinned code. */
  canaryHasPositiveControl: boolean;
  /** A real proof for this circuit, verified on the pinned bytes (a third party's program, not WalletWall's). */
  realProofOnPinnedKey: { transaction: string; programVKey: string; verifiedInProbe: boolean; established: boolean };
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

  const rt = ctx.inputs.probeFacts.verifierRuntime;
  const forbidden = rt.v610ForbiddenOpcodes;
  const probeBytesEqualMainnet = ctx.inputs.probeFacts.bytes.v610RuntimeEqualsMainnet === true;
  if (forbidden.length > 0)
    failures.push(`the verifier runtime has reachable ${forbidden.join("/")}: it is not immutable`);
  if (!probeBytesEqualMainnet) failures.push("the probe suite did not run the mainnet verifier bytes");
  // A verdict may depend only on the call's inputs: no reachable read of state or environment beyond the
  // self-call's code check, and every constant call target a BN254/modexp precompile.
  const extraReads = Object.keys(rt.v610ReachableEnvironmentReads).filter((r) => !ALLOWED_RUNTIME_READS.includes(r));
  if (extraReads.length > 0)
    failures.push(`the verifier runtime reads ${extraReads.join("/")}: its verdict could depend on mutable state`);
  const extraTargets = rt.v610ConstantStaticcallTargets.filter((t) => !ALLOWED_CONSTANT_CALL_TARGETS.includes(t));
  if (extraTargets.length > 0)
    failures.push(`the verifier runtime calls ${extraTargets.join("/")}, which is not a BN254/modexp precompile`);
  if (!rt.v610MetadataIsSolcCbor)
    failures.push("the runtime's trailing metadata is not solc's CBOR: the scan may miss code");

  // The pinned key itself, exercised by a real proof (a third party's program; it verifies by itself).
  const mp = ctx.mainnetProof;
  const semantics = ctx.inputs.probeFacts.semantics;
  const verifiedInProbe =
    semantics.realV610ProofAcceptedDirect === true && semantics.realV610TamperedRejectedDirectAndViaGateway === true;
  const realProofEstablished =
    verifiedInProbe &&
    lower(mp.decoded.proofSelector) === lower(sel.selector) &&
    mp.decoded.exitCode === "0" &&
    roots.length === 1 &&
    lower(mp.decoded.vkRoot) === roots[0] &&
    mp.source.receiptStatus === 1 &&
    mp.source.transactionOnBothProviders === true;
  if (!realProofEstablished)
    failures.push(
      "no real proof for this circuit is shown to verify on the pinned bytes (selector, vk root, source or probe)",
    );
  const circuitVersionMatchesSubject = ctx.sp1p1Receipt.subject.circuitVersion === sel.version;
  if (!circuitVersionMatchesSubject)
    failures.push(`the subject's SP1 circuit (${ctx.sp1p1Receipt.subject.circuitVersion}) is not the target version`);

  // The real proof exercises the v6.0.0 deployment of the shared template, so it speaks for v6.1.0 only while the
  // two wrappers carry the same non-constant statements.
  if (!ctx.fixture.templateComparison.nonConstantLinesSameMultiset)
    failures.push(
      "the v6.0.0 and v6.1.0 wrappers no longer share their statements: the chain-execution control does not transfer",
    );
  // The per-chain verdicts are evidence only for the calls this receipt names: every calldata is rebuilt from the
  // real proofs and the canary recipe and compared with what was sent, and the source proof is this receipt's.
  const rebuilt = expectedChainCalls(ctx);
  const chainCallsBound =
    lower(ctx.chainExec.proofSource?.transaction) === lower(mp.source.transaction) &&
    ctx.chainExec.proofSource?.observation === TD1_OBSERVATIONS.mainnetV610Proof.split("/").pop() &&
    Object.entries(rebuilt).every(([k, c]) => {
      const sent = ctx.chainExec.calls?.[k];
      return !!sent && sameAddress(sent.to, c.to) && lower(sent.data) === lower(c.data);
    });
  if (!chainCallsBound)
    failures.push("the per-chain calls are not the real proofs, tampered copies and canary this receipt names");
  // The canary detects a missing pairing precompile only if it is shown to: refused by the pinned code, accepted by
  // the same code whose pairing calls reach an empty account.
  const canaryHasPositiveControl =
    semantics.oddWordCanaryRefusedByPinnedCode === true &&
    semantics.oddWordCanaryAcceptedWithoutPairingPrecompile === true;
  if (!canaryHasPositiveControl)
    failures.push("the odd-word canary has no positive control: it cannot show a missing pairing precompile");
  const chainExecution = sel.requiredChains.map((id) => {
    const e = ctx.chainExec.chains[id];
    const verdictsAsExpected = !!e && Object.entries(REQUIRED_CHAIN_VERDICTS).every(([k, v]) => e.verdicts[k] === v);
    const providersAgree = !!e && e.providersAgree === true;
    if (!e) failures.push(`chain ${id}: the verifier template was not executed there`);
    else {
      if (!providersAgree) failures.push(`chain ${id}: the providers disagree on the verifier's verdicts`);
      if (!verdictsAsExpected) failures.push(`chain ${id}: the verifier template does not give the expected verdicts`);
    }
    return { chainId: id, block: e?.block ?? 0, providersAgree, verdictsAsExpected };
  });

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
    runtime: {
      forbiddenOpcodes: [...forbidden],
      probeBytesEqualMainnet,
      reachableEnvironmentReads: { ...rt.v610ReachableEnvironmentReads },
      constantCallTargets: [...rt.v610ConstantStaticcallTargets],
      computedCallTargets: rt.v610StaticcallSites.computedTarget,
      metadataIsSolcCbor: rt.v610MetadataIsSolcCbor,
    },
    chainExecution,
    chainCallsBound,
    canaryHasPositiveControl,
    realProofOnPinnedKey: {
      transaction: mp.source.transaction,
      programVKey: mp.call.programVKey,
      verifiedInProbe,
      established: realProofEstablished,
    },
    circuitVersionMatchesSubject,
    established: failures.length === 0,
    failures,
  };
}

const VERIFY_PROOF = new Interface(["function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes)"]);
const flipLastBit = (hex: string) => {
  const b = getBytes(hex);
  b[b.length - 1] ^= 1;
  return hexlify(b);
};

/**
 * The calls the per-chain check must have sent, rebuilt from the real proofs: the mainnet v6.1.0 proof and its
 * tampered copy on the pinned verifier, the odd-word canary (v6.1.0's selector, exit code 0, the vk root, nonce 0,
 * eight proof words of 1), and upstream's v6.0.0 fixture and its tampered copy on the CREATE2-authenticated template.
 */
export function expectedChainCalls(ctx: DecisionContext): Record<string, { to: string; data: string }> {
  const p = ctx.mainnetProof.call;
  const fx = ctx.fixture.fixture;
  const v610 = ctx.inputs.trustTargetSelection.verifier;
  const v600 = ctx.deployments.deployments["v6.0.0"]?.create2Derived ?? "";
  const canary = concat([
    ctx.inputs.trustTargetSelection.selector,
    AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256", "uint256[8]"],
      [0n, ctx.mainnetProof.decoded.vkRoot, 0n, Array(8).fill(1n)],
    ),
  ]);
  const call = (vkey: string, publicValues: string, proofBytes: string) =>
    VERIFY_PROOF.encodeFunctionData("verifyProof", [vkey, publicValues, proofBytes]);
  return {
    v610RealProof: { to: v610, data: call(p.programVKey, p.publicValues, p.proofBytes) },
    v610TamperedPublicValues: { to: v610, data: call(p.programVKey, flipLastBit(p.publicValues), p.proofBytes) },
    v610OddWordCanary: { to: v610, data: call(p.programVKey, p.publicValues, canary) },
    v600RealProof: { to: v600, data: call(fx.programVKey, fx.publicValues, fx.proofBytes) },
    v600TamperedPublicValues: { to: v600, data: call(fx.programVKey, flipLastBit(fx.publicValues), fx.proofBytes) },
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
  /**
   * A liveness lever is dual-use: it stops valid proofs, and when the verifier itself is unsound it also stops
   * forged ones. Recorded on the lever so the trade-off is visible, never folded into an authorization score;
   * always false on an authorization lever.
   */
  protectiveOnVerifierDefect: boolean;
}

/** WalletWall's own fail-closed lever, present under every option: the vault owner's pause(). */
const WALLETWALL_PAUSE =
  "WalletWall's own pauses, one per consumer of the verifier: each WalletWallVault, WalletWallMultiSigVault and StablecoinVaultSimulator deployment's owner-held pause() (gating its PQ-verifying entrypoints) and the PolicyControlBridge's one-way pause() (EMERGENCY_PAUSER) — liveness only; manual, several holders";

export interface OptionAuthority {
  id: string;
  decisionValue: Exclude<TrustTargetDecision, "UNRESOLVED">;
  label: string;
  path: string[];
  /** The contracts in (or read by) the accepted path, as the probe suite deployed them. */
  components: OptionInput["components"];
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
  /** Who can make verification fail closed if the pinned verifier proves unsound, in the order they can act. */
  defectResponse: string[];
  viable: boolean;
  rejectedBecause: string | null;
}

function gatewayOwnerLevers(
  posture: GatewayPosture,
  lever: string,
  scope: Lever["scope"],
  protectiveOnVerifierDefect: boolean,
): Lever[] {
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
    protectiveOnVerifierDefect,
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
      protectiveOnVerifierDefect: false,
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
            protectiveOnVerifierDefect: false,
          });
      } else {
        if (f.D_upstreamGatewayUnpinned.ownerAddRouteWidensAcceptedRelation)
          widen.push(...gatewayOwnerLevers(posture, "addRoute", "authorization", false));
        if (adder)
          widen.push({
            principal: adder,
            lever: "addRoute",
            scope: "authorization",
            chains: measuredChains,
            delaySeconds: 0,
            governed: false,
            protectiveOnVerifierDefect: false,
          });
      }
    }
    const freezeStops = fullyPinned
      ? f.B_selectorRouteCodePinned.ownerFreezeRejectsValidProof
      : f.D_upstreamGatewayUnpinned.ownerFreezeRejectsValidProof;
    if (freezeStops) disable.push(...gatewayOwnerLevers(posture, "freezeRoute", "liveness", true));
  }
  if (has("upstreamFreezeBit")) {
    // A read-only coupling: the gateway routes nothing here, so its owner cannot widen; its freeze of the pinned
    // selector makes verification fail closed (executed). Without the route pin the bit might belong to a route
    // that is not the pinned verifier's, and the coupling would protect nothing.
    const couplingHolds =
      FREEZE_COUPLING_PINS.every((p) => pinned(p)) &&
      f.AF_directFreezeCoupled.squattedRouteRejectedAtConstruction === true &&
      f.AF_directFreezeCoupled.otherSelectorRouteGrantsNothing === true;
    if (f.AF_directFreezeCoupled.upstreamFreezeFailsClosed)
      disable.push(...gatewayOwnerLevers(posture, "freezeRoute", "liveness", couplingHolds));
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
        protectiveOnVerifierDefect: false,
      });
    disable.push({
      principal: "WalletWall gateway admin",
      lever: "gatewayAdminFreezeRoute",
      scope: "liveness",
      chains: ["every chain the WalletWall gateway is deployed to"],
      delaySeconds: 0,
      governed: false,
      protectiveOnVerifierDefect: true,
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
      protectiveOnVerifierDefect: false,
    });

  const routeRegistry = has("upstreamGateway") || has("walletwallGateway");
  // Routing through the upstream gateway or reading its freeze bit both depend on its code and its owner.
  const readsUpstreamGateway = has("upstreamGateway") || has("upstreamFreezeBit");
  const gatewayCodeMutable = readsUpstreamGateway
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
    (!readsUpstreamGateway || f.bytes.gatewayRuntimeEqualsMainnet);

  const extraLive = posture.chains.filter((c) => c.extraLiveRoutes.length > 0);
  const ownerKinds = uniq(posture.chains.map((c) => `${c.chainId}: ${c.ownerKind}`));
  const crossChainIdentity = routeRegistry
    ? `per-chain owner and route table (${ownerKinds.join("; ")})` +
      (extraLive.length > 0
        ? `; extra live routes on ${extraLive.map((c) => `${c.chainId} (${c.extraLiveRoutes.map((r) => r.version).join(", ")})`).join(", ")}`
        : "")
    : identity.codeKeccak
      ? `one runtime code hash ${identity.codeKeccak} and the same proof verdicts on every measured chain (${identity.chains.map((c) => c.chainId).join(", ")}); any other chain needs the execution check first` +
        (has("upstreamFreezeBit")
          ? `; the freeze bit ties each chain to its gateway owner (${ownerKinds.join("; ")})`
          : "")
      : "code identity not established";
  // Who can fail verification closed if the pinned verifier proves unsound: WalletWall always, by pausing; an
  // external principal only where a protective freeze lever is in the path.
  const defectResponse = [
    WALLETWALL_PAUSE,
    ...externalDisable
      .filter((l) => l.protectiveOnVerifierDefect)
      .map((l) => `${l.principal} via ${l.lever} (fail-closed at once, at the holder's discretion)`),
  ];

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
    : has("upstreamFreezeBit")
      ? "upstream Ownable owner, read for its freeze bit only (no proxy)"
      : has("walletwallGateway")
        ? "WalletWall Ownable admin (no proxy)"
        : "none";

  return {
    id: option.id,
    decisionValue: option.decisionValue,
    label: option.label,
    path: option.path,
    components: option.components,
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
    defectResponse,
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
  /**
   * `agreeing` counts recorded results; `distinctComputations` counts distinct (tool, machine) pairs behind them.
   * The same ELF bytes from three environments, re-checked by one binary on one machine, are ONE computation.
   */
  crossCheck: { tool: string | null; agreeing: number; conflicting: number; distinctComputations: number };
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
    crossCheck: {
      tool: xc?.tool ?? null,
      agreeing,
      conflicting,
      distinctComputations: agreeing > 0 ? uniq([`${xc?.tool ?? ""} @ ${xc?.ranOn ?? ""}`]).length : 0,
    },
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
    /** Seconds between the mainnet v5.0.0 and v6.0.0 freezes: a batch, not an incident response. */
    advisedFreezeBatchedWithUnaffectedVersionSeconds: number | null;
    /** Hours from routing the broken first v6.1.0 build on Sepolia to freezing it. */
    brokenBuildFreezeHours: number | null;
  };
  decisions: {
    SP1_TRUST_TARGET_DECISION: TrustTargetDecision;
    SP1_TRUST_TARGET_OPTION: string | null;
    PROGRAM_IDENTITY_DECISION: ProgramIdentityDecision;
    AUTHORIZATION_AUTHORITY_DELTA: {
      /** No new principal can widen the accepted relation (the halt principal included). */
      classification: "NO_NEW_AUTHORIZATION_PRINCIPAL" | "NEW_AUTHORIZATION_PRINCIPAL";
      baseline: string;
      removed: Lever[];
      added: Lever[];
      retained: Lever[];
      inheritedByEveryOption: string;
      /** Widening capabilities proposed for TD2: accounted apart, outside the decided design, never authority-neutral. */
      proposedForTd2: { principal: string; capabilities: string[]; classification: string; status: string }[];
    };
    LIVENESS_DEPENDENCY: {
      onChainExternal: Lever[];
      removedVersusBaseline: Lever[];
      offChain: string[];
      inheritedByEveryOption: string;
    };
    /** Who gains or loses the power to stop valid proofs: the decided halt adds one WalletWall principal. */
    LIVENESS_AUTHORITY_DELTA: {
      classification:
        | "WALLETWALL_EMERGENCY_HALT_PRINCIPAL_ADDED_HALT_ONLY"
        | "WALLETWALL_EMERGENCY_PRINCIPAL_WITH_MORE_THAN_HALT"
        | "UNDECIDED";
      added: Lever[];
      removedVersusBaseline: Lever[];
    };
    UPGRADE_MODEL: "EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION" | "MUTABLE_ROUTING" | "UNRESOLVED";
    CROSS_CHAIN_MODEL: (typeof CROSS_CHAIN_MODELS)[number];
    PROGRAM_VKEY_DESIGNATION: VkeyDesignation;
    /** A trade-off the evidence frames but cannot settle: an owner decision, recorded open or decided, never dropped. */
    DEFECT_RESPONSE_COUPLING: {
      status: "OWNER_DECISION_REQUIRED" | "DECIDED" | "NOT_APPLICABLE";
      decision: string | null;
      mechanism: string | null;
      decidedBy: string | null;
      decidedOn: string | null;
      decidedOptionDefectResponse: string[];
      viableAlternatives: { id: string; defectResponse: string[]; externalLivenessPrincipals: string[] }[];
      choices: OwnerDecisionInput["choices"];
      recommendation: string | null;
      rationale: string | null;
      requiredBeforeRealValue: boolean;
      haltDesign: HaltDesign | null;
      /** The consumers the source scan found, and those with no way to replace their verifier. */
      measuredConsumers: string[];
      consumersWithoutRecoveryPath: string[];
      recoveryByConsumer: ConsumerRecovery[];
      /** The onlyOwner functions the multisig vault declares, against which its owner is accounted. */
      multisigOwnerOnlyFunctions: string[];
      amendments: NonNullable<OwnerDecisionInput["amendments"]>;
      authorityAccounting: AuthorityAccounting | null;
      td2Requirements: Td2Requirement[];
    };
    DEFECT_RESPONSE_MECHANISM: string;
    HALT_REVERSIBILITY: "ONE_WAY" | "REVERSIBLE" | "UNDECIDED";
    RECOVERY: string;
    UPSTREAM_GATEWAY_OWNER: "NOT_A_WALLETWALL_AUTHORITY" | "WALLETWALL_AUTHORITY";
    /** What still stands between this design and real value. */
    REAL_VALUE_BLOCKER: "TD2_IMPLEMENTATION_NOT_YET_BUILT" | "DEFECT_RESPONSE_COUPLING_UNDECIDED";
    /** The frozen TD2 requirements real value waits for; TD1 builds none of them. */
    REAL_VALUE_REQUIREMENTS: string[];
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
  "verification targets the designated trust target only: the CREATE2-authenticated v6.1.0 bytes (in a local EVM) or a chain deployment checked by EXTCODEHASH and by the per-chain execution check, never a gateway route",
  "the downloaded circuit artifacts are the pinned key's: sha256(groth16_vk.bin) must equal VERIFIER_HASH 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696 (two different 'v6.1.0' keys have existed)",
  "no real value: the lane is for testnet/local proofs; real value additionally needs the decided DEFECT_RESPONSE_COUPLING built and tested in TD2 — TD2-COMMON-VERIFIER-HALT (the local one-way verifier halt, through every consumer in its scope) and TD2-MULTISIG-ROTATION (WalletWallMultiSigVault's delayed verifier rotation, without which the halt may not reach it: TD1-N11) — and the frozen implementation lane",
];

function sameLever(a: Lever, b: Lever) {
  return a.principal === b.principal && a.lever === b.lever;
}

/**
 * Every capability beyond the retained vault rotation that can widen what verifies, judged by what it holds, not by
 * its own flags or status: each must then be a TD2 proposal, classified as new authority.
 */
function proposedWidening(accounting: AuthorityAccounting | null | undefined) {
  return Object.entries(accounting ?? {})
    .filter(
      ([key, a]: [string, AccountedAuthority]) =>
        key !== "vaultOwnerToday" && a.capabilities.some((c) => WIDENING_POWERS.includes(c)),
    )
    .map(([, a]: [string, AccountedAuthority]) => ({
      principal: a.principal,
      capabilities: a.capabilities,
      classification: a.classification ?? "UNCLASSIFIED",
      status: a.status ?? "UNSTATED",
    }));
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

  const event = (chainId: number, name: string, match: (e: RouteTimelineObservation["events"][number]) => boolean) =>
    ctx.timeline.events.find((e) => e.chainId === chainId && e.event === name && match(e) && e.providersAgree);
  const advisoryFreeze = event(1, "RouteFrozen", (e) => e.version === "v6.0.0");
  const advisoryTs = Date.parse(`${ctx.timeline.upstreamAdvisory.published}T00:00:00Z`) / 1000;
  const lag = advisoryFreeze ? Math.floor((advisoryFreeze.timestamp - advisoryTs) / 86400) : null;
  // The advised version's freeze shared a batch with an unaffected version's: a deprecation, not a response.
  const unaffectedFreeze = event(1, "RouteFrozen", (e) => e.version === "v5.0.0");
  const batchSeconds =
    advisoryFreeze && unaffectedFreeze ? Math.abs(advisoryFreeze.timestamp - unaffectedFreeze.timestamp) : null;
  // The one measured incident response: the broken first v6.1.0 build, routed and frozen on Sepolia.
  const brokenAdded = event(11155111, "RouteAdded", (e) => e.selector === BROKEN_V610_SELECTOR);
  const brokenFrozen = event(11155111, "RouteFrozen", (e) => e.selector === BROKEN_V610_SELECTOR);
  const brokenBuildFreezeHours =
    brokenAdded && brokenFrozen
      ? Math.round(((brokenFrozen.timestamp - brokenAdded.timestamp) / 3600) * 10) / 10
      : null;

  // When the pinned verifier itself proves unsound, who fails verification closed? Viable alternatives (so with no
  // external authorization lever) whose external levers are all protective freezes make that a trade-off the
  // evidence frames but cannot settle.
  const alternatives = options
    .filter((o) => o.viable && o.id !== decided?.id)
    .filter((o) => {
      const xs = ext(o.disable);
      return xs.length > 0 && xs.every((l) => l.protectiveOnVerifierDefect);
    })
    .map((o) => ({
      id: o.id,
      defectResponse: o.defectResponse,
      externalLivenessPrincipals: ext(o.disable).map((l) => l.principal),
    }));
  const od = ctx.inputs.ownerDecisions.find((x) => x.id === "DEFECT_RESPONSE_COUPLING");
  // The owner decided the defect response of a decided trust target; with none decided, there is nothing to carry.
  const ownerDecided = od?.status === "DECIDED" && !!decided;
  const halt = ownerDecided ? (od.haltDesign ?? null) : null;
  // A consumer leaves a halted wrapper by its own timelocked rotation, or — the policy bridge, which reads the
  // pqVerifier() of the consumer an intent names — by the rotation of every contract it can read one from. The halt
  // applies only where such a route exists; a consumer without one waits outside it for its TD2 gate (TD1-N11).
  const consumers = ctx.inputs.probeFacts.verifierConsumers;
  const measuredConsumers = [...consumers.pqVerifierConsumers].sort();
  const sourcesRotate =
    consumers.bridgeCredentialSources.length > 0 &&
    consumers.bridgeCredentialSources.every((s) => consumers.consumersWithTimelockedRotation.includes(s));
  const route = (c: string): ConsumerRecovery["route"] =>
    consumers.consumersWithTimelockedRotation.includes(c)
      ? "OWN_TIMELOCKED_ROTATION"
      : consumers.consumersFollowingTheirConsumer.includes(c) && sourcesRotate
        ? "ITS_CONSUMERS_TIMELOCKED_ROTATION"
        : "NONE";
  const applies = halt?.haltScope?.applies ?? [];
  const excluded = halt?.haltScope?.excludedUntilRecoverable ?? [];
  const recoveryByConsumer = measuredConsumers.map((c): ConsumerRecovery => {
    const gate = excluded.find((e) => e.consumer === c)?.gate ?? null;
    return {
      consumer: c,
      route: route(c),
      rotationDelaySeconds: route(c) === "OWN_TIMELOCKED_ROTATION" ? (consumers.rotationDelaySeconds[c] ?? null) : null,
      halt: applies.includes(c) ? "APPLIED" : gate ? "EXCLUDED_UNTIL_RECOVERABLE" : "UNSCOPED",
      gate,
    };
  });
  const accounting = ownerDecided ? (od.authorityAccounting ?? null) : null;
  const td2Requirements = ownerDecided ? (od.td2Requirements ?? []) : [];
  const defectCoupling: Td1DecisionReceipt["decisions"]["DEFECT_RESPONSE_COUPLING"] = {
    status: ownerDecided ? "DECIDED" : alternatives.length === 0 ? "NOT_APPLICABLE" : "OWNER_DECISION_REQUIRED",
    decision: ownerDecided ? (od.decision ?? null) : null,
    mechanism: ownerDecided ? (od.mechanism ?? null) : null,
    decidedBy: ownerDecided ? (od.decidedBy ?? null) : null,
    decidedOn: ownerDecided ? (od.decidedOn ?? null) : null,
    decidedOptionDefectResponse: decided?.defectResponse ?? [],
    viableAlternatives: alternatives,
    choices: od?.choices ?? [],
    recommendation: od?.recommendation ?? null,
    rationale: od?.rationale ?? null,
    requiredBeforeRealValue: od?.requiredBeforeRealValue ?? true,
    haltDesign: halt,
    measuredConsumers,
    consumersWithoutRecoveryPath: recoveryByConsumer.filter((x) => x.route === "NONE").map((x) => x.consumer),
    recoveryByConsumer,
    multisigOwnerOnlyFunctions: [...consumers.multisigOwnerOnlyFunctions].sort(),
    amendments: ownerDecided ? (od.amendments ?? []) : [],
    authorityAccounting: accounting,
    td2Requirements,
  };
  // The halt lever: WalletWall's own (governed), liveness only, and protective by construction.
  const haltLevers: Lever[] = halt
    ? [
        {
          principal: `WalletWall emergency halt principal (${halt.haltPrincipal.id})`,
          lever: "verifierHalt",
          scope: "liveness",
          chains: ["every chain WalletWall deploys to"],
          delaySeconds: 0,
          governed: true,
          protectiveOnVerifierDefect: true,
        },
      ]
    : [];
  const haltOnly = !!halt && JSON.stringify(halt.haltPrincipal.powers) === JSON.stringify(["HALT"]);
  const haltWidens = (halt?.haltPrincipal.powers ?? []).some((p) => WIDENING_POWERS.includes(p));
  const addedWiden = ext(decided?.widen).filter((l) => !ext(baseline?.widen).some((b) => sameLever(b, l)));
  // An upstream signal that moves the halt would make the upstream gateway owner a WalletWall authority again.
  const signalsMoveTheHalt =
    !!halt &&
    (halt.detectionSignalsControlState || halt.transitions.some((t) => halt.detectionSignals.includes(t.trigger)));
  const upstreamLeverInPath = [...ext(decided?.widen), ...ext(decided?.disable)].some((l) =>
    l.principal.startsWith("upstream gateway owner"),
  );
  // Recovery is claimed for every consumer only once the halt applies to every consumer and each can leave it.
  const everyConsumerRecovers =
    recoveryByConsumer.length > 0 && recoveryByConsumer.every((x) => x.halt === "APPLIED" && x.route !== "NONE");
  const haltScopeText =
    `TD2 tests it through every consumer in its scope (${applies.join(", ") || "none"})` +
    recoveryByConsumer
      .filter((x) => x.halt !== "APPLIED")
      .map(
        (x) =>
          `; ${x.consumer} ${x.route === "NONE" ? "has no recovery path and " : ""}stays off a haltable wrapper${x.gate ? ` until ${x.gate}` : ""}`,
      )
      .join("");

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
        ? `runtime ${identity.codeKeccak} on ${identity.chains.length} chains (two providers each), CREATE2-authenticated initcode, SP1-P1 own compile + Sourcify + VK join, no reachable state/code-changing opcode or state/environment read beyond its own code size, constant call targets only BN254/modexp precompiles, and the same verdicts on every measured chain`
        : `not established: ${identity.failures.join("; ")}`,
    },
    PINNED_VERIFYING_KEY_REAL_PROOF: {
      status: st(identity.realProofOnPinnedKey.established),
      basis: identity.realProofOnPinnedKey.established
        ? `a real v6.1.0 proof from mainnet transaction ${identity.realProofOnPinnedKey.transaction} (program ${identity.realProofOnPinnedKey.programVKey}, not WalletWall's) verifies on the CREATE2-authenticated bytes in the probe suite and by eth_call on every measured chain; its tampered copy and an odd-word canary are refused`
        : "no real proof for this circuit is shown to verify on the pinned bytes",
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
        ? `option ${decided.id}: external authorization levers ${ext(decided.widen).length}, external liveness levers ${ext(decided.disable).length}, beyond ${INHERITED_BY_EVERY_OPTION}`
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
          ? `${designation.vkey} for ELF ${designation.elfSha256} (${designation.elfBytes} B) on ${designation.independentHosts.length} hosts; outside cross-check ${designation.crossCheck.agreeing} agreeing results from ${designation.crossCheck.distinctComputations} distinct (binary, machine) computation, ${designation.crossCheck.conflicting} conflicting`
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
        "every vkey here comes from Succinct's sp1-prover: mldsa65-host inside each build environment, and the released cargo-prove binary run on the workstation (SP1-P1's cross-check and TD1's remap probe) — binary- and machine-level independence only; a WalletWall proof verifying on the pinned verifier is the next join",
    },
    GATEWAY_ROUTE_HISTORY_COMPLETE: {
      status: "NOT_ESTABLISHED",
      basis: gap
        ? `the Sepolia RouteFrozen ${gap.selector} in tx ${gap.tx} is ${gap.missingFromSp1P1History ? "absent from" : "present in"} the SP1-P1 indexer history and the indexer ${gap.indexerHasLog ? "has" : "lacks"} its log; enumerating a mutable route table is not needed under a code-pinned target`
        : "not assessed",
    },
    DEFECT_RESPONSE_PATH: {
      status: "NOT_ESTABLISHED",
      basis:
        defectCoupling.status === "DECIDED"
          ? `decided by the ${defectCoupling.decidedBy} on ${defectCoupling.decidedOn}: ${defectCoupling.decision} via ${defectCoupling.mechanism}; not built — until TD2 builds the halt, only WalletWall's manual pauses, one per consumer, fail a defect closed; ${haltScopeText}`
          : defectCoupling.status === "OWNER_DECISION_REQUIRED"
            ? `open owner decision DEFECT_RESPONSE_COUPLING (alternatives ${alternatives.map((a) => a.id).join(", ")}); until it is decided and built, a defect in the pinned verifier is stopped only by WalletWall's manual pauses, one per consumer (the policy bridge's is one-way), with no stated or tested response bound`
            : "no protective alternative exists; WalletWall's manual pauses, one per consumer (the policy bridge's is one-way), are the only fail-closed path, with no stated or tested response bound",
    },
    REAL_SP1_PROOF_GENERATED: {
      status: "NOT_ESTABLISHED",
      basis: "out of scope for TD1: no circuit download, no prover run",
    },
    REAL_SP1_PROOF_VERIFIED: {
      status: "NOT_ESTABLISHED",
      basis:
        "no WalletWall proof exists; the real proofs exercised are third parties' (upstream's v6 fixture, and a v6.1.0 proof from a mainnet transaction), as controls for the verifier and its key",
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
      advisedFreezeBatchedWithUnaffectedVersionSeconds: batchSeconds,
      brokenBuildFreezeHours,
    },
    decisions: {
      SP1_TRUST_TARGET_DECISION: target.decision,
      SP1_TRUST_TARGET_OPTION: target.optionId,
      PROGRAM_IDENTITY_DECISION: pid.decision,
      AUTHORIZATION_AUTHORITY_DELTA: {
        // A halt principal with any widening power would be authority, whatever it is called.
        classification:
          addedWiden.length === 0 && !haltWidens ? "NO_NEW_AUTHORIZATION_PRINCIPAL" : "NEW_AUTHORIZATION_PRINCIPAL",
        baseline: baseline ? `option ${baseline.id} (${baseline.label})` : "none",
        removed: ext(baseline?.widen).filter((l) => !ext(decided?.widen).some((d) => sameLever(d, l))),
        added: addedWiden,
        retained: (decided?.widen ?? []).filter((l) => l.governed),
        inheritedByEveryOption: INHERITED_BY_EVERY_OPTION,
        proposedForTd2: proposedWidening(accounting),
      },
      LIVENESS_DEPENDENCY: {
        onChainExternal: ext(decided?.disable),
        removedVersusBaseline: ext(baseline?.disable).filter(
          (l) => !ext(decided?.disable).some((d) => sameLever(d, l)),
        ),
        offChain: ctx.inputs.offChainLivenessDependencies,
        inheritedByEveryOption: INHERITED_BY_EVERY_OPTION,
      },
      LIVENESS_AUTHORITY_DELTA: {
        classification: !halt
          ? "UNDECIDED"
          : haltOnly
            ? "WALLETWALL_EMERGENCY_HALT_PRINCIPAL_ADDED_HALT_ONLY"
            : "WALLETWALL_EMERGENCY_PRINCIPAL_WITH_MORE_THAN_HALT",
        added: haltLevers,
        removedVersusBaseline: ext(baseline?.disable).filter(
          (l) => !ext(decided?.disable).some((d) => sameLever(d, l)),
        ),
      },
      UPGRADE_MODEL: !decided
        ? "UNRESOLVED"
        : decided.requiresRedeployToUpgrade
          ? "EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION"
          : "MUTABLE_ROUTING",
      // A code hash is necessary, not sufficient: the same bytes are the same relation only where the chain's
      // precompiles give the same verdicts, so the direct model always carries the per-chain execution check.
      CROSS_CHAIN_MODEL: !decided
        ? "UNRESOLVED"
        : decided.routeRegistry
          ? "PER_CHAIN_ROUTE_TABLE"
          : identity.established && identity.chainExecution.length >= 2
            ? "CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK"
            : "UNRESOLVED",
      PROGRAM_VKEY_DESIGNATION: designation,
      DEFECT_RESPONSE_COUPLING: defectCoupling,
      DEFECT_RESPONSE_MECHANISM: defectCoupling.mechanism ?? "UNDECIDED",
      HALT_REVERSIBILITY: !halt
        ? "UNDECIDED"
        : halt.transitions.some((t) => t.from === "HALTED")
          ? "REVERSIBLE"
          : "ONE_WAY",
      RECOVERY: !halt
        ? "UNDECIDED"
        : halt.recovery !== NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION || everyConsumerRecovers
          ? halt.recovery
          : NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE,
      UPSTREAM_GATEWAY_OWNER:
        upstreamLeverInPath || signalsMoveTheHalt ? "WALLETWALL_AUTHORITY" : "NOT_A_WALLETWALL_AUTHORITY",
      // Closing the decision does not lift the blocker: the halt is built and tested in TD2.
      REAL_VALUE_BLOCKER:
        defectCoupling.status === "OWNER_DECISION_REQUIRED"
          ? "DEFECT_RESPONSE_COUPLING_UNDECIDED"
          : "TD2_IMPLEMENTATION_NOT_YET_BUILT",
      REAL_VALUE_REQUIREMENTS: td2Requirements.map((r) => r.id),
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
    ...inputs.evidence.measurementFiles.map(({ path, sha256 }) => ({ path, sha256 })),
  ];
}

// ---------------------------------------------------------------------------------------------------------
// Rules: what no receipt may claim, checked on the receipt alone
// ---------------------------------------------------------------------------------------------------------

type DefectCoupling = Td1DecisionReceipt["decisions"]["DEFECT_RESPONSE_COUPLING"];

/**
 * The halt's scope (the owner's amendment): every measured consumer named once; the halt applied only where a
 * consumer can leave a halted wrapper; a consumer that cannot waits outside it for its own frozen TD2 gate, bound to
 * no part of the SP1 path, and one that can is never left outside (that would be a bypass, the policy bridge's
 * included). A gate is unbuilt in TD1, so its consumer can be neither in the scope nor shown a recovery route: if the
 * code ever shows one, the design no longer describes the code.
 */
function haltScopeErrors(h: HaltDesign, dc: DefectCoupling, repoDelay: number | undefined): string[] {
  const errors: string[] = [];
  const applies = h.haltScope?.applies ?? [];
  const excluded = h.haltScope?.excludedUntilRecoverable ?? [];
  const measured = dc.measuredConsumers ?? [];
  const rbc = dc.recoveryByConsumer ?? [];
  const reqs = dc.td2Requirements ?? [];
  const named = [...applies, ...excluded.map((e) => e.consumer)];
  const missing = measured.filter((c) => !named.includes(c));
  if (missing.length > 0)
    errors.push(`the halt's scope must name every consumer of the verifier (missing: ${missing.join(", ")})`);
  if (named.length !== new Set(named).size || named.some((c) => !measured.includes(c)))
    errors.push("the halt's scope names each measured consumer once, and only those");
  // A route the rules do not know is no route.
  const route = (c: string) => {
    const r = rbc.find((x) => x.consumer === c)?.route ?? "NONE";
    return RECOVERING_ROUTES.includes(r) ? r : "NONE";
  };
  for (const x of rbc)
    if (![...RECOVERING_ROUTES, "NONE"].includes(x.route))
      errors.push(`recoveryByConsumer: ${x.consumer} has an unknown route ${String(x.route)}`);
  for (const c of applies)
    if (route(c) === "NONE") errors.push(`the halt may not be applied to ${c}: it cannot leave a halted wrapper`);
  for (const e of excluded) {
    if (route(e.consumer) !== "NONE") errors.push(`${e.consumer} can recover, so it cannot be left outside the halt`);
    const g = reqs.find((r) => r.id === e.gate);
    if (!g || g.status !== "FROZEN_FOR_TD2")
      errors.push(`${e.consumer} waits for ${e.gate}, which is not a frozen TD2 requirement`);
    else if (g.consumer !== e.consumer) errors.push(`${e.consumer} waits for ${e.gate}, which is not its own gate`);
    if (e.interim !== EXCLUDED_INTERIM)
      errors.push(
        `until ${e.gate}, ${e.consumer} is bound to no part of the SP1 path (any other interim is an owner decision)`,
      );
  }
  // A recovery gate is unbuilt in TD1: its consumer waits outside the halt and shows no recovery route.
  for (const g of reqs.filter((r) => r.consumer !== undefined)) {
    const c = g.consumer as string;
    if (applies.includes(c)) errors.push(`${c} may not be in the halt's scope before ${g.id} is built`);
    if (!excluded.some((e) => e.consumer === c && e.gate === g.id))
      errors.push(`${c} waits outside the halt for ${g.id}`);
    if (route(c) !== "NONE")
      errors.push(`${c} shows a recovery route before ${g.id} is built: the design no longer describes the code`);
  }
  // A rotation that waits less than the repository's is not the timelocked rotation recovery relies on.
  for (const x of rbc.filter((r) => r.route === "OWN_TIMELOCKED_ROTATION"))
    if (repoDelay === undefined || !(typeof x.rotationDelaySeconds === "number" && x.rotationDelaySeconds >= repoDelay))
      errors.push(
        `${x.consumer}: its rotation must wait at least the repository's ${String(repoDelay)}s (measured: ${String(x.rotationDelaySeconds)})`,
      );
  // The per-consumer table says what the scope says, for exactly the measured consumers.
  const scopeOf = (c: string) => {
    const gate = excluded.find((e) => e.consumer === c)?.gate ?? null;
    return { halt: applies.includes(c) ? "APPLIED" : gate ? "EXCLUDED_UNTIL_RECOVERABLE" : "UNSCOPED", gate };
  };
  if (
    JSON.stringify(rbc.map((x) => x.consumer)) !== JSON.stringify(measured) ||
    rbc.some((x) => JSON.stringify({ halt: x.halt, gate: x.gate }) !== JSON.stringify(scopeOf(x.consumer)))
  )
    errors.push("recoveryByConsumer must list each measured consumer once, with the halt's scope and gate");
  if (
    JSON.stringify(dc.consumersWithoutRecoveryPath) !==
    JSON.stringify(rbc.filter((x) => x.route === "NONE").map((x) => x.consumer))
  )
    errors.push("consumersWithoutRecoveryPath must be the consumers with no recovery route");
  return errors;
}

/**
 * The principals the owner's amendment separates. The halt principal and the multisig vault's owner today hold
 * liveness only; the vault owner holds the retained rotation; a verifier rotation proposed for the multisig vault's
 * owner widens what verifies, so it is a new authorization capability however long its holder has existed. The halt
 * principal is none of the others.
 */
function accountingErrors(h: HaltDesign, dc: DefectCoupling): string[] {
  const a = dc.authorityAccounting;
  if (!a) return ["the decided halt needs its authority accounting"];
  if (JSON.stringify(Object.keys(a)) !== JSON.stringify(ACCOUNTING_KEYS))
    return [`the authority accounting holds exactly ${ACCOUNTING_KEYS.join(", ")}`];
  const errors: string[] = [];
  for (const [k, x] of Object.entries(a) as [string, AccountedAuthority][]) {
    const widens = x.capabilities.some((c) => WIDENING_POWERS.includes(c));
    if (x.widensAuthorization !== widens || x.scope !== (widens ? "authorization" : "liveness"))
      errors.push(
        widens
          ? `${k}: a capability that can widen what verifies is authorization`
          : `${k}: a capability that cannot widen what verifies is liveness`,
      );
  }
  const { haltPrincipal: hp, vaultOwnerToday: vo, multisigOwnerToday: mo, proposedMultisigRotation: pr } = a;
  if (hp.principal !== h.haltPrincipal.id || JSON.stringify(hp.capabilities) !== JSON.stringify(h.haltPrincipal.powers))
    errors.push("the halt principal is accounted with the halt design's principal and powers");
  if (vo.status !== "RETAINED" || JSON.stringify(vo.capabilities) !== JSON.stringify(VAULT_OWNER_CAPABILITIES))
    errors.push("the vault owner is accounted with the retained rotation and its pause, nothing more");
  if (JSON.stringify([...mo.capabilities].sort()) !== JSON.stringify(dc.multisigOwnerOnlyFunctions))
    errors.push("the multisig vault's owner is accounted with the onlyOwner functions its code declares");
  const beyond = mo.capabilities.filter((c) => !LIVENESS_OWNER_FUNCTIONS.includes(c));
  if (beyond.length > 0)
    errors.push(`the multisig vault's owner holds more than pause and unpause (${beyond.join(", ")})`);
  if (pr.principal !== mo.principal) errors.push("the rotation is proposed for the multisig vault's existing owner");
  if ([vo.principal, mo.principal, pr.principal].includes(hp.principal))
    errors.push("the halt principal is never a vault owner, and never holds a rotation");
  if (JSON.stringify(pr.capabilities) !== JSON.stringify(["PQ_VERIFIER_ROTATION"]))
    errors.push("the proposed capability is the multisig vault's pqVerifier rotation, and nothing else");
  if (pr.status !== "PROPOSED_FOR_TD2")
    errors.push("the multisig rotation is proposed for TD2, not part of the decided design");
  if (pr.classification !== NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL)
    errors.push("a rotation for an existing principal is a new authorization capability, never authority-neutral");
  for (const need of ["separate authority accounting", "executable review"])
    if (!(pr.requires ?? []).includes(need)) errors.push(`the proposed rotation requires ${need}`);
  return errors;
}

/**
 * What TD1 freezes for TD2: nothing built; the common halt, which must enforce every exclusion and prove what the
 * owner and the review named; and each recovery gate (a requirement that names its consumer) a delayed rotation no
 * weaker than the repository's own, with its proofs and its stop condition — the multisig vault's under the owner's
 * name.
 */
function td2RequirementErrors(dc: DefectCoupling, repoDelay: number | undefined): string[] {
  const errors: string[] = [];
  const reqs = dc.td2Requirements ?? [];
  for (const r of reqs)
    if (r.status !== "FROZEN_FOR_TD2") errors.push(`${r.id}: TD1 freezes requirements and builds none (${r.status})`);
  const common = reqs.find((r) => r.id === TD2_COMMON_VERIFIER_HALT);
  if (!common) errors.push(`${TD2_COMMON_VERIFIER_HALT} is frozen for TD2`);
  else {
    const kept = (dc.haltDesign?.haltScope?.excludedUntilRecoverable ?? []).map((e) => e.consumer).sort();
    if (JSON.stringify([...(common.excludedConsumersRefusedAHaltableWrapper ?? [])].sort()) !== JSON.stringify(kept))
      errors.push(`${common.id}: it must refuse a haltable wrapper to every consumer kept outside the halt`);
    const unproved = COMMON_HALT_PROOFS.filter((p) => !(common.executableProofs ?? []).includes(p));
    if (unproved.length > 0) errors.push(`${common.id}: it must prove ${unproved.join(" and ")}`);
  }
  if (!reqs.some((r) => r.id === TD2_MULTISIG_ROTATION && r.consumer === MULTISIG_VAULT))
    errors.push(`${TD2_MULTISIG_ROTATION} is ${MULTISIG_VAULT}'s frozen gate`);
  for (const g of reqs.filter((r) => r.consumer !== undefined)) {
    const inv = g.invariants;
    if (repoDelay === undefined || !(inv && inv.minimumDelaySeconds >= repoDelay))
      errors.push(`${g.id}: the rotation waits at least the repository's ${String(repoDelay)}s`);
    if (inv?.instantReplacement !== false) errors.push(`${g.id}: no instantaneous verifier replacement`);
    if (inv?.invokableByHaltPrincipal !== false) errors.push(`${g.id}: no halt principal may invoke the rotation`);
    if (inv?.targetMustPassEvidenceGates !== true)
      errors.push(`${g.id}: the rotation targets only a wrapper that passed the SP1 evidence gates`);
    if (inv?.oldWrapperUnhalt !== false) errors.push(`${g.id}: no HALTED -> ACTIVE on the old wrapper`);
    const unproved = RECOVERY_GATE_PROOFS.filter((p) => !(g.executableProofs ?? []).includes(p));
    if (unproved.length > 0) errors.push(`${g.id}: it must prove ${unproved.join(" and ")}`);
    const stop = g.stopCondition;
    if (
      stop?.when !== GATE_STOP_CONDITION.when ||
      stop.then !== GATE_STOP_CONDITION.then ||
      stop.never !== GATE_STOP_CONDITION.never
    )
      errors.push(`${g.id}: it stops and returns to design rather than weakening the one-way halt`);
  }
  return errors;
}

/**
 * The owner's decision (2026-10-15) and its amendment, checked on the receipt alone: a local, one-way, halt-only
 * breaker at the verifier wrapper, applied to every consumer that can recover from it, moved only by its principal,
 * recovered only by a new wrapper and the timelocked rotation, never an upstream authority; the principals accounted
 * apart; and the requirements TD2 must meet frozen.
 */
function decidedHaltErrors(
  d: Td1DecisionReceipt["decisions"],
  dc: DefectCoupling,
  decided: OptionAuthority | undefined,
  ext: (ls: Lever[] | undefined) => Lever[],
): string[] {
  const errors: string[] = [];
  const chosen = (dc.choices ?? []).find((c) => c.id === dc.decision);
  if (!chosen) errors.push("the owner's decision is not one of the offered choices");
  else if (!decided || !chosen.options.includes(decided.id))
    errors.push("the owner's decision must be realized by the decided trust target");
  if (dc.decision !== DECIDED_DEFECT_RESPONSE)
    errors.push(`the owner decided ${DECIDED_DEFECT_RESPONSE}; AF is not chosen`);
  if (dc.mechanism !== LOCAL_ONE_WAY_VERIFIER_HALT)
    errors.push(`the decided mechanism is ${LOCAL_ONE_WAY_VERIFIER_HALT}`);
  const h = dc.haltDesign;
  // The rotation delay the decision retains (the vault owner's governed lever): the floor for every recovery rotation.
  const repoDelay = decided?.widen.find((l) => l.lever === "pqVerifierRotation")?.delaySeconds;
  if (!h) errors.push("a decided defect response needs its halt design");
  else {
    if (h.location !== "VERIFIER_WRAPPER")
      errors.push("the halt sits at the verifier wrapper, which the consumers in its scope verify through");
    errors.push(...haltScopeErrors(h, dc, repoDelay));
    // A scope narrower than the measured consumers is the owner's amendment, not the lane's choice.
    if (
      (h.haltScope?.excludedUntilRecoverable ?? []).length > 0 &&
      !(dc.amendments ?? []).some((x) => x.by === "owner")
    )
      errors.push("a halt scope narrower than the measured consumers is the owner's amendment, on record");
    if (h.recoveryIdentity !== RECOVERY_IDENTITY)
      errors.push("recovery is to an independently established identity, never a fresh deployment of the halted one");
    if (JSON.stringify(h.transitions.map((t) => [t.from, t.to])) !== JSON.stringify([["ACTIVE", "HALTED"]]))
      errors.push("the halt has one transition, ACTIVE -> HALTED: nothing leaves HALTED in place");
    if (h.transitions.some((t) => t.trigger !== "HALT_PRINCIPAL_CALL"))
      errors.push("only the halt principal's call moves the halt; detection signals are evidence");
    if (h.detectionSignalsControlState !== false) errors.push("detection signals cannot control the halt");
    const extra = h.haltPrincipal.powers.filter((p) => p !== "HALT");
    if (extra.length > 0 || !h.haltPrincipal.powers.includes("HALT"))
      errors.push(`the halt principal may only halt (also holds: ${extra.join(", ") || "nothing, and no HALT"})`);
    if (h.wrapperIdentity.sp1Verifier !== "IMMUTABLE")
      errors.push("the wrapper's SP1 verifier is immutable, halted or not");
    if (h.wrapperIdentity.programVKey !== "IMMUTABLE")
      errors.push("the wrapper's PROGRAM_VKEY is immutable, halted or not");
    if (h.recovery !== NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION)
      errors.push("recovery from HALTED is a new wrapper and the timelocked rotation, nothing else");
    // The outputs say what the design says; RECOVERY claims every consumer only once every consumer can recover.
    const reversibility = h.transitions.some((t) => t.from === "HALTED") ? "REVERSIBLE" : "ONE_WAY";
    if (d.HALT_REVERSIBILITY !== reversibility)
      errors.push(`HALT_REVERSIBILITY disagrees with the halt design (${reversibility})`);
    const entry = (c: string) => (dc.recoveryByConsumer ?? []).find((x) => x.consumer === c);
    const everyConsumerRecovers =
      (dc.measuredConsumers ?? []).length > 0 &&
      (dc.measuredConsumers ?? []).every(
        (c) => entry(c)?.halt === "APPLIED" && RECOVERING_ROUTES.includes(entry(c)?.route ?? "NONE"),
      );
    const recovery =
      h.recovery !== NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION || everyConsumerRecovers
        ? h.recovery
        : NEW_WRAPPER_PLUS_TIMELOCKED_ROTATION_WITHIN_HALT_SCOPE;
    if (d.RECOVERY !== recovery)
      errors.push(`RECOVERY must be ${recovery}: it claims every consumer only once every consumer can recover`);
    if (
      d.AUTHORIZATION_AUTHORITY_DELTA?.classification === "NO_NEW_AUTHORIZATION_PRINCIPAL" &&
      h.haltPrincipal.powers.some((p) => WIDENING_POWERS.includes(p))
    )
      errors.push("a halt principal with widening power is authority: the delta cannot be authorization-neutral");
    errors.push(...accountingErrors(h, dc));
  }
  errors.push(...td2RequirementErrors(dc, repoDelay));
  if (d.UPSTREAM_GATEWAY_OWNER !== "NOT_A_WALLETWALL_AUTHORITY")
    errors.push("the upstream gateway owner is not a WalletWall authority under the decided response");
  if (
    decided &&
    [...ext(decided.widen), ...ext(decided.disable)].some((l) => l.principal.startsWith("upstream gateway owner"))
  )
    errors.push("the decided path gives the upstream gateway owner a lever");
  return errors;
}

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
  const trustResolved = d.SP1_TRUST_TARGET_DECISION !== "UNRESOLVED";
  const programResolved = d.PROGRAM_IDENTITY_DECISION !== "UNRESOLVED";
  const verdict =
    trustResolved && programResolved
      ? "DESIGN_DECIDED"
      : !trustResolved && !programResolved
        ? "STOP_NO_DESIGN_JUSTIFIED"
        : "PARTIAL_DECISION";
  if (r.verdict !== verdict) errors.push(`verdict ${String(r.verdict)} disagrees with the decisions (${verdict})`);

  // Authorization and liveness are never conflated.
  for (const o of options) {
    for (const l of o.widen ?? []) {
      if (l.scope !== "authorization")
        errors.push(`option ${o.id}: widen lever ${l.lever} is not scoped authorization`);
      if ((LIVENESS_LEVERS as readonly string[]).includes(l.lever))
        errors.push(`option ${o.id}: ${l.lever} can only stop verification; it is not an authorization lever`);
      // "Protective" describes a lever that can only stop verification; it never excuses a widening one.
      if (l.protectiveOnVerifierDefect === true)
        errors.push(`option ${o.id}: authorization lever ${l.lever} cannot be marked protective`);
    }
    for (const l of o.disable ?? []) {
      if (l.scope !== "liveness") errors.push(`option ${o.id}: disable lever ${l.lever} is not scoped liveness`);
      if ((AUTHORIZATION_LEVERS as readonly string[]).includes(l.lever))
        errors.push(`option ${o.id}: ${l.lever} widens the accepted relation; it cannot be classified liveness-only`);
      // A freeze protects exactly when it freezes the pinned verifier's own route: always on a route registry (the
      // proof travels through it), and on a freeze-bit reader only with the coupling pins.
      if ((LIVENESS_LEVERS as readonly string[]).includes(l.lever)) {
        const protects = o.routeRegistry || FREEZE_COUPLING_PINS.every((p) => (o.pins ?? []).includes(p));
        if (l.protectiveOnVerifierDefect !== protects)
          errors.push(`option ${o.id}: ${l.lever} must be recorded ${protects ? "protective" : "not protective"}`);
      }
    }
    // Routing through the upstream gateway, or reading its freeze bit, puts its owners' freeze in the path.
    if (
      (o.components ?? []).some((c) => c === "upstreamGateway" || c === "upstreamFreezeBit") &&
      !(o.disable ?? []).some((l) => l.lever === "freezeRoute")
    )
      errors.push(`option ${o.id}: an option that reads the upstream gateway must record its owners' freeze`);
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
    // Only an unpinned route registry can move the accepted relation without a redeploy.
    if (o.requiresRedeployToUpgrade !== !(o.routeRegistry && !(o.pins ?? []).includes("selector")))
      errors.push(`option ${o.id}: requiresRedeployToUpgrade disagrees with its route registry and pins`);
  }

  const decided = options.find((o) => o.id === d.SP1_TRUST_TARGET_OPTION);
  const exec = tt.chainExecution ?? [];
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
    if (tt.chains.some((c) => !c.providersAgree))
      errors.push("a trust target cannot be decided on a chain read that a second provider does not corroborate");
    if (d.SP1_TRUST_TARGET_DECISION === "DIRECT_IMMUTABLE_VERIFIER") {
      if (tt.runtime.forbiddenOpcodes.length > 0)
        errors.push("a direct immutable target cannot have reachable state- or code-changing opcodes");
      if (Object.keys(tt.runtime.reachableEnvironmentReads ?? {}).some((x) => !ALLOWED_RUNTIME_READS.includes(x)))
        errors.push("a direct immutable target cannot read state or environment beyond its own code size");
      if ((tt.runtime.constantCallTargets ?? []).some((t) => !ALLOWED_CONSTANT_CALL_TARGETS.includes(t)))
        errors.push("a direct immutable target may call only the BN254/modexp precompiles at constant addresses");
      if (tt.runtime.metadataIsSolcCbor !== true)
        errors.push("a direct immutable target's opcode scan needs solc's CBOR metadata to bound the code");
      if (!tt.create2.authenticated) errors.push("a direct immutable target needs CREATE2-authenticated initcode");
      if (uniq(tt.chains.map((c) => c.codeKeccak)).length !== 1)
        errors.push("a direct immutable target needs one code hash on every chain");
      if (decided && decided.verifierCodeMutable)
        errors.push("a direct immutable target cannot have mutable verifier code");
      if (exec.length !== tt.chains.length || exec.some((c) => !c.verdictsAsExpected || !c.providersAgree))
        errors.push("a direct immutable target needs the same verdicts from the deployed template on every chain");
      if (tt.realProofOnPinnedKey?.established !== true)
        errors.push("a direct immutable target needs a real proof verified on its pinned key");
      if (tt.chainCallsBound !== true)
        errors.push("a direct immutable target needs per-chain verdicts for the calls this receipt names");
      if (tt.canaryHasPositiveControl !== true)
        errors.push("a direct immutable target needs a canary shown to detect a missing pairing precompile");
    }
  }
  // Each measured chain once: four entries for one chain must not read as four chains.
  if (JSON.stringify(exec.map((c) => c.chainId).sort()) !== JSON.stringify(tt.chains.map((c) => c.chainId).sort()))
    errors.push("the per-chain execution entries must be exactly the measured chains");

  const upgrade = !decided
    ? "UNRESOLVED"
    : decided.requiresRedeployToUpgrade
      ? "EXPLICIT_REDEPLOY_AND_TIMELOCKED_ROTATION"
      : "MUTABLE_ROUTING";
  if (d.UPGRADE_MODEL !== upgrade)
    errors.push(`UPGRADE_MODEL ${String(d.UPGRADE_MODEL)} disagrees with the decided option (${upgrade})`);
  // One code hash is one relation only where each chain's precompiles give the same verdicts: a cross-chain
  // code-pin model needs the execution check on at least two chains.
  const perChainChecked = exec.length >= 2 && exec.every((c) => c.verdictsAsExpected && c.providersAgree);
  const crossChain = !decided
    ? "UNRESOLVED"
    : decided.routeRegistry
      ? "PER_CHAIN_ROUTE_TABLE"
      : tt.established && perChainChecked
        ? "CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK"
        : "UNRESOLVED";
  if (d.CROSS_CHAIN_MODEL !== crossChain)
    errors.push(`CROSS_CHAIN_MODEL ${String(d.CROSS_CHAIN_MODEL)} disagrees with the evidence (${crossChain})`);

  // Freeze levers are dual-use. A viable alternative whose external levers are all protective freezes is a
  // trade-off between authority minimisation and an upstream kill switch: an open owner decision, never dropped.
  // (A viable option with an external authorization lever is refused above.)
  const ext = (ls: Lever[] | undefined) => (ls ?? []).filter((l) => !l.governed);
  const failClosedAlternatives = options
    .filter(
      (o) =>
        o.viable &&
        o.id !== decided?.id &&
        ext(o.disable).length > 0 &&
        ext(o.disable).every((l) => l.protectiveOnVerifierDefect === true),
    )
    .map((o) => o.id)
    .sort();
  const dc = d.DEFECT_RESPONSE_COUPLING;
  const unblock = d.REAL_PROOF_LANE_UNBLOCKED;
  if (!dc) errors.push("DEFECT_RESPONSE_COUPLING is required");
  else {
    // A trade-off stays on the record — open, or decided by the owner — and is never marked not applicable.
    if (failClosedAlternatives.length > 0 && dc.status === "NOT_APPLICABLE")
      errors.push(
        `viable fail-closed alternatives (${failClosedAlternatives.join(", ")}) make the defect response an owner decision`,
      );
    const listed = (dc.viableAlternatives ?? []).map((a) => a.id).sort();
    if (JSON.stringify(listed) !== JSON.stringify(failClosedAlternatives))
      errors.push("DEFECT_RESPONSE_COUPLING must list exactly the viable fail-closed alternatives");
    if (dc.status === "DECIDED") errors.push(...decidedHaltErrors(d, dc, decided, ext));
    if (d.DEFECT_RESPONSE_MECHANISM !== (dc.mechanism ?? "UNDECIDED"))
      errors.push("DEFECT_RESPONSE_MECHANISM disagrees with the defect-response decision");
    // Closing the decision does not lift the blocker; only TD2's built and tested halt can.
    const blocker =
      dc.status === "OWNER_DECISION_REQUIRED"
        ? "DEFECT_RESPONSE_COUPLING_UNDECIDED"
        : "TD2_IMPLEMENTATION_NOT_YET_BUILT";
    if (d.REAL_VALUE_BLOCKER !== blocker)
      errors.push(`REAL_VALUE_BLOCKER must be ${blocker}: a design lane cannot lift it`);
    if (JSON.stringify(d.REAL_VALUE_REQUIREMENTS) !== JSON.stringify((dc.td2Requirements ?? []).map((x) => x.id)))
      errors.push(
        "REAL_VALUE_REQUIREMENTS must name every requirement frozen for TD2: real value waits for all of them",
      );
    // A widening capability proposed for TD2 stays on the authorization record, whatever it says of itself.
    if (
      JSON.stringify(d.AUTHORIZATION_AUTHORITY_DELTA?.proposedForTd2) !==
      JSON.stringify(proposedWidening(dc.authorityAccounting))
    )
      errors.push("AUTHORIZATION_AUTHORITY_DELTA must carry every widening capability proposed for TD2");
    if (dc.status !== "NOT_APPLICABLE") {
      const offered = (dc.choices ?? []).flatMap((c) => c.options);
      if (decided && !offered.includes(decided.id))
        errors.push(`the owner decision offers no choice realized by option ${decided.id}`);
      // An alternative may go unoffered only if an offered one has the same external principals and a shorter path
      // (B against AF): it would add components without changing who holds the lever.
      const option = (id: string) => options.find((o) => o.id === id);
      const principals = (id: string) =>
        JSON.stringify(
          ext(option(id)?.disable)
            .map((l) => l.principal)
            .sort(),
        );
      const dominated = (id: string) =>
        failClosedAlternatives.some(
          (p) =>
            offered.includes(p) &&
            principals(p) === principals(id) &&
            (option(p)?.path.length ?? 0) < (option(id)?.path.length ?? 0),
        );
      for (const id of failClosedAlternatives)
        if (!offered.includes(id) && !dominated(id))
          errors.push(`the owner decision offers no choice realized by option ${id}`);
      if (!(dc.choices ?? []).some((c) => c.id === dc.recommendation))
        errors.push("the owner decision's recommendation is not one of its choices");
      if (dc.requiredBeforeRealValue !== true) errors.push("the defect response must be required before real value");
    }
  }
  // The real-proof preconditions are the lane's, word for word (one names the decided response and its TD2 gates).
  if (JSON.stringify(unblock?.preconditions) !== JSON.stringify(REAL_PROOF_PRECONDITIONS))
    errors.push("the real-proof preconditions are not the lane's");

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
      "DEFECT_RESPONSE_PATH",
    ])
      if (claims[k]?.status !== "NOT_ESTABLISHED") errors.push(`${k} cannot be claimed by a design lane`);
    if (claims.TRUST_TARGET_CODE_IDENTITY?.status === "ESTABLISHED" && !tt.established)
      errors.push("TRUST_TARGET_CODE_IDENTITY cannot be ESTABLISHED without the evidence");
    if (
      claims.PINNED_VERIFYING_KEY_REAL_PROOF?.status === "ESTABLISHED" &&
      tt.realProofOnPinnedKey?.established !== true
    )
      errors.push(
        "PINNED_VERIFYING_KEY_REAL_PROOF cannot be ESTABLISHED without a real proof verified on the pinned key",
      );
    if (
      claims.DECIDED_TARGET_HAS_NO_EXTERNAL_LEVER?.status === "ESTABLISHED" &&
      (!decided || ext(decided.widen).length > 0 || ext(decided.disable).length > 0)
    )
      errors.push(
        "DECIDED_TARGET_HAS_NO_EXTERNAL_LEVER cannot be ESTABLISHED while the decided option has an external lever",
      );
    if (claims.GATEWAY_ROUTE_HISTORY_COMPLETE?.status === "ESTABLISHED")
      errors.push(
        "GATEWAY_ROUTE_HISTORY_COMPLETE cannot be ESTABLISHED: an indexer's event history is not a completeness proof",
      );
    if (
      claims.IDENTITY_REPRODUCED_OUTSIDE_VENDOR_IMAGE?.status === "ESTABLISHED" &&
      dz?.reproducedOutsideVendorImage !== true
    )
      errors.push("IDENTITY_REPRODUCED_OUTSIDE_VENDOR_IMAGE cannot be ESTABLISHED without the reproduction");
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

/** The tree id git records for `rel` at HEAD; null when it cannot be read (fails the freshness check). */
function headTree(repoRoot: string, rel: string): string | null {
  try {
    return execFileSync("git", ["rev-parse", `HEAD:${rel}`], {
      cwd: resolve(repoRoot),
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString("utf8")
      .trim();
  } catch {
    return null;
  }
}

/**
 * A JSON pointer without escapes ("/scripts/remap-build.sh"; no bound key contains "/" or "~"). A missing step
 * yields undefined or throws; the caller records either as unbound.
 */
function jsonPointer(doc: unknown, pointer: string): unknown {
  return pointer
    .split("/")
    .slice(1)
    .reduce<unknown>((cur, key) => (cur as Record<string, unknown>)[key], doc);
}

/** For each committed measurement input, the hash its bound observation recorded (null: nothing resolvable). */
export function boundMeasurementHashes(inputs: DecisionInputs, repoRoot = "."): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const m of inputs.evidence.measurementFiles) {
    let recorded: unknown;
    try {
      const observation: unknown = JSON.parse(readFileSync(resolve(repoRoot, m.boundTo.observation), "utf8"));
      recorded = jsonPointer(observation, m.boundTo.pointer);
    } catch {
      recorded = undefined;
    }
    out[m.path] = typeof recorded === "string" ? recorded : null;
  }
  return out;
}

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
    chainExec: json<ChainExecutionObservation>(TD1_OBSERVATIONS.chainExecution),
    mainnetProof: json<MainnetProofObservation>(TD1_OBSERVATIONS.mainnetV610Proof),
    gitTrees: { guest: headTree(repoRoot, "zkvm/guest"), host: headTree(repoRoot, "zkvm/host") },
    boundHashes: boundMeasurementHashes(inputs, repoRoot),
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
  // The working tree can match while HEAD records other trees (or the reverse): the subject is both.
  const subject = ctx.inputs.subject;
  if (ctx.gitTrees.guest !== subject.zkvmGuestTree)
    errors.push(`stale: HEAD:zkvm/guest is ${String(ctx.gitTrees.guest)}, not the subject's ${subject.zkvmGuestTree}`);
  if (ctx.gitTrees.host !== subject.zkvmHostTree)
    errors.push(`stale: HEAD:zkvm/host is ${String(ctx.gitTrees.host)}, not the subject's ${subject.zkvmHostTree}`);
  const listed = ctx.inputs.evidence.td1Observations.map((o) => o.path).sort();
  const expected: string[] = Object.values(TD1_OBSERVATIONS).slice().sort();
  if (JSON.stringify(listed) !== JSON.stringify(expected))
    errors.push("decision inputs must list exactly the TD1 observation files");
  // A committed measurement input is evidence only as the file an observation says it ran.
  for (const m of ctx.inputs.evidence.measurementFiles) {
    if (!expected.includes(m.boundTo.observation))
      errors.push(`unbound: ${m.path} is bound to ${m.boundTo.observation}, which is not a TD1 observation`);
    else if (ctx.boundHashes[m.path] !== m.sha256)
      errors.push(
        `unbound: ${m.path} (${m.sha256}) is not the file ${m.boundTo.observation} recorded at ${m.boundTo.pointer} (${String(ctx.boundHashes[m.path])})`,
      );
  }
  return errors;
}

export function validateCommittedDecisionReceipt(committed: unknown, ctx: DecisionContext): string[] {
  const errors = [...validateDecisionRules(committed), ...checkContextFresh(ctx)];
  if (JSON.stringify(committed) !== JSON.stringify(buildDecisionReceipt(ctx)))
    errors.push("committed decision receipt has drifted from the generator; run `npm run sp1-td1:receipt`");
  return errors;
}
