/**
 * The SP1 implementation lane's receipt (evidence/zk/sp1-impl/implementation-receipt.json;
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * Every status is computed here, from the repository and from executing the lane's own decision functions:
 *
 *   the compiled wrapper — its ABI and the compiler's AST of ZKMLDSAVerifier: the constructor's code-hash pin, the
 *     immutables, every call verify() makes out of the contract, the chain-id comparison, the journal's types, the halt;
 *   the generated records and their validators — wrapper builds, designations, the registry with its append-only
 *     history, SP1-TD1's receipt and SP1-TD2's record;
 *   the measured observations — the per-chain execution check, the canonical rebuild, the proving artifacts;
 *   probes — the deployment plan, the registry rules, the designation set rules and the RPC classifier, each run on an
 *     attack and on its positive control: a refusal counts only when the same call without the attack is accepted.
 *
 * The committed receipt must be exactly what this derives, so a hand edit fails validation. Behaviour that needs an
 * EVM is not asserted here: each status cites the tests that execute it (their titles must exist), and CI runs them.
 * The lane's STOP conditions are evaluated from the same inputs. PRODUCTION_SP1_BINDING_STATUS is ESTABLISHED only
 * when every prerequisite is met; a receipt cannot attest its own review, so the owner's merge is one no input meets.
 *
 * Provenance says which verifier and program these are; it does not say they are sound.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { getAddress, type Provider } from "ethers";

import { collectReports } from "../validate-bytecode-size";
import { fileHistoryErrors } from "./append-only-history";
import {
  MAIN_RULESET_OBSERVATION_REL,
  historyProtectionGaps,
  readRulesetObservation,
  rulesetObservationErrors,
  type RulesetObservation,
} from "./main-ruleset";
import { isExecutionFailure } from "./rpc-answer";
import {
  CANONICAL_REBUILD_OBSERVATION_REL,
  canonicalBuildVerdict,
  canonicalRebuildEvidenceErrors,
  conflictingVkeyCount,
  recordsDirOf,
  type CanonicalBuildObservation,
} from "./sp1-canonical-build";
import {
  CHAIN_EXECUTION_OBSERVATION_REL,
  REQUIRED_VERDICTS,
  SUPPORTED_DEPLOYMENT_CHAINS,
  chainExecutionObservationErrors,
  type ChainExecutionObservation,
} from "./sp1-chain-execution";
import {
  DESIGNATIONS_DIR,
  DESIGNATION_EVIDENCE_DIR,
  designationSetErrors,
  latestDesignation,
  readDesignations,
  subjectFreshnessErrors,
  validateDesignationsInRepo,
  type ProgramDesignation,
} from "./sp1-designation";
import {
  PROVING_ARCHIVES_DIR,
  PROVING_ARTIFACTS_OBSERVATION_REL,
  PROVING_AVAILABILITY_REL,
  provingAvailabilityErrors,
  provingAvailabilityFromRepo,
} from "./sp1-proving-availability";
import {
  MIGRATED_FROM,
  REGISTRY_REL,
  REGISTRY_SCHEMA,
  REGISTRY_V1_SCHEMA,
  readRegistry,
  registryErrors,
  registryExtensionErrors,
  registryState,
  validateRegistryInRepo,
  type RegistryDoc,
  type RegistryFact,
} from "./sp1-registry";
import {
  IMPL_RECEIPT_INTEGRATION_REL,
  MAIN_REF,
  descendantDriftErrors,
  gitObjects,
  receiptIntegrationErrors,
} from "./sp1-impl-receipt-integration";
import { finalizedBlock } from "./sp1-registration";
import { readDecisionContext, validateCommittedDecisionReceipt } from "./sp1-td1-decision";
import { TD1_RECEIPT_REL, TD2_RECORD_REL, validateCommittedTd2Record } from "./sp1-td2-record";
import {
  WRAPPER_BUILDS_DIR,
  WRAPPER_SOURCE,
  compiledWrapper,
  currentBuildErrors,
  readWrapperBuilds,
  walkAst,
  wrapperBuildErrors,
  type AstNode,
  type WrapperBuild,
} from "./sp1-wrapper-build";
import { planWrapperDeployment, type PlanInput } from "./zk-verifier-deployment";

export const IMPL_RECEIPT_REL = "evidence/zk/sp1-impl/implementation-receipt.json";
export const IMPL_RECEIPT_SCHEMA = "walletwall.sp1-impl-receipt.v1";
export const IMPL_LANE = "SP1-IMPL";
/** Where a real WalletWall proof's record would live; none exists, and none counts until a lane validates it. */
export const REAL_PROOF_RECORDS_DIR = "evidence/zk/sp1-real-proof";
const NEW_AUTHORITY = "NEW_AUTHORIZATION_CAPABILITY_FOR_AN_EXISTING_PRINCIPAL";
const MULTISIG_OWNER = "WALLETWALL_MULTISIG_VAULT_OWNER";
/** The contract sources this lane changes: the wrapper (the pin, F-1) and the F-1 test probe. */
export const LANE_CONTRACT_CHANGES = [
  { path: "contracts/mocks/ChainIdBindingProbe.sol", status: "A" },
  { path: WRAPPER_SOURCE, status: "M" },
];

export const STATUS_KEYS = [
  "SP1_DIRECT_VERIFIER_PIN",
  "SP1_VERIFIER_RUNTIME_HASH",
  "PROGRAM_IDENTITY_DECISION",
  "PROGRAM_VKEY_DESIGNATION",
  "CANONICAL_BUILD_STATUS",
  "SUCCESSOR_DESIGNATION_STATUS",
  "REGISTRY_APPEND_ONLY_STATUS",
  "REGISTRY_BUILD_PROVENANCE_STATUS",
  "CROSS_CHAIN_HALTED_IDENTITY_STATUS",
  "PER_CHAIN_EXECUTION_CHECK",
  "F1_CHAIN_ID_FIX",
  "TD2_HALT_INVARIANTS_PRESERVED",
  "MULTISIG_AUTHORIZATION_CLASS_PRESERVED",
  "PROVING_AVAILABILITY",
  "PRODUCTION_SP1_BINDING_STATUS",
] as const;
export type StatusKey = (typeof STATUS_KEYS)[number];

/** The lane's hard STOP conditions, in the lane's order. */
const STOP_CONDITIONS = [
  ["CANONICAL_BUILD_DOES_NOT_REPRODUCE", "the canonical build does not reproduce the designated ELF and vkey"],
  ["ONE_ELF_CONFLICTING_VKEYS", "one ELF maps to conflicting vkeys"],
  ["CHAINS_DISAGREE_ON_RUNTIME_IDENTITY", "supported chains disagree on the SP1 verifier's runtime identity"],
  ["PER_CHAIN_VERDICTS_DIVERGE", "the per-chain execution verdicts diverge"],
  ["PIN_BYPASSABLE_VIA_GATEWAY_ROUTING", "the code-hash pin can be bypassed through gateway routing"],
  ["PRODUCTION_VALUES_OVERRIDABLE", "production values can be overridden off a local chain"],
  ["REGISTRY_HISTORY_REWRITABLE_UNDETECTED", "registry history can be rewritten without detection"],
  ["HALTED_IDENTITY_REPUBLISHABLE_BY_ADDRESS_CHANGE", "a halted identity can be republished by changing an address"],
  ["CROSS_CHAIN_FIX_NEEDS_NEW_MUTABLE_PRINCIPAL", "the cross-chain fix needs a new mutable authorization principal"],
  ["F1_CHANGES_GUEST_ELF_VKEY_OR_PROOF_FORMAT", "F-1 changes the guest, the ELF, the vkey or the proof format"],
  ["RPC_FAILURE_FAILS_OPEN", "an RPC failure becomes fail-open"],
  ["TD2_INVARIANTS_WEAKENED", "SP1-TD2's invariants are weakened"],
  ["BYTECODE_EXCEEDS_BUDGET", "a contract's runtime exceeds its size budget (EIP-170)"],
] as const;
export const STOP_CONDITION_IDS = STOP_CONDITIONS.map(([id]) => id);

/** The tests that execute what each status depends on, as [suite, title]; the titles must exist (CI runs them). */
const CITED: Record<StatusKey, [string, string][]> = {
  SP1_DIRECT_VERIFIER_PIN: [
    ["Sp1ImplVerifierPin", "refuses in its constructor every target whose runtime is not the pinned code"],
    ["Sp1ImplVerifierPin", "accepts the real v6.1.0 bytes at two different addresses and binds each address immutably"],
    [
      "Sp1ImplVerifierPin",
      "adding an accept-all route, failing to replace v6.1.0's, and freezing it leave the forged withdrawal refused",
    ],
  ],
  SP1_VERIFIER_RUNTIME_HASH: [
    [
      "Sp1ImplVerifierPin",
      "records the pinned identity: each constant is SP1-TD1's measurement and what the pinned bytes report",
    ],
    [
      "Sp1ImplChainExecution",
      "covers every supported deployment chain (and the trust target's mainnets), each through two agreeing providers",
    ],
  ],
  PROGRAM_IDENTITY_DECISION: [
    [
      "Sp1ImplDesignation",
      "binds subject → digest-pinned procedure → lockfile → ELF → vkey → verifier, as SP1-TD1 measured them",
    ],
  ],
  PROGRAM_VKEY_DESIGNATION: [
    ["Sp1ImplDesignation", "the committed first designation is the derivation from SP1-TD1's evidence, byte for byte"],
    ["Sp1ImplDesignation", "a hand-edited value in the committed designation is drift, whatever the field"],
    [
      "Sp1ImplDesignation",
      "the zkvm subject on disk and at HEAD must be the latest designation's (the stale-vkey tripwire)",
    ],
  ],
  CANONICAL_BUILD_STATUS: [
    [
      "Sp1ImplCanonicalBuild",
      "the committed rebuild of the frozen subject reproduces the designated ELF and vkey, lockfile unchanged",
    ],
    ["Sp1ImplCanonicalBuildWorkflow", "fails unless both hosts and the recompute reproduce the designation"],
  ],
  SUCCESSOR_DESIGNATION_STATUS: [
    [
      "Sp1ImplSuccessorDesignation",
      "a genuinely new identity is designated next, naming its predecessor and why, and earlier files are untouched",
    ],
    [
      "Sp1ImplSuccessorDesignation",
      "the same verifier code and the same PROGRAM_VKEY are refused: a redeployment of the halted identity",
    ],
    ["Sp1ImplSuccessorDesignation", "changing only the verifier's address is the same identity, refused"],
  ],
  REGISTRY_APPEND_ONLY_STATUS: [
    [
      "Sp1ImplRegistry",
      "refuses a rewrite made on a side branch and merged, and a merge that resolves by dropping a fact",
    ],
    ["Sp1ImplRegistry", "refuses to judge without the full history: a shallow clone fails closed"],
    [
      "Sp1ImplRegistry",
      "this repository's own history keeps the registry, designations, bundles and builds append-only",
    ],
  ],
  REGISTRY_BUILD_PROVENANCE_STATUS: [
    ["Sp1ImplBindingGate", "a later recorded build leaves an earlier deployment genuine"],
    ["Sp1ImplBindingGate", "a registration that records another build than the code runs is refused"],
    ["Sp1ImplWrapperBuild", "an old build stays the build of the wrappers deployed from it after the contract changes"],
  ],
  CROSS_CHAIN_HALTED_IDENTITY_STATUS: [
    [
      "Sp1ImplBindingGate",
      "refused on Sepolia when the registry records its halt on Base Sepolia, though the Sepolia wrapper is ACTIVE",
    ],
    [
      "Sp1ImplBindingGate",
      "end to end: the deployment entry point refuses it from a registry that records the halt only on another chain",
    ],
  ],
  PER_CHAIN_EXECUTION_CHECK: [
    [
      "Sp1ImplChainExecution",
      "the same code whose pairing calls reach an empty account accepts the canary, and fails the check",
    ],
    [
      "Sp1ImplChainExecution",
      "an RPC that does not answer gives no verdict: the check throws, it never reads a failure as a refusal",
    ],
    [
      "Sp1ImplDeployTooling",
      "refuses a chain where the same code gives other verdicts (its pairing precompile broken), by execution",
    ],
  ],
  F1_CHAIN_ID_FIX: [
    ["Sp1ImplVerifierPin", "ids that differ only above bit 63 no longer collide (the truncating rule matched them)"],
    ["Sp1ImplVerifierPin", "verify() refuses a proven journal for another chain and accepts this chain's (31337)"],
    [
      "Sp1ImplVerifierPin",
      "the journal and the authorization are unchanged: 160 bytes with a uint64 tag, and EIP-712 binds the full id",
    ],
  ],
  TD2_HALT_INVARIANTS_PRESERVED: [
    ["Sp1Td2VerifierHalt", "the source writes `halted` in exactly one place, halt(), and only ever to true"],
    [
      "Sp1Td2VerifierHalt",
      "FAILS_CLOSED_AFTER_HALT_THROUGH_EVERY_CONSUMER_IN_SCOPE: one halt call refuses all three consumers at once",
    ],
    [
      "Sp1Td2VerifierRotation",
      "the delay and the apply window are the repository's (172,800 s and 14 days, WalletWallVault's constants)",
    ],
  ],
  MULTISIG_AUTHORIZATION_CLASS_PRESERVED: [
    [
      "Sp1Td2VerifierRotation",
      "the cut, executed: through the full delay the owner CAN install an accept-all verifier, which voids every tenant's PQ factor but not its ECDSA quorum",
    ],
  ],
  PROVING_AVAILABILITY: [
    [
      "Sp1ImplProvingAvailability",
      "the committed observation and record re-derive, and the status is OWNER_DOWNLOAD_REQUIRED",
    ],
    [
      "Sp1ImplProvingAvailability",
      "a WalletWall archive record is refused until a lane validates it; a local copy is not availability",
    ],
  ],
  PRODUCTION_SP1_BINDING_STATUS: [
    [
      "Sp1ImplReceipt",
      "PRODUCTION_SP1_BINDING_STATUS is ESTABLISHED only when every prerequisite is met; this lane leaves five unmet",
    ],
  ],
};
const CITATIONS = Object.fromEntries(
  STATUS_KEYS.map((k) => [k, CITED[k].map(([name, title]) => ({ test: `test/${name}.test.ts`, title }))]),
) as Record<StatusKey, { test: string; title: string }[]>;

const sha256 = (b: Uint8Array | string) => createHash("sha256").update(b).digest("hex");
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const yes = (b: boolean) => (b ? "yes" : "no");
const messageOf = (e: unknown) => (e instanceof Error ? e.message : String(e));

// ---------------------------------------------------------------------------------------------------------
// The compiled wrapper, read from the compiler's AST
// ---------------------------------------------------------------------------------------------------------

export interface WrapperAstFacts {
  /** The constructor reverts UndesignatedSP1Verifier unless the target's codehash is SP1_VERIFIER_CODEHASH, and
   *  stores exactly that checked target in SP1_VERIFIER. */
  constructorPinsCodehash: boolean;
  immutables: Record<string, string>;
  /** Every call verify() makes out of the contract, as "<receiver type>.<member>", sorted. */
  verifyExternalCalls: string[];
  /** What the ISP1Verifier(...) conversions in verify() convert: the call target of the proof check. */
  sp1CallTargets: string[];
  /** Conversions of block.chainid to a narrower type anywhere in the contract. */
  chainIdNarrowings: number;
  /** verify() hands block.chainid itself to _chainIdMatches, which compares at 256 bits. */
  chainIdComparedFullWidth: boolean;
  /** The types the journal (publicValues) is decoded as. */
  journalTypes: string[];
  /** `halted` is assigned once, in halt(), to true. */
  haltSetsOnlyTrue: boolean;
  /** verify()'s first statement returns false when halted. */
  verifyChecksHaltFirst: boolean;
  /** The ABI's state-changing functions. */
  mutatingFunctions: string[];
}

const isIdent = (n: AstNode | undefined, name: string | undefined) => n?.nodeType === "Identifier" && n.name === name;
/** A probe `hardhat test --coverage` injected (`__NomicFoundationCoverage.sendHit(...)`), not a statement an author wrote. */
const isCoverageHit = (s: AstNode | undefined) =>
  s?.nodeType === "ExpressionStatement" &&
  s.expression?.nodeType === "FunctionCall" &&
  s.expression.expression?.nodeType === "MemberAccess" &&
  s.expression.expression.memberName === "sendHit" &&
  String(s.expression.expression.expression?.name ?? "").includes("Coverage");
/** The first statement an author wrote: a block's first one that is no coverage probe, or the lone statement. */
const firstAuthored = (s: AstNode | undefined): AstNode | undefined =>
  s?.nodeType === "Block" ? (s.statements ?? []).find((x: AstNode) => !isCoverageHit(x)) : s;
const isChainId = (n: AstNode | undefined) =>
  n?.nodeType === "MemberAccess" && n.memberName === "chainid" && isIdent(n.expression, "block");

/** The facts the receipt reads from the compiled ZKMLDSAVerifier's AST and ABI. */
export function wrapperAstFacts(contract: AstNode, abi: readonly AstNode[]): WrapperAstFacts {
  const fns: AstNode[] = contract.nodes.filter((n: AstNode) => n.nodeType === "FunctionDefinition");
  const ctor = fns.find((f) => f.kind === "constructor");
  const fn = (name: string) => fns.find((f) => f.name === name);
  const target = ctor?.parameters?.parameters?.[0]?.name;

  let checks = false;
  let stores = false;
  walkAst(ctor?.body, (n) => {
    if (n.nodeType === "Assignment" && isIdent(n.leftHandSide, "SP1_VERIFIER") && isIdent(n.rightHandSide, target)) {
      stores = true;
    }
    if (n.nodeType !== "IfStatement" || n.condition?.nodeType !== "BinaryOperation" || n.condition.operator !== "!=")
      return;
    const sides = [n.condition.leftExpression, n.condition.rightExpression];
    const codehash = sides.some(
      (s) => s?.nodeType === "MemberAccess" && s.memberName === "codehash" && isIdent(s.expression, target),
    );
    let reverts = false;
    walkAst(n.trueBody, (m) => {
      if (m.nodeType === "RevertStatement" && isIdent(m.errorCall?.expression, "UndesignatedSP1Verifier"))
        reverts = true;
    });
    if (codehash && sides.some((s) => isIdent(s, "SP1_VERIFIER_CODEHASH")) && reverts) checks = true;
  });

  const vars: AstNode[] = contract.nodes.filter((n: AstNode) => n.nodeType === "VariableDeclaration");
  const immutables = Object.fromEntries(
    ["SP1_VERIFIER", "PROGRAM_VKEY", "HALT_PRINCIPAL"].map((name) => [
      name,
      String(vars.find((v) => v.name === name)?.mutability),
    ]),
  );

  const verify = fn("verify");
  const calls: string[] = [];
  const targets: string[] = [];
  walkAst(verify?.body, (n) => {
    if (n.nodeType !== "FunctionCall" || n.expression?.nodeType !== "MemberAccess") return;
    const receiver = String(n.expression.expression?.typeDescriptions?.typeString);
    if (!receiver.startsWith("contract ") && !receiver.startsWith("address")) return;
    calls.push(`${receiver}.${String(n.expression.memberName)}`);
    const conversion = n.expression.expression;
    if (conversion?.nodeType === "FunctionCall" && conversion.kind === "typeConversion") {
      targets.push(String(conversion.arguments?.[0]?.name));
    }
  });

  let narrowings = 0;
  walkAst(contract, (n) => {
    if (n.nodeType === "FunctionCall" && n.kind === "typeConversion" && isChainId(n.arguments?.[0])) {
      if (String(n.typeDescriptions?.typeString) !== "uint256") narrowings++;
    }
  });
  let passedWhole = false;
  walkAst(verify?.body, (n) => {
    if (n.nodeType === "FunctionCall" && isIdent(n.expression, "_chainIdMatches") && isChainId(n.arguments?.[1])) {
      passedWhole = true;
    }
  });
  let fullWidth = false;
  walkAst(fn("_chainIdMatches")?.body, (n) => {
    if (
      n.nodeType === "BinaryOperation" &&
      n.operator === "==" &&
      n.leftExpression?.typeDescriptions?.typeString === "uint256" &&
      n.rightExpression?.typeDescriptions?.typeString === "uint256"
    ) {
      fullWidth = true;
    }
  });

  let journalTypes: string[] = [];
  walkAst(fn("decodeProofPayload")?.body, (n) => {
    if (
      n.nodeType === "FunctionCall" &&
      n.expression?.nodeType === "MemberAccess" &&
      n.expression.memberName === "decode" &&
      isIdent(n.expression.expression, "abi") &&
      isIdent(n.arguments?.[0], "publicValues")
    ) {
      journalTypes = (n.arguments?.[1]?.components ?? []).map((c: AstNode) =>
        String(c?.typeName?.name ?? c?.typeDescriptions?.typeString),
      );
    }
  });

  const haltWrites: { fn: string; value: string }[] = [];
  for (const f of fns) {
    walkAst(f.body, (n) => {
      if (n.nodeType === "Assignment" && isIdent(n.leftHandSide, "halted")) {
        haltWrites.push({ fn: String(f.name || f.kind), value: String(n.rightHandSide?.value) });
      }
    });
  }
  const first = firstAuthored(verify?.body);
  const halting = firstAuthored(first?.trueBody);

  return {
    constructorPinsCodehash: checks && stores,
    immutables,
    verifyExternalCalls: calls.sort(),
    sp1CallTargets: targets,
    chainIdNarrowings: narrowings,
    chainIdComparedFullWidth: passedWhole && fullWidth,
    journalTypes,
    haltSetsOnlyTrue:
      haltWrites.length === 1 &&
      haltWrites[0].fn === "halt" &&
      haltWrites[0].value === "true" &&
      vars.find((v) => v.name === "halted")?.value == null,
    verifyChecksHaltFirst:
      first?.nodeType === "IfStatement" &&
      isIdent(first.condition, "halted") &&
      halting?.nodeType === "Return" &&
      halting.expression?.value === "false",
    mutatingFunctions: abi
      .filter((e) => e.type === "function" && e.stateMutability !== "view" && e.stateMutability !== "pure")
      .map((e) => String(e.name))
      .sort(),
  };
}

/** The types the journal is decoded as in a ZKMLDSAVerifier source text (the base's, for comparison). */
export function journalTypesInSource(source: string): string[] {
  const m = /abi\s*\.decode\(\s*publicValues\s*,\s*\(([^)]*)\)\s*\)/.exec(source);
  if (!m) throw new Error("the source decodes no journal (publicValues)");
  return m[1].split(",").map((t) => t.trim());
}

// ---------------------------------------------------------------------------------------------------------
// Probes: the lane's decision functions on an attack and on its positive control
// ---------------------------------------------------------------------------------------------------------

export interface ProbeResult {
  probe: string;
  controlAccepted: boolean;
  attackRefused: boolean;
  /** The line of the refusal that names the reason ("" when the attack was not refused for it). */
  refusal: string;
}
const passed = (p: ProbeResult) => p.controlAccepted && p.attackRefused;

function runProbe(probe: string, control: () => void, attack: () => void, reason: RegExp): ProbeResult {
  let controlAccepted = true;
  try {
    control();
  } catch {
    controlAccepted = false;
  }
  let message = "";
  try {
    attack();
  } catch (error) {
    message = messageOf(error);
  }
  const line = message.split("\n").find((l) => reason.test(l)) ?? "";
  return { probe, controlAccepted, attackRefused: line !== "", refusal: line.replace(/^\s*-\s*/, "").trim() };
}
async function runProbeAsync(
  probe: string,
  control: () => Promise<void>,
  attack: () => Promise<void>,
  reason: RegExp,
): Promise<ProbeResult> {
  let controlAccepted = true;
  try {
    await control();
  } catch {
    controlAccepted = false;
  }
  let message = "";
  try {
    await attack();
  } catch (error) {
    message = messageOf(error);
  }
  const line = message.split("\n").find((l) => reason.test(l)) ?? "";
  return { probe, controlAccepted, attackRefused: line !== "", refusal: line.replace(/^\s*-\s*/, "").trim() };
}
const noErrors = (errors: string[]) => {
  if (errors.length > 0) throw new Error(errors.join("\n"));
};

const PROBE = {
  deployer: getAddress("0x1111111111111111111111111111111111111111"),
  haltPrincipal: getAddress("0x2222222222222222222222222222222222222222"),
  wrapperA: getAddress("0x3333333333333333333333333333333333333333"),
  wrapperB: getAddress("0x4444444444444444444444444444444444444444"),
  elsewhere: getAddress("0x5555555555555555555555555555555555555555"),
  /** Succinct's SP1VerifierGateway, the address SP1-P1's runbook pointed at. */
  gateway: getAddress("0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"),
};
const word = (byte: string) => `0x${byte.repeat(32)}`;
const probeRegistry = (facts: RegistryFact[]): RegistryDoc => ({
  schema: REGISTRY_SCHEMA,
  note: "probe",
  migratedFrom: { ...MIGRATED_FROM },
  facts,
});
const planInput = (
  chainId: string,
  env: Record<string, string>,
  designations: readonly ProgramDesignation[],
  builds: readonly WrapperBuild[],
  registry: RegistryDoc,
): PlanInput => ({
  chainId: BigInt(chainId),
  env: { HALT_PRINCIPAL_ADDRESS: PROBE.haltPrincipal, ...env },
  deployer: PROBE.deployer,
  designations,
  builds,
  currentBuildErrors: [],
  registry,
});

/** Each off-local override, on every supported deployment chain, against the same plan without it. */
export function probeOverrides(
  plan: typeof planWrapperDeployment,
  designations: readonly ProgramDesignation[],
  builds: readonly WrapperBuild[],
): ProbeResult[] {
  const attacks: [string, Record<string, string>][] = [
    ["SP1_VERIFIER_ADDRESS (Succinct's gateway)", { SP1_VERIFIER_ADDRESS: PROBE.gateway }],
    ["PROGRAM_VKEY", { PROGRAM_VKEY: word("ab") }],
    ["ALLOW_MOCK_SP1", { ALLOW_MOCK_SP1: "true" }],
  ];
  return SUPPORTED_DEPLOYMENT_CHAINS.flatMap((chainId) =>
    attacks.map(([what, env]) =>
      runProbe(
        `an override of ${what} on chain ${chainId}`,
        () => void plan(planInput(chainId, {}, designations, builds, probeRegistry([]))),
        () => void plan(planInput(chainId, env, designations, builds, probeRegistry([]))),
        /no override exists/,
      ),
    ),
  );
}

function probeRegistration(seq: number, chainId: string, address: string, d: ProgramDesignation, build: WrapperBuild) {
  return {
    seq,
    kind: "WRAPPER_REGISTERED",
    chainId,
    address,
    identity: d.identity,
    observedAt: { block: 100, blockHash: word("11") },
    wrapperBuild: build.id,
    designation: d.id,
    sp1Verifier: { address: getAddress(d.verifier.address), runtimeCodeKeccak: d.verifier.runtimeCodeKeccak },
    programVKey: d.programVKey,
    haltPrincipal: PROBE.haltPrincipal,
    deployment: { txHash: word("22"), block: 90, deployer: PROBE.deployer },
    replaces: null,
  } as unknown as RegistryFact;
}
function probeHalt(seq: number, chainId: string, address: string, d: ProgramDesignation) {
  return {
    seq,
    kind: "WRAPPER_HALTED",
    chainId,
    address,
    identity: d.identity,
    observedAt: { block: 120, blockHash: word("33") },
    reason: "VERIFIER_SOUNDNESS",
    halt: { txHash: word("44"), block: 110 },
  } as unknown as RegistryFact;
}

/** The first designation's identity halted on one supported chain, then registered or deployed on another. */
export function probeHaltedIdentityElsewhere(
  designations: readonly ProgramDesignation[],
  builds: readonly WrapperBuild[],
): { registry: ProbeResult; deployPlan: ProbeResult } {
  const d = designations[0];
  const build = builds[builds.length - 1];
  const [a, b] = SUPPORTED_DEPLOYMENT_CHAINS;
  const registered = probeRegistration(1, a, PROBE.wrapperA, d, build);
  const halted = probeHalt(2, a, PROBE.wrapperA, d);
  return {
    registry: runProbe(
      `${d.id}'s identity, halted on chain ${a}, registered at another address on chain ${b}`,
      () =>
        noErrors(
          registryErrors(
            probeRegistry([registered, probeRegistration(2, b, PROBE.wrapperB, d, build)]),
            builds,
            designations,
          ),
        ),
      () =>
        noErrors(
          registryErrors(
            probeRegistry([registered, halted, probeRegistration(3, b, PROBE.wrapperB, d, build)]),
            builds,
            designations,
          ),
        ),
      /halted identity is never registered again/,
    ),
    deployPlan: runProbe(
      `a deployment on chain ${b} of ${d.id}'s identity, halted on chain ${a}`,
      () => void planWrapperDeployment(planInput(b, {}, designations, builds, probeRegistry([registered]))),
      () => void planWrapperDeployment(planInput(b, {}, designations, builds, probeRegistry([registered, halted]))),
      /recorded HALTED/,
    ),
  };
}

/** A successor that keeps the latest designation's verifier code and PROGRAM_VKEY and changes only the address. */
export function probeIdentityReuse(designations: readonly ProgramDesignation[]): ProbeResult {
  const last = designations[designations.length - 1];
  const next = designations.length + 1;
  const twin: ProgramDesignation = {
    ...structuredClone(last),
    id: `${last.program}-d${next}`,
    sequence: next,
    predecessor: { id: last.id, identity: last.identity },
    succession: { reason: "probe: the same verifier code and PROGRAM_VKEY at another address" },
    verifier: { ...structuredClone(last.verifier), address: PROBE.elsewhere },
  };
  return runProbe(
    `designation ${twin.id}: ${last.id}'s verifier code and PROGRAM_VKEY at another address`,
    () => noErrors(designationSetErrors(designations)),
    () => noErrors(designationSetErrors([...designations, twin])),
    /is already designated/,
  );
}

/**
 * STOP 7 rests on the history walk itself (scripts/lib/append-only-history.ts with the registry's extension rule), run
 * on a throwaway repository: a history that only appends facts passes, and one whose later commit drops a published
 * halt is refused. A walk that saw nothing would fail the probe, so its "no violation" on this repository means
 * something. (A rewrite of main itself is outside any walk: main's ruleset is measured for that.)
 */
export function probeRegistryHistory(
  designations: readonly ProgramDesignation[],
  builds: readonly WrapperBuild[],
): ProbeResult {
  const d = designations[0];
  const build = builds[builds.length - 1];
  const [a] = SUPPORTED_DEPLOYMENT_CHAINS;
  const registered = probeRegistration(1, a, PROBE.wrapperA, d, build);
  const halted = probeHalt(2, a, PROBE.wrapperA, d);
  const text = (doc: unknown) => `${JSON.stringify(doc, null, 2)}\n`;
  const v1 = text({ schema: REGISTRY_V1_SCHEMA, entries: [] });
  const walk = (versions: string[]) => {
    const repo = mkdtempSync(join(tmpdir(), "sp1-receipt-registry-probe-"));
    try {
      const run = (...args: string[]) =>
        execFileSync(
          "git",
          [
            "-c",
            "core.autocrlf=false",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.email=probe@example.invalid",
            "-c",
            "user.name=probe",
            ...args,
          ],
          // Fixed identities and times: the same versions give the same commits, so the refusal it records is stable.
          {
            cwd: repo,
            stdio: "pipe",
            env: {
              ...process.env,
              GIT_AUTHOR_DATE: "2026-01-01T00:00:00Z",
              GIT_COMMITTER_DATE: "2026-01-01T00:00:00Z",
              GIT_COMMITTER_NAME: "probe",
              GIT_COMMITTER_EMAIL: "probe@example.invalid",
            },
          },
        );
      run("init", "-q");
      versions.forEach((version, k) => {
        mkdirSync(dirname(join(repo, REGISTRY_REL)), { recursive: true });
        writeFileSync(join(repo, REGISTRY_REL), version);
        run("add", "-A");
        run("commit", "-q", "-m", `registry version ${k}`);
      });
      noErrors(fileHistoryErrors(repo, REGISTRY_REL, registryExtensionErrors));
    } finally {
      rmSync(repo, { recursive: true, force: true });
    }
  };
  return runProbe(
    "a published halt fact dropped from the registry by a later commit, seen by the history walk",
    () => walk([v1, text(probeRegistry([registered])), text(probeRegistry([registered, halted]))]),
    () =>
      walk([
        v1,
        text(probeRegistry([registered])),
        text(probeRegistry([registered, halted])),
        text(probeRegistry([registered])),
      ]),
    /removed or rewrote a published fact/,
  );
}

/**
 * A finalized-block read that fails, or a chain that names no finalized block, must leave a fact unobserved: never
 * read as some other block (review finding L-7; L-3 was a fallback to the latest block). The probe providers answer
 * "latest" either way, so a fallback would resolve, and the probe would see it.
 */
export async function probeFinalityReads(
  finalized: (provider: Provider) => Promise<{ block: number; blockHash: string }> = finalizedBlock,
): Promise<ProbeResult[]> {
  const provider = (answer: () => Promise<unknown>) =>
    ({
      getBlock: async (tag: unknown) => (tag === "finalized" ? answer() : { number: 130, hash: word("44") }),
    }) as unknown as Provider;
  const healthy = provider(async () => ({ number: 120, hash: word("33") }));
  const read = async (p: Provider) => {
    const at = await finalized(p);
    if (at.block !== 120) throw new Error(`observed at block ${at.block}, not the finalized block`);
  };
  return [
    await runProbeAsync(
      "a finalized-block read that fails (503), taken as a block to observe the facts at",
      () => read(healthy),
      () =>
        read(
          provider(async () => {
            throw Object.assign(new Error("server response 503 Service Unavailable"), { code: "SERVER_ERROR" });
          }),
        ),
      /503/,
    ),
    await runProbeAsync(
      "a chain that names no finalized block, taken as a block to observe the facts at",
      () => read(healthy),
      () => read(provider(async () => null)),
      /no finalized block/,
    ),
  ];
}

/** A rate limit must not read as the chain's answer; the chain's own revert must. */
export function probeRpcFailClosed(): ProbeResult {
  return runProbe(
    "an RPC rate limit (-32005) read as the chain's answer",
    () => {
      if (!isExecutionFailure({ code: 3, message: "execution reverted", data: "0x7fcdd1f4" })) {
        throw new Error("the chain's own revert is not read as its answer");
      }
    },
    () => {
      if (!isExecutionFailure({ code: -32005, message: "Too Many Requests" })) {
        throw new Error("a rate limit is not the chain's answer: no verdict");
      }
    },
    /not the chain's answer/,
  );
}

// ---------------------------------------------------------------------------------------------------------
// Inputs, derivation, receipt
// ---------------------------------------------------------------------------------------------------------

export interface ImplReceiptInputs {
  baseCommit: string;
  td1: { programIdentityDecision: string; trustTargetCodeKeccak: string; forbiddenOpcodes: string[]; errors: string[] };
  td2: { errors: string[]; multisigClass: string | null };
  designations: ProgramDesignation[];
  designationErrors: string[];
  /** The zkvm subject on disk and at HEAD is not the latest designation's: a demonstrated guest change. */
  subjectErrors: string[];
  builds: WrapperBuild[];
  buildErrors: string[];
  registry: RegistryDoc;
  registryErrors: string[];
  chainExecution: {
    designation: string;
    errors: string[];
    codes: string[];
    verdictsAsRequired: boolean;
    chains: { chainId: string; block: number; codeKeccak: string; verdicts: Record<string, string> }[];
  };
  canonical: {
    designation: string;
    oneHost: string;
    twoHost: string;
    hosts: string[];
    conflictingVkeys: number;
    lockUnchangedOn: string[];
    /** Why the committed observation is not what this tree's checker derives from its raw records (F3). */
    evidenceErrors: string[];
  };
  proving: { status: string | null; errors: string[] };
  ast: WrapperAstFacts;
  journalTypesAtBase: string[];
  contractsChanged: { path: string; status: string }[];
  sizes: { name: string; runtimeBytes: number; withinLimit: boolean }[];
  probes: {
    overrides: ProbeResult[];
    haltedIdentity: { registry: ProbeResult; deployPlan: ProbeResult };
    identityReuse: ProbeResult;
    rpc: ProbeResult;
    registryHistory: ProbeResult;
    finality: ProbeResult[];
  };
  /** Main's ruleset as measured (scripts/lib/main-ruleset.ts): why the record is none, and the gaps it shows. */
  ruleset: { observedAtUtc: string; errors: string[]; gaps: string[] };
  evidence: { path: string; sha256: string }[];
}

interface StatusEntry {
  value: string;
  basis: string[];
  verifiedBy: { test: string; title: string }[];
}
interface Prerequisite {
  id: string;
  met: boolean;
  /** False when no evidence this lane can produce meets it (a later lane, or the owner, must). */
  reachableInThisLane: boolean;
  basis: string;
}

export interface ImplReceipt {
  schema: string;
  lane: string;
  verdict: string;
  baseCommit: string;
  statuses: Record<StatusKey, StatusEntry>;
  productionBinding: { status: string; prerequisites: Prerequisite[] };
  stopConditions: { id: string; condition: string; triggered: boolean; basis: string }[];
  authorizationDelta: { value: string; basis: string[] };
  realValue: { blocked: boolean; blockers: string[] };
  soundness: string;
  probes: ImplReceiptInputs["probes"];
  wrapperAst: WrapperAstFacts;
  contractsChangedSinceBase: { path: string; status: string }[];
  runtimeSizes: ImplReceiptInputs["sizes"];
  evidence: { path: string; sha256: string }[];
}

/** ESTABLISHED only when every prerequisite is met. */
export function productionBindingStatus(prerequisites: readonly { met: boolean }[]): string {
  return prerequisites.length > 0 && prerequisites.every((p) => p.met) ? "ESTABLISHED" : "NOT_ESTABLISHED";
}

const probeLine = (p: ProbeResult) =>
  `probe: ${p.probe}: positive control accepted ${yes(p.controlAccepted)}; refused ${yes(p.attackRefused)}${p.refusal ? ` (${p.refusal})` : ""}`;

/** The receipt the inputs derive; pure. */
export function deriveImplReceipt(i: ImplReceiptInputs): ImplReceipt {
  const d = i.designations[0];
  const build = i.builds[i.builds.length - 1];
  const facts = Array.isArray(i.registry.facts) ? i.registry.facts : [];
  const s = {} as Record<StatusKey, StatusEntry>;
  const set = (k: StatusKey, value: string, basis: string[]) => {
    s[k] = { value, basis, verifiedBy: CITATIONS[k] };
  };

  const pinIsDesignated = build?.pins.sp1VerifierCodehash === d?.verifier.runtimeCodeKeccak;
  set(
    "SP1_DIRECT_VERIFIER_PIN",
    i.ast.constructorPinsCodehash &&
      i.ast.immutables.SP1_VERIFIER === "immutable" &&
      i.buildErrors.length === 0 &&
      pinIsDesignated
      ? "CONSTRUCTOR_CODE_HASH_PIN"
      : "NOT_PINNED",
    [
      `the compiler's AST: the constructor reverts UndesignatedSP1Verifier unless the target's codehash is SP1_VERIFIER_CODEHASH, and stores that target as SP1_VERIFIER: ${yes(i.ast.constructorPinsCodehash)}`,
      `SP1_VERIFIER is ${i.ast.immutables.SP1_VERIFIER}; verify() calls out only to ${i.ast.verifyExternalCalls.join(" and ")}, the proof check on ${i.ast.sp1CallTargets.join(", ")}: no gateway, route or selector indirection`,
      `the compiled wrapper is the latest recorded build ${build?.id}: ${yes(i.buildErrors.length === 0)}; its pin ${build?.pins.sp1VerifierCodehash} is designation ${d?.id}'s verifier code: ${yes(pinIsDesignated)}`,
      `checked once, at construction: SP1-TD1's runtime scan of the pinned verifier found forbidden opcodes [${i.td1.forbiddenOpcodes.join(", ")}], so its code cannot change after the check`,
    ],
  );

  const runtimeHashes = [
    d?.verifier.runtimeCodeKeccak,
    build?.pins.sp1VerifierCodehash,
    i.td1.trustTargetCodeKeccak,
    ...i.chainExecution.codes,
  ];
  set(
    "SP1_VERIFIER_RUNTIME_HASH",
    new Set(runtimeHashes).size === 1 && i.chainExecution.codes.length === 1
      ? d.verifier.runtimeCodeKeccak
      : "INCONSISTENT",
    [
      `designation ${d?.id}: ${d?.verifier.runtimeCodeKeccak} (SP1Verifier ${d?.verifier.version} at ${d?.verifier.address})`,
      `wrapper build ${build?.id} pins ${build?.pins.sp1VerifierCodehash}`,
      `SP1-TD1's trust target: ${i.td1.trustTargetCodeKeccak}`,
      `measured at finalized blocks on chains ${i.chainExecution.chains.map((c) => c.chainId).join(", ")}: ${i.chainExecution.codes.join(", ")}`,
    ],
  );

  set("PROGRAM_IDENTITY_DECISION", i.td1.errors.length === 0 ? i.td1.programIdentityDecision : "TD1_RECEIPT_INVALID", [
    `SP1-TD1's decision (${TD1_RECEIPT_REL}, which validates against its evidence: ${yes(i.td1.errors.length === 0)})`,
    ...i.td1.errors,
  ]);

  set("PROGRAM_VKEY_DESIGNATION", i.designationErrors.length === 0 ? `${d.id}: ${d.programVKey}` : "INVALID", [
    `generated from SP1-TD1's evidence, regenerating byte for byte, with the zkvm subject at HEAD the designated one: ${yes(i.designationErrors.length === 0)}`,
    `subject guest tree ${d?.subject.zkvmGuestTree}, host tree ${d?.subject.zkvmHostTree}, guest lockfile ${d?.subject.guestCargoLockSha256}`,
    `procedure ${d?.procedure.id}: ${d?.procedure.image}`,
    `ELF sha256 ${d?.elf.sha256} (${d?.elf.bytes} bytes) → PROGRAM_VKEY ${d?.programVKey}, built and reproduced on ${d?.hosts.join(" and ")}; recomputed from the ELF outside the build containers by ${d?.vkeyRecomputed.tool}: ${d?.vkeyRecomputed.agreeing} agreeing results of ${d?.vkeyRecomputed.distinctComputations} computation(s), ${d?.vkeyRecomputed.conflicting} conflicting`,
    `its guest lock policy (${d?.procedure.guestLock}) is the frozen procedure's: SP1-TD1's hosts hashed the lockfile before their builds only; this lane's rebuild measured it after (CANONICAL_BUILD_STATUS)`,
    `identity ${d?.identity} = keccak256(abi.encode(verifier runtime code hash, PROGRAM_VKEY)); soundness: ${d?.soundness}`,
    ...i.designationErrors,
  ]);

  const canonicalEvidenceValid = i.canonical.evidenceErrors.length === 0;
  set("CANONICAL_BUILD_STATUS", canonicalEvidenceValid ? i.canonical.oneHost : "EVIDENCE_INVALID", [
    `the frozen subject rebuilt by the canonical procedure on ${i.canonical.hosts.join(", ")}, compared with designation ${i.canonical.designation}: ${i.canonical.oneHost}`,
    `the committed observation is what this tree's checker derives from its committed raw records, made with this tree's driver and checker: ${yes(canonicalEvidenceValid)}; the records are what the driver wrote on the machine that ran it (self-attested for a local run)`,
    `the release rebuild needs two distinct machines: the committed evidence gives ${i.canonical.twoHost}; .github/workflows/sp1-canonical-build.yml rebuilds on two runners, recomputes the vkey on another from the ELFs alone, fails on any drift or incomplete build, and reports the "SP1 canonical build gate" (requiring it is the owner's ruleset change)`,
    `one ELF with another vkey, in a completed build or the outside recompute: ${i.canonical.conflictingVkeys}`,
    `the guest lockfile was the subject's before and after the build on: ${i.canonical.lockUnchangedOn.join(", ") || "no host"}`,
    "only PROGRAM_IDENTITY_DRIFT is the STOP; PROCEDURE_DRIFT, INCOMPLETE (a liveness failure: an absent record) and EVIDENCE_INVALID are no reproduction, and no STOP",
    ...i.canonical.evidenceErrors,
  ]);

  const successors = i.designations.filter((x) => x.predecessor !== null);
  set(
    "SUCCESSOR_DESIGNATION_STATUS",
    !passed(i.probes.identityReuse)
      ? "IDENTITY_REUSE_NOT_REFUSED"
      : successors.length === 0
        ? "PROGRAM_REBUILD_SUCCESSORS_ONLY_NONE_DESIGNATED"
        : `SUCCESSORS_DESIGNATED: ${successors.map((x) => x.id).join(", ")}`,
    [
      `successor designations: ${successors.length === 0 ? "none" : successors.map((x) => `${x.id} (succeeds ${String(x.predecessor?.id)})`).join(", ")}`,
      probeLine(i.probes.identityReuse),
      "a successor is a program rebuild: a new subject under the first designation's procedure, field for field, on a designated verifier; it names its predecessor and its reason, and leaves every earlier file byte-identical",
      "its ELF and vkey are what its evidence bundle reports until the canonical-build workflow, which compares with the latest designation, rebuilds that subject on two runners",
      "a new SP1 verifier cannot be designated by this tooling (it needs a trust-target derivation as SP1-TD1's): recovery from a halt for a verifier defect waits for that lane",
    ],
  );

  set("REGISTRY_APPEND_ONLY_STATUS", i.registryErrors.length === 0 ? "APPEND_ONLY_ON_FULL_HISTORY" : "VIOLATED", [
    `every parent edge of every commit reachable from HEAD, and the working tree, only extends ${REGISTRY_REL}, the designations, their evidence bundles and the wrapper builds: ${yes(i.registryErrors.length === 0)}`,
    "a shallow clone cannot show that, and fails closed",
    probeLine(i.probes.registryHistory),
    `a rewrite of main itself is outside any walk: main's ruleset forbids force pushes and deletion with nobody to bypass it, as measured at ${i.ruleset.observedAtUtc || "(no measurement)"} (${MAIN_RULESET_OBSERVATION_REL}): ${i.ruleset.errors.length > 0 ? "unmeasured" : yes(i.ruleset.gaps.length === 0)}; whoever administers the repository can change that, and only the next measurement would show it`,
    ...i.ruleset.gaps,
    ...i.ruleset.errors,
    ...i.registryErrors,
  ]);

  const factErrors = registryErrors(i.registry, i.builds, i.designations);
  set(
    "REGISTRY_BUILD_PROVENANCE_STATUS",
    factErrors.length === 0 && i.buildErrors.length === 0 ? "BUILD_RECORDED_PER_FACT" : "MISSING",
    [
      `${REGISTRY_REL} (${i.registry.schema}) holds ${facts.length} fact(s); a registration names the recorded wrapper build it was deployed from, and a wrapper is judged against that build, never today's compile (SP1-TD2 residual R2-3)`,
      `recorded builds: ${i.builds.map((b) => b.id).join(", ")}; the compiled wrapper is the latest: ${yes(i.buildErrors.length === 0)}`,
      ...factErrors,
      ...i.buildErrors,
    ],
  );

  const halts = facts.filter((f) => f.kind === "WRAPPER_HALTED");
  set(
    "CROSS_CHAIN_HALTED_IDENTITY_STATUS",
    passed(i.probes.haltedIdentity.registry) && passed(i.probes.haltedIdentity.deployPlan)
      ? "REPOSITORY_PUBLISHED_HALT_REFUSED_ON_EVERY_CHAIN"
      : "NOT_REFUSED",
    [
      probeLine(i.probes.haltedIdentity.registry),
      probeLine(i.probes.haltedIdentity.deployPlan),
      `halt facts recorded: ${halts.length}`,
      "a WRAPPER_HALTED fact, published by pull request, refuses its identity on every chain (registry, deployment plan, binding gate); it can only refuse: no oracle, no on-chain registry, no new principal",
      "liveness: another chain's tooling learns of a halt only once its fact is published; the halt principal's procedure must halt each chain's wrapper of the identity",
    ],
  );

  const perChain =
    i.chainExecution.errors.length === 0 && i.chainExecution.verdictsAsRequired && i.chainExecution.codes.length === 1;
  set("PER_CHAIN_EXECUTION_CHECK", perChain ? "PASSED" : "FAILED", [
    ...i.chainExecution.chains.map(
      (c) =>
        `chain ${c.chainId}, finalized block ${c.block}: real ${c.verdicts.real}, tampered ${c.verdicts.tampered}, canary ${c.verdicts.canary}`,
    ),
    `required (constants of the check): real ${REQUIRED_VERDICTS.real}, tampered ${REQUIRED_VERDICTS.tampered}, canary ${REQUIRED_VERDICTS.canary}; two agreeing providers per chain; the canary's positive control fires`,
    ...i.chainExecution.errors,
  ]);

  const f1 =
    i.ast.chainIdNarrowings > 0 || !i.ast.chainIdComparedFullWidth
      ? "TRUNCATING"
      : !same(i.ast.journalTypes, i.journalTypesAtBase)
        ? "PROOF_FORMAT_CHANGED"
        : i.designationErrors.length > 0 || i.subjectErrors.length > 0
          ? "GUEST_CHANGE_NOT_EXCLUDED"
          : "FULL_WIDTH_WRAPPER_ONLY";
  set("F1_CHAIN_ID_FIX", f1, [
    `conversions of block.chainid to a narrower type in the wrapper: ${i.ast.chainIdNarrowings}`,
    `verify() hands block.chainid itself to _chainIdMatches, which compares uint256(committed) == chainId: ${yes(i.ast.chainIdComparedFullWidth)}`,
    `the journal decodes as (${i.ast.journalTypes.join(", ")}), at the base ${i.baseCommit} as (${i.journalTypesAtBase.join(", ")})`,
    `the zkvm subject is the designated one, so the guest, the ELF and PROGRAM_VKEY are unchanged: ${yes(i.designationErrors.length === 0)}`,
    "F-2 stays informational: the journal's signature hash is not checked, and no authorization fact depends on which valid signature was used",
  ]);

  const outsideLane = !same(i.contractsChanged, LANE_CONTRACT_CHANGES);
  const td2Holds =
    same(i.ast.mutatingFunctions, ["halt"]) &&
    i.ast.haltSetsOnlyTrue &&
    i.ast.verifyChecksHaltFirst &&
    i.ast.immutables.HALT_PRINCIPAL === "immutable";
  const changed = i.contractsChanged.map((c) => `${c.status} ${c.path}`).join(", ");
  set(
    "TD2_HALT_INVARIANTS_PRESERVED",
    // What the code shows decides PRESERVED or WEAKENED; a TD2 record that does not validate is invalid evidence
    // (TD2_RECORD_INVALID: no STOP, and the verdict is EVIDENCE_INVALID), never a demonstrated weakening.
    outsideLane
      ? "CHANGED_OUTSIDE_THE_WRAPPER"
      : !td2Holds
        ? "WEAKENED"
        : i.td2.errors.length > 0
          ? "TD2_RECORD_INVALID"
          : "PRESERVED",
    [
      `SP1-TD2's record validates against SP1-TD1 and the repository: ${yes(i.td2.errors.length === 0)}`,
      `the wrapper's state-changing functions: ${i.ast.mutatingFunctions.join(", ")}; HALT_PRINCIPAL is ${i.ast.immutables.HALT_PRINCIPAL}`,
      `halted is written once, in halt(), only to true: ${yes(i.ast.haltSetsOnlyTrue)}; verify() first returns false when halted: ${yes(i.ast.verifyChecksHaltFirst)}`,
      `contract sources changed since the base ${i.baseCommit}: ${changed} (the lane's own: the wrapper and its F-1 probe; no consumer, rotation guard or delay)`,
      ...i.td2.errors,
    ],
  );

  const multisigHolds = i.td2.multisigClass === NEW_AUTHORITY && !outsideLane;
  set("MULTISIG_AUTHORIZATION_CLASS_PRESERVED", multisigHolds ? NEW_AUTHORITY : "CHANGED", [
    `SP1-TD2's authorization cut classifies the multisig vault owner's delayed rotation ${String(i.td2.multisigClass)} (the owner accepted it), never authority-neutral`,
    `no contract outside the wrapper changed, so the multisig vault, its 172,800 s rotation and its cut are SP1-TD2's: ${yes(!outsideLane)}`,
  ]);

  set(
    "PROVING_AVAILABILITY",
    i.proving.errors.length === 0 && i.proving.status !== null ? i.proving.status : "INVALID",
    [
      `${PROVING_AVAILABILITY_REL}, derived from ${PROVING_ARTIFACTS_OBSERVATION_REL}: ${String(i.proving.status)}`,
      "availability needs a verified WalletWall archive of the circuit artifacts and an exercised self-hosted proving path; upstream hosting them is not availability",
      ...i.proving.errors,
    ],
  );

  const active = facts.filter(
    (f) =>
      f.kind === "WRAPPER_REGISTERED" &&
      SUPPORTED_DEPLOYMENT_CHAINS.includes(f.chainId) &&
      i.designations.some((x) => x.identity === f.identity) &&
      registryState(i.registry).haltsOfIdentity(f.identity).length === 0,
  );
  // Every validator's record, by source: a receipt over invalid records shows nothing (review finding F6).
  const recordFailures = (
    [
      ["TD1_RECEIPT", i.td1.errors],
      ["TD2_RECORD", i.td2.errors],
      ["DESIGNATIONS", i.designationErrors],
      ["WRAPPER_BUILDS", i.buildErrors],
      ["REGISTRY", i.registryErrors],
      ["CHAIN_EXECUTION", i.chainExecution.errors],
      ["CANONICAL_REBUILD", i.canonical.evidenceErrors],
      ["PROVING", i.proving.errors],
      ["RULESET", i.ruleset.errors],
    ] as const
  )
    .filter(([, errors]) => errors.length > 0)
    .map(([source]) => source);

  const stop: Record<(typeof STOP_CONDITION_IDS)[number], [boolean, string]> = {
    // Only a completed rebuild that produced another ELF or vkey, in evidence that re-derives, shows the designation
    // is not reproduced; an incomplete build, a procedure that drifted or invalid evidence shows no reproduction, and
    // is not this STOP (invalid evidence is EVIDENCE_INVALID).
    CANONICAL_BUILD_DOES_NOT_REPRODUCE: [
      canonicalEvidenceValid &&
        (i.canonical.oneHost === "PROGRAM_IDENTITY_DRIFT" || i.canonical.twoHost === "PROGRAM_IDENTITY_DRIFT"),
      `rebuild: ${i.canonical.oneHost} (one host), ${i.canonical.twoHost} (two)`,
    ],
    ONE_ELF_CONFLICTING_VKEYS: [
      (canonicalEvidenceValid && i.canonical.conflictingVkeys > 0) ||
        i.designations.some((x) => x.vkeyRecomputed.conflicting !== 0) ||
        i.designationErrors.some((e) => e.includes("PROGRAM_IDENTITY_CONTRADICTION")),
      `conflicting vkeys for a designated ELF: ${i.canonical.conflictingVkeys} in the rebuild evidence; across the designations: ${i.designationErrors.filter((e) => e.includes("PROGRAM_IDENTITY_CONTRADICTION")).length}`,
    ],
    CHAINS_DISAGREE_ON_RUNTIME_IDENTITY: [
      i.chainExecution.codes.length !== 1 || s.SP1_VERIFIER_RUNTIME_HASH.value === "INCONSISTENT",
      `distinct verifier code hashes across the measured chains: ${i.chainExecution.codes.length}`,
    ],
    PER_CHAIN_VERDICTS_DIVERGE: [
      !i.chainExecution.verdictsAsRequired,
      `every chain gives the required verdicts: ${yes(i.chainExecution.verdictsAsRequired)}`,
    ],
    PIN_BYPASSABLE_VIA_GATEWAY_ROUTING: [
      !(
        i.ast.constructorPinsCodehash &&
        i.ast.immutables.SP1_VERIFIER === "immutable" &&
        same(i.ast.sp1CallTargets, ["SP1_VERIFIER"])
      ),
      `the proof check calls only the immutable, constructor-pinned SP1_VERIFIER: ${yes(same(i.ast.sp1CallTargets, ["SP1_VERIFIER"]))}`,
    ],
    PRODUCTION_VALUES_OVERRIDABLE: [
      !i.probes.overrides.every(passed),
      `override probes refused with their controls accepted: ${i.probes.overrides.filter(passed).length} of ${i.probes.overrides.length}`,
    ],
    // A rewrite inside the history is the walk's to see (the probe shows it can); a rewrite of main itself is the
    // ruleset's to forbid (measured). A violation the walk did detect is invalid evidence (REGISTRY), not this STOP.
    REGISTRY_HISTORY_REWRITABLE_UNDETECTED: [
      !passed(i.probes.registryHistory) || i.ruleset.gaps.length > 0,
      `${probeLine(i.probes.registryHistory)}; main's history protected by its ruleset: ${i.ruleset.errors.length > 0 ? "unmeasured (EVIDENCE_INVALID)" : i.ruleset.gaps.length === 0 ? `yes (observed ${i.ruleset.observedAtUtc})` : `no: ${i.ruleset.gaps.join("; ")}`}`,
    ],
    HALTED_IDENTITY_REPUBLISHABLE_BY_ADDRESS_CHANGE: [
      !(
        passed(i.probes.identityReuse) &&
        passed(i.probes.haltedIdentity.registry) &&
        passed(i.probes.haltedIdentity.deployPlan)
      ),
      "identity is keccak256(code hash, PROGRAM_VKEY), address-free; the reuse and halted-identity probes refuse with their controls accepted",
    ],
    CROSS_CHAIN_FIX_NEEDS_NEW_MUTABLE_PRINCIPAL: [
      !same(i.ast.mutatingFunctions, ["halt"]) || outsideLane,
      `the wrapper's only mutator is halt(), and no contract outside the wrapper changed: the cross-chain refusal is repository-published data`,
    ],
    F1_CHANGES_GUEST_ELF_VKEY_OR_PROOF_FORMAT: [
      f1 === "PROOF_FORMAT_CHANGED" || i.subjectErrors.length > 0,
      `F1_CHAIN_ID_FIX is ${f1}; the zkvm subject at HEAD is the designated one: ${yes(i.subjectErrors.length === 0)} (a designation that does not validate otherwise is EVIDENCE_INVALID)`,
    ],
    RPC_FAILURE_FAILS_OPEN: [
      !(passed(i.probes.rpc) && i.probes.finality.length > 0 && i.probes.finality.every(passed)),
      [i.probes.rpc, ...i.probes.finality].map(probeLine).join("; "),
    ],
    TD2_INVARIANTS_WEAKENED: [
      ["WEAKENED", "CHANGED_OUTSIDE_THE_WRAPPER"].includes(s.TD2_HALT_INVARIANTS_PRESERVED.value),
      `TD2_HALT_INVARIANTS_PRESERVED is ${s.TD2_HALT_INVARIANTS_PRESERVED.value}`,
    ],
    BYTECODE_EXCEEDS_BUDGET: [
      !i.sizes.every((x) => x.withinLimit),
      `every gated contract's runtime is within EIP-170: ${yes(i.sizes.every((x) => x.withinLimit))}`,
    ],
  };
  const stopConditions = STOP_CONDITIONS.map(([id, condition]) => ({
    id,
    condition,
    triggered: stop[id][0],
    basis: stop[id][1],
  }));
  const triggered = stopConditions.filter((c) => c.triggered).map((c) => c.id);

  const prerequisites: Prerequisite[] = [
    {
      id: "RECORDS_VALID",
      met: recordFailures.length === 0,
      reachableInThisLane: true,
      basis: `every record validates (TD1, TD2, designations, builds, registry, chain execution, canonical rebuild, proving, ruleset): ${recordFailures.length === 0 ? "yes" : `no: ${recordFailures.join(", ")}`}`,
    },
    {
      id: "DIRECT_VERIFIER_PIN",
      reachableInThisLane: true,
      met: s.SP1_DIRECT_VERIFIER_PIN.value === "CONSTRUCTOR_CODE_HASH_PIN",
      basis: `SP1_DIRECT_VERIFIER_PIN is ${s.SP1_DIRECT_VERIFIER_PIN.value}`,
    },
    {
      id: "PROGRAM_VKEY_DESIGNATION",
      reachableInThisLane: true,
      met: i.designationErrors.length === 0,
      basis: `PROGRAM_VKEY_DESIGNATION is ${s.PROGRAM_VKEY_DESIGNATION.value}`,
    },
    {
      id: "CANONICAL_RELEASE_REBUILD_TWO_HOSTS",
      reachableInThisLane: true,
      met:
        i.canonical.evidenceErrors.length === 0 &&
        i.canonical.twoHost === "REPRODUCED" &&
        i.canonical.designation === latestDesignation(i.designations)?.id,
      basis:
        `the committed rebuild evidence (valid: ${yes(i.canonical.evidenceErrors.length === 0)}), judged for the release (two distinct machines): ${i.canonical.twoHost}; ` +
        (i.canonical.designation === latestDesignation(i.designations)?.id
          ? `of the latest designation, ${i.canonical.designation}`
          : `of ${i.canonical.designation}, not the latest designation (${String(latestDesignation(i.designations)?.id)})`),
    },
    {
      id: "PER_CHAIN_EXECUTION_CHECK",
      reachableInThisLane: true,
      met: s.PER_CHAIN_EXECUTION_CHECK.value === "PASSED",
      basis: `PER_CHAIN_EXECUTION_CHECK is ${s.PER_CHAIN_EXECUTION_CHECK.value}`,
    },
    {
      id: "REGISTERED_ACTIVE_WRAPPER",
      reachableInThisLane: true,
      met: active.length > 0 && i.registryErrors.length === 0,
      basis: `registrations of a designated identity on a supported deployment chain, never recorded halted: ${active.length}; the registry validates, content and history: ${yes(i.registryErrors.length === 0)}; the binding gate reconciles each fact with the chain when it binds`,
    },
    {
      id: "REAL_WALLETWALL_PROOF",
      met: false,
      reachableInThisLane: false,
      basis: `${REAL_PROOF_RECORDS_DIR} holds no record, and no lane yet validates one: a WalletWall proof of the designated program, generated (the circuit download is the owner's to authorize) and verified by the designated verifier, needs that later lane`,
    },
    {
      id: "PROVING_AVAILABILITY",
      met: false,
      reachableInThisLane: false,
      basis: `PROVING_AVAILABILITY is ${s.PROVING_AVAILABILITY.value}: this lane derives only OWNER_DOWNLOAD_REQUIRED or LOCAL_COPY_NOT_ARCHIVED, never availability; a verified WalletWall archive of the circuit artifacts and an exercised proving path need a later lane`,
    },
    {
      id: "OWNER_REVIEW_AND_MERGE",
      met: false,
      reachableInThisLane: false,
      basis: "a receipt cannot attest its own review: the owner reviews and merges after this lane generates it",
    },
    {
      id: "NO_STOP_TRIGGERED",
      met: triggered.length === 0,
      reachableInThisLane: true,
      basis: `STOP conditions triggered: ${triggered.length === 0 ? "none" : triggered.join(", ")}`,
    },
  ];
  const binding = productionBindingStatus(prerequisites);
  const unmet = prerequisites.filter((p) => !p.met);
  set("PRODUCTION_SP1_BINDING_STATUS", binding, [
    `prerequisites unmet: ${unmet.length === 0 ? "none" : unmet.map((p) => p.id).join(", ")}`,
    "provenance says which verifier and program these are; it does not say they are sound",
  ]);

  const delta = same(i.ast.mutatingFunctions, ["halt"]) && !outsideLane;
  return {
    schema: IMPL_RECEIPT_SCHEMA,
    lane: IMPL_LANE,
    // A STOP outranks invalid evidence, which outranks a lane that is built and tested (review finding F6).
    verdict:
      triggered.length > 0
        ? `STOP: ${triggered.join(", ")}`
        : recordFailures.length > 0
          ? `EVIDENCE_INVALID: ${recordFailures.join(", ")}`
          : "BUILT_AND_TESTED_AWAITING_OWNER_REVIEW",
    baseCommit: i.baseCommit,
    statuses: Object.fromEntries(STATUS_KEYS.map((k) => [k, s[k]])) as Record<StatusKey, StatusEntry>,
    productionBinding: { status: binding, prerequisites },
    stopConditions,
    authorizationDelta: {
      value: delta ? "NONE_BEYOND_TD2" : "CHANGED",
      basis: [
        `the wrapper's only state-changing function is halt(), SP1-TD2's: ${yes(same(i.ast.mutatingFunctions, ["halt"]))}`,
        `no consumer, rotation guard or vault contract changed: ${yes(!outsideLane)}`,
        "the code-hash pin and F-1 only narrow what verifies; designations, the registry, the deployment plan and the per-chain check are process and liveness, holding no authorization",
      ],
    },
    realValue: {
      blocked: binding !== "ESTABLISHED",
      blockers: unmet.map((p) => `${p.id}: ${p.basis}`),
    },
    soundness: "NOT_ESTABLISHED_BY_PROVENANCE",
    probes: i.probes,
    wrapperAst: i.ast,
    contractsChangedSinceBase: i.contractsChanged,
    runtimeSizes: i.sizes,
    evidence: i.evidence,
  };
}

export function serializeImplReceipt(r: ImplReceipt): string {
  return `${JSON.stringify(r, null, 2)}\n`;
}

/** Whether a committed receipt's text is the derived receipt. */
export function compareReceipt(text: string, derived: ImplReceipt): string[] {
  if (text === serializeImplReceipt(derived)) return [];
  let committed: Record<string, unknown> = {};
  try {
    committed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return [`${IMPL_RECEIPT_REL} is not JSON`];
  }
  const differing = Object.keys(derived).filter(
    (k) => !same(committed[k], (derived as unknown as Record<string, unknown>)[k]),
  );
  return [
    `${IMPL_RECEIPT_REL} is not what the repository derives (${differing.join(", ") || "formatting"}): what changed ` +
      "needs new evidence: the historical receipt is never regenerated (docs/SP1_Impl_Receipt_Integration.md)",
  ];
}

/** git, reading the objects themselves (no replace ref, no graft), as the integration binding reads them. */
function git(repoRoot: string, args: string[]): string {
  return gitObjects(repoRoot, args).toString("utf8");
}

const jsonFiles = (repoRoot: string, dir: string) =>
  existsSync(resolve(repoRoot, dir))
    ? readdirSync(resolve(repoRoot, dir))
        .filter((f) => f.endsWith(".json"))
        .sort()
        .map((f) => `${dir}/${f}`)
    : [];

/**
 * The commit that last wrote the committed receipt, as of HEAD; HEAD when the receipt is uncommitted (being
 * generated). Its lane validated the receipt there. After the merge the binding names the writer as of the reviewed
 * head instead (readBoundReceiptInputs): a descendant that rewrote and restored the receipt moves this, not that.
 */
export function receiptCommit(repoRoot = "."): string {
  const uncommitted = git(repoRoot, ["status", "--porcelain", "--", IMPL_RECEIPT_REL]).trim() !== "";
  const last = uncommitted ? "" : git(repoRoot, ["log", "-1", "--format=%H", "--", IMPL_RECEIPT_REL]).trim();
  return last || git(repoRoot, ["rev-parse", "HEAD"]).trim();
}

/**
 * Whether `rev` carries the receipt. A commit git cannot read carries nothing it can show; such a base also fails the
 * rule's other checks (it is on no first-parent history git can read), so reading it as "carries none" passes nothing.
 */
function carriesReceipt(repoRoot: string, rev: string): boolean {
  try {
    git(repoRoot, ["cat-file", "-e", `${rev}:${IMPL_RECEIPT_REL}`]);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Supersession (SP1-PA2B: the archive record moves PROVING_AVAILABILITY, a status this receipt binds)
// ---------------------------------------------------------------------------------------------------------------
//
// The receipt reads proving availability from the working tree, so the lane that admits a WalletWall archive record
// (which moves the status to ARCHIVED_VERIFIED_UNEXERCISED and rewrites the availability record) would make every
// descendant re-derive another receipt. Restamping the historical receipt would erase what it proved. Instead, as
// SP1-P1's receipt was superseded, a supersession record pins the receipt's exact bytes, names a first-parent main
// commit at which the receipt was live, and names what superseded it; the superseded status and the availability
// file's digest are then derived at that commit, read from git, while everything else is still judged live. Only
// PROVING_AVAILABILITY can be superseded this way, and only once the live availability record validates and names an
// archived state: a supersession that hides a live refusal, or one filed while nothing moved, is itself refused.

export const IMPL_SUPERSESSION_REL = "evidence/zk/sp1-impl/receipt-supersession.json";
export const IMPL_SUPERSESSION_SCHEMA = "walletwall.sp1-impl-receipt-supersession.v1";
/** The statuses a supersession may hold at their historical derivation. */
export const SUPERSEDABLE_STATUSES: readonly StatusKey[] = ["PROVING_AVAILABILITY"];
/** The statuses proving availability may name while this receipt is live (SP1-IMPL derived only these). */
export const LIVE_AVAILABILITY_STATUSES: readonly string[] = ["OWNER_DOWNLOAD_REQUIRED", "LOCAL_COPY_NOT_ARCHIVED"];

export interface ImplSupersession {
  schema: string;
  receipt: string;
  /** sha256 of the committed receipt bytes: the record is pinned, never restamped. */
  receiptSha256: string;
  /** A first-parent commit of origin/main at which the receipt was live: its superseded bindings are read there. */
  historicalSubject: string;
  supersedes: StatusKey[];
  /** The records that supersede it; the first is the archive record that moved proving availability. */
  supersededBy: { lane: string; record: string; reason: string }[];
}

/** The supersession record, or null while the receipt is live. */
export function readImplSupersession(repoRoot = "."): unknown {
  const path = resolve(repoRoot, IMPL_SUPERSESSION_REL);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as unknown;
}

function availabilityStatusAt(repoRoot: string, commit: string): string | null {
  try {
    const doc = JSON.parse(gitObjects(repoRoot, ["show", `${commit}:${PROVING_AVAILABILITY_REL}`]).toString("utf8"));
    return typeof doc?.status === "string" ? doc.status : null;
  } catch {
    return null;
  }
}

/** The live proving-availability record's verdict: its validator's errors, and its status when it validates. */
export interface LiveAvailability {
  errors: string[];
  status: string | null;
}

export function liveAvailability(repoRoot = "."): LiveAvailability {
  const errors = provingAvailabilityErrors(repoRoot);
  return { errors, status: errors.length === 0 ? provingAvailabilityFromRepo(repoRoot).status : null };
}

/**
 * The proving-availability inputs the receipt derives from: live (the working tree, validated), or, once superseded,
 * the file as the historical subject committed it, read from git, with the status it names there and no live errors
 * (the supersession already established that the record was valid and live at that commit).
 */
export function provingAvailabilityInputs(
  repoRoot: string,
  historical: { commit: string } | null,
): LiveAvailability & { bytes: Buffer } {
  if (historical === null) {
    const live = liveAvailability(repoRoot);
    return { ...live, bytes: readFileSync(resolve(repoRoot, PROVING_AVAILABILITY_REL)) };
  }
  const bytes = gitObjects(repoRoot, ["show", `${historical.commit}:${PROVING_AVAILABILITY_REL}`]);
  const doc = JSON.parse(bytes.toString("utf8"));
  return { errors: [], status: typeof doc?.status === "string" ? doc.status : null, bytes };
}

/**
 * The validated supersession's historical subject, null while the receipt is live; an invalid supersession throws
 * naming every reason (a descendant that files one cannot make the receipt derive by it).
 */
export function boundSupersession(
  repoRoot = ".",
  live: LiveAvailability = liveAvailability(repoRoot),
): { commit: string } | null {
  const supersession = readImplSupersession(repoRoot);
  if (supersession === null) return null;
  const bad = implSupersessionErrors(supersession, readFileSync(resolve(repoRoot, IMPL_RECEIPT_REL)), repoRoot, live);
  if (bad.length > 0) throw new Error(`${IMPL_SUPERSESSION_REL} is invalid: ${bad.join("; ")}`);
  return { commit: (supersession as ImplSupersession).historicalSubject };
}

/** Every reason `value` is not a valid supersession of the committed receipt bytes in this repository. */
export function implSupersessionErrors(
  value: unknown,
  receiptBytes: Buffer,
  repoRoot = ".",
  live: LiveAvailability = liveAvailability(repoRoot),
): string[] {
  const errors: string[] = [];
  const s = value as Partial<ImplSupersession> | null;
  if (s === null || typeof s !== "object" || Array.isArray(s)) return ["the supersession record is not an object"];
  if (s.schema !== IMPL_SUPERSESSION_SCHEMA) errors.push(`supersession schema must be ${IMPL_SUPERSESSION_SCHEMA}`);
  if (s.receipt !== IMPL_RECEIPT_REL) errors.push(`supersession must name ${IMPL_RECEIPT_REL}`);
  if (s.receiptSha256 !== sha256(receiptBytes)) {
    errors.push(
      "the committed receipt is not the bytes the supersession pinned (a superseded receipt is never restamped)",
    );
  }
  if (!same(s.supersedes, SUPERSEDABLE_STATUSES)) {
    errors.push(
      `supersedes must be exactly ${SUPERSEDABLE_STATUSES.join(", ")}: no other status is superseded this way`,
    );
  }
  const commit =
    typeof s.historicalSubject === "string" && /^[0-9a-f]{40}$/.test(s.historicalSubject) ? s.historicalSubject : null;
  if (commit === null) {
    errors.push("historicalSubject must be a full commit id");
  } else {
    let mainline: string[] = [];
    try {
      mainline = git(repoRoot, ["rev-list", "--first-parent", MAIN_REF]).split("\n").filter(Boolean);
    } catch {
      errors.push("origin/main is not available, with its history: the historical subject cannot be verified");
    }
    if (mainline.length > 0 && !mainline.includes(commit)) {
      errors.push(`the historical subject ${commit} is no commit of origin/main's first-parent history`);
    }
    try {
      git(repoRoot, ["merge-base", "--is-ancestor", commit, "HEAD"]);
    } catch {
      errors.push(`the historical subject ${commit} is not an ancestor of HEAD, or the history is unavailable`);
    }
    let then: Buffer | null = null;
    try {
      then = gitObjects(repoRoot, ["show", `${commit}:${IMPL_RECEIPT_REL}`]);
    } catch {
      then = null;
    }
    if (then === null) errors.push(`the receipt is not in the repository at ${commit} (or the commit is unavailable)`);
    else if (!then.equals(receiptBytes)) errors.push(`the receipt at ${commit} is not the committed receipt`);
    const historical = availabilityStatusAt(repoRoot, commit);
    if (historical === null || !LIVE_AVAILABILITY_STATUSES.includes(historical)) {
      errors.push(
        `at ${commit} proving availability was ${String(historical)}, not a status this receipt derived live (${LIVE_AVAILABILITY_STATUSES.join(", ")})`,
      );
    }
  }
  // The supersession is justified only by a live availability record that validates and has moved to an archived state.
  if (live.errors.length > 0) {
    errors.push(
      `the live proving-availability record does not validate, so nothing supersedes the receipt: ${live.errors.join("; ")}`,
    );
  } else if (live.status === null || LIVE_AVAILABILITY_STATUSES.includes(live.status)) {
    errors.push(
      `proving availability is still ${String(live.status)}: nothing superseded the receipt, so no supersession may be filed`,
    );
  }
  if (!Array.isArray(s.supersededBy) || s.supersededBy.length === 0) {
    errors.push("supersededBy must name at least one superseding record");
  } else {
    const first = s.supersededBy[0];
    if (typeof first?.record !== "string" || !first.record.startsWith(`${PROVING_ARCHIVES_DIR}/`)) {
      errors.push(`the first superseding record must be the archive record under ${PROVING_ARCHIVES_DIR}`);
    }
    for (const r of s.supersededBy) {
      if (
        typeof r?.lane !== "string" ||
        r.lane.length === 0 ||
        typeof r?.reason !== "string" ||
        r.reason.length === 0
      ) {
        errors.push("each superseding record has a lane and a reason");
      }
      if (typeof r?.record !== "string" || !existsSync(resolve(repoRoot, r.record))) {
        errors.push(`superseding record ${String(r?.record)} does not exist`);
      }
    }
  }
  return errors;
}

/**
 * Why `base` is not the receipt's base (review finding F5). The base decides which contract sources changed and what
 * the journal decoded as before, so it is verified, never taken from the receipt: it must be a published main commit
 * (on origin/main's first-parent history), an ancestor of HEAD, and the latest main commit in the history of `at`,
 * the commit that wrote the receipt. That holds where the lane wrote it, at a pull request's synthetic merge, and on
 * main after the merge; a lane commit, or an older main commit (one that would hide a revert), is refused. A base
 * that already carries the receipt (the lane's own merge, or any main after it) is refused too: a lane's base precedes
 * its receipt, and against such a base the lane's own changes read as none (the false STOP). Without origin/main and
 * its history nothing is judged.
 */
export function baseCommitErrors(repoRoot: string, base: string, at: string): string[] {
  if (!/^[0-9a-f]{40}$/.test(String(base))) return ["the base commit must be a full commit id"];
  const list = (args: string[]) => git(repoRoot, args).split("\n").filter(Boolean);
  let mainline: string[];
  try {
    mainline = list(["rev-list", "--first-parent", MAIN_REF]);
  } catch {
    return [
      "origin/main is not available, with its history: the base cannot be verified, and the receipt is not judged",
    ];
  }
  const errors: string[] = [];
  if (carriesReceipt(repoRoot, base)) {
    errors.push(
      `the base ${base} already carries ${IMPL_RECEIPT_REL}: a lane's base precedes its receipt. Once merged, the ` +
        "receipt is historical and never regenerated: npm run validate:sp1-impl-receipt judges a descendant against " +
        `its integrated subject (${IMPL_RECEIPT_INTEGRATION_REL})`,
    );
  }
  const index = mainline.indexOf(base);
  if (index === -1) {
    errors.push(`the base ${base} is no commit of origin/main's first-parent history: only a published main is a base`);
  }
  try {
    git(repoRoot, ["merge-base", "--is-ancestor", base, "HEAD"]);
  } catch {
    errors.push(`the base ${base} is not an ancestor of HEAD, or the history is unavailable`);
  }
  if (index > 0) {
    let since: Set<string>;
    try {
      since = new Set(list(["rev-list", at, `^${base}`]));
    } catch {
      return [...errors, `cannot read the history of ${at}`];
    }
    const self = git(repoRoot, ["rev-parse", "--verify", `${at}^{commit}`]).trim();
    const later = mainline.slice(0, index).find((c) => since.has(c) && c !== self);
    if (later !== undefined) {
      errors.push(
        `the base ${base} is not the latest main commit in the history of ${at}: ${later} is later; regenerate the ` +
          "receipt (npm run sp1-impl:receipt)",
      );
    }
  }
  return errors;
}

/**
 * Main's ruleset as the receipt reads it: a missing or malformed record is invalid evidence (errors) and shows no
 * gaps, because it shows nothing; only a well-formed record has gaps to show.
 */
export function rulesetInput(obs: RulesetObservation | null): ImplReceiptInputs["ruleset"] {
  const errors = obs === null ? [`no observation at ${MAIN_RULESET_OBSERVATION_REL}`] : rulesetObservationErrors(obs);
  return {
    observedAtUtc: String(obs?.observedAtUtc ?? ""),
    errors,
    gaps: obs !== null && errors.length === 0 ? historyProtectionGaps(obs) : [],
  };
}

/** The contract sources changed since `rev`, against the working tree (what the receipt states as changed). */
function contractsChangedSince(repoRoot: string, rev: string): { path: string; status: string }[] {
  return git(repoRoot, ["diff", "--name-status", "--no-renames", rev, "--", "contracts"])
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => {
      const [status, path] = l.split("\t");
      return { path, status };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Everything the derivation needs, read from the repository at `repoRoot` (compile first). The base is verified at
 * `at`: HEAD when generating, the commit that wrote the receipt (as of its reviewed head) when validating it. Whether
 * main moved under the receipt after its base (the re-review's A2) is the integration binding's to judge
 * (readBoundReceiptInputs), against the merge that carried the reviewed subject into main.
 */
export async function readImplReceiptInputs(
  repoRoot: string,
  baseCommit: string,
  at = "HEAD",
  /** A validated supersession's historical subject: the superseded status and file are read from git there. */
  historical: { commit: string } | null = null,
): Promise<ImplReceiptInputs> {
  const baseErrors = baseCommitErrors(repoRoot, baseCommit, at);
  if (baseErrors.length > 0) throw new Error(baseErrors.join("; "));
  if (jsonFiles(repoRoot, REAL_PROOF_RECORDS_DIR).length > 0) {
    throw new Error(
      `${REAL_PROOF_RECORDS_DIR}: real-proof records have no validator in this lane; a lane must define and validate them before they count`,
    );
  }
  const proving = provingAvailabilityInputs(repoRoot, historical);
  const read = (rel: string) =>
    rel === PROVING_AVAILABILITY_REL ? proving.bytes : readFileSync(resolve(repoRoot, rel));

  const td1 = JSON.parse(read(TD1_RECEIPT_REL).toString("utf8"));
  const td2 = JSON.parse(read(TD2_RECORD_REL).toString("utf8"));
  const designations = readDesignations(repoRoot);
  const builds = readWrapperBuilds(repoRoot);
  const registry = readRegistry(repoRoot);

  const chainObs = JSON.parse(read(CHAIN_EXECUTION_OBSERVATION_REL).toString("utf8")) as ChainExecutionObservation;
  const chainDesignation = designations.find((x) => x.id === chainObs.designation);
  const chains = Object.entries(chainObs.chains ?? {})
    .map(([chainId, c]) => ({
      chainId,
      block: Number(c.finalized?.block),
      codeKeccak: String(c.codeKeccak),
      verdicts: { ...c.verdicts },
      providersAgree: c.providersAgree === true,
    }))
    .sort((a, b) => Number(a.chainId) - Number(b.chainId));

  const canonObs = JSON.parse(read(CANONICAL_REBUILD_OBSERVATION_REL).toString("utf8")) as CanonicalBuildObservation;
  const canonDesignation = designations.find((x) => x.id === canonObs.designation);
  if (!canonDesignation) throw new Error(`the rebuild observation names no designation (${canonObs.designation})`);
  const canonRecords = recordsDirOf(CANONICAL_REBUILD_OBSERVATION_REL);
  const canonRecordFiles = existsSync(resolve(repoRoot, canonRecords))
    ? git(repoRoot, ["ls-files", "--", canonRecords]).split("\n").filter(Boolean).sort()
    : [];

  const { abi, contract } = compiledWrapper(repoRoot);
  const contractsChanged = contractsChangedSince(repoRoot, baseCommit);
  const multisig = (Array.isArray(td2.authorizationCut) ? td2.authorizationCut : []).find(
    (c: { principal?: string }) => c?.principal === MULTISIG_OWNER,
  );

  const ruleset = rulesetInput(readRulesetObservation(repoRoot));

  const evidenceFiles = [
    TD1_RECEIPT_REL,
    TD2_RECORD_REL,
    ...jsonFiles(repoRoot, DESIGNATIONS_DIR),
    ...jsonFiles(repoRoot, DESIGNATION_EVIDENCE_DIR),
    ...jsonFiles(repoRoot, WRAPPER_BUILDS_DIR),
    REGISTRY_REL,
    CHAIN_EXECUTION_OBSERVATION_REL,
    CANONICAL_REBUILD_OBSERVATION_REL,
    ...canonRecordFiles,
    PROVING_ARTIFACTS_OBSERVATION_REL,
    PROVING_AVAILABILITY_REL,
    MAIN_RULESET_OBSERVATION_REL,
    WRAPPER_SOURCE,
  ];

  return {
    baseCommit,
    td1: {
      programIdentityDecision: String(td1.decisions?.PROGRAM_IDENTITY_DECISION),
      trustTargetCodeKeccak: String(td1.trustTarget?.codeKeccak),
      forbiddenOpcodes: Array.isArray(td1.trustTarget?.runtime?.forbiddenOpcodes)
        ? td1.trustTarget.runtime.forbiddenOpcodes.map(String)
        : ["(not recorded)"],
      errors: validateCommittedDecisionReceipt(td1, readDecisionContext(repoRoot)),
    },
    td2: {
      errors: validateCommittedTd2Record(repoRoot),
      multisigClass: multisig ? String(multisig.classification) : null,
    },
    designations,
    designationErrors: validateDesignationsInRepo(repoRoot),
    subjectErrors:
      designations.length > 0 ? subjectFreshnessErrors(designations[designations.length - 1], repoRoot) : [],
    builds,
    buildErrors: [...wrapperBuildErrors(builds), ...currentBuildErrors(repoRoot)],
    registry,
    registryErrors: validateRegistryInRepo(repoRoot),
    chainExecution: {
      designation: chainObs.designation,
      errors: chainDesignation
        ? chainExecutionObservationErrors(chainObs, chainDesignation, repoRoot)
        : [`the per-chain observation names no designation (${chainObs.designation})`],
      codes: [...new Set(chains.map((c) => c.codeKeccak))],
      verdictsAsRequired:
        chains.length > 0 && chains.every((c) => c.providersAgree && same(c.verdicts, REQUIRED_VERDICTS)),
      chains: chains.map(({ chainId, block, codeKeccak, verdicts }) => ({ chainId, block, codeKeccak, verdicts })),
    },
    canonical: {
      designation: canonDesignation.id,
      oneHost: canonicalBuildVerdict(canonObs, canonDesignation, { minimumHosts: 1 }),
      twoHost: canonicalBuildVerdict(canonObs, canonDesignation, { minimumHosts: 2 }),
      hosts: canonObs.builds.map((b) => b.hostId),
      conflictingVkeys: conflictingVkeyCount(canonObs, canonDesignation),
      evidenceErrors: canonicalRebuildEvidenceErrors(repoRoot),
      lockUnchangedOn: canonObs.builds
        .filter(
          (b) =>
            b.guestLockBefore === canonDesignation.subject.guestCargoLockSha256 &&
            b.guestLockAfter === canonDesignation.subject.guestCargoLockSha256,
        )
        .map((b) => b.hostId),
    },
    proving: { status: proving.status, errors: proving.errors },
    ast: wrapperAstFacts(contract, abi),
    journalTypesAtBase: journalTypesInSource(git(repoRoot, ["show", `${baseCommit}:${WRAPPER_SOURCE}`])),
    contractsChanged,
    sizes: collectReports().map((r) => ({ name: r.name, runtimeBytes: r.runtimeBytes, withinLimit: !r.overLimit })),
    probes: {
      overrides: probeOverrides(planWrapperDeployment, designations, builds),
      haltedIdentity: probeHaltedIdentityElsewhere(designations, builds),
      identityReuse: probeIdentityReuse(designations),
      rpc: probeRpcFailClosed(),
      registryHistory: probeRegistryHistory(designations, builds),
      finality: await probeFinalityReads(),
    },
    ruleset,
    evidence: evidenceFiles.map((path) => ({ path, sha256: sha256(read(path)) })),
  };
}

/**
 * The inputs the committed receipt is judged by after its merge. This tree is first bound to the receipt's integrated
 * subject (scripts/lib/sp1-impl-receipt-integration.ts): the committed binding must be what git derives, HEAD must
 * descend from the merge, and HEAD and the working tree must carry its contracts and the receipt byte for byte. The
 * receipt is then derived from its historical lane base, verified where the lane wrote it, as the binding names them:
 * never from the receipt's own text, and never against HEAD's history, which now holds the merge itself.
 */
export async function readBoundReceiptInputs(repoRoot = "."): Promise<ImplReceiptInputs> {
  const { errors, record } = receiptIntegrationErrors(repoRoot, IMPL_RECEIPT_REL);
  if (record === null) throw new Error(errors.join("; "));
  const drift = descendantDriftErrors(repoRoot, record.descendantDriftBaseline);
  if (drift.length > 0) throw new Error(drift.join("; "));
  return readImplReceiptInputs(
    repoRoot,
    record.historicalReceipt.historicalLaneBase,
    record.historicalReceipt.writtenAt,
    boundSupersession(repoRoot),
  );
}

/** Every reason the committed receipt is not what the repository derives, judged as readBoundReceiptInputs binds it. */
export async function implReceiptErrors(repoRoot = "."): Promise<string[]> {
  try {
    const inputs = await readBoundReceiptInputs(repoRoot);
    return compareReceipt(readFileSync(resolve(repoRoot, IMPL_RECEIPT_REL), "utf8"), deriveImplReceipt(inputs));
  } catch (error) {
    return [messageOf(error)];
  }
}
