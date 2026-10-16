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
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { getAddress } from "ethers";

import { collectReports } from "../validate-bytecode-size";
import { isExecutionFailure } from "./rpc-answer";
import {
  CANONICAL_REBUILD_OBSERVATION_REL,
  canonicalBuildVerdict,
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
  readDesignations,
  validateDesignationsInRepo,
  type ProgramDesignation,
} from "./sp1-designation";
import {
  PROVING_ARTIFACTS_OBSERVATION_REL,
  PROVING_AVAILABILITY_REL,
  provingAvailabilityErrors,
  provingAvailabilityFromRepo,
} from "./sp1-proving-availability";
import {
  MIGRATED_FROM,
  REGISTRY_REL,
  REGISTRY_SCHEMA,
  readRegistry,
  registryErrors,
  registryState,
  validateRegistryInRepo,
  type RegistryDoc,
  type RegistryFact,
} from "./sp1-registry";
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
  const first = verify?.body?.statements?.[0];

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
      first.trueBody?.nodeType === "Return" &&
      first.trueBody.expression?.value === "false",
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
  canonical: { designation: string; oneHost: string; twoHost: string; hosts: string[]; conflictingVkeys: number };
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
  };
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
    `ELF sha256 ${d?.elf.sha256} (${d?.elf.bytes} bytes) → PROGRAM_VKEY ${d?.programVKey}, recomputed outside the build by ${d?.vkeyRecomputed.tool} (${d?.vkeyRecomputed.agreeing} agreeing, ${d?.vkeyRecomputed.conflicting} conflicting) on ${d?.hosts.join(" and ")}`,
    `identity ${d?.identity} = keccak256(abi.encode(verifier runtime code hash, PROGRAM_VKEY)); soundness: ${d?.soundness}`,
    ...i.designationErrors,
  ]);

  set("CANONICAL_BUILD_STATUS", i.canonical.oneHost, [
    `the frozen subject rebuilt by the canonical procedure on ${i.canonical.hosts.join(", ")}, compared with designation ${i.canonical.designation}: ${i.canonical.oneHost}`,
    `the release rebuild needs two hosts: the committed evidence gives ${i.canonical.twoHost}; .github/workflows/sp1-canonical-build.yml rebuilds on two runners, recomputes the vkey on another from the ELFs alone and fails on any drift`,
    `one ELF with another vkey, in a build or the outside recompute: ${i.canonical.conflictingVkeys}`,
  ]);

  const successors = i.designations.filter((x) => x.predecessor !== null);
  set(
    "SUCCESSOR_DESIGNATION_STATUS",
    !passed(i.probes.identityReuse)
      ? "IDENTITY_REUSE_NOT_REFUSED"
      : successors.length === 0
        ? "SUCCESSOR_PATH_READY_NONE_DESIGNATED"
        : `SUCCESSORS_DESIGNATED: ${successors.map((x) => x.id).join(", ")}`,
    [
      `successor designations: ${successors.length === 0 ? "none" : successors.map((x) => `${x.id} (succeeds ${String(x.predecessor?.id)})`).join(", ")}`,
      probeLine(i.probes.identityReuse),
      "a successor is derived from a committed evidence bundle meeting the first designation's contract, names its predecessor and its reason, and leaves every earlier file byte-identical",
    ],
  );

  set("REGISTRY_APPEND_ONLY_STATUS", i.registryErrors.length === 0 ? "APPEND_ONLY_ON_FULL_HISTORY" : "VIOLATED", [
    `every parent edge of every commit reachable from HEAD, and the working tree, only extends ${REGISTRY_REL}, the designations, their evidence bundles and the wrapper builds: ${yes(i.registryErrors.length === 0)}`,
    "a shallow clone cannot show that, and fails closed",
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
        : i.designationErrors.length > 0
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
    i.td2.errors.length === 0 &&
    same(i.ast.mutatingFunctions, ["halt"]) &&
    i.ast.haltSetsOnlyTrue &&
    i.ast.verifyChecksHaltFirst &&
    i.ast.immutables.HALT_PRINCIPAL === "immutable";
  const changed = i.contractsChanged.map((c) => `${c.status} ${c.path}`).join(", ");
  set(
    "TD2_HALT_INVARIANTS_PRESERVED",
    outsideLane ? "CHANGED_OUTSIDE_THE_WRAPPER" : td2Holds ? "PRESERVED" : "WEAKENED",
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
  const prerequisites: Prerequisite[] = [
    {
      id: "DIRECT_VERIFIER_PIN",
      met: s.SP1_DIRECT_VERIFIER_PIN.value === "CONSTRUCTOR_CODE_HASH_PIN",
      basis: `SP1_DIRECT_VERIFIER_PIN is ${s.SP1_DIRECT_VERIFIER_PIN.value}`,
    },
    {
      id: "PROGRAM_VKEY_DESIGNATION",
      met: i.designationErrors.length === 0,
      basis: `PROGRAM_VKEY_DESIGNATION is ${s.PROGRAM_VKEY_DESIGNATION.value}`,
    },
    {
      id: "CANONICAL_RELEASE_REBUILD_TWO_HOSTS",
      met: i.canonical.twoHost === "REPRODUCED",
      basis: `the committed rebuild evidence, judged for the release (two hosts): ${i.canonical.twoHost}`,
    },
    {
      id: "PER_CHAIN_EXECUTION_CHECK",
      met: s.PER_CHAIN_EXECUTION_CHECK.value === "PASSED",
      basis: `PER_CHAIN_EXECUTION_CHECK is ${s.PER_CHAIN_EXECUTION_CHECK.value}`,
    },
    {
      id: "REGISTERED_ACTIVE_WRAPPER",
      met: active.length > 0,
      basis: `registrations of a designated identity on a supported deployment chain, never recorded halted: ${active.length}`,
    },
    {
      id: "REAL_WALLETWALL_PROOF",
      met: false,
      basis: `${REAL_PROOF_RECORDS_DIR} holds no record: no WalletWall proof of the designated program has been generated and verified by the designated verifier`,
    },
    {
      id: "PROVING_AVAILABILITY",
      met: i.proving.status === "ESTABLISHED",
      basis: `PROVING_AVAILABILITY is ${s.PROVING_AVAILABILITY.value}`,
    },
    {
      id: "OWNER_REVIEW_AND_MERGE",
      met: false,
      basis: "a receipt cannot attest its own review: the owner reviews and merges after it is generated",
    },
  ];
  const binding = productionBindingStatus(prerequisites);
  const unmet = prerequisites.filter((p) => !p.met);
  set("PRODUCTION_SP1_BINDING_STATUS", binding, [
    `prerequisites unmet: ${unmet.length === 0 ? "none" : unmet.map((p) => p.id).join(", ")}`,
    "provenance says which verifier and program these are; it does not say they are sound",
  ]);

  const stop: Record<(typeof STOP_CONDITION_IDS)[number], [boolean, string]> = {
    CANONICAL_BUILD_DOES_NOT_REPRODUCE: [i.canonical.oneHost !== "REPRODUCED", `rebuild: ${i.canonical.oneHost}`],
    ONE_ELF_CONFLICTING_VKEYS: [
      i.canonical.conflictingVkeys > 0 || i.designations.some((x) => x.vkeyRecomputed.conflicting !== 0),
      `conflicting vkeys for a designated ELF: ${i.canonical.conflictingVkeys} in the rebuild evidence`,
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
    REGISTRY_HISTORY_REWRITABLE_UNDETECTED: [
      i.registryErrors.length > 0,
      `the append-only proof over the full history passes: ${yes(i.registryErrors.length === 0)}`,
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
      f1 === "PROOF_FORMAT_CHANGED" || f1 === "GUEST_CHANGE_NOT_EXCLUDED",
      `F1_CHAIN_ID_FIX is ${f1}`,
    ],
    RPC_FAILURE_FAILS_OPEN: [!passed(i.probes.rpc), probeLine(i.probes.rpc)],
    TD2_INVARIANTS_WEAKENED: [
      s.TD2_HALT_INVARIANTS_PRESERVED.value !== "PRESERVED",
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

  const delta = same(i.ast.mutatingFunctions, ["halt"]) && !outsideLane;
  return {
    schema: IMPL_RECEIPT_SCHEMA,
    lane: IMPL_LANE,
    verdict: triggered.length > 0 ? `STOP: ${triggered.join(", ")}` : "BUILT_AND_TESTED_AWAITING_OWNER_REVIEW",
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
    `${IMPL_RECEIPT_REL} is not what the repository derives (${differing.join(", ") || "formatting"}): regenerate it with npm run sp1-impl:receipt`,
  ];
}

function git(repoRoot: string, args: string[]): string {
  return execFileSync("git", ["-C", resolve(repoRoot), ...args], { encoding: "utf8" });
}

const jsonFiles = (repoRoot: string, dir: string) =>
  existsSync(resolve(repoRoot, dir))
    ? readdirSync(resolve(repoRoot, dir))
        .filter((f) => f.endsWith(".json"))
        .sort()
        .map((f) => `${dir}/${f}`)
    : [];

/** Everything the derivation needs, read from the repository at `repoRoot` (compile first). */
export function readImplReceiptInputs(repoRoot: string, baseCommit: string): ImplReceiptInputs {
  if (!/^[0-9a-f]{40}$/.test(String(baseCommit))) throw new Error("the base commit must be a full commit id");
  try {
    git(repoRoot, ["merge-base", "--is-ancestor", baseCommit, "HEAD"]);
  } catch {
    throw new Error(`the base ${baseCommit} is not an ancestor of HEAD, or the history is unavailable`);
  }
  if (jsonFiles(repoRoot, REAL_PROOF_RECORDS_DIR).length > 0) {
    throw new Error(
      `${REAL_PROOF_RECORDS_DIR}: real-proof records have no validator in this lane; a lane must define and validate them before they count`,
    );
  }
  const read = (rel: string) => readFileSync(resolve(repoRoot, rel));

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
  const designatedElf = canonDesignation.elf.sha256;
  const conflictingVkeys =
    (canonObs.vkeyRecompute?.results ?? []).filter(
      (r) => r.elfSha256 === designatedElf && r.vkey !== canonDesignation.programVKey,
    ).length +
    canonObs.builds.filter((b) =>
      Object.values(b.programs ?? {}).some(
        (p) => p.elfSha256 === designatedElf && p.vkey !== canonDesignation.programVKey,
      ),
    ).length;

  const provingErrors = provingAvailabilityErrors(repoRoot);
  const { abi, contract } = compiledWrapper(repoRoot);
  const contractsChanged = git(repoRoot, ["diff", "--name-status", "--no-renames", baseCommit, "--", "contracts"])
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => {
      const [status, path] = l.split("\t");
      return { path, status };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
  const multisig = (Array.isArray(td2.authorizationCut) ? td2.authorizationCut : []).find(
    (c: { principal?: string }) => c?.principal === MULTISIG_OWNER,
  );

  const evidenceFiles = [
    TD1_RECEIPT_REL,
    TD2_RECORD_REL,
    ...jsonFiles(repoRoot, DESIGNATIONS_DIR),
    ...jsonFiles(repoRoot, DESIGNATION_EVIDENCE_DIR),
    ...jsonFiles(repoRoot, WRAPPER_BUILDS_DIR),
    REGISTRY_REL,
    CHAIN_EXECUTION_OBSERVATION_REL,
    CANONICAL_REBUILD_OBSERVATION_REL,
    PROVING_ARTIFACTS_OBSERVATION_REL,
    PROVING_AVAILABILITY_REL,
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
      conflictingVkeys,
    },
    proving: {
      status: provingErrors.length === 0 ? provingAvailabilityFromRepo(repoRoot).status : null,
      errors: provingErrors,
    },
    ast: wrapperAstFacts(contract, abi),
    journalTypesAtBase: journalTypesInSource(git(repoRoot, ["show", `${baseCommit}:${WRAPPER_SOURCE}`])),
    contractsChanged,
    sizes: collectReports().map((r) => ({ name: r.name, runtimeBytes: r.runtimeBytes, withinLimit: !r.overLimit })),
    probes: {
      overrides: probeOverrides(planWrapperDeployment, designations, builds),
      haltedIdentity: probeHaltedIdentityElsewhere(designations, builds),
      identityReuse: probeIdentityReuse(designations),
      rpc: probeRpcFailClosed(),
    },
    evidence: evidenceFiles.map((path) => ({ path, sha256: sha256(read(path)) })),
  };
}

/** Every reason the committed receipt is not what the repository derives (its base is the committed one). */
export function implReceiptErrors(repoRoot = "."): string[] {
  const path = resolve(repoRoot, IMPL_RECEIPT_REL);
  if (!existsSync(path)) return [`${IMPL_RECEIPT_REL} is missing: generate it with npm run sp1-impl:receipt`];
  const text = readFileSync(path, "utf8");
  let base: string;
  try {
    base = String((JSON.parse(text) as { baseCommit?: unknown }).baseCommit);
  } catch {
    return [`${IMPL_RECEIPT_REL} is not JSON`];
  }
  try {
    return compareReceipt(text, deriveImplReceipt(readImplReceiptInputs(repoRoot, base)));
  } catch (error) {
    return [messageOf(error)];
  }
}
