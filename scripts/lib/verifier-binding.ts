/**
 * SP1-TD2 binding gate: which PQ verifier the deployment and rotation tooling lets a WalletWall consumer be bound
 * to (docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md; extended by the SP1 implementation lane,
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * Two jobs, both process rather than chain:
 *
 *   1. The halt's scope is enforced, not only stated (EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER). A consumer
 *      the owner keeps outside the halt may be bound to no part of the SP1 path — a haltable wrapper least of all,
 *      since a halt would lock it. WalletWallMultiSigVault was that consumer until its gate TD2-MULTISIG-ROTATION;
 *      the owner accepted the gate on 2026-10-16 (HALT_ADMISSION = ACCEPTED_SUBJECT_TO_FROZEN_SP1_BINDING_GATES),
 *      so the TD2 record admits it and it is held to every rule below, like the others. A consumer inside the
 *      scope, if it is on the SP1 path at all, must verify through a haltable wrapper, or the halt would not reach
 *      it (a bypass, not a scope choice).
 *   2. Recovery-target gating (TD1-N12). A target on the SP1 path must be a ZKMLDSAVerifier of a recorded wrapper
 *      build (its runtime is that build's template outside the immutable slots, metadata included), ACTIVE, not
 *      haltable by the signer, and of no identity that is halted — at this consumer (its stored and recorded
 *      identities), at any wrapper in the WalletWall registry for the chain (state read live), or anywhere the
 *      registry records a halt of it, on ANY chain. On any chain where the local override does not apply it must
 *      also be registered, be the only ACTIVE registered wrapper of its identity (so one halt call reaches every
 *      consumer), match a designation (evidence/zk/sp1/designations/: the first, or a successor), and, off a local
 *      chain, its SP1 verifier must run the very code its build pins (a wrapper whose constructor pin was bypassed
 *      is never bound).
 *
 * The registry (evidence/zk/sp1-td2/wrapper-registry.json, a v2 fact log) must agree with the chain: a registered
 * wrapper must run the build its registration records (R2-3: judged against its own build, never today's), a halt
 * the registry records but the chain does not show refuses (one of them is wrong), and a halt the chain shows but the
 * registry does not record refuses until it is published, because the registry is how every other chain learns of it.
 *
 * Every measurement fails closed: a call the RPC did not answer stops the gate (only the chain's own answer — a
 * revert, running out of gas, a short return — reads as "no answer", as on chain), and a genuine wrapper that
 * cannot be measured completely is refused. The gate checks the registry's own rules; its cross-references to the
 * builds and designations, and its append-only history, are checked by CI and by the deployment tooling.
 *
 * The chain enforces part of (2) on its own (contracts/verifiers/VerifierRotationGuard.sol); an owner who skips this
 * tooling can still install any code-bearing verifier after the delay. That is the authorization cut the TD2 doc
 * reports.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AbiCoder, getAddress, id, keccak256, type Provider } from "ethers";

import { isExecutionFailure } from "./rpc-answer";
import { readDesignations as readProgramDesignations } from "./sp1-designation";
import {
  REGISTRY_REL,
  REGISTRY_SCHEMA,
  readRegistry,
  registryShapeErrors,
  registryState,
  type RegistryDoc,
} from "./sp1-registry";
import { TD2_RECORD_REL, admittedConsumers, effectiveHaltScope } from "./sp1-td2-record";
import {
  WRAPPER_ARTIFACT_REL as BUILD_ARTIFACT_REL,
  buildMatching,
  readWrapperBuilds,
  type WrapperBuild,
} from "./sp1-wrapper-build";

export { isExecutionFailure } from "./rpc-answer";

export const TD1_RECEIPT_REL = "evidence/zk/sp1-td1/decision-receipt.json";
export const WRAPPER_REGISTRY_REL = REGISTRY_REL;
export const WRAPPER_REGISTRY_SCHEMA = REGISTRY_SCHEMA;
export const WRAPPER_ARTIFACT_REL = BUILD_ARTIFACT_REL;
export const ZK_ALGORITHM_ID = id("ZK-ML-DSA-65");
/** Chains where a mock SP1 verifier may stand in (with an explicit flag), and nowhere else. */
export const LOCAL_CHAIN_IDS = [31337n, 1337n] as const;

export const CONSUMERS = [
  "PolicyControlBridge",
  "StablecoinVaultSimulator",
  "WalletWallMultiSigVault",
  "WalletWallVault",
] as const;
export type ConsumerName = (typeof CONSUMERS)[number];

/** The EIP-712 domain name each rotating consumer reports through `eip712Domain()`. */
export const CONSUMER_BY_DOMAIN_NAME: Record<string, ConsumerName> = {
  WalletWallVault: "WalletWallVault",
  WalletWallStablecoinVault: "StablecoinVaultSimulator",
  WalletWallMultiSigVault: "WalletWallMultiSigVault",
};

export interface HaltScope {
  applies: string[];
  /** Each exclusion names its gate, its interim and the owner amendment that authorized it (SP1-TD1 #215). */
  excludedUntilRecoverable: { consumer: string; gate: string; interim: string; authorizedBy: string }[];
}

/** A designated identity: the SP1 verifier's runtime code hash (per chain, with a fallback) and the vkey. */
export interface Designation {
  source: string;
  sp1VerifierCodeKeccak: string;
  sp1VerifierCodeKeccakByChain: Record<string, string>;
  programVKey: string;
}

/** What a verifier is, measured from the chain (never from what an operator says it is). */
export interface VerifierProfile {
  address: string;
  hasCode: boolean;
  /** Its runtime code is a recorded ZKMLDSAVerifier build's (wrapperBuild names it). */
  genuineWrapper: boolean;
  /** The recorded wrapper build its runtime matches (evidence/zk/sp1/wrapper-builds/), or null. */
  wrapperBuild: string | null;
  /** The SP1 verifier runtime code hash that build pins (its SP1_VERIFIER_CODEHASH), or null. */
  pinnedSp1VerifierCodehash: string | null;
  algorithmId: string | null;
  sp1Verifier: string | null;
  sp1VerifierCodeKeccak: string | null;
  programVKey: string | null;
  haltPrincipal: string | null;
  halted: boolean | null;
  /** keccak256(abi.encode(EXTCODEHASH(sp1Verifier), PROGRAM_VKEY)): the identity the on-chain guard compares. */
  identity: string | null;
}

export interface BindingRequest {
  consumer: string;
  target: VerifierProfile;
  chainId: bigint;
  /** The account that will send the deployment or the rotation proposal. */
  signer: string;
  /** Local chains only: accept a mock SP1 verifier, an unregistered wrapper and an undesignated identity. */
  allowMockSp1: boolean;
  /** For a rotation: what the consumer verifies through now (its halt state and halt principal, read live). */
  current: VerifierProfile | null;
  /** For a rotation: the identity the consumer stored when it installed its current verifier. */
  currentIdentity: string | null;
  /** Whether the consumer recorded the target's identity as halted (haltedVerifierIdentities). */
  targetIdentityRecordedHalted: boolean;
  scope: HaltScope;
  designations: Designation[];
  /** Every WalletWall wrapper registered for this chain, profiled live. */
  registered: VerifierProfile[];
  /** The WalletWall registry's facts, every chain's: registrations, their builds, and the recorded halts. */
  registry: RegistryDoc;
}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_WORD = `0x${"0".repeat(64)}`;
const abi = AbiCoder.defaultAbiCoder();

// ---------------------------------------------------------------------------------------------------------
// Inputs: the SP1-TD1 receipt (scope), the designations, the wrapper registry, the recorded builds
// ---------------------------------------------------------------------------------------------------------

function td1Receipt(repoRoot: string): any {
  return JSON.parse(readFileSync(resolve(repoRoot, TD1_RECEIPT_REL), "utf8"));
}

/**
 * The owner-decided halt scope: SP1-TD1's (DEFECT_RESPONSE_COUPLING.haltDesign.haltScope, as amended), with each
 * consumer it excluded until a TD2 gate admitted once the TD2 record shows that gate built and tested and the owner's
 * acceptance (SP1-TD1: WalletWallMultiSigVault "joins the scope only through TD2-MULTISIG-ROTATION"). Without a TD2
 * record nothing is admitted, so the exclusion holds.
 */
export function readHaltScope(repoRoot = "."): HaltScope {
  const scope = td1Receipt(repoRoot).decisions.DEFECT_RESPONSE_COUPLING.haltDesign.haltScope as HaltScope;
  const record = resolve(repoRoot, TD2_RECORD_REL);
  const admitted = existsSync(record) ? admittedConsumers(JSON.parse(readFileSync(record, "utf8"))) : [];
  return effectiveHaltScope(scope, admitted);
}

/**
 * The designations (evidence/zk/sp1/designations/, generated from evidence): each one's SP1 verifier runtime code
 * hash (and per measured chain) and PROGRAM_VKEY. The first is SP1-TD1's; successors follow.
 */
export function readDesignations(repoRoot = "."): Designation[] {
  return readProgramDesignations(repoRoot).map((d) => ({
    source: d.id,
    sp1VerifierCodeKeccak: d.verifier.runtimeCodeKeccak,
    sp1VerifierCodeKeccakByChain: Object.fromEntries(d.verifier.measuredChains.map((c) => [c.chainId, c.codeKeccak])),
    programVKey: d.programVKey,
  }));
}

/** Problems with a wrapper registry document by its own rules; empty means well formed. */
export function wrapperRegistryErrors(value: unknown): string[] {
  if (value === null || typeof value !== "object") return ["the wrapper registry is not an object"];
  return registryShapeErrors(value as RegistryDoc);
}

/** The registered WalletWall wrapper addresses for `chainId`; throws on a malformed registry. */
export function readWrapperRegistry(chainId: bigint, repoRoot = "."): string[] {
  const doc = JSON.parse(readFileSync(resolve(repoRoot, WRAPPER_REGISTRY_REL), "utf8")) as unknown;
  const errors = wrapperRegistryErrors(doc);
  if (errors.length > 0) throw new Error(`malformed ${WRAPPER_REGISTRY_REL}:\n - ${errors.join("\n - ")}`);
  return registryState(doc as RegistryDoc).registeredOn(chainId.toString());
}

// ---------------------------------------------------------------------------------------------------------
// Measuring a verifier
// ---------------------------------------------------------------------------------------------------------

/**
 * One word from a view function, or null when the call reverts, runs out of gas or returns less than a word (as
 * the guard reads). A call the RPC did not answer throws: read as "no answer" it would drop refusals that nothing
 * on chain backs, such as a registered wrapper's halt (the review's R2-2).
 */
async function word(provider: Provider, to: string, data: string, blockTag?: number): Promise<string | null> {
  try {
    const out = await provider.call({ to, data, ...(blockTag === undefined ? {} : { blockTag }) });
    return out.length >= 66 ? `0x${out.slice(2, 66)}` : null;
  } catch (error) {
    if (isExecutionFailure(error)) return null;
    throw new Error(`reading ${data.slice(0, 10)} from ${to} got no answer from the chain; refusing to guess one`, {
      cause: error,
    });
  }
}

const selector = (signature: string) => id(signature).slice(0, 10);

const asAddress = (w: string | null) =>
  w !== null && BigInt(w) >> 160n === 0n ? getAddress(`0x${w.slice(26)}`) : null;

export async function profileVerifier(
  provider: Provider,
  address: string,
  builds: readonly WrapperBuild[] = readWrapperBuilds(),
  blockTag?: number,
): Promise<VerifierProfile> {
  const code = await provider.getCode(address, blockTag);
  const sp1Verifier = asAddress(await word(provider, address, selector("SP1_VERIFIER()"), blockTag));
  const programVKey = await word(provider, address, selector("PROGRAM_VKEY()"), blockTag);
  const haltPrincipal = asAddress(await word(provider, address, selector("HALT_PRINCIPAL()"), blockTag));
  const haltedWord = await word(provider, address, selector("halted()"), blockTag);
  let sp1VerifierCodeKeccak: string | null = null;
  if (sp1Verifier !== null) {
    const sp1Code = await provider.getCode(sp1Verifier, blockTag);
    sp1VerifierCodeKeccak = sp1Code === "0x" ? null : keccak256(sp1Code);
  }
  const build = buildMatching(code, builds);
  return {
    address: getAddress(address),
    hasCode: code !== "0x",
    genuineWrapper: build !== null,
    wrapperBuild: build === null ? null : build.id,
    pinnedSp1VerifierCodehash: build === null ? null : build.pins.sp1VerifierCodehash,
    algorithmId: await word(provider, address, selector("algorithmId()"), blockTag),
    sp1Verifier,
    sp1VerifierCodeKeccak,
    programVKey,
    haltPrincipal: haltPrincipal === ZERO_ADDRESS ? null : haltPrincipal,
    halted: haltedWord === null ? null : BigInt(haltedWord) !== 0n,
    identity:
      sp1VerifierCodeKeccak !== null && programVKey !== null
        ? keccak256(abi.encode(["bytes32", "bytes32"], [sp1VerifierCodeKeccak, programVKey]))
        : null,
  };
}

/** The SP1 path: a genuine wrapper, or anything reporting the ZK algorithm id, an SP1 identity, or a halt surface. */
export function isOnSp1Path(p: VerifierProfile): boolean {
  return (
    p.genuineWrapper ||
    p.algorithmId === ZK_ALGORITHM_ID ||
    p.sp1Verifier !== null ||
    p.programVKey !== null ||
    p.haltPrincipal !== null ||
    p.halted !== null
  );
}

/** A haltable wrapper reports both its halt principal and its state. */
export function isHaltable(p: VerifierProfile): boolean {
  return p.haltPrincipal !== null && p.halted !== null;
}

/**
 * A genuine wrapper always answers its halt principal and state and has an identity, unless its SP1 verifier has
 * no code. The gate refuses a genuine wrapper it could not measure completely rather than skip the rules that
 * need the missing reading.
 */
function measuredCompletely(p: VerifierProfile): boolean {
  return p.haltPrincipal !== null && p.halted !== null && p.identity !== null;
}

const unmeasured = (p: VerifierProfile, role: string) =>
  `${role} ${p.address} is a genuine wrapper whose halt principal, halt state or identity could not be measured ` +
  `(an SP1 verifier without code?): refusing rather than skipping the rules that need it`;

// ---------------------------------------------------------------------------------------------------------
// The gate (pure)
// ---------------------------------------------------------------------------------------------------------

/** Every reason the binding is refused; empty means the tooling may proceed. */
export function bindingRefusals(req: BindingRequest): string[] {
  const refusals: string[] = [];
  const t = req.target;
  const local = (LOCAL_CHAIN_IDS as readonly bigint[]).includes(req.chainId);
  if (req.allowMockSp1 && !local)
    refusals.push(`no override exists on chain ${req.chainId}: a mock SP1 verifier is local-only`);
  if (!t.hasCode) refusals.push(`${t.address} has no code`);

  const excluded = req.scope.excludedUntilRecoverable.find((e) => e.consumer === req.consumer);
  const applies = req.scope.applies.includes(req.consumer);
  if (!excluded && !applies) {
    refusals.push(`${req.consumer} is not a consumer the halt's scope names; refusing to bind it`);
    return refusals;
  }
  if (!isOnSp1Path(t)) return refusals;

  if (excluded) {
    refusals.push(
      `${req.consumer} waits outside the halt for ${excluded.gate} (interim ${excluded.interim}, authorized by ` +
        `${excluded.authorizedBy}): it may be bound to no part of the SP1 path` +
        `${isHaltable(t) ? ", and a haltable wrapper would lock its funds" : ""}`,
    );
    return refusals;
  }

  if (!isHaltable(t)) {
    refusals.push(`${t.address} is on the SP1 path but not haltable: the halt would not reach ${req.consumer}`);
    return refusals;
  }
  if (!t.genuineWrapper) {
    refusals.push(
      `${t.address} is not a ZKMLDSAVerifier compiled from this tree: its runtime code is no recorded wrapper build's`,
    );
  } else if (!measuredCompletely(t)) {
    refusals.push(unmeasured(t, "the target"));
  }
  if (t.halted) refusals.push(`${t.address} is HALTED: a halted wrapper is never a binding or rotation target`);
  const signer = getAddress(req.signer);
  if (t.haltPrincipal !== null && t.haltPrincipal === signer) {
    refusals.push(
      `the signer ${req.signer} is ${t.address}'s halt principal: the halt principal never governs a consumer`,
    );
  }
  if (req.current !== null && req.current.haltPrincipal !== null && req.current.haltPrincipal === signer) {
    refusals.push(
      `the signer ${req.signer} can halt the current verifier: the halt principal never governs a consumer`,
    );
  }
  if (req.current?.genuineWrapper && !measuredCompletely(req.current)) {
    refusals.push(unmeasured(req.current, "the current verifier"));
  }

  // The registry for this chain, against the chain: genuine, measurable, the build of record, the same halt state.
  const chain = req.chainId.toString();
  const state = registryState(req.registry);
  for (const r of req.registered) {
    if (!r.genuineWrapper)
      refusals.push(`registered wrapper ${r.address} is not a ZKMLDSAVerifier compiled from this tree`);
    else if (!measuredCompletely(r)) refusals.push(unmeasured(r, "registered wrapper"));
    const fact = state.registration(chain, r.address);
    // A fact is a measurement: every field it records must still be what the chain reports.
    if (fact !== undefined) {
      for (const [field, recorded, live] of [
        ["identity", fact.identity, r.identity],
        ["PROGRAM_VKEY", fact.programVKey, r.programVKey],
        ["SP1 verifier", fact.sp1Verifier?.address, r.sp1Verifier],
        ["SP1 verifier code", fact.sp1Verifier?.runtimeCodeKeccak, r.sp1VerifierCodeKeccak],
        ["halt principal", fact.haltPrincipal, r.haltPrincipal],
      ] as const) {
        if (recorded !== live) {
          refusals.push(
            `registered wrapper ${r.address}: the registry records ${field} ${String(recorded)}, but the chain reports ` +
              `${String(live)}: the registry or the RPC is wrong; refusing rather than guessing`,
          );
        }
      }
    }
    if (fact !== undefined && r.wrapperBuild !== null && fact.wrapperBuild !== r.wrapperBuild) {
      refusals.push(
        `registered wrapper ${r.address} runs build ${r.wrapperBuild}, not the build its registration records ` +
          `(${String(fact.wrapperBuild)})`,
      );
    }
    const recorded = state.recordedHalted(chain, r.address);
    if (recorded && r.halted === false) {
      refusals.push(
        `the registry records ${r.address} HALTED but the chain reports it ACTIVE: the registry or the RPC is wrong; ` +
          `refusing rather than guessing`,
      );
    }
    if (!recorded && r.halted === true) {
      refusals.push(
        `${r.address} is HALTED on chain ${chain} but the registry does not record it: append its WRAPPER_HALTED ` +
          `fact (the registry is how every other chain learns of a halt) before binding here`,
      );
    }
  }
  if (t.identity !== null) {
    if (req.targetIdentityRecordedHalted) {
      refusals.push(`${t.address} has the identity of a halted wrapper ${req.consumer} recorded (${t.identity})`);
    }
    if (req.current?.halted && req.currentIdentity === t.identity) {
      refusals.push(`${t.address} is a fresh deployment of the halted identity ${t.identity}`);
    }
    for (const r of req.registered) {
      if (r.halted && r.identity === t.identity && r.address !== t.address) {
        refusals.push(`${t.address} has the identity of registered wrapper ${r.address}, which is HALTED`);
      }
    }
    // A halt anywhere the registry records it refuses the identity everywhere (the cross-chain residual of SP1-TD2).
    for (const h of state.haltsOfIdentity(t.identity)) {
      refusals.push(
        `${t.address}'s identity ${t.identity} is recorded HALTED in the WalletWall registry (fact #${h.seq}: ` +
          `${h.address} on chain ${h.chainId}, ${h.reason}): a halted identity is never a binding target, on any chain`,
      );
    }
  }

  // Registration and designation: no override off a local chain.
  if (req.allowMockSp1 && local) return refusals;
  if (!req.registered.some((r) => r.address === t.address)) {
    refusals.push(`${t.address} is not in the WalletWall wrapper registry for chain ${req.chainId}`);
  }
  const twins = req.registered.filter(
    (r) => r.address !== t.address && r.identity === t.identity && r.halted === false,
  );
  if (twins.length > 0) {
    refusals.push(
      `${twins.map((r) => r.address).join(", ")} is another ACTIVE registered wrapper of ${t.address}'s identity: ` +
        `one halt call must reach every consumer`,
    );
  }
  const designated = req.designations.some(
    (d) =>
      (d.sp1VerifierCodeKeccakByChain[req.chainId.toString()] ?? d.sp1VerifierCodeKeccak) === t.sp1VerifierCodeKeccak &&
      d.programVKey === t.programVKey,
  );
  if (!designated) {
    refusals.push(
      `${t.address}'s identity (SP1 verifier code ${String(t.sp1VerifierCodeKeccak)}, PROGRAM_VKEY ${String(t.programVKey)}) ` +
        `matches no designation (${req.designations.map((d) => d.source).join(", ")}): a recovery identity needs a ` +
        `successor designation from the designation process`,
    );
  }
  // The pin is a constant of the build, and the constructor checks it; off a local chain the code behind a wrapper
  // must still be that pinned code, so a deployment that skipped the constructor's check is never bound.
  if (
    !local &&
    t.genuineWrapper &&
    t.sp1VerifierCodeKeccak !== null &&
    t.sp1VerifierCodeKeccak !== t.pinnedSp1VerifierCodehash
  ) {
    refusals.push(
      `${t.address}: its SP1 verifier runs code ${t.sp1VerifierCodeKeccak}, not the code its build pins ` +
        `(${String(t.pinnedSp1VerifierCodehash)}): a wrapper whose constructor pin was bypassed is never bound`,
    );
  }
  return refusals;
}

/** Throws with every refusal, or returns quietly when the binding may proceed. */
export function assertBindable(req: BindingRequest): void {
  const refusals = bindingRefusals(req);
  if (refusals.length > 0) {
    throw new Error(`refusing to bind ${req.consumer} to ${req.target.address}:\n - ${refusals.join("\n - ")}`);
  }
}

// ---------------------------------------------------------------------------------------------------------
// The two tooling entry points (deployment and rotation), shared by the scripts and their tests
// ---------------------------------------------------------------------------------------------------------

export interface GateOptions {
  allowMockSp1: boolean;
  repoRoot?: string;
  /** Designations to accept; the committed ones by default. A successor designation is the designation process's. */
  designations?: Designation[];
  /** The registry's facts; the committed registry by default. */
  registry?: RegistryDoc;
}

async function context(provider: Provider, options: GateOptions) {
  const chainId = (await provider.getNetwork()).chainId;
  // Every wrapper the gate reads is read at one block, so no two answers come from different chain states.
  const blockTag = await provider.getBlockNumber();
  const builds = readWrapperBuilds(options.repoRoot);
  const registry = options.registry ?? readRegistry(options.repoRoot ?? ".");
  const malformed = wrapperRegistryErrors(registry);
  if (malformed.length > 0) throw new Error(`malformed ${WRAPPER_REGISTRY_REL}:\n - ${malformed.join("\n - ")}`);
  const addresses = registryState(registry).registeredOn(chainId.toString());
  const registered = await Promise.all(addresses.map((a) => profileVerifier(provider, a, builds, blockTag)));
  return {
    chainId,
    blockTag,
    builds,
    registry,
    registered,
    scope: readHaltScope(options.repoRoot),
    designations: options.designations ?? readDesignations(options.repoRoot),
  };
}

/** Checks that `consumer` may be deployed bound to `verifier`, signed by `signer`. */
export async function checkDeploymentBinding(
  provider: Provider,
  consumer: ConsumerName,
  verifier: string,
  signer: string,
  options: GateOptions,
): Promise<VerifierProfile> {
  const ctx = await context(provider, options);
  const target = await profileVerifier(provider, verifier, ctx.builds, ctx.blockTag);
  assertBindable({
    consumer,
    target,
    chainId: ctx.chainId,
    signer,
    allowMockSp1: options.allowMockSp1,
    current: null,
    currentIdentity: null,
    targetIdentityRecordedHalted: false,
    scope: ctx.scope,
    designations: ctx.designations,
    registered: ctx.registered,
    registry: ctx.registry,
  });
  return target;
}

/** Identifies a deployed rotating consumer by the EIP-712 domain name it reports; refuses anything else. */
export async function identifyConsumer(provider: Provider, address: string, blockTag?: number): Promise<ConsumerName> {
  let name: string | undefined;
  try {
    const out = await provider.call({
      to: address,
      data: selector("eip712Domain()"),
      ...(blockTag === undefined ? {} : { blockTag }),
    });
    name = abi.decode(["bytes1", "string", "string", "uint256", "address", "bytes32", "uint256[]"], out)[1] as string;
  } catch {
    name = undefined;
  }
  const consumer = name === undefined ? undefined : CONSUMER_BY_DOMAIN_NAME[name];
  if (consumer === undefined) throw new Error(`${address} is not a WalletWall consumer with a verifier rotation`);
  return consumer;
}

/** Checks that the consumer at `consumerAddress` may be rotated to `newVerifier` by `signer`. */
export async function checkRotationBinding(
  provider: Provider,
  consumerAddress: string,
  newVerifier: string,
  signer: string,
  options: GateOptions,
): Promise<{ consumer: ConsumerName; target: VerifierProfile; current: VerifierProfile }> {
  // Every read at the gate's one block: the consumer, its verifiers, its identity and its halted-identity record.
  const ctx = await context(provider, options);
  const consumer = await identifyConsumer(provider, consumerAddress, ctx.blockTag);
  const currentAddress = asAddress(await word(provider, consumerAddress, selector("pqVerifier()"), ctx.blockTag));
  if (currentAddress === null) throw new Error(`${consumerAddress} reports no pqVerifier`);
  const current = await profileVerifier(provider, currentAddress, ctx.builds, ctx.blockTag);
  const target = await profileVerifier(provider, newVerifier, ctx.builds, ctx.blockTag);
  const stored = await word(provider, consumerAddress, selector("pqVerifierIdentity()"), ctx.blockTag);
  let recorded = false;
  if (target.identity !== null) {
    const out = await provider.call({
      to: consumerAddress,
      data: selector("haltedVerifierIdentities(bytes32)") + target.identity.slice(2),
      blockTag: ctx.blockTag,
    });
    recorded = BigInt(out) !== 0n;
  }
  assertBindable({
    consumer,
    target,
    chainId: ctx.chainId,
    signer,
    allowMockSp1: options.allowMockSp1,
    current,
    currentIdentity: stored === null || stored === ZERO_WORD ? null : stored,
    targetIdentityRecordedHalted: recorded,
    scope: ctx.scope,
    designations: ctx.designations,
    registered: ctx.registered,
    registry: ctx.registry,
  });
  return { consumer, target, current };
}
