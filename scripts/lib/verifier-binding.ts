/**
 * SP1-TD2 binding gate: which PQ verifier the deployment and rotation tooling lets a WalletWall consumer be bound
 * to (docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md).
 *
 * Two jobs, both process rather than chain:
 *
 *   1. The halt's scope is enforced, not only stated (EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER). A consumer
 *      the owner kept outside the halt (WalletWallMultiSigVault, until its gate TD2-MULTISIG-ROTATION is built,
 *      tested and its cut accepted) may be bound to no part of the SP1 path — a haltable wrapper least of all,
 *      since a halt would lock it. A consumer inside the scope, if it is on the SP1 path at all, must verify
 *      through a haltable wrapper, or the halt would not reach it (a bypass, not a scope choice).
 *   2. Recovery-target gating (TD1-N12). A target on the SP1 path must be a ZKMLDSAVerifier compiled from this
 *      tree (its runtime code, immutables masked and metadata excluded, is the artifact's), ACTIVE, not haltable by
 *      the signer, and of no identity that is halted — at this consumer (its stored and recorded identities) or at
 *      any wrapper in the WalletWall wrapper registry for the chain, whose state is read live. On any chain where
 *      the local override does not apply it must also be registered, be the only ACTIVE registered wrapper of its
 *      identity (so one halt call reaches every consumer), and match a designation: SP1-TD1's (the SP1 verifier's
 *      runtime code hash per chain and PROGRAM_VKEY) or a successor designation the caller supplies.
 *
 * Every measurement fails closed: a call the RPC did not answer stops the gate (only the chain's own answer — a
 * revert, running out of gas, a short return — reads as "no answer", as on chain), and a genuine wrapper that
 * cannot be measured completely is refused.
 *
 * The scope and SP1-TD1's designation are read from its decision receipt; the registry from
 * evidence/zk/sp1-td2/wrapper-registry.json. A successor designation is produced by the designation process of
 * the frozen implementation lane; until one exists the gate can admit no recovery from a halt of the designated
 * identity on a chain without the local override, and says so. The chain enforces part of (2) on its own
 * (contracts/verifiers/VerifierRotationGuard.sol); an owner who skips this tooling can still install any
 * code-bearing verifier after the delay. That is the authorization cut the TD2 doc reports.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AbiCoder, getAddress, id, isAddress, keccak256, type Provider } from "ethers";

import { decodeSolcMetadataBoundary } from "./reproducibility-evidence";

export const TD1_RECEIPT_REL = "evidence/zk/sp1-td1/decision-receipt.json";
export const WRAPPER_REGISTRY_REL = "evidence/zk/sp1-td2/wrapper-registry.json";
export const WRAPPER_REGISTRY_SCHEMA = "walletwall.sp1-wrapper-registry.v1";
export const WRAPPER_ARTIFACT_REL = "artifacts/contracts/verifiers/ZKMLDSAVerifier.sol/ZKMLDSAVerifier.json";
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

/** The compiled wrapper a target's runtime code must be: deployed bytecode and its immutables' positions. */
export interface WrapperArtifact {
  deployedBytecode: string;
  immutableReferences: Record<string, { start: number; length: number }[]>;
}

/** What a verifier is, measured from the chain (never from what an operator says it is). */
export interface VerifierProfile {
  address: string;
  hasCode: boolean;
  /** Its runtime code is the ZKMLDSAVerifier artifact's, immutables masked and metadata excluded. */
  genuineWrapper: boolean;
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
}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_WORD = `0x${"0".repeat(64)}`;
const abi = AbiCoder.defaultAbiCoder();

// ---------------------------------------------------------------------------------------------------------
// Inputs: the SP1-TD1 receipt, the wrapper registry, the compiled wrapper
// ---------------------------------------------------------------------------------------------------------

function td1Receipt(repoRoot: string): any {
  return JSON.parse(readFileSync(resolve(repoRoot, TD1_RECEIPT_REL), "utf8"));
}

/** The owner-decided halt scope (SP1-TD1 DEFECT_RESPONSE_COUPLING.haltDesign.haltScope, as amended). */
export function readHaltScope(repoRoot = "."): HaltScope {
  const scope = td1Receipt(repoRoot).decisions.DEFECT_RESPONSE_COUPLING.haltDesign.haltScope;
  return {
    applies: [...scope.applies],
    excludedUntilRecoverable: scope.excludedUntilRecoverable.map((e: any) => ({ ...e })),
  };
}

/** SP1-TD1's designation: the trust target's runtime code hash (and per chain) and the program's PROGRAM_VKEY. */
export function readDesignations(repoRoot = "."): Designation[] {
  const r = td1Receipt(repoRoot);
  return [
    {
      source: "SP1-TD1 decision receipt",
      sp1VerifierCodeKeccak: r.trustTarget.codeKeccak,
      sp1VerifierCodeKeccakByChain: Object.fromEntries(
        r.trustTarget.chains.map((c: { chainId: string; codeKeccak: string }) => [c.chainId, c.codeKeccak]),
      ),
      programVKey: r.decisions.PROGRAM_VKEY_DESIGNATION.vkey,
    },
  ];
}

/** Problems with a wrapper registry document; empty means well formed. */
export function wrapperRegistryErrors(value: unknown): string[] {
  const errors: string[] = [];
  const r = value as { schema?: unknown; entries?: unknown } | null;
  if (r === null || typeof r !== "object") return ["the wrapper registry is not an object"];
  if (r.schema !== WRAPPER_REGISTRY_SCHEMA)
    errors.push(`the wrapper registry's schema must be ${WRAPPER_REGISTRY_SCHEMA}`);
  if (!Array.isArray(r.entries)) return [...errors, "the wrapper registry's entries must be a list"];
  const seen = new Set<string>();
  for (const e of r.entries as { chainId?: unknown; address?: unknown }[]) {
    if (typeof e?.chainId !== "string" || !/^[1-9][0-9]*$/.test(e.chainId)) {
      errors.push(`registry entry ${JSON.stringify(e)}: chainId must be a decimal string`);
      continue;
    }
    if (typeof e.address !== "string" || !isAddress(e.address)) {
      errors.push(`registry entry ${JSON.stringify(e)}: address must be an address`);
      continue;
    }
    const key = `${e.chainId}:${getAddress(e.address)}`;
    if (seen.has(key)) errors.push(`registry entry ${key} is listed twice`);
    seen.add(key);
  }
  return errors;
}

/** The registered WalletWall wrapper addresses for `chainId`; throws on a malformed registry. */
export function readWrapperRegistry(chainId: bigint, repoRoot = "."): string[] {
  const doc = JSON.parse(readFileSync(resolve(repoRoot, WRAPPER_REGISTRY_REL), "utf8")) as unknown;
  const errors = wrapperRegistryErrors(doc);
  if (errors.length > 0) throw new Error(`malformed ${WRAPPER_REGISTRY_REL}:\n - ${errors.join("\n - ")}`);
  return (doc as { entries: { chainId: string; address: string }[] }).entries
    .filter((e) => e.chainId === chainId.toString())
    .map((e) => getAddress(e.address));
}

/** The compiled ZKMLDSAVerifier (run `npx hardhat compile` first). */
export function readWrapperArtifact(repoRoot = "."): WrapperArtifact {
  const a = JSON.parse(readFileSync(resolve(repoRoot, WRAPPER_ARTIFACT_REL), "utf8"));
  return { deployedBytecode: a.deployedBytecode, immutableReferences: a.immutableReferences ?? {} };
}

/**
 * Whether `runtime` is the artifact's runtime code: the same length, the same CBOR metadata boundary, and the
 * same bytes before it once every immutable's position is masked. The metadata (which hashes the source,
 * comments included) is excluded; executable code is not.
 */
export function matchesWrapperArtifact(runtime: string, artifact: WrapperArtifact): boolean {
  if (runtime === "0x" || runtime.length !== artifact.deployedBytecode.length) return false;
  const expected = decodeSolcMetadataBoundary(artifact.deployedBytecode);
  const actual = decodeSolcMetadataBoundary(runtime);
  if (!expected.ok || !actual.ok || expected.regionStart !== actual.regionStart) return false;
  const code = Buffer.from(runtime.slice(2), "hex");
  const reference = Buffer.from(artifact.deployedBytecode.slice(2), "hex");
  for (const refs of Object.values(artifact.immutableReferences)) {
    for (const { start, length } of refs) {
      code.fill(0, start, start + length);
      reference.fill(0, start, start + length);
    }
  }
  return code.subarray(0, expected.regionStart).equals(reference.subarray(0, expected.regionStart));
}

// ---------------------------------------------------------------------------------------------------------
// Measuring a verifier
// ---------------------------------------------------------------------------------------------------------

const EXECUTION_FAILURE =
  /revert|out of gas|gas required exceeds|invalid opcode|invalid jump|stack (?:under|over)flow|vm execution error/i;

/**
 * Whether a failed eth_call is the chain's answer — the call ran and reverted or ran out of gas, which the guard
 * reads as "no answer" — rather than the RPC failing to answer (a rate limit, a timeout, a refused connection).
 * EIP-1474 code 3 is a revert; a node reports running out of gas (and some clients a revert without data) as a
 * server error whose message says so. Anything else is not an answer.
 */
export function isExecutionFailure(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  const { code, message } = error as { code?: unknown; message?: unknown };
  if (code === 3 || code === "CALL_EXCEPTION") return true;
  return (
    (code === -32000 || code === -32015 || code === -32603) &&
    typeof message === "string" &&
    EXECUTION_FAILURE.test(message)
  );
}

/**
 * One word from a view function, or null when the call reverts, runs out of gas or returns less than a word (as
 * the guard reads). A call the RPC did not answer throws: read as "no answer" it would drop refusals that nothing
 * on chain backs, such as a registered wrapper's halt (the review's R2-2).
 */
async function word(provider: Provider, to: string, data: string): Promise<string | null> {
  try {
    const out = await provider.call({ to, data });
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
  artifact: WrapperArtifact = readWrapperArtifact(),
): Promise<VerifierProfile> {
  const code = await provider.getCode(address);
  const sp1Verifier = asAddress(await word(provider, address, selector("SP1_VERIFIER()")));
  const programVKey = await word(provider, address, selector("PROGRAM_VKEY()"));
  const haltPrincipal = asAddress(await word(provider, address, selector("HALT_PRINCIPAL()")));
  const haltedWord = await word(provider, address, selector("halted()"));
  let sp1VerifierCodeKeccak: string | null = null;
  if (sp1Verifier !== null) {
    const sp1Code = await provider.getCode(sp1Verifier);
    sp1VerifierCodeKeccak = sp1Code === "0x" ? null : keccak256(sp1Code);
  }
  return {
    address: getAddress(address),
    hasCode: code !== "0x",
    genuineWrapper: matchesWrapperArtifact(code, artifact),
    algorithmId: await word(provider, address, selector("algorithmId()")),
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
      `${t.address} is not a ZKMLDSAVerifier compiled from this tree: its runtime code is not the artifact's`,
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

  for (const r of req.registered) {
    if (!r.genuineWrapper)
      refusals.push(`registered wrapper ${r.address} is not a ZKMLDSAVerifier compiled from this tree`);
    else if (!measuredCompletely(r)) refusals.push(unmeasured(r, "registered wrapper"));
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
  /** Designations to accept; SP1-TD1's by default. A successor designation is the designation process's. */
  designations?: Designation[];
  /** Registered wrapper addresses for this chain; the committed registry by default. */
  registry?: string[];
}

async function context(provider: Provider, options: GateOptions) {
  const chainId = (await provider.getNetwork()).chainId;
  const artifact = readWrapperArtifact(options.repoRoot);
  const addresses = options.registry ?? readWrapperRegistry(chainId, options.repoRoot);
  const registered = await Promise.all(addresses.map((a) => profileVerifier(provider, a, artifact)));
  return {
    chainId,
    artifact,
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
  const target = await profileVerifier(provider, verifier, ctx.artifact);
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
  });
  return target;
}

/** Identifies a deployed rotating consumer by the EIP-712 domain name it reports; refuses anything else. */
export async function identifyConsumer(provider: Provider, address: string): Promise<ConsumerName> {
  let name: string | undefined;
  try {
    const out = await provider.call({ to: address, data: selector("eip712Domain()") });
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
  const consumer = await identifyConsumer(provider, consumerAddress);
  const currentAddress = asAddress(await word(provider, consumerAddress, selector("pqVerifier()")));
  if (currentAddress === null) throw new Error(`${consumerAddress} reports no pqVerifier`);
  const ctx = await context(provider, options);
  const current = await profileVerifier(provider, currentAddress, ctx.artifact);
  const target = await profileVerifier(provider, newVerifier, ctx.artifact);
  const stored = await word(provider, consumerAddress, selector("pqVerifierIdentity()"));
  let recorded = false;
  if (target.identity !== null) {
    const out = await provider.call({
      to: consumerAddress,
      data: selector("haltedVerifierIdentities(bytes32)") + target.identity.slice(2),
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
  });
  return { consumer, target, current };
}
