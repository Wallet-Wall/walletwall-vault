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
 *   2. Recovery-target gating (TD1-N12): a wrapper may be a binding or rotation target only if it is ACTIVE, is
 *      not a halted identity, cannot be halted by the signer, and — on any non-local chain, with no override —
 *      its SP1 verifier's runtime code hash and its PROGRAM_VKEY are the SP1-TD1 designations.
 *
 * The scope and the designations are read from the SP1-TD1 decision receipt, never typed here. The chain enforces
 * part of (2) on its own (contracts/verifiers/VerifierRotationGuard.sol: halt principal, halted wrapper, halted
 * identity); whether a target passed the evidence gates it cannot see, and an owner who skips this tooling can
 * still install any code-bearing verifier after the delay. That is the authorization cut the TD2 doc reports.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AbiCoder, getAddress, id, keccak256, type Provider } from "ethers";

export const TD1_RECEIPT_REL = "evidence/zk/sp1-td1/decision-receipt.json";
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

export interface Designations {
  /** The trust target's runtime code hash (SP1Verifier v6.1.0), and per measured chain. */
  sp1VerifierCodeKeccak: string;
  sp1VerifierCodeKeccakByChain: Record<string, string>;
  /** The designated PROGRAM_VKEY of mldsa65-withdrawal. */
  programVKey: string;
}

/** What a verifier is, measured from the chain (never from what an operator says it is). */
export interface VerifierProfile {
  address: string;
  hasCode: boolean;
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
  /** Local chains only: accept a mock SP1 verifier and an undesignated vkey. */
  allowMockSp1: boolean;
  /** For a rotation: what the consumer verifies through now. */
  current: VerifierProfile | null;
  /** Whether the consumer recorded the target's identity as halted (haltedVerifierIdentities). */
  targetIdentityRecordedHalted: boolean;
  scope: HaltScope;
  designations: Designations;
}

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const abi = AbiCoder.defaultAbiCoder();

// ---------------------------------------------------------------------------------------------------------
// Inputs from the SP1-TD1 receipt
// ---------------------------------------------------------------------------------------------------------

function td1Receipt(repoRoot: string): any {
  return JSON.parse(readFileSync(resolve(repoRoot, TD1_RECEIPT_REL), "utf8"));
}

/** The owner-decided halt scope (SP1-TD1 DEFECT_RESPONSE_COUPLING.haltDesign.haltScope, amended 2026-10-15). */
export function readHaltScope(repoRoot = "."): HaltScope {
  const scope = td1Receipt(repoRoot).decisions.DEFECT_RESPONSE_COUPLING.haltDesign.haltScope;
  return {
    applies: [...scope.applies],
    excludedUntilRecoverable: scope.excludedUntilRecoverable.map((e: any) => ({ ...e })),
  };
}

/** The SP1-TD1 trust-target and program designations. */
export function readDesignations(repoRoot = "."): Designations {
  const r = td1Receipt(repoRoot);
  return {
    sp1VerifierCodeKeccak: r.trustTarget.codeKeccak,
    sp1VerifierCodeKeccakByChain: Object.fromEntries(
      r.trustTarget.chains.map((c: { chainId: string; codeKeccak: string }) => [c.chainId, c.codeKeccak]),
    ),
    programVKey: r.decisions.PROGRAM_VKEY_DESIGNATION.vkey,
  };
}

// ---------------------------------------------------------------------------------------------------------
// Measuring a verifier
// ---------------------------------------------------------------------------------------------------------

/** One word from a view function, or null when the call fails or returns less than a word (as the guard reads). */
async function word(provider: Provider, to: string, signature: string): Promise<string | null> {
  try {
    const out = await provider.call({ to, data: id(signature).slice(0, 10) });
    return out.length >= 66 ? `0x${out.slice(2, 66)}` : null;
  } catch {
    return null;
  }
}

const asAddress = (w: string | null) =>
  w !== null && BigInt(w) >> 160n === 0n ? getAddress(`0x${w.slice(26)}`) : null;

export async function profileVerifier(provider: Provider, address: string): Promise<VerifierProfile> {
  const code = await provider.getCode(address);
  const hasCode = code !== "0x";
  const sp1Verifier = asAddress(await word(provider, address, "SP1_VERIFIER()"));
  const programVKey = await word(provider, address, "PROGRAM_VKEY()");
  const haltPrincipal = asAddress(await word(provider, address, "HALT_PRINCIPAL()"));
  const haltedWord = await word(provider, address, "halted()");
  let sp1VerifierCodeKeccak: string | null = null;
  if (sp1Verifier !== null) {
    const sp1Code = await provider.getCode(sp1Verifier);
    sp1VerifierCodeKeccak = sp1Code === "0x" ? null : keccak256(sp1Code);
  }
  return {
    address: getAddress(address),
    hasCode,
    algorithmId: await word(provider, address, "algorithmId()"),
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

/** The SP1 path: anything reporting the ZK algorithm id, an SP1 identity, or a halt surface. */
export function isOnSp1Path(p: VerifierProfile): boolean {
  return (
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
  if (t.halted) refusals.push(`${t.address} is HALTED: a halted wrapper is never a binding or rotation target`);
  if (t.haltPrincipal !== null && t.haltPrincipal === getAddress(req.signer)) {
    refusals.push(
      `the signer ${req.signer} is ${t.address}'s halt principal: the halt principal never governs a consumer`,
    );
  }
  if (
    req.current !== null &&
    req.current.haltPrincipal !== null &&
    req.current.haltPrincipal === getAddress(req.signer)
  ) {
    refusals.push(
      `the signer ${req.signer} can halt the current verifier: the halt principal never governs a consumer`,
    );
  }
  if (t.identity !== null) {
    if (req.targetIdentityRecordedHalted) {
      refusals.push(`${t.address} has the identity of a halted wrapper ${req.consumer} recorded (${t.identity})`);
    }
    if (req.current?.halted && req.current.identity === t.identity) {
      refusals.push(`${t.address} is a fresh deployment of the halted identity ${t.identity}`);
    }
  }

  // The evidence gates: the SP1-TD1 designations, with no override off a local chain.
  if (req.allowMockSp1 && local) return refusals;
  const expectedCode =
    req.designations.sp1VerifierCodeKeccakByChain[req.chainId.toString()] ?? req.designations.sp1VerifierCodeKeccak;
  if (t.sp1VerifierCodeKeccak !== expectedCode) {
    refusals.push(
      `${t.address}'s SP1 verifier runtime code hash is ${String(t.sp1VerifierCodeKeccak)}, not the designated ${expectedCode}`,
    );
  }
  if (t.programVKey !== req.designations.programVKey) {
    refusals.push(
      `${t.address}'s PROGRAM_VKEY is ${String(t.programVKey)}, not the designated ${req.designations.programVKey}`,
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
}

/** Checks that `consumer` may be deployed bound to `verifier`, signed by `signer`. */
export async function checkDeploymentBinding(
  provider: Provider,
  consumer: ConsumerName,
  verifier: string,
  signer: string,
  options: GateOptions,
): Promise<VerifierProfile> {
  const target = await profileVerifier(provider, verifier);
  assertBindable({
    consumer,
    target,
    chainId: (await provider.getNetwork()).chainId,
    signer,
    allowMockSp1: options.allowMockSp1,
    current: null,
    targetIdentityRecordedHalted: false,
    scope: readHaltScope(options.repoRoot),
    designations: readDesignations(options.repoRoot),
  });
  return target;
}

/** Identifies a deployed rotating consumer by the EIP-712 domain name it reports; refuses anything else. */
export async function identifyConsumer(provider: Provider, address: string): Promise<ConsumerName> {
  let name: string | undefined;
  try {
    const out = await provider.call({ to: address, data: id("eip712Domain()").slice(0, 10) });
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
  const currentAddress = asAddress(await word(provider, consumerAddress, "pqVerifier()"));
  if (currentAddress === null) throw new Error(`${consumerAddress} reports no pqVerifier`);
  const current = await profileVerifier(provider, currentAddress);
  const target = await profileVerifier(provider, newVerifier);
  let recorded = false;
  if (target.identity !== null) {
    const out = await provider.call({
      to: consumerAddress,
      data: id("haltedVerifierIdentities(bytes32)").slice(0, 10) + target.identity.slice(2),
    });
    recorded = BigInt(out) !== 0n;
  }
  assertBindable({
    consumer,
    target,
    chainId: (await provider.getNetwork()).chainId,
    signer,
    allowMockSp1: options.allowMockSp1,
    current,
    targetIdentityRecordedHalted: recorded,
    scope: readHaltScope(options.repoRoot),
    designations: readDesignations(options.repoRoot),
  });
  return { consumer, target, current };
}
