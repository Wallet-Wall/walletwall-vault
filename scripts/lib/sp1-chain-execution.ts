/**
 * CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK (SP1-TD1 finding TD1-N8; the SP1 implementation lane,
 * docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * A runtime code hash pins the verifier's bytes, not what they do: the Groth16 verifier ANDs its pairing call's
 * success with the call's first output word, so on a chain where the 0x08 precompile is missing (or behaves otherwise)
 * an invalid proof whose first word is odd verifies under the pinned code. Each chain's governance decides its
 * precompiles, and an L2's upgrade keys can change them, so the check is per chain, before a deployment and again
 * whenever the chain may have changed. By eth_call on the designated verifier:
 *
 *   real      a real v6.1.0 proof (a third party's, from a successful mainnet call; it authenticates itself) — success
 *   tampered  the same proof with the last public-value bit flipped                                         — ProofInvalid
 *   canary    v6.1.0's selector, exit code 0, the vk root, nonce 0, eight proof words of 1                  — ProofInvalid
 *
 * The calldata is rebuilt here from committed evidence (the designation's verifier and the real-proof observation);
 * the required verdicts are constants of this module, never values an observation brings; and the canary's positive
 * control is executed: the same runtime with its pairing calls aimed at an empty account accepts the canary, so the
 * canary does detect the broken environment. An RPC that does not answer gives no verdict: the check throws.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AbiCoder, Interface, concat, getAddress, getBytes, hexlify, id, keccak256, type Provider } from "ethers";

import { EXPECTED_CHAIN_ID } from "./deployment-guards";
import { isExecutionFailure, revertDataOf } from "./rpc-answer";
import type { ProgramDesignation } from "./sp1-designation";

export const CHAIN_EXECUTION_OBSERVATION_REL = "evidence/zk/sp1-impl/observations/chain-execution.raw.json";
export const CHAIN_EXECUTION_SCHEMA = "walletwall.sp1-chain-execution.v1";
/** The script that makes the measurement; the observation names it by sha256, and must name this tree's. */
export const CHAIN_EXECUTION_SCRIPT_REL = "scripts/check-sp1-chain-execution.ts";
/** The real v6.1.0 proof SP1-TD1 took from a successful mainnet call into the pinned verifier. */
export const REAL_PROOF_REL = "evidence/zk/sp1-td1/observations/mainnet-v610-proof.raw.json";
/** SP1-TD1's CREATE2-authenticated initcode of the verifier, for the positive control on a development chain. */
export const VERIFIER_BYTECODE_REL = "evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json";
export const PROOF_INVALID = id("ProofInvalid()").slice(0, 10);
/** What the designated verifier must answer on a chain. Constants: an observation never relaxes them. */
export const REQUIRED_VERDICTS = {
  real: "success",
  tampered: `revert ${PROOF_INVALID}`,
  canary: `revert ${PROOF_INVALID}`,
} as const;
export type CallName = keyof typeof REQUIRED_VERDICTS;
const CALL_NAMES = Object.keys(REQUIRED_VERDICTS) as CallName[];
const LOCAL_CHAINS = ["31337", "1337"];
/** Every chain the deployment tooling may deploy a wrapper to (scripts/lib/deployment-guards.ts), local ones aside. */
export const SUPPORTED_DEPLOYMENT_CHAINS = [...new Set(Object.values(EXPECTED_CHAIN_ID).map(String))]
  .filter((c) => !LOCAL_CHAINS.includes(c))
  .sort();
/** The chains SP1-TD1 measured the trust target on beyond those: measured again, never deployed to. */
export const TRUST_TARGET_ONLY_CHAINS = ["1", "8453"];

export interface Call {
  to: string;
  data: string;
}
export type ExecutionCalls = Record<CallName, Call>;
export type Verdicts = Record<CallName, string>;

const VERIFY_PROOF = new Interface(["function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes)"]);
const sha256Hex = (data: Buffer | Uint8Array) => createHash("sha256").update(data).digest("hex");
const flipLastBit = (hex: string) => {
  const b = getBytes(hex);
  b[b.length - 1] ^= 1;
  return hexlify(b);
};

/** The three calls, rebuilt from committed evidence for the designation's verifier. */
export function chainExecutionCalls(designation: ProgramDesignation, repoRoot = "."): ExecutionCalls {
  const proof = JSON.parse(readFileSync(resolve(repoRoot, REAL_PROOF_REL), "utf8"));
  const v = designation.verifier;
  if (String(proof.source?.transaction).toLowerCase() !== v.realProofOnPinnedKey.transaction.toLowerCase()) {
    throw new Error(`${REAL_PROOF_REL} is not the real proof ${designation.id}'s verifier evidence names`);
  }
  const selector = v.verifierHash.slice(0, 10);
  const { programVKey, publicValues, proofBytes } = proof.call;
  if (String(proofBytes).slice(0, 10).toLowerCase() !== selector) {
    throw new Error(`the real proof is not for ${designation.id}'s verifier (selector ${selector})`);
  }
  const canary = concat([
    selector,
    AbiCoder.defaultAbiCoder().encode(
      ["uint256", "uint256", "uint256", "uint256[8]"],
      [0n, v.vkRoot, 0n, Array(8).fill(1n)],
    ),
  ]);
  const call = (pv: string, pb: string): Call => ({
    to: v.address,
    data: VERIFY_PROOF.encodeFunctionData("verifyProof", [programVKey, pv, pb]),
  });
  return {
    real: call(publicValues, proofBytes),
    tampered: call(flipLastBit(publicValues), proofBytes),
    canary: call(publicValues, canary),
  };
}

/** A call's verdict: "success" (no return data), "success <data>", or "revert <data>"; an RPC that did not answer throws. */
export async function verdictOf(provider: Provider, call: Call, blockTag?: number | string): Promise<string> {
  try {
    const out = await provider.call({ to: call.to, data: call.data, ...(blockTag === undefined ? {} : { blockTag }) });
    return out === "0x" ? "success" : `success ${out}`;
  } catch (error) {
    if (isExecutionFailure(error)) return `revert ${revertDataOf(error) ?? "0x"}`;
    throw new Error(`eth_call ${call.data.slice(0, 10)} on ${call.to} got no answer from the chain; no verdict`, {
      cause: error,
    });
  }
}

/** The three verdicts on one provider, against the required ones. Throws when the RPC does not answer. */
export async function runChainExecutionCheck(
  provider: Provider,
  calls: ExecutionCalls,
  blockTag?: number | string,
): Promise<{ verdicts: Verdicts; pass: boolean; failures: string[] }> {
  const verdicts = {} as Verdicts;
  for (const name of CALL_NAMES) verdicts[name] = await verdictOf(provider, calls[name], blockTag);
  const failures = CALL_NAMES.filter((n) => verdicts[n] !== REQUIRED_VERDICTS[n]).map(
    (n) => `${n}: ${verdicts[n]}, required ${REQUIRED_VERDICTS[n]}`,
  );
  return { verdicts, pass: failures.length === 0, failures };
}

/**
 * The runtime with each pairing STATICCALL (PUSH1 0x08 GAS STATICCALL; PUSH data skipped, so data never matches)
 * aimed at an empty account, as on a chain without the precompile. The v6.1.0 verifier has two such sites.
 */
export function patchPairingToEmptyAccount(runtime: string, expectedSites = 2): string {
  const code = Uint8Array.from(getBytes(runtime));
  let sites = 0;
  for (let i = 0; i < code.length; i++) {
    if (code[i] === 0x60 && code[i + 1] === 0x08 && code[i + 2] === 0x5a && code[i + 3] === 0xfa) {
      code[i + 1] = 0xee;
      sites++;
    }
    if (code[i] >= 0x60 && code[i] <= 0x7f) i += code[i] - 0x5f;
  }
  if (sites !== expectedSites) throw new Error(`expected ${expectedSites} pairing call sites, found ${sites}`);
  return hexlify(code);
}

/**
 * Whether the canary's positive control fired: the pinned code refuses the canary as the check requires, and the
 * same code with its pairing calls aimed at an empty account accepts it. Either alone is no detector.
 */
export function controlDetects(pinnedCode: unknown, withoutPairingPrecompile: unknown): boolean {
  return pinnedCode === REQUIRED_VERDICTS.canary && withoutPairingPrecompile === "success";
}

/** A provider for a development chain, which can install code (hardhat_setCode). */
export type DevProvider = Provider & { send(method: string, params: unknown[]): Promise<unknown> };

/**
 * The canary's positive control, on a development chain: the verifier's runtime (from its CREATE2-authenticated
 * initcode, checked against `runtimeCodeKeccak`) refuses `canaryData`, and the same runtime with its pairing calls
 * aimed at an empty account accepts it. `detects` is true only when both hold.
 */
export async function canaryPositiveControl(
  provider: DevProvider,
  canaryData: string,
  runtimeCodeKeccak: string,
  repoRoot = ".",
): Promise<{ pinnedCode: string; withoutPairingPrecompile: string; detects: boolean }> {
  const initcode = JSON.parse(readFileSync(resolve(repoRoot, VERIFIER_BYTECODE_REL), "utf8")).deployments["v6.1.0"]
    .initcode;
  const runtime = await provider.call({ data: initcode });
  if (keccak256(runtime) !== runtimeCodeKeccak) {
    throw new Error(`the initcode's runtime is not the designated verifier's (${runtimeCodeKeccak})`);
  }
  const at = (label: string) => getAddress(`0x${id(`sp1 canary positive control: ${label}`).slice(26)}`);
  await provider.send("hardhat_setCode", [at("pinned"), runtime]);
  await provider.send("hardhat_setCode", [at("without pairing"), patchPairingToEmptyAccount(runtime)]);
  const pinnedCode = await verdictOf(provider, { to: at("pinned"), data: canaryData });
  const withoutPairingPrecompile = await verdictOf(provider, { to: at("without pairing"), data: canaryData });
  return {
    pinnedCode,
    withoutPairingPrecompile,
    detects: controlDetects(pinnedCode, withoutPairingPrecompile),
  };
}

// ---------------------------------------------------------------------------------------------------------
// The committed read-only measurement
// ---------------------------------------------------------------------------------------------------------

export interface ProviderReading {
  blockHash: string;
  codeKeccak: string;
  verdicts: Verdicts;
}

export interface ChainExecutionObservation {
  schema: string;
  measuredAtUtc: string;
  designation: string;
  verifier: { address: string; runtimeCodeKeccak: string };
  proofSource: { path: string; sha256: string; transaction: string };
  calls: Record<CallName, Call & { dataSha256: string }>;
  canaryPositiveControl: { pinnedCode: string; withoutPairingPrecompile: string; detects: boolean };
  tool: { script: string; scriptSha256: string; node: string; ethers: string };
  chains: Record<
    string,
    {
      finalized: { block: number; blockHash: string };
      providers: Record<string, ProviderReading>;
      providersAgree: boolean;
      codeKeccak: string;
      verdicts: Verdicts;
    }
  >;
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Every way the observation fails to show the designated verifier giving the required verdicts on every chain it must
 * cover (the supported deployment chains and the trust target's mainnets), through two agreeing providers at one
 * finalized block, for calls rebuilt from committed evidence; empty when it does.
 */
export function chainExecutionObservationErrors(
  obs: ChainExecutionObservation,
  designation: ProgramDesignation,
  repoRoot = ".",
): string[] {
  const errors: string[] = [];
  if (obs?.schema !== CHAIN_EXECUTION_SCHEMA) errors.push(`the observation's schema must be ${CHAIN_EXECUTION_SCHEMA}`);
  if (obs?.designation !== designation.id) errors.push(`the observation is not of designation ${designation.id}`);
  if (
    String(obs?.verifier?.address).toLowerCase() !== designation.verifier.address.toLowerCase() ||
    obs?.verifier?.runtimeCodeKeccak !== designation.verifier.runtimeCodeKeccak
  ) {
    errors.push(`the observation's verifier is not ${designation.id}'s`);
  }
  const proofBytes = readFileSync(resolve(repoRoot, REAL_PROOF_REL));
  if (
    obs?.proofSource?.path !== REAL_PROOF_REL ||
    obs.proofSource.sha256 !== sha256Hex(proofBytes) ||
    String(obs.proofSource.transaction).toLowerCase() !==
      designation.verifier.realProofOnPinnedKey.transaction.toLowerCase()
  ) {
    errors.push(`the proof source is not ${REAL_PROOF_REL} as committed`);
  }
  const rebuilt = chainExecutionCalls(designation, repoRoot);
  for (const name of CALL_NAMES) {
    const sent = obs?.calls?.[name];
    if (
      !sent ||
      sent.to.toLowerCase() !== rebuilt[name].to.toLowerCase() ||
      sent.data !== rebuilt[name].data ||
      sent.dataSha256 !== sha256Hex(getBytes(rebuilt[name].data))
    ) {
      errors.push(`the observation's ${name} calldata is not the call rebuilt from committed evidence`);
    }
  }
  // The control is judged from its recorded verdicts, never from its flag (review finding F7).
  const control = obs?.canaryPositiveControl;
  if (!controlDetects(control?.pinnedCode, control?.withoutPairingPrecompile) || control?.detects !== true) {
    errors.push(
      `the canary's positive control did not fire: the pinned code gave ${String(control?.pinnedCode)} ` +
        `(required ${REQUIRED_VERDICTS.canary}), without the pairing precompile ${String(control?.withoutPairingPrecompile)} ` +
        `(required success), recorded as detecting: ${String(control?.detects)}`,
    );
  }
  let script = "";
  try {
    script = sha256Hex(readFileSync(resolve(repoRoot, CHAIN_EXECUTION_SCRIPT_REL)));
  } catch {
    script = "(unreadable)";
  }
  if (obs?.tool?.script !== CHAIN_EXECUTION_SCRIPT_REL || obs.tool.scriptSha256 !== script) {
    errors.push(
      `the observation was not made by ${CHAIN_EXECUTION_SCRIPT_REL} as committed (sha256 ${script}): re-measure`,
    );
  }
  const codes = new Set<string>();
  for (const chainId of [...SUPPORTED_DEPLOYMENT_CHAINS, ...TRUST_TARGET_ONLY_CHAINS]) {
    const c = obs?.chains?.[chainId];
    if (!c) {
      errors.push(`chain ${chainId}: not measured`);
      continue;
    }
    const readings = Object.entries(c.providers ?? {});
    if (readings.length < 2) errors.push(`chain ${chainId}: needs two providers`);
    for (const [host, r] of readings) {
      if (r.blockHash !== c.finalized?.blockHash) errors.push(`chain ${chainId}: provider ${host} read another block`);
      if (r.codeKeccak !== c.codeKeccak) errors.push(`chain ${chainId}: the providers disagree on the verifier's code`);
      if (!same(r.verdicts, c.verdicts)) errors.push(`chain ${chainId}: the providers disagree on the verdicts`);
    }
    if (c.providersAgree !== true) errors.push(`chain ${chainId}: the providers are not recorded as agreeing`);
    if (c.codeKeccak !== designation.verifier.runtimeCodeKeccak) {
      errors.push(`chain ${chainId}: the verifier's code ${String(c.codeKeccak)} is not ${designation.id}'s`);
    }
    codes.add(String(c.codeKeccak));
    for (const name of CALL_NAMES) {
      if (c.verdicts?.[name] !== REQUIRED_VERDICTS[name]) {
        errors.push(`chain ${chainId}: ${name}: ${String(c.verdicts?.[name])}, required ${REQUIRED_VERDICTS[name]}`);
      }
    }
  }
  if (codes.size > 1) errors.push("the designated verifier's runtime differs across chains (STOP)");
  return errors;
}
