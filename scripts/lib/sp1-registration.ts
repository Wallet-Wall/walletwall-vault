/**
 * Registry facts measured from the chain (the SP1 implementation lane; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 *   registrationFact — a WRAPPER_REGISTERED fact from the deployment transaction's receipt (it created the wrapper,
 *     and who sent it) and the wrapper's measured profile (its recorded build, SP1 verifier and that verifier's code
 *     hash, PROGRAM_VKEY, identity, halt principal, ACTIVE), joined to the designation of that identity.
 *   haltFact — a WRAPPER_HALTED fact from the halt transaction's receipt (the wrapper emitted VerifierHalted) and the
 *     wrapper's measured state (HALTED), for a wrapper already registered.
 *
 * Each fact is checked against the registry it would extend (registryErrors, with the builds and designations) before
 * it is returned; nothing here writes to a chain, and every RPC failure propagates.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { getAddress, id, type Provider } from "ethers";

import type { ProgramDesignation } from "./sp1-designation";
import { HALT_REASONS, registryErrors, registryState, type RegistryDoc, type RegistryFact } from "./sp1-registry";
import type { WrapperBuild } from "./sp1-wrapper-build";
import { profileVerifier } from "./verifier-binding";

const VERIFIER_HALTED = id("VerifierHalted(address)");

/** The block the facts are observed at: the finalized one where the chain has it, else the latest. */
async function observedAt(provider: Provider): Promise<{ block: number; blockHash: string }> {
  let block = null;
  try {
    block = await provider.getBlock("finalized");
  } catch (error) {
    // A node without the finalized tag answers with an error; any other failure is not an answer.
    if (!/finalized|not supported|unknown block|invalid block tag/i.test(String((error as Error)?.message)))
      throw error;
  }
  block ??= await provider.getBlock("latest");
  if (block === null || block.hash === null) throw new Error("the chain gave no block to observe the facts at");
  return { block: block.number, blockHash: block.hash };
}

function checked(
  registry: RegistryDoc,
  fact: RegistryFact,
  builds: readonly WrapperBuild[],
  designations: readonly ProgramDesignation[] | null,
): RegistryFact {
  const errors = registryErrors({ ...registry, facts: [...registry.facts, fact] }, builds, designations);
  if (errors.length > 0) throw new Error(`the measured fact does not extend the registry:\n - ${errors.join("\n - ")}`);
  return fact;
}

/** The registration fact of `wrapper`, deployed by `deploymentTx`, measured from the chain and checked. */
export async function registrationFact(
  provider: Provider,
  input: {
    wrapper: string;
    deploymentTx: string;
    designations: readonly ProgramDesignation[];
    builds: readonly WrapperBuild[];
    registry: RegistryDoc;
    replaces?: string | null;
  },
): Promise<RegistryFact> {
  const wrapper = getAddress(input.wrapper);
  const receipt = await provider.getTransactionReceipt(input.deploymentTx);
  if (
    receipt === null ||
    receipt.status !== 1 ||
    receipt.contractAddress === null ||
    getAddress(receipt.contractAddress) !== wrapper
  ) {
    throw new Error(`transaction ${input.deploymentTx} did not deploy ${wrapper}`);
  }
  const p = await profileVerifier(provider, wrapper, input.builds);
  if (p.wrapperBuild === null) throw new Error(`${wrapper} is no recorded wrapper build`);
  if (
    p.halted !== false ||
    p.haltPrincipal === null ||
    p.identity === null ||
    p.sp1Verifier === null ||
    p.programVKey === null
  ) {
    throw new Error(`${wrapper} could not be measured as an ACTIVE wrapper with an identity and a halt principal`);
  }
  const designation = input.designations.find((d) => d.identity === p.identity);
  if (!designation) throw new Error(`no designation has ${wrapper}'s identity ${p.identity}`);
  const chainId = (await provider.getNetwork()).chainId.toString();
  return checked(
    input.registry,
    {
      seq: input.registry.facts.length + 1,
      kind: "WRAPPER_REGISTERED",
      chainId,
      address: wrapper,
      identity: p.identity,
      observedAt: await observedAt(provider),
      wrapperBuild: p.wrapperBuild,
      designation: designation.id,
      sp1Verifier: { address: p.sp1Verifier, runtimeCodeKeccak: String(p.sp1VerifierCodeKeccak) },
      programVKey: p.programVKey,
      haltPrincipal: p.haltPrincipal,
      deployment: { txHash: input.deploymentTx, block: receipt.blockNumber, deployer: getAddress(receipt.from) },
      replaces: input.replaces ? { address: getAddress(input.replaces) } : null,
    },
    input.builds,
    input.designations,
  );
}

/** The halt fact of a registered `wrapper`, halted by `haltTx`, measured from the chain and checked. */
export async function haltFact(
  provider: Provider,
  input: { wrapper: string; haltTx: string; reason: string; registry: RegistryDoc; builds: readonly WrapperBuild[] },
): Promise<RegistryFact> {
  const wrapper = getAddress(input.wrapper);
  if (!(HALT_REASONS as readonly string[]).includes(input.reason)) {
    throw new Error(`the halt reason must be one of ${HALT_REASONS.join(", ")}`);
  }
  const chainId = (await provider.getNetwork()).chainId.toString();
  const registration = registryState(input.registry).registration(chainId, wrapper);
  if (registration === undefined) throw new Error(`${wrapper} is not registered on chain ${chainId}`);
  const receipt = await provider.getTransactionReceipt(input.haltTx);
  const halted =
    receipt?.logs.some((l) => getAddress(l.address) === wrapper && l.topics[0] === VERIFIER_HALTED) ?? false;
  if (receipt === null || receipt.status !== 1 || !halted) {
    throw new Error(`transaction ${input.haltTx} emitted no VerifierHalted from ${wrapper}`);
  }
  const p = await profileVerifier(provider, wrapper, input.builds);
  if (p.halted !== true) throw new Error(`${wrapper} is not HALTED on chain ${chainId}`);
  return checked(
    input.registry,
    {
      seq: input.registry.facts.length + 1,
      kind: "WRAPPER_HALTED",
      chainId,
      address: wrapper,
      identity: registration.identity,
      observedAt: await observedAt(provider),
      reason: input.reason,
      halt: { txHash: input.haltTx, block: receipt.blockNumber },
    },
    input.builds,
    null,
  );
}
