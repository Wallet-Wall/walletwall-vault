/**
 * Registry facts measured from the chain (the SP1 implementation lane; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 *   registrationFact — a WRAPPER_REGISTERED fact from the deployment transaction's receipt (it created the wrapper,
 *     and who sent it) and the wrapper's measured profile (its recorded build, SP1 verifier and that verifier's code
 *     hash, PROGRAM_VKEY, identity, halt principal), joined to the designation of that identity; a wrapper already
 *     halted is registered too, so that its halt can be published (the re-review's L1).
 *   haltFact — a WRAPPER_HALTED fact from the halt transaction's receipt (the wrapper emitted VerifierHalted) and the
 *     wrapper's measured state (HALTED, and still the wrapper its registration records), with the measured identity.
 *
 * Every fact is observed at the chain's finalized block: the transaction it records must be final by then, and the
 * wrapper is measured at that block, so the fact holds what one chain state shows. A finalized read that fails is no
 * answer and throws (it is never replaced by the latest block). Each fact is checked against the registry it would
 * extend (registryErrors, with the builds and designations) before it is returned; nothing here writes to a chain,
 * and every RPC failure propagates.
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { getAddress, id, type Provider } from "ethers";

import type { ProgramDesignation } from "./sp1-designation";
import { HALT_REASONS, registryErrors, registryState, type RegistryDoc, type RegistryFact } from "./sp1-registry";
import type { WrapperBuild } from "./sp1-wrapper-build";
import { profileVerifier } from "./verifier-binding";

const VERIFIER_HALTED = id("VerifierHalted(address)");

/** The finalized block the facts are observed at. A chain or RPC that gives none fails the measurement. */
export async function finalizedBlock(provider: Provider): Promise<{ block: number; blockHash: string }> {
  const block = await provider.getBlock("finalized");
  if (block === null || block.hash === null)
    throw new Error("the chain gave no finalized block to observe the facts at");
  return { block: block.number, blockHash: block.hash };
}

function final(what: string, txBlock: number, observedAt: { block: number }): void {
  if (txBlock > observedAt.block) {
    throw new Error(
      `${what} in block ${txBlock} is not final yet (the finalized block is ${observedAt.block}): record it once it is`,
    );
  }
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
  const observedAt = await finalizedBlock(provider);
  const receipt = await provider.getTransactionReceipt(input.deploymentTx);
  if (
    receipt === null ||
    receipt.status !== 1 ||
    receipt.contractAddress === null ||
    getAddress(receipt.contractAddress) !== wrapper
  ) {
    throw new Error(`transaction ${input.deploymentTx} did not deploy ${wrapper}`);
  }
  final(`the deployment of ${wrapper}`, receipt.blockNumber, observedAt);
  const p = await profileVerifier(provider, wrapper, input.builds, observedAt.block);
  if (p.wrapperBuild === null) throw new Error(`${wrapper} is no recorded wrapper build`);
  // A wrapper already HALTED is registered all the same: what a registration records is immutable, and its halt can
  // only be published once it is registered (the re-review's L1). Until the halt fact follows, the binding gate
  // refuses it, because the chain shows a halt the registry does not record.
  if (
    p.halted === null ||
    p.haltPrincipal === null ||
    p.identity === null ||
    p.sp1Verifier === null ||
    p.programVKey === null
  ) {
    throw new Error(
      `${wrapper} could not be measured as a wrapper with an identity, a halt principal and a halt state`,
    );
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
      observedAt,
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
  const observedAt = await finalizedBlock(provider);
  const receipt = await provider.getTransactionReceipt(input.haltTx);
  const halted =
    receipt?.logs.some((l) => getAddress(l.address) === wrapper && l.topics[0] === VERIFIER_HALTED) ?? false;
  if (receipt === null || receipt.status !== 1 || !halted) {
    throw new Error(`transaction ${input.haltTx} emitted no VerifierHalted from ${wrapper}`);
  }
  final(`the halt of ${wrapper}`, receipt.blockNumber, observedAt);
  const p = await profileVerifier(provider, wrapper, input.builds, observedAt.block);
  if (p.halted !== true) throw new Error(`${wrapper} is not HALTED on chain ${chainId}`);
  // The halted wrapper must be the one its registration describes: the identity a halt retires is the one measured.
  const differs = (
    [
      ["identity", registration.identity, p.identity],
      ["PROGRAM_VKEY", registration.programVKey, p.programVKey],
      ["SP1 verifier", registration.sp1Verifier?.address, p.sp1Verifier],
      ["SP1 verifier code", registration.sp1Verifier?.runtimeCodeKeccak, p.sp1VerifierCodeKeccak],
      ["halt principal", registration.haltPrincipal, p.haltPrincipal],
      ["wrapper build", registration.wrapperBuild, p.wrapperBuild],
    ] as const
  ).filter(([, recorded, measured]) => recorded !== measured);
  if (differs.length > 0) {
    throw new Error(
      `${wrapper} measured on chain ${chainId} is not what its registration records (fact #${registration.seq}): ` +
        differs
          .map(([field, recorded, measured]) => `${field} ${String(recorded)} recorded, ${String(measured)} measured`)
          .join("; "),
    );
  }
  return checked(
    input.registry,
    {
      seq: input.registry.facts.length + 1,
      kind: "WRAPPER_HALTED",
      chainId,
      address: wrapper,
      identity: String(p.identity),
      observedAt,
      reason: input.reason,
      halt: { txHash: input.haltTx, block: receipt.blockNumber },
    },
    input.builds,
    null,
  );
}
