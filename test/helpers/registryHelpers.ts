/**
 * Test fixtures for the v2 wrapper registry (scripts/lib/sp1-registry.ts): fact logs that mirror measured profiles,
 * and wrappers of a synthetic later build. Test-only: real facts are written by scripts/register-sp1-wrapper.ts from
 * chain reads.
 */
import { ethers, networkHelpers } from "./connection";
import { MIGRATED_FROM, REGISTRY_SCHEMA, type RegistryDoc, type RegistryFact } from "../../scripts/lib/sp1-registry";
import type { VerifierProfile } from "../../scripts/lib/verifier-binding";
import type { WrapperBuild } from "../../scripts/lib/sp1-wrapper-build";

const word = (label: string) => ethers.id(label);

/** One registration per profile on `chainId` (and a halt fact for each one measured HALTED), in order. */
export function registryFromProfiles(
  chainId: bigint | string,
  profiles: readonly VerifierProfile[],
  extraFacts: readonly Omit<RegistryFact, "seq">[] = [],
): RegistryDoc {
  const facts: RegistryFact[] = [];
  const push = (f: Omit<RegistryFact, "seq">) => facts.push({ ...f, seq: facts.length + 1 } as RegistryFact);
  for (const p of profiles) {
    push({
      kind: "WRAPPER_REGISTERED",
      chainId: chainId.toString(),
      address: ethers.getAddress(p.address),
      identity: p.identity ?? ethers.ZeroHash,
      observedAt: { block: 1, blockHash: word(`observed ${p.address}`) },
      wrapperBuild: p.wrapperBuild ?? "zkmldsa-verifier-b1",
      designation: "mldsa65-withdrawal-d1",
      sp1Verifier: {
        address: ethers.getAddress(p.sp1Verifier ?? ethers.ZeroAddress),
        runtimeCodeKeccak: p.sp1VerifierCodeKeccak ?? ethers.ZeroHash,
      },
      programVKey: p.programVKey ?? ethers.ZeroHash,
      haltPrincipal: ethers.getAddress(p.haltPrincipal ?? ethers.ZeroAddress),
      deployment: { txHash: word(`deploy ${p.address}`), block: 1, deployer: ethers.getAddress(ethers.ZeroAddress) },
      replaces: null,
    });
  }
  for (const p of profiles) {
    if (p.halted === true) {
      push({
        kind: "WRAPPER_HALTED",
        chainId: chainId.toString(),
        address: ethers.getAddress(p.address),
        identity: p.identity ?? ethers.ZeroHash,
        observedAt: { block: 2, blockHash: word(`halt observed ${p.address}`) },
        reason: "VERIFIER_SOUNDNESS",
        halt: { txHash: word(`halt ${p.address}`), block: 2 },
      });
    }
  }
  for (const f of extraFacts) push(f);
  return { schema: REGISTRY_SCHEMA, note: "test", migratedFrom: { ...MIGRATED_FROM }, facts };
}

/**
 * A later wrapper build: `base` with its pinned SP1 verifier code hash replaced by `pin` wherever the constant appears
 * in the runtime (the SP1_VERIFIER_CODEHASH getter), as a successor build that pins a fixed verifier would differ.
 */
export function laterBuild(base: WrapperBuild, pin: string, sequence: number): WrapperBuild {
  const from = base.pins.sp1VerifierCodehash.slice(2);
  const template = `0x${base.runtime.template.slice(2).split(from).join(pin.slice(2).toLowerCase())}`;
  if (template === base.runtime.template) throw new Error("the pinned constant is not in the runtime");
  return {
    ...base,
    id: `zkmldsa-verifier-b${sequence}`,
    sequence,
    pins: { ...base.pins, sp1VerifierCodehash: pin.toLowerCase() },
    runtime: { ...base.runtime, template, templateKeccak: ethers.keccak256(template) },
  };
}

/**
 * Installs a wrapper of `build` at a fresh address: its runtime with the immutables written in (the SP1 verifier,
 * PROGRAM_VKEY, the halt principal) and halted = false, exactly what that build's constructor would leave.
 */
export async function installWrapperOfBuild(
  build: WrapperBuild,
  sp1Verifier: string,
  programVKey: string,
  haltPrincipal: string,
): Promise<string> {
  const code = ethers.getBytes(build.runtime.template);
  const values: Record<string, string> = {
    SP1_VERIFIER: ethers.zeroPadValue(sp1Verifier, 32),
    PROGRAM_VKEY: programVKey,
    HALT_PRINCIPAL: ethers.zeroPadValue(haltPrincipal, 32),
  };
  for (const [name, refs] of Object.entries(build.runtime.immutableReferences)) {
    for (const { start } of refs) code.set(ethers.getBytes(values[name]), start);
  }
  const address = ethers.getAddress(ethers.dataSlice(ethers.id(`${build.id} at ${sp1Verifier} ${programVKey}`), 12));
  await networkHelpers.setCode(address, ethers.hexlify(code));
  return address;
}
