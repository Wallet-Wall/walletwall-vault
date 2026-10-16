/**
 * Shared fixtures for the SP1-TD2 suites (docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md): haltable
 * ZKMLDSAVerifier wrappers over a program-bound SP1 stand-in, and proofs for them.
 *
 * `ProgramBoundMockSP1Verifier` accepts a proof only for a (program vkey, journal) pair a test registered as
 * proven, so "valid" here means "a journal an honest execution of that program would commit": the real EIP-712
 * digest, the registered ML-DSA-65 key and a real ML-DSA-65 signature over the digest, the chain id and the
 * wrapper's own address. Anything never registered stands for a proof that cannot exist.
 */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { ethers } from "./connection";
import { withPinnedSp1Code } from "./sp1PinnedVerifier";
import { ProverClient } from "../../scripts/prover-client";

export const ABI = ethers.AbiCoder.defaultAbiCoder();

/** Labelled test identities: two withdrawal-program builds whose wrappers are independently established. */
export const VKEY_A = ethers.id("SP1-TD2 test identity: withdrawal program, build A");
export const VKEY_B = ethers.id("SP1-TD2 test identity: withdrawal program, build B");

export const MODE = { EcdsaOnly: 0, PqOnly: 1, Hybrid: 2 } as const;
export const DAY = 24 * 60 * 60;
/** The repository's verifier-rotation delay (WalletWallVault.PQ_VERIFIER_UPDATE_DELAY). */
export const ROTATION_DELAY = 2 * DAY;
export const GRACE_PERIOD = 14 * DAY;

export interface MlDsaKey {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export const mlDsaKey = (): MlDsaKey => ml_dsa65.keygen();
export const mlDsaSign = (digest: string, key: MlDsaKey) => ml_dsa65.sign(ethers.getBytes(digest), key.secretKey);

export async function deploySp1(): Promise<any> {
  return (await ethers.getContractFactory("ProgramBoundMockSP1Verifier")).deploy();
}

/** The genuine ZKMLDSAVerifier over a stand-in SP1 verifier, which keeps its address, code and state. */
export async function deployWrapper(sp1: any, vkey: string, haltPrincipal: string): Promise<any> {
  const address = await sp1.getAddress();
  const factory = await ethers.getContractFactory("ZKMLDSAVerifier");
  return withPinnedSp1Code(address, () => factory.deploy(address, vkey, haltPrincipal));
}

/**
 * A proof `wrapper` accepts for (digest, key, signature): the honest journal, registered as proven for the
 * wrapper's own PROGRAM_VKEY on its own SP1 verifier, encoded as ZKMLDSAVerifier expects.
 */
export async function proveFor(wrapper: any, digest: string, publicKey: Uint8Array, signature: Uint8Array) {
  const sp1 = await ethers.getContractAt("ProgramBoundMockSP1Verifier", await wrapper.SP1_VERIFIER());
  const journal = ProverClient.encodePublicValues(
    digest,
    publicKey,
    signature,
    (await ethers.provider.getNetwork()).chainId,
    await wrapper.getAddress(),
  );
  await (await sp1.setProven(await wrapper.PROGRAM_VKEY(), journal)).wait();
  return ABI.encode(["bytes", "bytes"], [journal, "0x01"]);
}

/** A journal nobody proved: the same fields, never registered (a proof that cannot exist). */
export async function unprovenFor(wrapper: any, digest: string, publicKey: Uint8Array, signature: Uint8Array) {
  const journal = ProverClient.encodePublicValues(
    digest,
    publicKey,
    signature,
    (await ethers.provider.getNetwork()).chainId,
    await wrapper.getAddress(),
  );
  return ABI.encode(["bytes", "bytes"], [journal, "0x01"]);
}

/** Every non-view, non-pure function in a contract's ABI, by name. */
export function mutatingFunctions(contract: { interface: any }): string[] {
  const names: string[] = [];
  contract.interface.forEachFunction((f: any) => {
    if (f.stateMutability !== "view" && f.stateMutability !== "pure") names.push(f.name);
  });
  return names.sort();
}
