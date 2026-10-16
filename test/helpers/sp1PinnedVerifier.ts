/**
 * The designated SP1 verifier for tests (the SP1 implementation lane; docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * `ZKMLDSAVerifier` refuses, in its constructor, any SP1 verifier whose runtime code is not Succinct's Groth16
 * SP1Verifier v6.1.0 (`SP1_VERIFIER_CODEHASH`). The real bytes come from the CREATE2 initcode SP1-TD1 recorded and
 * authenticated against the mainnet address (evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json), so a
 * test deploys exactly the code the pin names.
 *
 * No WalletWall proof exists yet (the v6.1.0 circuit download is the owner's gate), so a test that needs a proof to
 * VERIFY still uses a stand-in SP1 verifier (a mock, a program-bound stand-in, an upstream probe). `withPinnedSp1Code`
 * builds the genuine wrapper over such a stand-in: it puts the v6.1.0 runtime at the stand-in's address for the
 * constructor's check only, then puts the stand-in's own code back (storage is never touched, so the stand-in keeps
 * its state and its address). That is a test fixture, possible only on a development chain (`hardhat_setCode`):
 * on a real chain the code at the pinned verifier's address cannot change (its runtime has no reachable
 * SELFDESTRUCT, DELEGATECALL or CALLCODE; SP1-TD1). It also reproduces the wrapper SP1-TD1 measured before the pin
 * existed, which SP1-TD1's option probes still need.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { ethers, networkHelpers } from "./connection";

const BYTECODE = JSON.parse(
  readFileSync(resolve("evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json"), "utf8"),
);

/** Succinct's CREATE2 initcode for the Groth16 SP1Verifier v6.1.0, as deployed on mainnet. */
export const V610_INITCODE: string = BYTECODE.deployments["v6.1.0"].initcode;

let cachedRuntime: string | null = null;

/** Deploys the real v6.1.0 SP1 verifier bytes (no constructor arguments, no immutables) and returns the address. */
export async function deployPinnedSp1Verifier(): Promise<string> {
  const [deployer] = await ethers.getSigners();
  const receipt = await (await deployer.sendTransaction({ data: V610_INITCODE })).wait();
  return receipt!.contractAddress as string;
}

/** The v6.1.0 runtime code (what the pin's code hash measures). */
export async function v610Runtime(): Promise<string> {
  if (cachedRuntime === null) cachedRuntime = await ethers.provider.getCode(await deployPinnedSp1Verifier());
  return cachedRuntime;
}

/**
 * Runs `deploy` while the account at `sp1` carries the v6.1.0 runtime, then restores the code it had. Use it to
 * build the genuine `ZKMLDSAVerifier` over a stand-in SP1 verifier; never to build one over the real bytes (deploy
 * those with `deployPinnedSp1Verifier`, which needs no swap).
 */
export async function withPinnedSp1Code<T>(sp1: string, deploy: () => Promise<T>): Promise<T> {
  const original = await ethers.provider.getCode(sp1);
  if (original === "0x") throw new Error(`withPinnedSp1Code: ${sp1} has no code to stand in for`);
  await networkHelpers.setCode(sp1, await v610Runtime());
  try {
    const result = await deploy();
    const pending = result as { waitForDeployment?: () => Promise<unknown> };
    if (typeof pending?.waitForDeployment === "function") await pending.waitForDeployment();
    return result;
  } finally {
    await networkHelpers.setCode(sp1, original);
  }
}
