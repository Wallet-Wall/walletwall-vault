/**
 * Read-only per-chain execution check of a designation's SP1 verifier (CODE_HASH_PIN_WITH_PER_CHAIN_EXECUTION_CHECK;
 * scripts/lib/sp1-chain-execution.ts).
 *
 * For every supported deployment chain and the trust target's mainnets, at the chain's FINALIZED block and through two
 * public providers each: the verifier's runtime code hash and the three verdicts (real proof, tampered copy, odd-word
 * canary), for calldata rebuilt from committed evidence. The canary's positive control runs on the in-process EVM.
 * Only eth_chainId, eth_getBlockByNumber, eth_getCode and eth_call are sent: nothing is signed or written.
 *
 * Usage:
 *   npm run sp1:chain-exec                         # measure and print; exit non-zero on any failure (STOP)
 *   SP1_CHAIN_EXEC_WRITE=1 npm run sp1:chain-exec  # also write evidence/zk/sp1-impl/observations/chain-execution.raw.json
 *   SP1_DESIGNATION_ID=<id>                        # another designation (default: the first)
 *
 * Research prototype. Not audited. Testnet/local only. Do not use real funds.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { network } from "hardhat";
import { JsonRpcProvider, getBytes, keccak256, version as ethersVersion } from "ethers";

import { readDesignations } from "./lib/sp1-designation";
import {
  CHAIN_EXECUTION_OBSERVATION_REL,
  CHAIN_EXECUTION_SCHEMA,
  REAL_PROOF_REL,
  SUPPORTED_DEPLOYMENT_CHAINS,
  TRUST_TARGET_ONLY_CHAINS,
  canaryPositiveControl,
  chainExecutionCalls,
  chainExecutionObservationErrors,
  runChainExecutionCheck,
  type ChainExecutionObservation,
  type DevProvider,
  type ProviderReading,
} from "./lib/sp1-chain-execution";
import { runScript } from "./lib/run-script";

/** Two independent public providers per chain (no keys; nothing here authenticates or signs). */
const PROVIDERS: Record<string, string[]> = {
  "1": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"],
  "8453": ["https://mainnet.base.org", "https://base.gateway.tenderly.co"],
  "11155111": ["https://ethereum-sepolia-rpc.publicnode.com", "https://eth-sepolia.api.onfinality.io/public"],
  "84532": ["https://sepolia.base.org", "https://base-sepolia-rpc.publicnode.com"],
};
const SCRIPT_REL = "scripts/check-sp1-chain-execution.ts";
const sha256Hex = (data: Buffer | Uint8Array) => createHash("sha256").update(data).digest("hex");

async function measureChain(
  chainId: string,
  urls: string[],
  calls: ReturnType<typeof chainExecutionCalls>,
  verifier: string,
) {
  const providers = urls.map((u) => new JsonRpcProvider(u, Number(chainId), { staticNetwork: true }));
  for (const [i, p] of providers.entries()) {
    const reported = BigInt(String(await p.send("eth_chainId", [])));
    if (reported !== BigInt(chainId)) throw new Error(`${urls[i]} reports chain ${reported}, not ${chainId}`);
  }
  const finalized = await providers[0].getBlock("finalized");
  if (finalized === null || finalized.hash === null) throw new Error(`chain ${chainId}: no finalized block`);
  const providersRead: Record<string, ProviderReading> = {};
  for (const [i, p] of providers.entries()) {
    const block = await p.getBlock(finalized.number);
    const code = await p.getCode(verifier, finalized.number);
    const { verdicts } = await runChainExecutionCheck(p, calls, finalized.number);
    providersRead[new URL(urls[i]).host] = { blockHash: String(block?.hash), codeKeccak: keccak256(code), verdicts };
  }
  for (const p of providers) p.destroy();
  const readings = Object.values(providersRead);
  const providersAgree = readings.every(
    (r) =>
      r.blockHash === finalized.hash &&
      r.codeKeccak === readings[0].codeKeccak &&
      JSON.stringify(r.verdicts) === JSON.stringify(readings[0].verdicts),
  );
  return {
    finalized: { block: finalized.number, blockHash: finalized.hash },
    providers: providersRead,
    providersAgree,
    codeKeccak: readings[0].codeKeccak,
    verdicts: readings[0].verdicts,
  };
}

async function main() {
  const designations = readDesignations();
  const wanted = process.env.SP1_DESIGNATION_ID ?? designations[0]?.id;
  const d = designations.find((x) => x.id === wanted);
  if (!d) throw new Error(`no designation ${String(wanted)}`);
  const calls = chainExecutionCalls(d);
  const local = await network.create("default");
  const control = await canaryPositiveControl(
    local.ethers.provider as unknown as DevProvider,
    calls.canary.data,
    d.verifier.runtimeCodeKeccak,
  );
  if (!control.detects) throw new Error(`the canary's positive control did not fire: ${JSON.stringify(control)}`);

  const chains: ChainExecutionObservation["chains"] = {};
  for (const chainId of [...SUPPORTED_DEPLOYMENT_CHAINS, ...TRUST_TARGET_ONLY_CHAINS]) {
    const urls = PROVIDERS[chainId];
    if (!urls) throw new Error(`no providers configured for chain ${chainId}`);
    chains[chainId] = await measureChain(chainId, urls, calls, d.verifier.address);
    console.log(`chain ${chainId} @ ${chains[chainId].finalized.block}: ${JSON.stringify(chains[chainId].verdicts)}`);
  }
  const observation: ChainExecutionObservation = {
    schema: CHAIN_EXECUTION_SCHEMA,
    measuredAtUtc: new Date().toISOString(),
    designation: d.id,
    verifier: { address: d.verifier.address, runtimeCodeKeccak: d.verifier.runtimeCodeKeccak },
    proofSource: {
      path: REAL_PROOF_REL,
      sha256: sha256Hex(readFileSync(resolve(REAL_PROOF_REL))),
      transaction: d.verifier.realProofOnPinnedKey.transaction,
    },
    calls: {
      real: { ...calls.real, dataSha256: sha256Hex(getBytes(calls.real.data)) },
      tampered: { ...calls.tampered, dataSha256: sha256Hex(getBytes(calls.tampered.data)) },
      canary: { ...calls.canary, dataSha256: sha256Hex(getBytes(calls.canary.data)) },
    },
    canaryPositiveControl: control,
    tool: {
      script: SCRIPT_REL,
      scriptSha256: sha256Hex(readFileSync(resolve(SCRIPT_REL))),
      node: process.version,
      ethers: ethersVersion,
    },
    chains,
  };
  const errors = chainExecutionObservationErrors(observation, d);
  if (process.env.SP1_CHAIN_EXEC_WRITE === "1") {
    mkdirSync(dirname(resolve(CHAIN_EXECUTION_OBSERVATION_REL)), { recursive: true });
    writeFileSync(resolve(CHAIN_EXECUTION_OBSERVATION_REL), `${JSON.stringify(observation, null, 2)}\n`);
    console.log(`wrote ${CHAIN_EXECUTION_OBSERVATION_REL}`);
  }
  if (errors.length > 0) throw new Error(`STOP: the per-chain execution check failed:\n - ${errors.join("\n - ")}`);
  console.log(`PASS: ${d.id}'s verifier gives the required verdicts on every measured chain.`);
}

runScript(main);
