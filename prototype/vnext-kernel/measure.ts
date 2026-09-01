/**
 * EXPERIMENTAL PROTOTYPE MEASUREMENT — reads compiled artifacts only.
 *
 * Run:  npx hardhat --config prototype/vnext-kernel/hardhat.config.ts compile
 *       npx tsx prototype/vnext-kernel/measure.ts
 *
 * Never run against a coverage-instrumented build: solidity-coverage rewrites
 * source and inflates every figure.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.join("prototype", "vnext-kernel");
const ART = path.join(ROOT, "artifacts", ROOT, "contracts");

/** WalletWall size vocabulary (architecture section 19.0). */
export const NETWORK_RUNTIME_LIMIT = 24_576;
export const NETWORK_INITCODE_LIMIT = 49_152;
export const WALLETWALL_PORTABILITY_BUDGET = 24_576;
export const WALLETWALL_INTERNAL_RESERVE = 2_600;
export const TARGET_KERNEL_CEILING = WALLETWALL_PORTABILITY_BUDGET - WALLETWALL_INTERNAL_RESERVE;

export interface Measurement {
  readonly name: string;
  readonly runtime: number;
  readonly initcode: number;
  readonly immutableSlots: number;
  readonly runtimeKeccakOfArtifact: string;
  readonly selectors: number;
}

const keccakLike = (hex: string) =>
  createHash("sha256")
    .update(Buffer.from(hex.slice(2), "hex"))
    .digest("hex");

export function measure(file: string, name: string): Measurement {
  const p = path.join(ART, file, `${name}.json`);
  const a = JSON.parse(fs.readFileSync(p, "utf8"));
  const runtime = (a.deployedBytecode.length - 2) / 2;
  const initcode = (a.bytecode.length - 2) / 2;
  const selectors = (a.abi as { type: string }[]).filter((e) => e.type === "function").length;
  return {
    name,
    runtime,
    initcode,
    immutableSlots: Object.keys(a.immutableReferences ?? {}).length,
    runtimeKeccakOfArtifact: `sha256:${keccakLike(a.deployedBytecode)}`,
    selectors,
  };
}

export function verdict(runtime: number): string {
  if (runtime <= TARGET_KERNEL_CEILING) return "TARGET PASS";
  if (runtime <= WALLETWALL_PORTABILITY_BUDGET) return "ARCHITECTURE PRESSURE";
  return "CURRENT PORTABILITY FAIL";
}

function main(): void {
  const rows = [
    measure("VaultKernelPrototype.sol", "VaultKernelPrototype"),
    measure("VaultKernelFactoryPrototype.sol", "VaultKernelFactoryPrototype"),
  ];
  const out = {
    solc: "0.8.24",
    evmVersion: "cancun",
    optimizer: { enabled: true, runs: 200 },
    viaIR: false,
    limits: {
      NETWORK_RUNTIME_LIMIT,
      NETWORK_INITCODE_LIMIT,
      WALLETWALL_PORTABILITY_BUDGET,
      WALLETWALL_INTERNAL_RESERVE,
      TARGET_KERNEL_CEILING,
    },
    contracts: rows.map((r) => ({
      ...r,
      headroomVsPortabilityBudget: WALLETWALL_PORTABILITY_BUDGET - r.runtime,
      headroomVsTargetCeiling: TARGET_KERNEL_CEILING - r.runtime,
      initcodeHeadroom: NETWORK_INITCODE_LIMIT - r.initcode,
      verdict: verdict(r.runtime),
    })),
  };
  console.log(JSON.stringify(out, null, 2));
}

main();
