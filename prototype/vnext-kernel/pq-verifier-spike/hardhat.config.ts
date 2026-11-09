/**
 * GEN2-PQ-CONFORMANCE-1 — ISOLATED Hardhat configuration for the ML-DSA-65 verifier conformance spike.
 *
 * EXPERIMENTAL · UNAUDITED · NOT PRODUCTION · NOT CONNECTED TO ANY KERNEL.
 *
 * This configuration shares NO source, artifact or cache path with the production project
 * (`hardhat.config.ts` at the repository root), with the vNext kernel prototype
 * (`prototype/vnext-kernel/hardhat.config.ts`) or with the Generation-2 candidate
 * (`prototype/vnext-kernel/generation-2/`, whose evidence receipts walk that directory and would
 * move if anything were added under it). Nothing here is compiled or run by any CI workflow: the
 * suites are run by explicit path, and their results are recorded in SPIKE_RECORD.md.
 *
 * Only the harness contracts (`harness/`) are compiled through Hardhat. The VENDORED verifier
 * closure (`vendor/`) is compiled by `lib/compile.ts` straight from the pinned solc binary with
 * the vendor's own source-unit names and settings, so the bytes recorded in MEASUREMENTS.json are
 * reproducible without this file. Hardhat's part is to supply the pinned compiler binary and the
 * simulated EVM (EDR, Osaka rules: EIP-7825 per-transaction gas cap in force).
 *
 * Compiler settings are the vendor's (ZKNoxHQ/ETHDILITHIUM, branch mldsa-65, 4c370bb5,
 * foundry.toml [profile.default]): solc 0.8.30, evm osaka, via-IR, optimizer runs 1,000,000.
 */
import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

const SPIKE = "prototype/vnext-kernel/pq-verifier-spike";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  paths: {
    sources: `${SPIKE}/harness`,
    tests: { mocha: `${SPIKE}/test` },
    cache: `${SPIKE}/cache`,
    artifacts: `${SPIKE}/artifacts`,
  },
  typechain: {
    outDir: `${SPIKE}/typechain-types`,
  },
  solidity: {
    version: "0.8.30",
    settings: {
      evmVersion: "osaka",
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 1_000_000,
      },
    },
  },
  networks: {
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
      hardfork: "osaka",
      blockGasLimit: 40_000_000,
      allowUnlimitedContractSize: false,
      initialBaseFeePerGas: 0,
    },
  },
});
