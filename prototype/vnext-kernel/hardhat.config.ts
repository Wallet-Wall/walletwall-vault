/**
 * EXPERIMENTAL PROTOTYPE BUILD — deliberately ISOLATED from the production
 * Hardhat compilation unit.
 *
 * The production config compiles `contracts/` into `artifacts/` and runs
 * `test/`. This config compiles `prototype/vnext-kernel/contracts/` into
 * `prototype/vnext-kernel/artifacts/` and runs `prototype/vnext-kernel/test/`.
 * The two share NO source path, NO artifact path and NO cache path, which is
 * what keeps production runtime-byte claims, deployment manifests and
 * reproducibility evidence untouched by this experiment.
 *
 * The solc settings are PINNED IDENTICAL to the production config, so every
 * byte figure is comparable to the monolith's without a compiler caveat.
 */
import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthers],
  paths: {
    sources: "prototype/vnext-kernel/contracts",
    tests: { mocha: "prototype/vnext-kernel/test" },
    cache: "prototype/vnext-kernel/cache",
    artifacts: "prototype/vnext-kernel/artifacts",
  },
  typechain: {
    outDir: "prototype/vnext-kernel/typechain-types",
  },
  solidity: {
    version: "0.8.24",
    settings: {
      evmVersion: "cancun",
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
});
