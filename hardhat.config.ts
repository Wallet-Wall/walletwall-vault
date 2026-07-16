// Load environment variables from a local, git-ignored .env file before any
// config below reads process.env. This is what makes the documented
// `cp .env.example .env` workflow actually work for `hardhat run` /
// `npm run deploy:*` — Hardhat does not load .env on its own. Never commit .env.
import "dotenv/config";

import { defineConfig } from "hardhat/config";
import hardhatToolboxMochaEthers from "@nomicfoundation/hardhat-toolbox-mocha-ethers";

const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
const accounts = deployerKey ? [deployerKey] : [];

export default defineConfig({
  // Hardhat 3 requires plugins to be declared explicitly (no side-effect imports).
  plugins: [hardhatToolboxMochaEthers],
  // Keep the descriptive generated-types directory name. Hardhat 3's typechain
  // plugin nests the ethers-v6 output under `<outDir>/ethers-contracts/`.
  typechain: {
    outDir: "typechain-types",
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
  networks: {
    localhost: {
      type: "http",
      url: process.env.RPC_URL ?? "http://127.0.0.1:8545",
    },
    sepolia: {
      type: "http",
      url: process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com",
      accounts,
    },
    "base-sepolia": {
      type: "http",
      url: process.env.BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org",
      accounts,
    },
  },
});
