// Load environment variables from a local, git-ignored .env file before any
// config below reads process.env. This is what makes the documented
// `cp .env.example .env` workflow actually work for `hardhat run` /
// `npm run deploy:*` — Hardhat does not load .env on its own. Never commit .env.
import "dotenv/config";

import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;

const config: HardhatUserConfig = {
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
      url: process.env.RPC_URL ?? "http://127.0.0.1:8545",
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com",
      accounts: deployerKey ? [deployerKey] : [],
    },
    "base-sepolia": {
      url: process.env.BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org",
      accounts: deployerKey ? [deployerKey] : [],
    },
  },
};

export default config;
