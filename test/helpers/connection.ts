import { network } from "hardhat";

// Hardhat 3 removed the global `ethers` and network-helpers singletons that Hardhat 2
// attached to the HRE; in Hardhat 3 they are obtained per network connection. The Mocha
// runner loads every test file into a single process, so we open ONE shared network
// connection here (top-level await — this module is ESM) and re-export its `ethers` and
// `networkHelpers`. Tests and test helpers import these instead of `{ ethers } from
// "hardhat"` and the old standalone `@nomicfoundation/hardhat-network-helpers` package.
//
// This preserves the Hardhat 2 single-shared-network semantics the suite already relies
// on: each test deploys fresh contract instances in its own beforeEach hook, so no
// cross-test snapshot/reset is required.
const connection = await network.create();

export const ethers = connection.ethers;
export const networkHelpers = connection.networkHelpers;
