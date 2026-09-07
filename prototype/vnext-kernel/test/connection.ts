/**
 * EXPERIMENTAL PROTOTYPE — network connection for the prototype suite.
 *
 * Mirrors `test/helpers/connection.ts`: Hardhat 3 removed the global `ethers`
 * singleton, so one shared connection is opened here and re-exported. Kept
 * separate from the production helper so the prototype suite has no import into
 * the production test tree.
 */
import { network } from "hardhat";

const connection = await network.create();

export const ethers = connection.ethers;
export const networkHelpers = connection.networkHelpers;
