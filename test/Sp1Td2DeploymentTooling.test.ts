/**
 * SP1-TD2 deployment tooling (scripts/lib/deployment-guards.ts), the code scripts/deploy-multisig.ts and
 * scripts/deploy-zk-verifier.ts run:
 *
 *   EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER at the tool's entry point — deployMultisigVault refuses a haltable
 *     wrapper (and any SP1-path verifier) for WalletWallMultiSigVault before sending a transaction, and deploys the
 *     vault on the mock or another off-path verifier (positive controls).
 *   The halt principal is explicit off a local chain, and on a local chain it is not the deployer.
 *   The chain guard refuses unsupported networks, mainnets and a mismatched RPC.
 */
import assert from "node:assert/strict";

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import { VKEY_A, deploySp1, deployWrapper } from "./helpers/td2Helpers";
import {
  EXPECTED_CHAIN_ID,
  FORBIDDEN_MAINNET_CHAIN_IDS,
  assertDeployableChain,
  deployMultisigVault,
  resolveHaltPrincipal,
} from "../scripts/lib/deployment-guards";

describe("SP1-TD2 deployment tooling", function () {
  let deployer: any, haltPrincipal: any, other: any;

  beforeEach(async function () {
    [deployer, haltPrincipal, other] = await ethers.getSigners();
  });

  describe("deployMultisigVault: EXCLUDED_CONSUMER_REFUSED_A_HALTABLE_WRAPPER at the tool's entry point", function () {
    it("refuses a haltable wrapper for the multisig vault before sending any transaction", async function () {
      const wrapper = await deployWrapper(await deploySp1(), VKEY_A, haltPrincipal.address);
      const nonce = await ethers.provider.getTransactionCount(deployer.address);
      await assert.rejects(
        deployMultisigVault(ethers, deployer, { pqcVerifierAddress: await wrapper.getAddress(), allowMockSp1: true }),
        /WalletWallMultiSigVault waits outside the halt for TD2-MULTISIG-ROTATION/,
      );
      expect(await ethers.provider.getTransactionCount(deployer.address), "nothing was sent").to.equal(nonce);
    });

    it("refuses a non-haltable SP1-path verifier too, and an address that is not one", async function () {
      const unhaltable = await (
        await ethers.getContractFactory("UnhaltableZkVerifierMock")
      ).deploy(await (await deploySp1()).getAddress(), VKEY_A);
      await assert.rejects(
        deployMultisigVault(ethers, deployer, {
          pqcVerifierAddress: await unhaltable.getAddress(),
          allowMockSp1: true,
        }),
        /may be bound to no part of the SP1 path/,
      );
      await assert.rejects(
        deployMultisigVault(ethers, deployer, { pqcVerifierAddress: "0x1234", allowMockSp1: true }),
        /PQC_VERIFIER_ADDRESS is not a valid address/,
      );
    });

    it("positive controls: deploys on a fresh mock when no verifier is named, or on a named off-path verifier", async function () {
      const fresh = await deployMultisigVault(ethers, deployer, { allowMockSp1: false });
      expect(fresh.deployedMockVerifier).to.equal(true);
      expect(await fresh.vault.pqVerifier()).to.equal(fresh.verifierAddress);
      expect(await fresh.vault.owner()).to.equal(deployer.address);
      const mock = await (await ethers.getContractFactory("MockMLDSAVerifier")).deploy();
      const named = await deployMultisigVault(ethers, deployer, {
        pqcVerifierAddress: await mock.getAddress(),
        allowMockSp1: false,
      });
      expect(named.deployedMockVerifier).to.equal(false);
      expect(await named.vault.pqVerifier()).to.equal(await mock.getAddress());
    });
  });

  describe("resolveHaltPrincipal (deploy-zk-verifier.ts)", function () {
    it("requires HALT_PRINCIPAL_ADDRESS on a non-local chain, even with a local default available", function () {
      assert.throws(
        () => resolveHaltPrincipal(undefined, false, haltPrincipal.address),
        /HALT_PRINCIPAL_ADDRESS is required/,
      );
      assert.throws(() => resolveHaltPrincipal("", false, haltPrincipal.address), /HALT_PRINCIPAL_ADDRESS is required/);
    });

    it("defaults to the given local account on a local chain, and refuses when there is none", function () {
      expect(resolveHaltPrincipal(undefined, true, haltPrincipal.address)).to.equal(haltPrincipal.address);
      assert.throws(() => resolveHaltPrincipal(undefined, true, undefined), /HALT_PRINCIPAL_ADDRESS is required/);
    });

    it("refuses a malformed or zero address and returns the checksummed principal", function () {
      assert.throws(() => resolveHaltPrincipal("0x1234", false), /must be a non-zero address/);
      assert.throws(
        () => resolveHaltPrincipal(ethers.ZeroAddress, true, haltPrincipal.address),
        /must be a non-zero address/,
      );
      expect(resolveHaltPrincipal(other.address.toLowerCase(), false)).to.equal(other.address);
    });
  });

  describe("assertDeployableChain (deploy-multisig.ts)", function () {
    it("accepts each supported network on its own chain", function () {
      for (const [name, id] of Object.entries(EXPECTED_CHAIN_ID)) assertDeployableChain(name, id);
    });

    it("refuses an unsupported network, every listed mainnet and a mismatched RPC", function () {
      assert.throws(() => assertDeployableChain("mainnet", 1n), /unsupported network: mainnet/);
      for (const [id, label] of FORBIDDEN_MAINNET_CHAIN_IDS) {
        assert.throws(() => assertDeployableChain("sepolia", id), new RegExp(`REFUSING TO DEPLOY.*${label}`));
      }
      assert.throws(() => assertDeployableChain("sepolia", 84532n), /expected 11155111 but the RPC reports 84532/);
      expect(FORBIDDEN_MAINNET_CHAIN_IDS.size).to.equal(7);
    });
  });
});
