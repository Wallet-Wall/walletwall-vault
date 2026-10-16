/**
 * SP1-TD2 deployment tooling (scripts/lib/deployment-guards.ts), the code scripts/deploy-multisig.ts and
 * scripts/deploy-zk-verifier.ts run:
 *
 *   The binding gate at the tool's entry point — deployMultisigVault gates WalletWallMultiSigVault before sending a
 *     transaction. Admitted to the halt's scope through TD2-MULTISIG-ROTATION (the owner's acceptance, 2026-10-16),
 *     it is held to the common rules: an SP1-path verifier the halt would not reach, or one the deployer can halt, is
 *     refused, and off the local override nothing unregistered binds; a haltable genuine wrapper deploys locally, as
 *     do the mock and other off-path verifiers. (While it was excluded the gate refused it every SP1-path verifier:
 *     test/Sp1Td2VerifierBinding.test.ts.)
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

  describe("deployMultisigVault: the binding gate at the tool's entry point (the multisig vault admitted)", function () {
    it("refuses an SP1-path verifier the halt would not reach, or one the deployer can halt, before sending any transaction", async function () {
      const sp1 = await deploySp1();
      const unhaltable = await (
        await ethers.getContractFactory("UnhaltableZkVerifierMock")
      ).deploy(await sp1.getAddress(), VKEY_A);
      const ownWrapper = await deployWrapper(sp1, VKEY_A, deployer.address);
      const nonce = await ethers.provider.getTransactionCount(deployer.address);
      await assert.rejects(
        deployMultisigVault(ethers, deployer, {
          pqcVerifierAddress: await unhaltable.getAddress(),
          allowMockSp1: true,
        }),
        /not haltable: the halt would not reach WalletWallMultiSigVault/,
      );
      await assert.rejects(
        deployMultisigVault(ethers, deployer, {
          pqcVerifierAddress: await ownWrapper.getAddress(),
          allowMockSp1: true,
        }),
        /halt principal never governs a consumer/,
      );
      expect(await ethers.provider.getTransactionCount(deployer.address), "nothing was sent").to.equal(nonce);
      await assert.rejects(
        deployMultisigVault(ethers, deployer, { pqcVerifierAddress: "0x1234", allowMockSp1: true }),
        /PQC_VERIFIER_ADDRESS is not a valid address/,
      );
    });

    it("binds a haltable genuine wrapper only under the local override: unregistered and undesignated, it is refused without it", async function () {
      const wrapper = await deployWrapper(await deploySp1(), VKEY_A, haltPrincipal.address);
      const nonce = await ethers.provider.getTransactionCount(deployer.address);
      await assert.rejects(
        deployMultisigVault(ethers, deployer, { pqcVerifierAddress: await wrapper.getAddress(), allowMockSp1: false }),
        /not in the WalletWall wrapper registry for chain 31337.*matches no designation/s,
      );
      expect(await ethers.provider.getTransactionCount(deployer.address), "nothing was sent").to.equal(nonce);
      const deployed = await deployMultisigVault(ethers, deployer, {
        pqcVerifierAddress: await wrapper.getAddress(),
        allowMockSp1: true,
      });
      expect(await deployed.vault.pqVerifier()).to.equal(await wrapper.getAddress());
      expect(await deployed.vault.owner()).to.equal(deployer.address);
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
