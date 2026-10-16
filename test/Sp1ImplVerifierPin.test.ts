/**
 * SP1 implementation lane: `ZKMLDSAVerifier` bound directly to the designated immutable SP1 verifier and F-1
 * (docs/SP1_Implementation_Pin_Designation_Registry.md).
 *
 * SP1-TD1 decided DIRECT_IMMUTABLE_VERIFIER: the wrapper is bound to Succinct's Groth16 SP1Verifier v6.1.0, pinned by
 * its runtime code hash, never to the owner-mutable SP1VerifierGateway. The pin is a compile-time constant checked in
 * the constructor; the expected values below come from the SP1-TD1 decision receipt (measured on four chains through
 * two providers each), and the v6.1.0 bytes from its CREATE2-authenticated initcode — never from the contract.
 *
 * F-1 (SP1-P1, disposition NO_AUTHORIZATION_IMPACT): verify() compared `committedChainId != uint64(block.chainid)`,
 * so on a chain whose id is 2^64 or more a journal committing (id mod 2^64) matched. The repair compares the full
 * 256-bit id, a contract-only change: the guest, the ELF, PROGRAM_VKEY and the 160-byte journal are unchanged.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { ethers } from "./helpers/connection";
import { deployPinnedSp1Verifier, v610Runtime, withPinnedSp1Code } from "./helpers/sp1PinnedVerifier";
import { findContract, findFunctionDefinition, loadSourceAst, walkAst, type AstNode } from "./helpers/solidityAst";
import { findExternalCallFindings } from "./helpers/astExternalCallAnalysis";
import { WITHDRAWAL_TYPES, withdrawalDomain } from "./helpers/vaultHelpers";
import { TEST_HALT_PRINCIPAL } from "./helpers/zkVerifierHelpers";
import { ProverClient } from "../scripts/prover-client";

const readJson = (rel: string) => JSON.parse(readFileSync(resolve(rel), "utf8"));
const RECEIPT = readJson("evidence/zk/sp1-td1/decision-receipt.json");
const TRUST_TARGET = RECEIPT.trustTarget;
const PROGRAM_VKEY: string = RECEIPT.decisions.PROGRAM_VKEY_DESIGNATION.vkey;
const OBS = "evidence/zk/sp1-td1/observations";
const BYTECODE = readJson(`${OBS}/deployment-bytecode.raw.json`);
const V610_PROOF = readJson(`${OBS}/mainnet-v610-proof.raw.json`).call;

const V610_SELECTOR = "0x4388a21c";
const ROGUE_SELECTOR = "0xdeadbeef";
const PQ_ONLY = 1;
const TWO_POW_64 = 2n ** 64n;
const ABI = ethers.AbiCoder.defaultAbiCoder();

const GATEWAY_ABI = [
  "function addRoute(address verifier)",
  "function freezeRoute(bytes4 selector)",
  "function routes(bytes4) view returns (address verifier, bool frozen)",
  "function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes) view",
  "error RouteAlreadyExists(address verifier)",
  "error RouteIsFrozen(bytes4 selector)",
];
const VERIFIER_ABI = [
  "function VERIFIER_HASH() pure returns (bytes32)",
  "function VK_ROOT() pure returns (bytes32)",
  "function VERSION() pure returns (string)",
  "function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes) view",
];

describe("SP1 implementation lane — ZKMLDSAVerifier is pinned to the designated SP1 verifier (and F-1)", function () {
  let deployer: any, gatewayOwner: any, vaultAdmin: any, vaultOwner: any, attacker: any;
  let factory: any;

  async function deployRaw(initcode: string): Promise<string> {
    const receipt = await (await deployer.sendTransaction({ data: initcode })).wait();
    return receipt.contractAddress as string;
  }
  const deployGateway = async (owner: string) =>
    new ethers.Contract(
      await deployRaw(ethers.concat([BYTECODE.deployments.gateway.creationCode, ABI.encode(["address"], [owner])])),
      GATEWAY_ABI,
      deployer,
    );
  const wrap = (sp1: string, vkey = PROGRAM_VKEY) => factory.deploy(sp1, vkey, TEST_HALT_PRINCIPAL);
  const codehash = async (address: string) => ethers.keccak256(await ethers.provider.getCode(address));
  const acceptAll = async (selector: string) =>
    (await ethers.getContractFactory("AcceptAllRouteVerifierProbe")).deploy(
      ethers.zeroPadBytes(selector, 32).slice(0, 10) + "ab".repeat(28),
    );

  before(async function () {
    [deployer, gatewayOwner, vaultAdmin, vaultOwner, attacker] = await ethers.getSigners();
    factory = await ethers.getContractFactory("ZKMLDSAVerifier");
  });

  describe("the pin: only the v6.1.0 runtime, at any address", function () {
    it("accepts the real v6.1.0 bytes at two different addresses and binds each address immutably", async function () {
      const a = await deployPinnedSp1Verifier();
      const b = await deployPinnedSp1Verifier();
      expect(a).to.not.equal(b);
      // The runtime the initcode produces is the one SP1-TD1 measured on chain (independent of the contract).
      expect(await codehash(a)).to.equal(TRUST_TARGET.codeKeccak);
      for (const sp1 of [a, b]) {
        const zk = await wrap(sp1);
        expect(await zk.SP1_VERIFIER()).to.equal(sp1);
        expect(await zk.PROGRAM_VKEY()).to.equal(PROGRAM_VKEY);
      }
    });

    it("refuses in its constructor every target whose runtime is not the pinned code", async function () {
      const gateway = await deployGateway(gatewayOwner.address);
      const v610 = await deployPinnedSp1Verifier();
      await gateway.connect(gatewayOwner).addRoute(v610);
      // One flipped byte in an otherwise identical runtime, at a fresh address.
      const nearMiss = ethers.getBytes(await v610Runtime());
      nearMiss[100] ^= 0x01;
      const nearMissAddress = ethers.getAddress(ethers.dataSlice(ethers.id("sp1-impl: near-miss runtime"), 12));
      await ethers.provider.send("hardhat_setCode", [nearMissAddress, ethers.hexlify(nearMiss)]);
      const targets: [string, string][] = [
        ["the SP1VerifierGateway, even routing v6.1.0", await gateway.getAddress()],
        ["another SP1 version (v6.0.0)", await deployRaw(BYTECODE.deployments["v6.0.0"].initcode)],
        [
          "an accept-all verifier answering to the v6.1.0 selector",
          await (await acceptAll(V610_SELECTOR)).getAddress(),
        ],
        [
          "the always-accepting mock",
          await (await (await ethers.getContractFactory("MockSP1Verifier")).deploy()).getAddress(),
        ],
        [
          "the program-bound stand-in",
          await (await (await ethers.getContractFactory("ProgramBoundMockSP1Verifier")).deploy()).getAddress(),
        ],
        ["the v6.1.0 runtime with one byte changed", nearMissAddress],
      ];
      for (const [label, target] of targets) {
        await expect(wrap(target), label)
          .to.be.revertedWithCustomError(factory, "UndesignatedSP1Verifier")
          .withArgs(target, await codehash(target));
      }
      // No code at all is its own refusal.
      for (const target of [attacker.address, ethers.ZeroAddress]) {
        await expect(wrap(target), target).to.be.revertedWithCustomError(factory, "InvalidSP1Verifier");
      }
    });

    it("records the pinned identity: each constant is SP1-TD1's measurement and what the pinned bytes report", async function () {
      const zk = await wrap(await deployPinnedSp1Verifier());
      const v610 = new ethers.Contract(await zk.SP1_VERIFIER(), VERIFIER_ABI, deployer);
      expect(await zk.SP1_VERIFIER_CODEHASH()).to.equal(TRUST_TARGET.codeKeccak);
      expect(await zk.SP1_VERIFIER_HASH()).to.equal(TRUST_TARGET.verifierHash);
      expect(await zk.SP1_VK_ROOT()).to.equal(TRUST_TARGET.vkRoot);
      expect(await zk.SP1_VERSION()).to.equal(TRUST_TARGET.version);
      expect(await v610.VERIFIER_HASH()).to.equal(TRUST_TARGET.verifierHash);
      expect(await v610.VK_ROOT()).to.equal(TRUST_TARGET.vkRoot);
      expect(await v610.VERSION()).to.equal(TRUST_TARGET.version);
      expect(TRUST_TARGET.verifierHash.slice(0, 10)).to.equal(V610_SELECTOR);
    });

    it("SP1_VERIFIER and PROGRAM_VKEY are immutables assigned only by the constructor; halt() is the only state change", function () {
      const contract = findContract(loadSourceAst("contracts/verifiers/ZKMLDSAVerifier.sol"), "ZKMLDSAVerifier");
      const vars = contract.nodes.filter((n: AstNode) => n.nodeType === "VariableDeclaration");
      const mutability = Object.fromEntries(vars.map((v: AstNode) => [v.name, v.mutability]));
      expect(mutability).to.include({
        SP1_VERIFIER: "immutable",
        PROGRAM_VKEY: "immutable",
        HALT_PRINCIPAL: "immutable",
        SP1_VERIFIER_CODEHASH: "constant",
        SP1_VERIFIER_HASH: "constant",
        SP1_VK_ROOT: "constant",
        SP1_VERSION: "constant",
        halted: "mutable",
      });
      const mutating: string[] = [];
      factory.interface.forEachFunction((f: any) => {
        if (f.stateMutability !== "view" && f.stateMutability !== "pure") mutating.push(f.name);
      });
      expect(mutating).to.deep.equal(["halt"]);
    });
  });

  describe("SP1-TD1's exact attack, re-run on the pinned wrapper: the gateway owner holds no lever", function () {
    let gateway: any, v610: string, zk: any, vault: any, pq: ReturnType<typeof ml_dsa65.keygen>;

    beforeEach(async function () {
      gateway = await deployGateway(gatewayOwner.address);
      v610 = await deployPinnedSp1Verifier();
      await gateway.connect(gatewayOwner).addRoute(v610);
      zk = await wrap(v610);
      vault = await (await ethers.getContractFactory("WalletWallVault", vaultAdmin)).deploy(await zk.getAddress());
      pq = ml_dsa65.keygen();
      await vault.connect(vaultOwner).createVault(ethers.ZeroAddress, pq.publicKey, PQ_ONLY);
      await vault.connect(vaultOwner).deposit({ value: ethers.parseEther("10") });
    });

    async function forgedWithdrawal() {
      const request = {
        vaultOwner: vaultOwner.address,
        recipient: attacker.address,
        amount: ethers.parseEther("10"),
        nonce: await vault.nonces(vaultOwner.address),
        deadline: BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 3600n,
        vaultMode: PQ_ONLY,
      };
      const digest = ethers.TypedDataEncoder.hash(await withdrawalDomain(vault), WITHDRAWAL_TYPES, request);
      const journal = ProverClient.encodePublicValues(
        digest,
        pq.publicKey,
        new Uint8Array(3309),
        (await ethers.provider.getNetwork()).chainId,
        await zk.getAddress(),
      );
      return {
        request,
        proof: ABI.encode(["bytes", "bytes"], [journal, ethers.concat([ROGUE_SELECTOR, ethers.ZeroHash])]),
      };
    }

    it("adding an accept-all route, failing to replace v6.1.0's, and freezing it leave the forged withdrawal refused", async function () {
      const forged = await forgedWithdrawal();
      await expect(vault.connect(attacker).withdraw(forged.request, "0x", forged.proof)).to.be.revertedWithCustomError(
        vault,
        "InvalidPQSignature",
      );
      // Every lever the gateway owner has: a new route (it widened option D's unpinned wrapper in SP1-TD1), an
      // attempt to replace the pinned version's route, and a freeze.
      await gateway.connect(gatewayOwner).addRoute(await (await acceptAll(ROGUE_SELECTOR)).getAddress());
      await expect(
        gateway.connect(gatewayOwner).addRoute(await (await acceptAll(V610_SELECTOR)).getAddress()),
      ).to.be.revertedWithCustomError(gateway, "RouteAlreadyExists");
      await gateway.connect(gatewayOwner).freezeRoute(V610_SELECTOR);
      await expect(vault.connect(attacker).withdraw(forged.request, "0x", forged.proof)).to.be.revertedWithCustomError(
        vault,
        "InvalidPQSignature",
      );
      // Positive control: the freeze stopped the gateway path, not the direct one — a real v6.1.0 proof (a third
      // party's program, from mainnet) still verifies on the verifier the wrapper is bound to.
      await expect(
        gateway.verifyProof.staticCall(V610_PROOF.programVKey, V610_PROOF.publicValues, V610_PROOF.proofBytes),
      ).to.be.revertedWithCustomError(gateway, "RouteIsFrozen");
      await new ethers.Contract(v610, VERIFIER_ABI, deployer).verifyProof.staticCall(
        V610_PROOF.programVKey,
        V610_PROOF.publicValues,
        V610_PROOF.proofBytes,
      );
      expect(await zk.halted()).to.equal(false);
    });

    it("the wrapper's only call out of itself is to SP1_VERIFIER: no route, selector or gateway indirection exists", function () {
      const contract = findContract(loadSourceAst("contracts/verifiers/ZKMLDSAVerifier.sol"), "ZKMLDSAVerifier");
      const verify = findFunctionDefinition(contract, "verify");
      const receivers = findExternalCallFindings(verify.body).map((f) => ({
        member: f.memberName,
        receiver: f.receiverTypeString,
      }));
      expect(receivers).to.deep.equal([
        { member: "decodeProofPayload", receiver: "contract ZKMLDSAVerifier" },
        { member: "verifyProof", receiver: "contract ISP1Verifier" },
      ]);
      // ...and the ISP1Verifier it calls is the immutable, never a value read at call time.
      const sp1Calls: string[] = [];
      walkAst(verify.body, (n: AstNode) => {
        if (n.nodeType === "FunctionCall" && n.expression?.memberName === "verifyProof") {
          sp1Calls.push(n.expression.expression.arguments[0].name);
        }
      });
      expect(sp1Calls).to.deep.equal(["SP1_VERIFIER"]);
    });
  });

  describe("F-1: the chain id is compared at full width", function () {
    let probe: any;

    before(async function () {
      probe = await (
        await ethers.getContractFactory("ChainIdBindingProbe")
      ).deploy(await deployPinnedSp1Verifier(), PROGRAM_VKEY, TEST_HALT_PRINCIPAL);
    });

    it("ids that differ only above bit 63 no longer collide (the truncating rule matched them)", async function () {
      const truncatingRuleMatched = (committed: bigint, chainId: bigint) => BigInt.asUintN(64, chainId) === committed;
      for (const id of [1n, 31337n, 11155111n, 84532n, TWO_POW_64 - 1n]) {
        expect(await probe.chainIdMatches(id, id), `${id}`).to.equal(true);
        expect(await probe.chainIdMatches(id, id + TWO_POW_64), `${id} + 2^64`).to.equal(false);
        expect(truncatingRuleMatched(id, id + TWO_POW_64), `the old rule, ${id} + 2^64`).to.equal(true);
      }
      expect(await probe.chainIdMatches(0n, TWO_POW_64)).to.equal(false);
      expect(await probe.chainIdMatches(1n, 2n)).to.equal(false);
    });

    it("verify() refuses a proven journal for another chain and accepts this chain's (31337)", async function () {
      const sp1 = await (await ethers.getContractFactory("ProgramBoundMockSP1Verifier")).deploy();
      const sp1Address = await sp1.getAddress();
      const zk = await withPinnedSp1Code(sp1Address, () => wrap(sp1Address));
      const digest = ethers.id("sp1-impl: F-1 digest");
      const key = ml_dsa65.keygen();
      const signature = ml_dsa65.sign(ethers.getBytes(digest), key.secretKey);
      const chainId = (await ethers.provider.getNetwork()).chainId;
      expect(chainId).to.equal(31337n);
      const proofFor = async (id: bigint) => {
        const journal = ProverClient.encodePublicValues(digest, key.publicKey, signature, id, await zk.getAddress());
        await sp1.setProven(PROGRAM_VKEY, journal);
        return ABI.encode(["bytes", "bytes"], [journal, "0x01"]);
      };
      expect(await zk.verify(digest, key.publicKey, await proofFor(chainId))).to.equal(true);
      expect(await zk.verify(digest, key.publicKey, await proofFor(chainId + 1n))).to.equal(false);
      // A journal cannot even carry an id of 2^64 or more: the uint64 field refuses it, before any comparison.
      const wide = ABI.encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [
          digest,
          ethers.keccak256(key.publicKey),
          ethers.keccak256(signature),
          chainId + TWO_POW_64,
          await zk.getAddress(),
        ],
      );
      await sp1.setProven(PROGRAM_VKEY, wide);
      expect(await zk.verify(digest, key.publicKey, ABI.encode(["bytes", "bytes"], [wide, "0x01"]))).to.equal(false);
    });

    it("verify() hands block.chainid itself to the comparison, never a narrowed copy", function () {
      const contract = findContract(loadSourceAst("contracts/verifiers/ZKMLDSAVerifier.sol"), "ZKMLDSAVerifier");
      const verify = findFunctionDefinition(contract, "verify");
      const comparisons: AstNode[][] = [];
      walkAst(verify.body, (n: AstNode) => {
        if (n.nodeType === "FunctionCall" && n.expression?.name === "_chainIdMatches") comparisons.push(n.arguments);
      });
      expect(comparisons.length).to.equal(1);
      const [committed, chainId] = comparisons[0];
      expect(committed.nodeType).to.equal("Identifier");
      expect(committed.name).to.equal("committedChainId");
      expect(chainId.nodeType).to.equal("MemberAccess");
      expect(chainId.memberName).to.equal("chainid");
      expect(chainId.expression.name).to.equal("block");
      // No other read of the chain id anywhere in verify().
      let chainIdReads = 0;
      walkAst(verify.body, (n: AstNode) => {
        if (n.nodeType === "MemberAccess" && n.memberName === "chainid") chainIdReads++;
      });
      expect(chainIdReads).to.equal(1);
    });

    it("the journal and the authorization are unchanged: 160 bytes with a uint64 tag, and EIP-712 binds the full id", async function () {
      const decoder = factory.interface.getFunction("decodeProofPayload");
      expect(decoder.outputs.map((o: any) => o.type)).to.deep.equal([
        "bytes",
        "bytes",
        "bytes32",
        "bytes32",
        "uint64",
        "address",
      ]);
      const domain = (chainId: bigint) =>
        ethers.TypedDataEncoder.hashDomain({
          name: "WalletWallVault",
          version: "1",
          chainId,
          verifyingContract: ethers.ZeroAddress,
        });
      expect(domain(1n)).to.not.equal(domain(1n + TWO_POW_64));
      expect(domain(31337n)).to.not.equal(domain(31337n + TWO_POW_64));
    });
  });
});
