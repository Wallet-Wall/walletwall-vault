/**
 * SP1-TD1 executable trust-target probes (docs/SP1_TD1_Trust_Target_Program_Identity.md).
 *
 * Each option for the verifier `ZKMLDSAVerifier` trusts runs against the EXACT mainnet bytes of Succinct's
 * SP1VerifierGateway and Groth16 SP1Verifier v6.0.0 / v6.1.0: the initcode comes from the deployment
 * transactions recorded in evidence/zk/sp1-td1/observations/deployment-bytecode.raw.json (authenticated
 * by CREATE2 against the deployed addresses) and every deployed runtime is checked against the mainnet
 * code hash in chain-state.raw.json before any probe runs. A real upstream v6 Groth16 proof
 * (upstream-proof-fixture.raw.json) is the positive control for the shared verifier template.
 *
 * Every outcome asserted here is also a fact in evidence/zk/sp1-td1/decision-inputs.json
 * (`probeFacts`), which the TD1 decision validator consumes: if an execution and the recorded fact
 * disagree, this suite fails. No network, no SP1 toolchain, no proving.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { ethers, networkHelpers } from "./helpers/connection";
import { WITHDRAWAL_TYPES, withdrawalDomain } from "./helpers/vaultHelpers";
import { ProverClient } from "../scripts/prover-client";

const OBS = "evidence/zk/sp1-td1/observations";
const readJson = (rel: string) => JSON.parse(readFileSync(resolve(rel), "utf8"));
const BYTECODE = readJson(`${OBS}/deployment-bytecode.raw.json`);
const CHAIN = readJson(`${OBS}/chain-state.raw.json`);
const FIXTURE = readJson(`${OBS}/upstream-proof-fixture.raw.json`).fixture;
const FACTS = readJson("evidence/zk/sp1-td1/decision-inputs.json").probeFacts;

const MAINNET = CHAIN.chains["1"];
const V610_SELECTOR = "0x4388a21c";
const V600_SELECTOR = "0x0e78f4db";
const ROGUE_SELECTOR = "0xdeadbeef";
/** The vendor-image withdrawal vkey (SP1-P1 environments B and C): a realistic PROGRAM_VKEY. */
const PROGRAM_VKEY = "0x0001a4c62de43425bce9febc352a74acc01bac70c02d8acedc09085c4eb8c2dc";
const PQ_ONLY = 1;

const GATEWAY_ABI = [
  "function owner() view returns (address)",
  "function routes(bytes4) view returns (address verifier, bool frozen)",
  "function addRoute(address verifier)",
  "function freezeRoute(bytes4 selector)",
  "function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes) view",
  "error RouteNotFound(bytes4 selector)",
  "error RouteIsFrozen(bytes4 selector)",
  "error RouteAlreadyExists(address verifier)",
  "error OwnableUnauthorizedAccount(address account)",
];
const VERIFIER_ABI = [
  "function VERIFIER_HASH() pure returns (bytes32)",
  "function VK_ROOT() pure returns (bytes32)",
  "function VERSION() pure returns (string)",
  "function verifyProof(bytes32 programVKey, bytes publicValues, bytes proofBytes) view",
  "error WrongVerifierSelector(bytes4 received, bytes4 expected)",
  "error InvalidExitCode()",
  "error InvalidVkRoot()",
  "error ProofInvalid()",
  "error PublicInputNotInField()",
];
/** Opcodes that would let a contract change state, run foreign code or replace code. */
const STATE_OR_CODE_CHANGING = new Map<number, string>([
  [0x55, "SSTORE"],
  [0x5d, "TSTORE"],
  [0xa0, "LOG0"],
  [0xa1, "LOG1"],
  [0xa2, "LOG2"],
  [0xa3, "LOG3"],
  [0xa4, "LOG4"],
  [0xf0, "CREATE"],
  [0xf1, "CALL"],
  [0xf2, "CALLCODE"],
  [0xf4, "DELEGATECALL"],
  [0xf5, "CREATE2"],
  [0xff, "SELFDESTRUCT"],
]);

/** Instructions after which execution cannot fall through: STOP, JUMP, RETURN, REVERT, INVALID, SELFDESTRUCT. */
const TERMINAL = new Set([0x00, 0x56, 0xf3, 0xfd, 0xfe, 0xff]);

/**
 * Reachable state- or code-changing instructions in a solc runtime. Decoding is the EVM's own (linear, PUSH
 * immediates skipped, so a 0x5b counts only where the EVM would accept it as a JUMPDEST); bytes after a
 * terminal instruction are dead until the next JUMPDEST, and the trailing CBOR metadata is excluded. The dead
 * spans matter: solc places constants after INVALID, and the BN254 moduli there contain 0x5d (TSTORE) bytes.
 */
function forbiddenOpcodes(runtime: string): string[] {
  const code = ethers.getBytes(runtime);
  const metadataLength = (code[code.length - 2] << 8) | code[code.length - 1];
  const end = code.length - 2 - metadataLength;
  const found = new Set<string>();
  let reachable = true;
  for (let i = 0; i < end; i++) {
    const op = code[i];
    if (op === 0x5b) reachable = true;
    const name = STATE_OR_CODE_CHANGING.get(op);
    if (reachable && name) found.add(name);
    if (op >= 0x60 && op <= 0x7f) i += op - 0x5f;
    if (TERMINAL.has(op)) reachable = false;
  }
  return [...found].sort();
}

async function revertData(call: Promise<unknown>): Promise<string> {
  try {
    await call;
  } catch (error) {
    const data = (error as { data?: string }).data;
    if (typeof data === "string") return data;
    throw error;
  }
  throw new Error("expected a revert");
}

describe("SP1-TD1 trust-target probes (exact mainnet verifier and gateway bytes)", function () {
  let deployer: any, gatewayOwner: any, vaultAdmin: any, vaultOwner: any, attacker: any;
  let chainId: bigint;

  async function deployRaw(initcode: string): Promise<string> {
    const receipt = await (await deployer.sendTransaction({ data: initcode })).wait();
    return receipt.contractAddress as string;
  }
  // Raw-ABI contracts (the upstream bytes have no typechain bindings): typed dynamically, as elsewhere here.
  async function deployVerifier(version: "v6.0.0" | "v6.1.0"): Promise<any> {
    const address = await deployRaw(BYTECODE.deployments[version].initcode);
    return new ethers.Contract(address, VERIFIER_ABI, deployer);
  }
  async function deployGateway(owner: string): Promise<any> {
    const initcode = ethers.concat([
      BYTECODE.deployments.gateway.creationCode,
      ethers.AbiCoder.defaultAbiCoder().encode(["address"], [owner]),
    ]);
    return new ethers.Contract(await deployRaw(initcode), GATEWAY_ABI, deployer);
  }
  const runtimeKeccak = async (address: string) => ethers.keccak256(await ethers.provider.getCode(address));
  const acceptAll = async (verifierHash: string) =>
    (await ethers.getContractFactory("AcceptAllRouteVerifierProbe")).deploy(verifierHash);
  const rogueHash = (selector: string) => ethers.zeroPadBytes(selector, 32).slice(0, 10) + "ab".repeat(28);
  const zkVerifier = async (sp1Verifier: string) =>
    (await ethers.getContractFactory("ZKMLDSAVerifier")).deploy(sp1Verifier, PROGRAM_VKEY);
  const payload = (publicValues: string, proofBytes: string) =>
    ethers.AbiCoder.defaultAbiCoder().encode(["bytes", "bytes"], [publicValues, proofBytes]);
  /** A journal that claims `publicKey` signed `digest`: anyone can write one; only a proof makes it count. */
  const forgedJournal = (digest: string, publicKey: Uint8Array, verifier: string) =>
    ProverClient.encodePublicValues(digest, publicKey, new Uint8Array(3309), chainId, verifier);
  /** A v6.1.0-shaped proof: selector, exit code, vk root, nonce, eight proof words. */
  const v610Proof = (exitCode: bigint, vkRoot: string, word: bigint) =>
    ethers.concat([
      V610_SELECTOR,
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256", "uint256", "uint256[8]"],
        [exitCode, vkRoot, 0n, Array(8).fill(word)],
      ),
    ]);

  before(async function () {
    [deployer, gatewayOwner, vaultAdmin, vaultOwner, attacker] = await ethers.getSigners();
    chainId = (await ethers.provider.getNetwork()).chainId;
  });

  describe("probe targets are the production bytes", function () {
    it("the gateway, v6.0.0 and v6.1.0 runtimes deployed here equal the mainnet code hashes", async function () {
      const gateway = await deployGateway(gatewayOwner.address);
      const v610 = await deployVerifier("v6.1.0");
      const v600 = await deployVerifier("v6.0.0");
      const observed = {
        gatewayRuntimeEqualsMainnet: (await runtimeKeccak(await gateway.getAddress())) === MAINNET.gateway.codeKeccak,
        v610RuntimeEqualsMainnet:
          (await runtimeKeccak(await v610.getAddress())) === MAINNET.verifiers["v6.1.0"].codeKeccak,
        v600RuntimeEqualsMainnet:
          (await runtimeKeccak(await v600.getAddress())) === MAINNET.verifiers["v6.0.0"].codeKeccak,
      };
      expect(observed).to.deep.equal({
        gatewayRuntimeEqualsMainnet: true,
        v610RuntimeEqualsMainnet: true,
        v600RuntimeEqualsMainnet: true,
      });
      expect(observed).to.deep.equal(FACTS.bytes);
    });

    it("the initcode is the one CREATE2 placed at each mainnet address", async function () {
      for (const key of ["v6.1.0", "v6.0.0", "gateway"]) {
        const d = BYTECODE.deployments[key];
        expect(ethers.keccak256(d.initcode), key).to.equal(d.initcodeKeccak);
        const derived = ethers.getCreate2Address(BYTECODE.create2Deployer, d.salt, d.initcodeKeccak);
        expect(derived, key).to.equal(d.create2Derived);
      }
      expect(BYTECODE.deployments["v6.1.0"].create2Derived).to.equal(MAINNET.verifiers["v6.1.0"].address);
      expect(BYTECODE.deployments.gateway.create2Derived).to.equal(MAINNET.gateway.address);
    });

    it("the v6.1.0 verifier reports the mainnet selector, vk root and version", async function () {
      const v610 = await deployVerifier("v6.1.0");
      expect(await v610.VERIFIER_HASH()).to.equal(MAINNET.verifiers["v6.1.0"].VERIFIER_HASH);
      expect((await v610.VERIFIER_HASH()).slice(0, 10)).to.equal(V610_SELECTOR);
      expect(await v610.VK_ROOT()).to.equal(MAINNET.verifiers["v6.1.0"].VK_ROOT);
      expect(await v610.VERSION()).to.equal("v6.1.0");
    });
  });

  describe("direct calls and gateway calls are the same verification", function () {
    it("the gateway forwards ZKMLDSAVerifier's (vkey, public values, proof) tuple unchanged", async function () {
      const gateway = await deployGateway(gatewayOwner.address);
      const exact = await (await ethers.getContractFactory("ExactTupleVerifierProbe")).deploy(rogueHash("0x7e57c0de"));
      await gateway.connect(gatewayOwner).addRoute(await exact.getAddress());
      const zk = await zkVerifier(await gateway.getAddress());
      const digest = ethers.id("td1: forwarding probe digest");
      const publicKey = new Uint8Array(1952).fill(0x11);
      const publicValues = forgedJournal(digest, publicKey, await zk.getAddress());
      const proofBytes = ethers.concat(["0x7e57c0de", ethers.id("td1: forwarding probe proof")]);
      expect(await zk.verify(digest, publicKey, payload(publicValues, proofBytes))).to.equal(false);
      await exact.register(PROGRAM_VKEY, publicValues, proofBytes);
      expect(await zk.verify(digest, publicKey, payload(publicValues, proofBytes))).to.equal(true);
      // Any other tuple (one proof byte changed, selector kept) does not match what was forwarded.
      const altered = ethers.concat(["0x7e57c0de", ethers.id("td1: a different proof")]);
      expect(await zk.verify(digest, publicKey, payload(publicValues, altered))).to.equal(false);
      expect(FACTS.semantics.gatewayForwardsConsumerTupleUnchanged).to.equal(true);
    });

    it("positive control: a real upstream v6 proof verifies on the verifier directly and through the gateway", async function () {
      const v600 = await deployVerifier("v6.0.0");
      const gateway = await deployGateway(gatewayOwner.address);
      await gateway.connect(gatewayOwner).addRoute(await v600.getAddress());
      const { programVKey, publicValues, proofBytes } = FIXTURE;
      expect(proofBytes.slice(0, 10)).to.equal(V600_SELECTOR);
      await v600.verifyProof.staticCall(programVKey, publicValues, proofBytes);
      await gateway.verifyProof.staticCall(programVKey, publicValues, proofBytes);
      expect(FACTS.semantics.realProofAcceptedDirect).to.equal(true);
      expect(FACTS.semantics.realProofAcceptedViaGateway).to.equal(true);
    });

    it("negative control: one changed public-value bit is rejected with the same revert data on both paths", async function () {
      const v600 = await deployVerifier("v6.0.0");
      const gateway = await deployGateway(gatewayOwner.address);
      await gateway.connect(gatewayOwner).addRoute(await v600.getAddress());
      const bytes = ethers.getBytes(FIXTURE.publicValues);
      bytes[bytes.length - 1] ^= 0x01;
      const tampered = ethers.hexlify(bytes);
      const direct = await revertData(v600.verifyProof.staticCall(FIXTURE.programVKey, tampered, FIXTURE.proofBytes));
      const routed = await revertData(
        gateway.verifyProof.staticCall(FIXTURE.programVKey, tampered, FIXTURE.proofBytes),
      );
      expect(direct).to.equal(routed);
      expect(direct).to.equal(v600.interface.getError("ProofInvalid")!.selector);
      // The same proof presented for another program vkey: also refused, identically, on both paths.
      const otherKey = ethers.toBeHex(BigInt(FIXTURE.programVKey) + 1n, 32);
      const keyDirect = await revertData(
        v600.verifyProof.staticCall(otherKey, FIXTURE.publicValues, FIXTURE.proofBytes),
      );
      const keyRouted = await revertData(
        gateway.verifyProof.staticCall(otherKey, FIXTURE.publicValues, FIXTURE.proofBytes),
      );
      expect(keyDirect).to.equal(keyRouted);
      expect(keyDirect).to.equal(v600.interface.getError("ProofInvalid")!.selector);
      expect(FACTS.semantics.tamperedProofRejectedDirectAndViaGateway).to.equal(true);
    });

    it("on v6.1.0 bytes every pre-check rejects with identical revert data directly and through the gateway", async function () {
      const v610 = await deployVerifier("v6.1.0");
      const gateway = await deployGateway(gatewayOwner.address);
      await gateway.connect(gatewayOwner).addRoute(await v610.getAddress());
      const vkRoot = await v610.VK_ROOT();
      const publicValues = ethers.hexlify(new Uint8Array(160).fill(0x22));
      const cases: [string, string, string][] = [
        ["exit code 1", v610Proof(1n, vkRoot, 1n), "InvalidExitCode"],
        ["foreign vk root", v610Proof(0n, ethers.ZeroHash, 1n), "InvalidVkRoot"],
        ["proof points off the curve", v610Proof(0n, vkRoot, 1n), "ProofInvalid"],
      ];
      for (const [label, proofBytes, error] of cases) {
        const direct = await revertData(v610.verifyProof.staticCall(PROGRAM_VKEY, publicValues, proofBytes));
        const routed = await revertData(gateway.verifyProof.staticCall(PROGRAM_VKEY, publicValues, proofBytes));
        expect(direct, label).to.equal(routed);
        expect(direct, label).to.equal(v610.interface.getError(error)!.selector);
      }
      expect(FACTS.semantics.v610PreCheckRevertDataIdenticalDirectAndViaGateway).to.equal(true);
    });

    it("a selector no verifier answers to is rejected on both paths (each with its own error)", async function () {
      const v610 = await deployVerifier("v6.1.0");
      const gateway = await deployGateway(gatewayOwner.address);
      await gateway.connect(gatewayOwner).addRoute(await v610.getAddress());
      const proofBytes = ethers.concat([ROGUE_SELECTOR, ethers.ZeroHash]);
      const publicValues = ethers.hexlify(new Uint8Array(160));
      await expect(v610.verifyProof.staticCall(PROGRAM_VKEY, publicValues, proofBytes))
        .to.be.revertedWithCustomError(v610, "WrongVerifierSelector")
        .withArgs(ROGUE_SELECTOR, V610_SELECTOR);
      await expect(gateway.verifyProof.staticCall(PROGRAM_VKEY, publicValues, proofBytes))
        .to.be.revertedWithCustomError(gateway, "RouteNotFound")
        .withArgs(ROGUE_SELECTOR);
      expect(FACTS.semantics.unroutedSelectorRejectedDirectAndViaGateway).to.equal(true);
    });

    it("the reachability scan itself: it finds reachable writes and ignores only dead data", function () {
      const noMetadata = "0000";
      // PUSH1 0 PUSH1 0 SSTORE: reachable.
      expect(forbiddenOpcodes("0x6000600055" + noMetadata)).to.deep.equal(["SSTORE"]);
      // INVALID then a 0x55 byte: dead data.
      expect(forbiddenOpcodes("0xfe55" + noMetadata)).to.deep.equal([]);
      // INVALID, then a JUMPDEST makes what follows reachable again.
      expect(forbiddenOpcodes("0xfe5b55" + noMetadata)).to.deep.equal(["SSTORE"]);
      // A 0x5b inside PUSH data is not a JUMPDEST, so it cannot revive a dead span.
      expect(forbiddenOpcodes("0xfe605b55" + noMetadata)).to.deep.equal([]);
      // DELEGATECALL right at the start is reachable.
      expect(forbiddenOpcodes("0xf4" + noMetadata)).to.deep.equal(["DELEGATECALL"]);
    });

    it("the v6.1.0 runtime cannot write state, call out mutably, run foreign code or replace code; the gateway can write", async function () {
      const v610 = await deployVerifier("v6.1.0");
      const gateway = await deployGateway(gatewayOwner.address);
      const v610Forbidden = forbiddenOpcodes(await ethers.provider.getCode(await v610.getAddress()));
      const gatewayOps = forbiddenOpcodes(await ethers.provider.getCode(await gateway.getAddress()));
      expect(v610Forbidden).to.deep.equal([]);
      expect(gatewayOps).to.include("SSTORE");
      expect(v610Forbidden).to.deep.equal(FACTS.verifierRuntime.v610ForbiddenOpcodes);
      expect(gatewayOps.includes("SSTORE")).to.equal(FACTS.verifierRuntime.gatewayHasSstore);
    });
  });

  describe("Option D — the upstream gateway, unpinned (today's runbook)", function () {
    let gateway: any, v610: any, zk: any, vault: any, pq: ReturnType<typeof ml_dsa65.keygen>;

    beforeEach(async function () {
      gateway = await deployGateway(gatewayOwner.address);
      v610 = await deployVerifier("v6.1.0");
      await gateway.connect(gatewayOwner).addRoute(await v610.getAddress());
      zk = await zkVerifier(await gateway.getAddress());
      vault = await (await ethers.getContractFactory("WalletWallVault", vaultAdmin)).deploy(await zk.getAddress());
      pq = ml_dsa65.keygen();
      await vault.connect(vaultOwner).createVault(ethers.ZeroAddress, pq.publicKey, PQ_ONLY);
      await vault.connect(vaultOwner).deposit({ value: ethers.parseEther("10") });
    });

    async function withdrawalTo(recipient: string, amount: bigint) {
      const request = {
        vaultOwner: vaultOwner.address,
        recipient,
        amount,
        nonce: await vault.nonces(vaultOwner.address),
        deadline: (await networkHelpers.time.latest()) + 3600,
        vaultMode: PQ_ONLY,
      };
      const digest = ethers.TypedDataEncoder.hash(await withdrawalDomain(vault), WITHDRAWAL_TYPES, request);
      return { request, digest };
    }

    it("the gateway owner alone widens the accepted relation and drains a PqOnly vault the key never signed for", async function () {
      const w = await withdrawalTo(attacker.address, ethers.parseEther("10"));
      const forged = payload(
        forgedJournal(w.digest, pq.publicKey, await zk.getAddress()),
        ethers.concat([ROGUE_SELECTOR, ethers.ZeroHash]),
      );
      // Positive control: before the owner acts, the forged authorization is refused.
      await expect(vault.connect(attacker).withdraw(w.request, "0x", forged)).to.be.revertedWithCustomError(
        vault,
        "InvalidPQSignature",
      );
      await gateway.connect(gatewayOwner).addRoute(await (await acceptAll(rogueHash(ROGUE_SELECTOR))).getAddress());
      const before = await ethers.provider.getBalance(attacker.address);
      await expect(vault.connect(attacker).withdraw(w.request, "0x", forged)).to.emit(vault, "Withdrawn");
      expect((await ethers.provider.getBalance(attacker.address)) > before).to.equal(true);
      expect(FACTS.D_upstreamGatewayUnpinned.ownerAddRouteWidensAcceptedRelation).to.equal(true);
      expect(FACTS.D_upstreamGatewayUnpinned.ownerAddRouteDrainsPqOnlyVault).to.equal(true);
    });

    it("only the gateway owner can add a route, and no one can replace an existing one", async function () {
      const rogue = await acceptAll(rogueHash(ROGUE_SELECTOR));
      await expect(gateway.connect(attacker).addRoute(await rogue.getAddress())).to.be.revertedWithCustomError(
        gateway,
        "OwnableUnauthorizedAccount",
      );
      const squatter = await acceptAll(rogueHash(V610_SELECTOR));
      await expect(gateway.connect(gatewayOwner).addRoute(await squatter.getAddress()))
        .to.be.revertedWithCustomError(gateway, "RouteAlreadyExists")
        .withArgs(await v610.getAddress());
      expect(FACTS.D_upstreamGatewayUnpinned.nonOwnerCanAddRoute).to.equal(false);
      expect(FACTS.D_upstreamGatewayUnpinned.ownerCanReplaceExistingRoute).to.equal(false);
    });

    it("freezing is a liveness lever only: a valid proof stops verifying, nothing previously rejected starts", async function () {
      const v600 = await deployVerifier("v6.0.0");
      await gateway.connect(gatewayOwner).addRoute(await v600.getAddress());
      await gateway.verifyProof.staticCall(FIXTURE.programVKey, FIXTURE.publicValues, FIXTURE.proofBytes);
      await gateway.connect(gatewayOwner).freezeRoute(V600_SELECTOR);
      await expect(gateway.verifyProof.staticCall(FIXTURE.programVKey, FIXTURE.publicValues, FIXTURE.proofBytes))
        .to.be.revertedWithCustomError(gateway, "RouteIsFrozen")
        .withArgs(V600_SELECTOR);
      // The same valid proof still verifies on the verifier itself: only the gateway path lost liveness.
      await v600.verifyProof.staticCall(FIXTURE.programVKey, FIXTURE.publicValues, FIXTURE.proofBytes);
      // And a freeze accepts nothing new: the forged withdrawal is still refused.
      const w = await withdrawalTo(attacker.address, ethers.parseEther("1"));
      await gateway.connect(gatewayOwner).freezeRoute(V610_SELECTOR);
      const forged = payload(
        forgedJournal(w.digest, pq.publicKey, await zk.getAddress()),
        v610Proof(0n, await v610.VK_ROOT(), 1n),
      );
      await expect(vault.connect(attacker).withdraw(w.request, "0x", forged)).to.be.revertedWithCustomError(
        vault,
        "InvalidPQSignature",
      );
      expect(FACTS.D_upstreamGatewayUnpinned.ownerFreezeRejectsValidProof).to.equal(true);
      expect(FACTS.D_upstreamGatewayUnpinned.freezeAcceptsNoPreviouslyRejectedInput).to.equal(true);
    });
  });

  describe("Option C — a WalletWall-governed gateway", function () {
    it("its admin widens the relation in the next block, while the vault's own verifier rotation waits two days", async function () {
      const gateway = await deployGateway(vaultAdmin.address);
      const v610 = await deployVerifier("v6.1.0");
      await gateway.connect(vaultAdmin).addRoute(await v610.getAddress());
      const zk = await zkVerifier(await gateway.getAddress());
      const vault = await (
        await ethers.getContractFactory("WalletWallVault", vaultAdmin)
      ).deploy(await zk.getAddress());
      const pq = ml_dsa65.keygen();
      await vault.connect(vaultOwner).createVault(ethers.ZeroAddress, pq.publicKey, PQ_ONLY);
      await vault.connect(vaultOwner).deposit({ value: ethers.parseEther("10") });

      // The vault's governed path: a replacement verifier is proposable now and applicable only after the delay.
      const rogueSp1 = await acceptAll(rogueHash(ROGUE_SELECTOR));
      const rogueZk = await zkVerifier(await rogueSp1.getAddress());
      await vault.connect(vaultAdmin).proposePQVerifier(await rogueZk.getAddress());
      const delay = (await vault.pendingPQVerifierValidAfter()) - BigInt(await networkHelpers.time.latest());
      await expect(vault.connect(vaultAdmin).applyPQVerifierUpdate()).to.be.revertedWithCustomError(
        vault,
        "PQVerifierUpdateNotReady",
      );
      await vault.connect(vaultAdmin).cancelPQVerifierUpdate();

      // The gateway path: the same admin widens instantly; the forged withdrawal pays in the next block.
      const addRouteBlock = await (await gateway.connect(vaultAdmin).addRoute(await rogueSp1.getAddress())).wait();
      const request = {
        vaultOwner: vaultOwner.address,
        recipient: attacker.address,
        amount: ethers.parseEther("10"),
        nonce: await vault.nonces(vaultOwner.address),
        deadline: (await networkHelpers.time.latest()) + 3600,
        vaultMode: PQ_ONLY,
      };
      const digest = ethers.TypedDataEncoder.hash(await withdrawalDomain(vault), WITHDRAWAL_TYPES, request);
      const forged = payload(
        forgedJournal(digest, pq.publicKey, await zk.getAddress()),
        ethers.concat([ROGUE_SELECTOR, ethers.ZeroHash]),
      );
      const paid = await (await vault.connect(attacker).withdraw(request, "0x", forged)).wait();
      expect(paid!.blockNumber).to.equal(addRouteBlock!.blockNumber + 1);
      expect(delay).to.equal(BigInt(FACTS.C_walletwallGateway.vaultVerifierRotationDelaySeconds));
      expect(FACTS.C_walletwallGateway.vaultVerifierRotationDelaySeconds).to.equal(172800);
      expect(FACTS.C_walletwallGateway.adminAddRouteWidensAcceptedRelation).to.equal(true);
      expect(FACTS.C_walletwallGateway.adminWidensWithoutDelay).to.equal(true);
    });
  });

  describe("Option B — WalletWall pins the gateway route", function () {
    it("a selector-only pin is defeated where the selector is not yet routed: the owner squats it", async function () {
      const gateway = await deployGateway(gatewayOwner.address);
      const probe = await (
        await ethers.getContractFactory("SelectorPinnedGatewayProbe")
      ).deploy(await gateway.getAddress(), V610_SELECTOR);
      const zk = await zkVerifier(await probe.getAddress());
      const digest = ethers.id("td1: squat digest");
      const publicKey = new Uint8Array(1952).fill(0x33);
      const forged = payload(
        forgedJournal(digest, publicKey, await zk.getAddress()),
        ethers.concat([V610_SELECTOR, ethers.ZeroHash]),
      );
      expect(await zk.verify(digest, publicKey, forged)).to.equal(false);
      await gateway.connect(gatewayOwner).addRoute(await (await acceptAll(rogueHash(V610_SELECTOR))).getAddress());
      expect(await zk.verify(digest, publicKey, forged)).to.equal(true);
      expect(FACTS.B0_selectorOnlyPin.routeSquatOnUnroutedChainAccepted).to.equal(true);
    });

    it("selector + route + code pins refuse a squatted route at construction", async function () {
      const gateway = await deployGateway(gatewayOwner.address);
      const v610 = await deployVerifier("v6.1.0");
      const squatter = await acceptAll(rogueHash(V610_SELECTOR));
      await gateway.connect(gatewayOwner).addRoute(await squatter.getAddress());
      const factory = await ethers.getContractFactory("RoutePinnedGatewayProbe");
      await expect(
        factory.deploy(
          await gateway.getAddress(),
          MAINNET.gateway.codeKeccak,
          V610_SELECTOR,
          await v610.getAddress(),
          MAINNET.verifiers["v6.1.0"].codeKeccak,
        ),
      ).to.be.revertedWithCustomError(factory, "RouteVerifierMismatch");
      expect(FACTS.B_selectorRouteCodePinned.squattedRouteRejectedAtConstruction).to.equal(true);
    });

    it("pinned to an honest route, the owner can no longer widen and keeps only the freeze lever", async function () {
      const gateway = await deployGateway(gatewayOwner.address);
      const v600 = await deployVerifier("v6.0.0");
      await gateway.connect(gatewayOwner).addRoute(await v600.getAddress());
      const probe = await (
        await ethers.getContractFactory("RoutePinnedGatewayProbe")
      ).deploy(
        await gateway.getAddress(),
        MAINNET.gateway.codeKeccak,
        V600_SELECTOR,
        await v600.getAddress(),
        MAINNET.verifiers["v6.0.0"].codeKeccak,
      );
      // Positive control: the real proof verifies through the pinned route.
      await probe.verifyProof.staticCall(FIXTURE.programVKey, FIXTURE.publicValues, FIXTURE.proofBytes);
      // The owner adds an accept-all route: the pin refuses its selector.
      await gateway.connect(gatewayOwner).addRoute(await (await acceptAll(rogueHash(ROGUE_SELECTOR))).getAddress());
      await expect(
        probe.verifyProof.staticCall(
          FIXTURE.programVKey,
          FIXTURE.publicValues,
          ethers.concat([ROGUE_SELECTOR, "0x00"]),
        ),
      ).to.be.revertedWithCustomError(probe, "UnexpectedSelector");
      // The pinned route cannot be redirected.
      await expect(
        gateway.connect(gatewayOwner).addRoute(await (await acceptAll(rogueHash(V600_SELECTOR))).getAddress()),
      ).to.be.revertedWithCustomError(gateway, "RouteAlreadyExists");
      // Freezing it stops the valid proof: liveness, not authorization.
      await gateway.connect(gatewayOwner).freezeRoute(V600_SELECTOR);
      await expect(
        probe.verifyProof.staticCall(FIXTURE.programVKey, FIXTURE.publicValues, FIXTURE.proofBytes),
      ).to.be.revertedWithCustomError(gateway, "RouteIsFrozen");
      expect(FACTS.B_selectorRouteCodePinned).to.deep.equal({
        squattedRouteRejectedAtConstruction: true,
        realProofAcceptedThroughPin: true,
        otherSelectorRouteRejected: true,
        pinnedRouteReplaceable: false,
        ownerFreezeRejectsValidProof: true,
      });
    });
  });

  describe("Option A — ZKMLDSAVerifier bound directly to the immutable verifier, pinned by code hash", function () {
    const V610_CODEHASH = MAINNET.verifiers["v6.1.0"].codeKeccak;
    const pinned = async (target: string) =>
      (await ethers.getContractFactory("ZKMLDSAVerifierCodePinnedProbe")).deploy(target, PROGRAM_VKEY, V610_CODEHASH);

    it("the code pin accepts the canonical verifier code at any address and refuses every other code", async function () {
      const factory = await ethers.getContractFactory("ZKMLDSAVerifierCodePinnedProbe");
      const v610 = await deployVerifier("v6.1.0");
      const v610Again = await deployVerifier("v6.1.0");
      expect(await v610Again.getAddress()).to.not.equal(await v610.getAddress());
      await pinned(await v610.getAddress());
      await pinned(await v610Again.getAddress());
      const gateway = await deployGateway(gatewayOwner.address);
      await gateway.connect(gatewayOwner).addRoute(await v610.getAddress());
      const v600 = await deployVerifier("v6.0.0");
      const rogue = await acceptAll(rogueHash(V610_SELECTOR));
      for (const [label, target] of [
        ["the gateway (even routing to v6.1.0)", await gateway.getAddress()],
        ["another verifier version", await v600.getAddress()],
        ["an accept-all verifier answering to the v6.1.0 selector", await rogue.getAddress()],
      ]) {
        await expect(pinned(target), label).to.be.revertedWithCustomError(factory, "SP1VerifierCodeMismatch");
      }
      expect(FACTS.A_directCodePinned).to.include({
        acceptsCanonicalCode: true,
        acceptsSameCodeAtAnotherAddress: true,
        rejectsGateway: true,
        rejectsOtherVerifierVersion: true,
        rejectsAcceptAllVerifier: true,
      });
    });

    it("bound directly, the unmodified consumer refuses every forged proof shape and no principal exists to change that", async function () {
      const v610 = await deployVerifier("v6.1.0");
      const zk = await zkVerifier(await v610.getAddress());
      const digest = ethers.id("td1: direct digest");
      const publicKey = new Uint8Array(1952).fill(0x44);
      const journal = forgedJournal(digest, publicKey, await zk.getAddress());
      for (const proofBytes of [
        ethers.concat([ROGUE_SELECTOR, ethers.ZeroHash]),
        v610Proof(0n, await v610.VK_ROOT(), 1n),
        v610Proof(1n, await v610.VK_ROOT(), 1n),
        "0x01",
      ]) {
        expect(await zk.verify(digest, publicKey, payload(journal, proofBytes))).to.equal(false);
      }
      // The verifier exposes no owner and no route administration: there is no lever to pull.
      const probe = new ethers.Contract(await v610.getAddress(), GATEWAY_ABI, attacker);
      await expect(probe.owner()).to.revert(ethers);
      await expect(probe.addRoute(attacker.address)).to.revert(ethers);
      expect(FACTS.A_directCodePinned.unmodifiedConsumerRejectsForgedRouteProof).to.equal(true);
      expect(FACTS.A_directCodePinned.noPrincipalCanAlterAcceptedRelation).to.equal(
        FACTS.verifierRuntime.v610ForbiddenOpcodes.length === 0,
      );
    });
  });
});
