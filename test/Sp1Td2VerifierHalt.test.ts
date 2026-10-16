/**
 * SP1-TD2 — TD2-COMMON-VERIFIER-HALT: the local one-way verifier halt, executed
 * (docs/SP1_TD2_Verifier_Halt_And_Multisig_Rotation.md; frozen by SP1-TD1 as
 * DEFECT_RESPONSE_COUPLING.haltDesign and td2Requirements[0]).
 *
 * The halt lives in the WalletWall verifier wrapper, ZKMLDSAVerifier: ACTIVE -> HALTED, called by its halt
 * principal and nobody else, and nothing leads back. This suite proves, each with a positive control:
 *
 *   VALID_VERIFICATION_WHILE_ACTIVE — a valid proof verifies while ACTIVE, at the wrapper and through
 *     WalletWallVault, StablecoinVaultSimulator and PolicyControlBridge (the consumers in the halt's scope).
 *   FAILS_CLOSED_AFTER_HALT_THROUGH_EVERY_CONSUMER_IN_SCOPE — after one halt call, the same otherwise-valid
 *     authorization is refused through every one of them, in the same block.
 *   HALT_PRINCIPAL_CANNOT_MAKE_AN_INVALID_PROOF_VALID — the halt principal's only function makes nothing
 *     verify that did not, and the wrapper offers it no other function.
 *   plus the frozen design's tests: no transition out of HALTED, and no upstream signal moves the state.
 *
 * The rotation-side proofs (the halt principal cannot rotate, the halted identity is refused as a recovery
 * target) are in test/Sp1Td2VerifierRotation.test.ts; the tooling exclusion in test/Sp1Td2VerifierBinding.test.ts.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { expect } from "chai";

import { ethers } from "./helpers/connection";
import { findContract, loadSourceAst, walkAst, type AstNode } from "./helpers/solidityAst";
import { WITHDRAWAL_TYPES, withdrawalDomain } from "./helpers/vaultHelpers";
import { simulatorDomain } from "./helpers/simulatorHelpers";
import {
  ABI,
  MODE,
  VKEY_A,
  deploySp1,
  deployWrapper,
  mlDsaKey,
  mlDsaSign,
  mutatingFunctions,
  proveFor,
  unprovenFor,
  type MlDsaKey,
} from "./helpers/td2Helpers";
import { ProverClient } from "../scripts/prover-client";

const ROTATE_TYPES = {
  RotateCredentials: [
    { name: "vaultOwner", type: "address" },
    { name: "newEcdsaSigner", type: "address" },
    { name: "newPQPublicKey", type: "bytes" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};
const ENROLL_TYPES = {
  EnrollController: [
    { name: "consumer", type: "address" },
    { name: "owner", type: "address" },
    { name: "policy", type: "address" },
    { name: "asset", type: "address" },
    { name: "controller", type: "address" },
    { name: "epoch", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

describe("SP1-TD2 common verifier halt (TD2-COMMON-VERIFIER-HALT)", function () {
  let admin: any, haltPrincipal: any, tenant: any, recipient: any, attacker: any, pauser: any, tenant2: any;
  let sp1: any;
  let wrapper: any;

  beforeEach(async function () {
    [admin, haltPrincipal, tenant, recipient, attacker, pauser, tenant2] = await ethers.getSigners();
    sp1 = await deploySp1();
    wrapper = await deployWrapper(sp1, VKEY_A, haltPrincipal.address);
  });

  const deadline = async () => BigInt((await ethers.provider.getBlock("latest"))!.timestamp) + 30n * 86400n;

  // -------------------------------------------------------------------------------------------------------
  // The wrapper itself
  // -------------------------------------------------------------------------------------------------------

  describe("the wrapper: ACTIVE -> HALTED, by the halt principal only", function () {
    it("starts ACTIVE with its identity and halt principal fixed at construction", async function () {
      expect(await wrapper.halted()).to.equal(false);
      expect(await wrapper.HALT_PRINCIPAL()).to.equal(haltPrincipal.address);
      expect(await wrapper.SP1_VERIFIER()).to.equal(await sp1.getAddress());
      expect(await wrapper.PROGRAM_VKEY()).to.equal(VKEY_A);
    });

    it("refuses a zero halt principal at construction (the breaker would be uncallable forever)", async function () {
      const factory = await ethers.getContractFactory("ZKMLDSAVerifier");
      await expect(factory.deploy(await sp1.getAddress(), VKEY_A, ethers.ZeroAddress)).to.be.revertedWithCustomError(
        factory,
        "ZeroHaltPrincipal",
      );
    });

    it("only the halt principal can halt; the halt emits VerifierHalted and sets HALTED", async function () {
      for (const who of [admin, tenant, attacker, pauser]) {
        await expect(wrapper.connect(who).halt()).to.be.revertedWithCustomError(wrapper, "NotHaltPrincipal");
      }
      expect(await wrapper.halted(), "a refused halt changed nothing").to.equal(false);
      await expect(wrapper.connect(haltPrincipal).halt())
        .to.emit(wrapper, "VerifierHalted")
        .withArgs(haltPrincipal.address);
      expect(await wrapper.halted()).to.equal(true);
    });

    it("VALID_VERIFICATION_WHILE_ACTIVE: positive control at the wrapper, then the same proof is refused once HALTED", async function () {
      const key = mlDsaKey();
      const digest = ethers.id("SP1-TD2: a withdrawal digest");
      const signature = mlDsaSign(digest, key);
      const proof = await proveFor(wrapper, digest, key.publicKey, signature);
      expect(await wrapper.verify(digest, key.publicKey, proof), "positive control").to.equal(true);

      await wrapper.connect(haltPrincipal).halt();
      expect(await wrapper.verify(digest, key.publicKey, proof), "the identical call, after the halt").to.equal(false);
    });
  });

  describe("HALT_PRINCIPAL_CANNOT_MAKE_AN_INVALID_PROOF_VALID", function () {
    it("the halt principal's whole surface is halt(): the wrapper exposes no other state-changing function", async function () {
      expect(mutatingFunctions(wrapper)).to.deep.equal(["halt"]);
    });

    it("no proof that fails while ACTIVE verifies after anything the halt principal can do, and a valid one stops verifying", async function () {
      const key = mlDsaKey();
      const other = mlDsaKey();
      const digest = ethers.id("SP1-TD2: the digest under test");
      const otherDigest = ethers.id("SP1-TD2: another digest");
      const signature = mlDsaSign(digest, key);
      const unprovenSignature = Uint8Array.from(signature, (b, i) => (i === 0 ? b ^ 1 : b));
      const chainId = (await ethers.provider.getNetwork()).chainId;
      const proven = async (journal: string) => {
        await sp1.setProven(VKEY_A, journal);
        return ABI.encode(["bytes", "bytes"], [journal, "0x01"]);
      };
      const journalWith = (d: string, pk: Uint8Array, cid: bigint, verifier: string) =>
        ProverClient.encodePublicValues(d, pk, signature, cid, verifier);
      const self = await wrapper.getAddress();

      const invalid: [string, string][] = [
        // Same digest and key, another signature's journal: nobody proved it (the valid proof below proves only its own).
        [
          "an honest-looking journal no proof covers",
          await unprovenFor(wrapper, digest, key.publicKey, unprovenSignature),
        ],
        ["a proven journal for another digest", await proven(journalWith(otherDigest, key.publicKey, chainId, self))],
        ["a proven journal for another key", await proven(journalWith(digest, other.publicKey, chainId, self))],
        ["a proven journal for another chain", await proven(journalWith(digest, key.publicKey, chainId + 1n, self))],
        [
          "a proven journal naming another verifier",
          await proven(journalWith(digest, key.publicKey, chainId, attacker.address)),
        ],
        ["malformed proof bytes", ethers.hexlify(ethers.randomBytes(100))],
        ["an empty proof", ABI.encode(["bytes", "bytes"], [journalWith(digest, key.publicKey, chainId, self), "0x"])],
      ];
      const valid = await proveFor(wrapper, digest, key.publicKey, signature);

      const answers = async () => {
        const out: string[] = [];
        for (const [label, proof] of invalid) {
          out.push(`${label}: ${await wrapper.connect(haltPrincipal).verify(digest, key.publicKey, proof)}`);
        }
        out.push(`the valid proof: ${await wrapper.connect(haltPrincipal).verify(digest, key.publicKey, valid)}`);
        return out;
      };

      const active = await answers();
      expect(
        active.slice(0, -1).every((a) => a.endsWith(": false")),
        active.join("\n"),
      ).to.equal(true);
      expect(active.at(-1), "positive control").to.equal("the valid proof: true");

      // Everything the halt principal can send: every state-changing function in the ABI (only halt()).
      for (const name of mutatingFunctions(wrapper)) await wrapper.connect(haltPrincipal).getFunction(name)();
      const halted = await answers();
      expect(
        halted.every((a) => a.endsWith(": false")),
        halted.join("\n"),
      ).to.equal(true);
      // ...and the identity it verifies under did not move.
      expect(await wrapper.SP1_VERIFIER()).to.equal(await sp1.getAddress());
      expect(await wrapper.PROGRAM_VKEY()).to.equal(VKEY_A);
      expect(await wrapper.HALT_PRINCIPAL()).to.equal(haltPrincipal.address);
    });
  });

  describe("no transition out of HALTED, and no upstream signal moves the state", function () {
    it("once HALTED, no call by anyone leaves HALTED: a second halt reverts AlreadyHalted", async function () {
      await wrapper.connect(haltPrincipal).halt();
      await expect(wrapper.connect(haltPrincipal).halt()).to.be.revertedWithCustomError(wrapper, "AlreadyHalted");
      for (const who of [admin, tenant, attacker, haltPrincipal]) {
        for (const name of mutatingFunctions(wrapper)) {
          await expect(wrapper.connect(who).getFunction(name)()).to.be.revert(ethers);
        }
      }
      expect(await wrapper.halted()).to.equal(true);
    });

    it("the source writes `halted` in exactly one place, halt(), and only ever to true", function () {
      const contract = findContract(loadSourceAst("contracts/verifiers/ZKMLDSAVerifier.sol"), "ZKMLDSAVerifier");
      const stateVar = (contract.nodes as AstNode[]).find(
        (n) => n.nodeType === "VariableDeclaration" && n.name === "halted" && n.stateVariable === true,
      )!;
      expect(stateVar, "the halted state variable").to.not.equal(undefined);
      const writes: string[] = [];
      for (const fn of contract.nodes as AstNode[]) {
        if (fn.nodeType !== "FunctionDefinition" && fn.nodeType !== "ModifierDefinition") continue;
        walkAst(fn, (node) => {
          const target =
            node.nodeType === "Assignment"
              ? (node.leftHandSide as AstNode)
              : node.nodeType === "UnaryOperation" && node.operator === "delete"
                ? (node.subExpression as AstNode)
                : undefined;
          if (target?.nodeType === "Identifier" && target.referencedDeclaration === stateVar.id) {
            const rhs = node.nodeType === "Assignment" ? (node.rightHandSide as AstNode) : undefined;
            writes.push(
              `${String(fn.name || fn.kind)}: ${rhs?.nodeType === "Literal" ? String(rhs.value) : "non-literal"}`,
            );
          }
        });
      }
      expect(writes).to.deep.equal(["halt: true"]);
    });

    it("an upstream RouteFrozen for the pinned selector is evidence only: the wrapper stays ACTIVE and answers as before", async function () {
      const obs = (rel: string) => JSON.parse(readFileSync(resolve(`evidence/zk/sp1-td1/observations/${rel}`), "utf8"));
      const bytecode = obs("deployment-bytecode.raw.json");
      const deployRaw = async (data: string) =>
        (await (await admin.sendTransaction({ data })).wait()).contractAddress as string;
      const v610 = await deployRaw(bytecode.deployments["v6.1.0"].initcode);
      const gateway = new ethers.Contract(
        await deployRaw(
          ethers.concat([bytecode.deployments.gateway.creationCode, ABI.encode(["address"], [admin.address])]),
        ),
        [
          "function addRoute(address)",
          "function freezeRoute(bytes4)",
          "function routes(bytes4) view returns (address, bool)",
        ],
        admin,
      );
      await gateway.addRoute(v610);
      // The wrapper is bound directly to the immutable verifier (the TD1 decision); the gateway is not in its path.
      const direct = await (
        await ethers.getContractFactory("ZKMLDSAVerifier")
      ).deploy(v610, VKEY_A, haltPrincipal.address);
      const key = mlDsaKey();
      const digest = ethers.id("SP1-TD2: upstream signal");
      const payload = await unprovenFor(direct, digest, key.publicKey, mlDsaSign(digest, key));
      const before = await direct.verify(digest, key.publicKey, payload);

      await gateway.freezeRoute("0x4388a21c");
      expect((await gateway.routes("0x4388a21c"))[1], "the upstream route really is frozen").to.equal(true);
      expect(await direct.halted(), "a signal is not a state input").to.equal(false);
      expect(await direct.verify(digest, key.publicKey, payload)).to.equal(before);
      // Only the halt principal moves it, as it would after reading such a signal.
      await direct.connect(haltPrincipal).halt();
      expect(await direct.halted()).to.equal(true);
    });
  });

  // -------------------------------------------------------------------------------------------------------
  // Through every consumer in the halt's scope
  // -------------------------------------------------------------------------------------------------------

  describe("through every consumer in scope: valid while ACTIVE, refused once HALTED", function () {
    async function walletWallVault(verifier: any) {
      return (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    }

    async function vaultWithdrawal(vault: any, owner: any, key: MlDsaKey | null, mode: number, amount: bigint) {
      const request = {
        vaultOwner: owner.address,
        recipient: recipient.address,
        amount,
        nonce: await vault.nonces(owner.address),
        deadline: await deadline(),
        vaultMode: mode,
      };
      const digest = ethers.TypedDataEncoder.hash(await withdrawalDomain(vault), WITHDRAWAL_TYPES, request);
      const ecdsa =
        mode === MODE.PqOnly
          ? "0x"
          : await owner.signTypedData(await withdrawalDomain(vault), WITHDRAWAL_TYPES, request);
      const pq = key === null ? "0x" : await proveFor(wrapper, digest, key.publicKey, mlDsaSign(digest, key));
      return { request, ecdsa, pq };
    }

    for (const [label, mode] of [
      ["PqOnly", MODE.PqOnly],
      ["Hybrid", MODE.Hybrid],
    ] as const) {
      it(`WalletWallVault, ${label} withdrawal: VALID_VERIFICATION_WHILE_ACTIVE, then FAILS_CLOSED_AFTER_HALT`, async function () {
        const vault = await walletWallVault(wrapper);
        const key = mlDsaKey();
        await vault
          .connect(tenant)
          .createVault(mode === MODE.PqOnly ? ethers.ZeroAddress : tenant.address, key.publicKey, mode, {
            value: ethers.parseEther("10"),
          });

        const first = await vaultWithdrawal(vault, tenant, key, mode, ethers.parseEther("1"));
        await expect(vault.withdraw(first.request, first.ecdsa, first.pq), "positive control").to.emit(
          vault,
          "Withdrawn",
        );

        const next = await vaultWithdrawal(vault, tenant, key, mode, ethers.parseEther("1"));
        await vault.withdraw.staticCall(next.request, next.ecdsa, next.pq); // valid while ACTIVE
        await wrapper.connect(haltPrincipal).halt();
        await expect(vault.withdraw(next.request, next.ecdsa, next.pq)).to.be.revertedWithCustomError(
          vault,
          "InvalidPQSignature",
        );
        expect(await vault.nonces(tenant.address), "nothing was consumed").to.equal(next.request.nonce);
      });
    }

    it("WalletWallVault, credential rotation: VALID_VERIFICATION_WHILE_ACTIVE, then FAILS_CLOSED_AFTER_HALT", async function () {
      const vault = await walletWallVault(wrapper);
      const key = mlDsaKey();
      const incoming = mlDsaKey();
      await vault.connect(tenant).createVault(ethers.ZeroAddress, key.publicKey, MODE.PqOnly, { value: 1n });
      const rotationDeadline = await deadline();
      const message = {
        vaultOwner: tenant.address,
        newEcdsaSigner: ethers.ZeroAddress,
        newPQPublicKey: ethers.hexlify(incoming.publicKey),
        nonce: await vault.nonces(tenant.address),
        deadline: rotationDeadline,
      };
      const digest = ethers.TypedDataEncoder.hash(await withdrawalDomain(vault), ROTATE_TYPES, message);
      const auth = {
        currentEcdsaSignature: "0x",
        currentPqSignature: await proveFor(wrapper, digest, key.publicKey, mlDsaSign(digest, key)),
        newEcdsaSignature: "0x",
        newPqSignature: await proveFor(wrapper, digest, incoming.publicKey, mlDsaSign(digest, incoming)),
      };
      const rotate = () =>
        vault.rotateCredentials(tenant.address, ethers.ZeroAddress, incoming.publicKey, rotationDeadline, auth);
      await vault.rotateCredentials.staticCall(
        tenant.address,
        ethers.ZeroAddress,
        incoming.publicKey,
        rotationDeadline,
        auth,
      );
      await wrapper.connect(haltPrincipal).halt();
      await expect(rotate()).to.be.revertedWithCustomError(vault, "InvalidPQSignature");
    });

    it("WalletWallVault, EcdsaOnly withdrawal: unaffected by the halt (it verifies no PQ signature)", async function () {
      const vault = await walletWallVault(wrapper);
      await vault.connect(tenant).createVault(tenant.address, "0x", MODE.EcdsaOnly, { value: ethers.parseEther("2") });
      await wrapper.connect(haltPrincipal).halt();
      const w = await vaultWithdrawal(vault, tenant, null, MODE.EcdsaOnly, ethers.parseEther("1"));
      await expect(vault.withdraw(w.request, w.ecdsa, "0x")).to.emit(vault, "Withdrawn");
    });

    for (const [label, mode] of [
      ["PqOnly", MODE.PqOnly],
      ["Hybrid", MODE.Hybrid],
    ] as const) {
      it(`StablecoinVaultSimulator, ${label} withdrawal: VALID_VERIFICATION_WHILE_ACTIVE, then FAILS_CLOSED_AFTER_HALT`, async function () {
        const token = await (await ethers.getContractFactory("MockUSDC")).deploy();
        const sim = await (
          await ethers.getContractFactory("StablecoinVaultSimulator", admin)
        ).deploy(await token.getAddress(), await wrapper.getAddress());
        const key = mlDsaKey();
        await sim
          .connect(tenant)
          .createVault(mode === MODE.PqOnly ? ethers.ZeroAddress : tenant.address, key.publicKey, mode);
        await token.connect(tenant).mint(tenant.address, 1_000_000_000n);
        await token.connect(tenant).approve(await sim.getAddress(), 1_000_000_000n);
        await sim.connect(tenant).deposit(1_000_000_000n);

        const withdrawal = async () => {
          const request = {
            vaultOwner: tenant.address,
            recipient: recipient.address,
            amount: 100_000_000n,
            nonce: await sim.nonces(tenant.address),
            deadline: await deadline(),
            vaultMode: mode,
          };
          const domain = await simulatorDomain(sim);
          const digest = ethers.TypedDataEncoder.hash(domain, WITHDRAWAL_TYPES, request);
          const ecdsa = mode === MODE.PqOnly ? "0x" : await tenant.signTypedData(domain, WITHDRAWAL_TYPES, request);
          return { request, ecdsa, pq: await proveFor(wrapper, digest, key.publicKey, mlDsaSign(digest, key)) };
        };
        const first = await withdrawal();
        await expect(sim.withdraw(first.request, first.ecdsa, first.pq), "positive control").to.emit(sim, "Withdrawn");
        const next = await withdrawal();
        await sim.withdraw.staticCall(next.request, next.ecdsa, next.pq);
        await wrapper.connect(haltPrincipal).halt();
        await expect(sim.withdraw(next.request, next.ecdsa, next.pq)).to.be.revertedWithCustomError(
          sim,
          "InvalidPQSignature",
        );
      });
    }

    async function bridgeFixture(consumer: any) {
      const bridge = await (await ethers.getContractFactory("PolicyControlBridge")).deploy(pauser.address);
      const target = await (await ethers.getContractFactory("PolicyControlTargetMock")).deploy();
      const enroll = async (owner: any, key: MlDsaKey, mode: number) => {
        const request = {
          consumer: await consumer.getAddress(),
          owner: owner.address,
          policy: await target.getAddress(),
          asset: ethers.ZeroAddress,
          controller: await bridge.getAddress(),
          epoch: await consumer.policyControlEpoch(owner.address),
          nonce: await bridge.controlNonce(await consumer.getAddress(), owner.address),
          deadline: await deadline(),
        };
        const domain = {
          name: "WalletWallPolicyControlBridge",
          version: "1",
          chainId: (await ethers.provider.getNetwork()).chainId,
          verifyingContract: await bridge.getAddress(),
        };
        const digest = ethers.TypedDataEncoder.hash(domain, ENROLL_TYPES, request);
        const ecdsa = mode === MODE.PqOnly ? "0x" : await owner.signTypedData(domain, ENROLL_TYPES, request);
        return { request, ecdsa, pq: await proveFor(wrapper, digest, key.publicKey, mlDsaSign(digest, key)) };
      };
      return { bridge, target, enroll };
    }

    for (const [label, mode] of [
      ["PqOnly", MODE.PqOnly],
      ["Hybrid", MODE.Hybrid],
    ] as const) {
      it(`PolicyControlBridge, ${label} tenant: VALID_VERIFICATION_WHILE_ACTIVE, then FAILS_CLOSED_AFTER_HALT (it verifies through the consumer's pqVerifier)`, async function () {
        const vault = await walletWallVault(wrapper);
        const key = mlDsaKey();
        await vault
          .connect(tenant)
          .createVault(mode === MODE.PqOnly ? ethers.ZeroAddress : tenant.address, key.publicKey, mode, { value: 1n });
        const { bridge, target, enroll } = await bridgeFixture(vault);
        expect(await vault.pqVerifier()).to.equal(await wrapper.getAddress());

        const first = await enroll(tenant, key, mode);
        await bridge.enrollController(first.request, first.ecdsa, first.pq);
        expect(await target.callCount(), "positive control").to.equal(1n);

        const next = await enroll(tenant, key, mode);
        await bridge.enrollController.staticCall(next.request, next.ecdsa, next.pq);
        await wrapper.connect(haltPrincipal).halt();
        await expect(bridge.enrollController(next.request, next.ecdsa, next.pq)).to.be.revertedWithCustomError(
          bridge,
          "InvalidPQSignature",
        );
        expect(await target.callCount()).to.equal(1n);
      });
    }

    it("FAILS_CLOSED_AFTER_HALT_THROUGH_EVERY_CONSUMER_IN_SCOPE: one halt call refuses all three consumers at once", async function () {
      // One wrapper behind a WalletWallVault, a StablecoinVaultSimulator and the bridge (reading the vault).
      const vault = await walletWallVault(wrapper);
      const token = await (await ethers.getContractFactory("MockUSDC")).deploy();
      const sim = await (
        await ethers.getContractFactory("StablecoinVaultSimulator", admin)
      ).deploy(await token.getAddress(), await wrapper.getAddress());
      const key = mlDsaKey();
      await vault.connect(tenant).createVault(ethers.ZeroAddress, key.publicKey, MODE.PqOnly, {
        value: ethers.parseEther("5"),
      });
      await sim.connect(tenant2).createVault(ethers.ZeroAddress, key.publicKey, MODE.PqOnly);
      await token.connect(tenant2).mint(tenant2.address, 500n);
      await token.connect(tenant2).approve(await sim.getAddress(), 500n);
      await sim.connect(tenant2).deposit(500n);
      const { bridge, enroll } = await bridgeFixture(vault);

      const vaultW = await vaultWithdrawal(vault, tenant, key, MODE.PqOnly, ethers.parseEther("1"));
      const simRequest = {
        vaultOwner: tenant2.address,
        recipient: recipient.address,
        amount: 100n,
        nonce: 0n,
        deadline: await deadline(),
        vaultMode: MODE.PqOnly,
      };
      const simDigest = ethers.TypedDataEncoder.hash(await simulatorDomain(sim), WITHDRAWAL_TYPES, simRequest);
      const simPq = await proveFor(wrapper, simDigest, key.publicKey, mlDsaSign(simDigest, key));
      const intent = await enroll(tenant, key, MODE.PqOnly);

      const calls = {
        WalletWallVault: () => vault.withdraw.staticCall(vaultW.request, "0x", vaultW.pq),
        StablecoinVaultSimulator: () => sim.withdraw.staticCall(simRequest, "0x", simPq),
        PolicyControlBridge: () => bridge.enrollController.staticCall(intent.request, intent.ecdsa, intent.pq),
      };
      const verdicts = async () => {
        const out: Record<string, string> = {};
        for (const [name, call] of Object.entries(calls)) {
          try {
            await call();
            out[name] = "accepted";
          } catch (error) {
            out[name] = (error as { data?: string }).data === undefined ? "reverted" : "refused";
          }
        }
        return out;
      };
      expect(await verdicts(), "positive control: all three accept while ACTIVE").to.deep.equal({
        WalletWallVault: "accepted",
        StablecoinVaultSimulator: "accepted",
        PolicyControlBridge: "accepted",
      });
      await wrapper.connect(haltPrincipal).halt();
      expect(await verdicts(), "one halt, every consumer in scope refuses").to.deep.equal({
        WalletWallVault: "refused",
        StablecoinVaultSimulator: "refused",
        PolicyControlBridge: "refused",
      });
      // The refusals are the consumers' own PQ errors, not some other failure.
      await expect(calls.WalletWallVault()).to.be.revertedWithCustomError(vault, "InvalidPQSignature");
      await expect(calls.StablecoinVaultSimulator()).to.be.revertedWithCustomError(sim, "InvalidPQSignature");
      await expect(calls.PolicyControlBridge()).to.be.revertedWithCustomError(bridge, "InvalidPQSignature");
    });
  });
});
