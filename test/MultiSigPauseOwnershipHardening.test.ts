/**
 * NF-1 and NF-2 — WalletWallMultiSigVault pause and ownership hardening.
 *
 * THE DEFECTS THIS PINS
 * ---------------------
 * NF-1. `WalletWallMultiSigVault` is `Ownable2Step` + `Pausable`, `pause()`/`unpause()` are
 * `onlyOwner`, and `withdraw` is `whenNotPaused`. #180 disabled the inherited
 * `renounceOwnership()` on `WalletWallVault` and `StablecoinVaultSimulator` but never on this
 * contract, so a single principal could still run
 *
 *     pause()              -> withdraw stops for every tenant
 *     renounceOwnership()  -> owner() becomes address(0); unpause() is uncallable forever
 *
 * and this variant has no recovery path of any kind, so the freeze is permanent.
 *
 * NF-2. The contract's accounted ingress surface is exactly `deposit()` and `depositFor()`, both
 * of which credited a balance while paused (`createVault` is not payable and books zero).
 *
 * WHAT THIS SUITE PROVES, AND WHAT IT DOES NOT
 * --------------------------------------------
 * On the production contract: the owner can never become zero, a rejected renunciation moves no
 * ownership state (a pending two-step transfer included), the hazard sequence stays escapable,
 * deposits are refused while paused and credit once unpaused, and the signer/quorum rules give
 * the same answers as the frozen pre-fix baseline across a table of honest and hostile cases.
 *
 * On the frozen baseline (the 40c7c063 bytecode in test/fixtures/multisig): the permanent freeze
 * is exercised on real state against every state-changing function in the ABI, and deposits book
 * while paused. That keeps both defects executable after the fix.
 *
 * It does NOT claim a paused MultiSig receives no ETH: forced ETH reaches an address without any
 * function call and is pinned below as still arriving uncredited. It adds no principal, no
 * substitute admin and no recovery path; `pause()` keeps its owner and its unbounded duration.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";

import { expect } from "chai";
import { Contract, ContractFactory, type BaseContract, type Fragment, type Interface, type ParamType } from "ethers";

import { ethers, networkHelpers } from "./helpers/connection";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import type { MockMLDSAVerifier, WalletWallMultiSigVault } from "../typechain-types";

const ZERO = "0x0000000000000000000000000000000000000000";
const FIXTURE_PATH = "test/fixtures/multisig/WalletWallMultiSigVault.40c7c063.json";

interface FrozenFixture {
  sourceCommit: string;
  creationBytecodeKeccak256: string;
  runtimeBytes: number;
  abi: unknown[];
  bytecode: string;
}

const WITHDRAWAL_TYPES = {
  MultiSigWithdrawal: [
    { name: "vaultOwner", type: "address" },
    { name: "recipient", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

/** A structurally valid signature for MockMLDSAVerifier: 3,309 bytes with a non-zero prefix. */
const pqSignature = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
/** A signature MockMLDSAVerifier refuses: the right length, an all-zero prefix. */
const refusedPqSignature = () => ethers.hexlify(new Uint8Array(3309));

/** Send a call and report only whether it failed, never how (the property is about state). */
async function reverts(send: () => Promise<unknown>): Promise<boolean> {
  try {
    const result = await send();
    if (result && typeof (result as { wait?: unknown }).wait === "function") {
      await (result as { wait: () => Promise<unknown> }).wait();
    }
    return false;
  } catch {
    return true;
  }
}

/**
 * The custom error a call reverts with, decoded from the raw revert data against the contract's
 * own interface, or "ok" when the call would succeed. Hardhat's provider raises its own error type
 * for a reverted eth_call, carrying the revert bytes in `data` rather than an ethers `revert` field,
 * so reading only `revert` would label every refusal "unknown" and make any comparison vacuous.
 */
async function outcome(call: () => Promise<unknown>, iface: Interface): Promise<string> {
  try {
    await call();
    return "ok";
  } catch (error) {
    const e = error as { data?: unknown; revert?: { name?: string } };
    if (typeof e.data === "string" && e.data.startsWith("0x")) {
      const parsed = iface.parseError(e.data);
      if (parsed) return parsed.name;
    }
    return e.revert?.name ?? "undecoded";
  }
}

describe("WalletWallMultiSigVault: pause and ownership hardening (NF-1, NF-2)", function () {
  let admin: HardhatEthersSigner;
  let tenant: HardhatEthersSigner;
  let signerA: HardhatEthersSigner;
  let signerB: HardhatEthersSigner;
  let signerC: HardhatEthersSigner;
  let successor: HardhatEthersSigner;
  let stranger: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;

  let verifier: MockMLDSAVerifier;
  let multiSig: WalletWallMultiSigVault;

  const PQ_KEYS = [0, 1, 2].map(() => ethers.hexlify(ethers.randomBytes(1952)));
  const fixture = JSON.parse(readFileSync(resolve(FIXTURE_PATH), "utf8")) as FrozenFixture;

  /** The three ECDSA signers in the ascending address order `withdraw` requires. */
  const ordered = (signers: HardhatEthersSigner[]) =>
    [...signers].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));

  /** A tenant vault: 2-of-3 ECDSA and 2-of-3 PQ, funded while unpaused. */
  async function openVault(target: BaseContract, funding = ethers.parseEther("1")) {
    const vault = target as unknown as WalletWallMultiSigVault;
    const signers = ordered([signerA, signerB, signerC]).map((s) => s.address);
    await vault.connect(tenant).createVault(signers, 2, PQ_KEYS, 2);
    await vault.connect(tenant).deposit({ value: funding });
  }

  async function withdrawalFor(target: BaseContract, amount: bigint, signers: HardhatEthersSigner[]) {
    const vault = target as unknown as WalletWallMultiSigVault;
    const request = {
      vaultOwner: tenant.address,
      recipient: recipient.address,
      amount,
      nonce: (await vault.getVault(tenant.address)).nonce,
      deadline: BigInt(await networkHelpers.time.latest()) + 3600n,
    };
    const domain = {
      name: "WalletWallMultiSigVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
    };
    const ecdsa = await Promise.all(signers.map((s) => s.signTypedData(domain, WITHDRAWAL_TYPES, request)));
    return { request, ecdsa };
  }

  /** The frozen pre-fix contract, deployed from its 40c7c063 bytecode. */
  async function deployFrozenBaseline(): Promise<Contract> {
    const factory = new ContractFactory(fixture.abi as Fragment[], fixture.bytecode, admin);
    const deployed = await factory.deploy(await verifier.getAddress());
    await deployed.waitForDeployment();
    return deployed as unknown as Contract;
  }

  beforeEach(async function () {
    [admin, tenant, signerA, signerB, signerC, successor, stranger, recipient] = await ethers.getSigners();
    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    multiSig = await (
      await ethers.getContractFactory("WalletWallMultiSigVault", admin)
    ).deploy(await verifier.getAddress());
  });

  // ---------------------------------------------------------------------------------------------
  // NF-1 on the production contract.
  // ---------------------------------------------------------------------------------------------

  describe("NF-1: the renunciation transition is unreachable", function () {
    // The state invariant, deliberately free of any revert matcher: it does not care how the call
    // fails, only that the owner slot cannot reach address(0).
    it("the owner can never become the zero address", async function () {
      const before = await multiSig.owner();
      await reverts(() => multiSig.connect(admin).renounceOwnership());
      expect(await multiSig.owner(), "renounceOwnership zeroed the owner").to.equal(before);
    });

    it("renounceOwnership reverts OwnershipRenunciationDisabled for the owner, and ownership is unchanged", async function () {
      await expect(multiSig.connect(admin).renounceOwnership()).to.be.revertedWithCustomError(
        multiSig,
        "OwnershipRenunciationDisabled",
      );
      expect(await multiSig.owner()).to.equal(admin.address);
      expect(await multiSig.pendingOwner()).to.equal(ZERO);
    });

    it("a non-owner cannot use renounceOwnership to move any ownership state", async function () {
      await multiSig.connect(admin).transferOwnership(successor.address);

      expect(await reverts(() => multiSig.connect(stranger).renounceOwnership())).to.equal(true);
      expect(await multiSig.owner()).to.equal(admin.address);
      expect(await multiSig.pendingOwner()).to.equal(successor.address);
    });

    it("a pending two-step transfer survives a rejected renunciation and still completes", async function () {
      await multiSig.connect(admin).transferOwnership(successor.address);
      await reverts(() => multiSig.connect(admin).renounceOwnership());

      expect(await multiSig.pendingOwner(), "a renunciation must not clear the pending owner").to.equal(
        successor.address,
      );
      await multiSig.connect(successor).acceptOwnership();
      expect(await multiSig.owner()).to.equal(successor.address);
    });

    it("the hazard sequence stays escapable: pause, rejected renunciation, unpause, and the withdrawal pays", async function () {
      await openVault(multiSig);
      const amount = ethers.parseEther("0.25");
      const { request, ecdsa } = await withdrawalFor(multiSig, amount, ordered([signerA, signerC]));
      const pq = [pqSignature(), pqSignature()];

      await multiSig.connect(admin).pause();
      await expect(multiSig.withdraw(request, ecdsa, pq, [0, 2])).to.be.revertedWithCustomError(
        multiSig,
        "EnforcedPause",
      );

      await reverts(() => multiSig.connect(admin).renounceOwnership());
      expect(await multiSig.owner(), "the owner survives, so the pause is still suspensive").to.equal(admin.address);

      await multiSig.connect(admin).unpause();
      await expect(multiSig.withdraw(request, ecdsa, pq, [0, 2]))
        .to.emit(multiSig, "Withdrawn")
        .withArgs(tenant.address, recipient.address, amount, 0n);
    });
  });

  // ---------------------------------------------------------------------------------------------
  // NF-2 on the production contract.
  // ---------------------------------------------------------------------------------------------

  describe("NF-2: accounted ingress is refused while paused", function () {
    beforeEach(async function () {
      await multiSig.connect(tenant).createVault(
        ordered([signerA, signerB, signerC]).map((s) => s.address),
        2,
        PQ_KEYS,
        2,
      );
    });

    it("deposit(): refused while paused with nothing booked, and credits again once unpaused", async function () {
      const at = await multiSig.getAddress();
      await multiSig.connect(admin).pause();

      await expect(multiSig.connect(tenant).deposit({ value: 1_000n })).to.be.revertedWithCustomError(
        multiSig,
        "EnforcedPause",
      );
      expect((await multiSig.getVault(tenant.address)).balance, "a paused MultiSig booked a deposit").to.equal(0n);
      expect(await ethers.provider.getBalance(at)).to.equal(0n);

      await multiSig.connect(admin).unpause();
      await expect(multiSig.connect(tenant).deposit({ value: 1_000n }))
        .to.emit(multiSig, "Deposited")
        .withArgs(tenant.address, tenant.address, 1_000n);
      expect((await multiSig.getVault(tenant.address)).balance).to.equal(1_000n);
    });

    it("depositFor(): a third-party funder is refused while paused, and once unpaused credits the named vault, not the funder", async function () {
      await multiSig.connect(admin).pause();

      await expect(
        multiSig.connect(stranger).depositFor(tenant.address, { value: 2_000n }),
      ).to.be.revertedWithCustomError(multiSig, "EnforcedPause");
      expect((await multiSig.getVault(tenant.address)).balance).to.equal(0n);

      await multiSig.connect(admin).unpause();
      await expect(multiSig.connect(stranger).depositFor(tenant.address, { value: 2_000n }))
        .to.emit(multiSig, "Deposited")
        .withArgs(tenant.address, stranger.address, 2_000n);
      expect((await multiSig.getVault(tenant.address)).balance).to.equal(2_000n);
      expect((await multiSig.getVault(stranger.address)).exists).to.equal(false);
    });

    it("no other path carries value: createVault is not payable and plain transfers are refused, paused or not", async function () {
      const at = await multiSig.getAddress();
      const createData = multiSig.interface.encodeFunctionData("createVault", [[stranger.address], 1, [PQ_KEYS[0]], 1]);

      for (const paused of [false, true]) {
        if (paused) await multiSig.connect(admin).pause();
        // Explicit gasLimit so each attempt is really mined rather than refused by estimateGas.
        const sends = [
          () => stranger.sendTransaction({ to: at, value: 1n, gasLimit: 500_000n }),
          () => stranger.sendTransaction({ to: at, data: createData, value: 1n, gasLimit: 500_000n }),
        ];
        for (const send of sends) {
          expect(await reverts(async () => (await send()).wait()), `value must not enter (paused=${paused})`).to.equal(
            true,
          );
        }
      }
      expect(await ethers.provider.getBalance(at)).to.equal(0n);
    });

    it("withdrawal pause behaviour is unchanged: refused while paused, paid once unpaused", async function () {
      await multiSig.connect(tenant).deposit({ value: ethers.parseEther("1") });
      const amount = ethers.parseEther("0.5");
      const { request, ecdsa } = await withdrawalFor(multiSig, amount, ordered([signerA, signerB]));
      const pq = [pqSignature(), pqSignature()];

      await multiSig.connect(admin).pause();
      await expect(multiSig.withdraw(request, ecdsa, pq, [0, 1])).to.be.revertedWithCustomError(
        multiSig,
        "EnforcedPause",
      );
      await multiSig.connect(admin).unpause();
      await expect(multiSig.withdraw(request, ecdsa, pq, [0, 1])).to.emit(multiSig, "Withdrawn");
      expect((await multiSig.getVault(tenant.address)).balance).to.equal(ethers.parseEther("0.5"));
    });

    it("forced ETH still reaches a paused MultiSig and is never credited: no modifier can refuse it", async function () {
      const at = await multiSig.getAddress();
      await multiSig.connect(admin).pause();

      const ForceSend = await ethers.getContractFactory("ForceSend", stranger);
      await (await ForceSend.deploy(at, { value: 5_000n })).waitForDeployment();

      expect(await ethers.provider.getBalance(at), "forced ETH arrives regardless of pause").to.equal(5_000n);
      expect((await multiSig.getVault(tenant.address)).balance, "forced ETH is never booked").to.equal(0n);
    });
  });

  // ---------------------------------------------------------------------------------------------
  // Signer/quorum authorization: the same answers as the frozen baseline.
  // ---------------------------------------------------------------------------------------------

  describe("quorum authorization is unchanged (production vs the frozen 40c7c063 baseline)", function () {
    it("every honest and hostile case gets the identical answer on both contracts", async function () {
      const frozen = await deployFrozenBaseline();
      const answers: Record<string, string[]> = {};

      for (const [label, target] of [
        ["production", multiSig],
        ["frozen baseline", frozen],
      ] as const) {
        await openVault(target);
        const vault = target as unknown as WalletWallMultiSigVault;
        const amount = ethers.parseEther("0.1");
        const two = await withdrawalFor(target, amount, ordered([signerA, signerB]));
        const [low, high] = ordered([signerA, signerB]);
        const outsider = await withdrawalFor(target, amount, ordered([signerA, stranger]));
        const one = await withdrawalFor(target, amount, [signerA]);
        const dup = await withdrawalFor(target, amount, [signerA, signerA]);
        const descending = await withdrawalFor(target, amount, [high, low]);
        const pq = () => [pqSignature(), pqSignature()];

        const cases: [string, () => Promise<unknown>][] = [
          [
            "one ECDSA signature below threshold",
            () => vault.withdraw.staticCall(one.request, one.ecdsa, pq(), [0, 1]),
          ],
          ["a repeated ECDSA signer", () => vault.withdraw.staticCall(dup.request, dup.ecdsa, pq(), [0, 1])],
          [
            "ECDSA signers out of order",
            () => vault.withdraw.staticCall(descending.request, descending.ecdsa, pq(), [0, 1]),
          ],
          [
            "an ECDSA signer outside the set",
            () => vault.withdraw.staticCall(outsider.request, outsider.ecdsa, pq(), [0, 1]),
          ],
          [
            "one PQ signature below threshold",
            () => vault.withdraw.staticCall(two.request, two.ecdsa, [pqSignature()], [0]),
          ],
          ["a repeated PQ key index", () => vault.withdraw.staticCall(two.request, two.ecdsa, pq(), [1, 1])],
          ["PQ key indices out of order", () => vault.withdraw.staticCall(two.request, two.ecdsa, pq(), [2, 0])],
          ["a PQ key index out of range", () => vault.withdraw.staticCall(two.request, two.ecdsa, pq(), [0, 3])],
          [
            "a PQ signature the verifier refuses",
            () => vault.withdraw.staticCall(two.request, two.ecdsa, [pqSignature(), refusedPqSignature()], [0, 1]),
          ],
          [
            "PQ signatures and indices of different lengths",
            () => vault.withdraw.staticCall(two.request, two.ecdsa, pq(), [0]),
          ],
          [
            "an honest 2-of-3 ECDSA and 2-of-3 PQ withdrawal",
            () => vault.withdraw.staticCall(two.request, two.ecdsa, pq(), [0, 2]),
          ],
        ];
        answers[label] = [];
        for (const [name, call] of cases) answers[label].push(`${name}: ${await outcome(call, vault.interface)}`);

        // The honest case really pays, on both contracts.
        await expect(vault.withdraw(two.request, two.ecdsa, pq(), [0, 2])).to.emit(vault, "Withdrawn");
      }

      expect(answers["production"], "production must answer exactly as the pre-fix contract did").to.deep.equal(
        answers["frozen baseline"],
      );
      // Equality alone could hide a defect both contracts share, so the answers are also pinned to a
      // table derived by hand from the contract's rules (withdraw's count checks, then
      // _verifySignatures' strictly-ascending signer and index rules and the verifier's verdict).
      expect(answers["production"]).to.deep.equal([
        "one ECDSA signature below threshold: InsufficientSignatures",
        "a repeated ECDSA signer: InvalidSignature",
        "ECDSA signers out of order: InvalidSignature",
        "an ECDSA signer outside the set: InvalidSignature",
        "one PQ signature below threshold: InsufficientSignatures",
        "a repeated PQ key index: InvalidSignature",
        "PQ key indices out of order: InvalidSignature",
        "a PQ key index out of range: InvalidSignature",
        "a PQ signature the verifier refuses: InvalidSignature",
        "PQ signatures and indices of different lengths: InvalidSignature",
        "an honest 2-of-3 ECDSA and 2-of-3 PQ withdrawal: ok",
      ]);
    });
  });

  // ---------------------------------------------------------------------------------------------
  // Structural assurance.
  // ---------------------------------------------------------------------------------------------

  describe("structural assurance", function () {
    it("the compiled renounceOwnership is the pure override, not the inherited nonpayable one", function () {
      const artifact = JSON.parse(
        readFileSync(resolve("artifacts/contracts/WalletWallMultiSigVault.sol/WalletWallMultiSigVault.json"), "utf8"),
      ) as { abi: { type: string; name?: string; stateMutability?: string }[] };
      const fn = artifact.abi.find((e) => e.type === "function" && e.name === "renounceOwnership");
      expect(fn?.stateMutability, "'nonpayable' means the inherited Ownable implementation is back").to.equal("pure");
    });

    // NF-1 survived #180 because that lane enumerated its production contracts by hand. This check
    // enumerates them from the compiled artifacts instead: any production contract that is both
    // Ownable (exposes renounceOwnership) and Pausable (exposes paused/pause/unpause) can strand a
    // pause, so it must carry the pure override. Ownable-only contracts are out of scope on purpose:
    // with no pause to strand, renouncing them is not this hazard.
    it("every Ownable and Pausable production contract disables renunciation, found from the artifacts", function () {
      const root = resolve("artifacts/contracts");
      const files = (readdirSync(root, { recursive: true }) as string[])
        .map((f) => f.split("\\").join("/"))
        .filter((f) => f.endsWith(".json") && !f.endsWith(".dbg.json") && !f.startsWith("mocks/"));

      const found: Record<string, string> = {};
      for (const file of files) {
        const artifact = JSON.parse(readFileSync(join(root, file), "utf8")) as {
          contractName?: string;
          abi?: { type: string; name?: string; stateMutability?: string }[];
        };
        if (!Array.isArray(artifact.abi)) continue;
        const fn = (name: string) => artifact.abi?.find((e) => e.type === "function" && e.name === name);
        if (fn("renounceOwnership") && fn("paused") && fn("pause") && fn("unpause")) {
          found[artifact.contractName ?? file] = fn("renounceOwnership")?.stateMutability ?? "missing";
        }
      }

      // Not vacuous: the three known pausable production contracts must be discovered.
      expect(Object.keys(found)).to.include.members([
        "WalletWallVault",
        "StablecoinVaultSimulator",
        "WalletWallMultiSigVault",
      ]);
      for (const [name, mutability] of Object.entries(found)) {
        expect(mutability, `${name} can strand a pause through an inherited renounceOwnership`).to.equal("pure");
      }
    });
  });

  // ---------------------------------------------------------------------------------------------
  // The frozen 40c7c063 baseline: both defects, exercised on real state.
  // ---------------------------------------------------------------------------------------------

  describe("frozen baseline (40c7c063): the hazards were real", function () {
    it("the fixture is the recorded 40c7c063 build", function () {
      expect(fixture.sourceCommit).to.equal("40c7c063a6049f3c26cf40e9ac26c906f772db3f");
      expect(ethers.keccak256(fixture.bytecode)).to.equal(fixture.creationBytecodeKeccak256);
    });

    it("pause plus the inherited renounceOwnership froze withdrawal PERMANENTLY, across every state-changing function", async function () {
      const frozen = await deployFrozenBaseline();
      await openVault(frozen);
      const vault = frozen as unknown as WalletWallMultiSigVault;
      const { request, ecdsa } = await withdrawalFor(frozen, ethers.parseEther("0.5"), ordered([signerA, signerB]));
      const pq = [pqSignature(), pqSignature()];

      // A pending two-step transfer, so the would-be escape hatch exists before the renunciation.
      await (await frozen.getFunction("transferOwnership").send(successor.address)).wait();
      await (await frozen.getFunction("pause").send()).wait();

      // The renunciation SUCCEEDS on the pre-fix contract.
      await (await frozen.getFunction("renounceOwnership").send()).wait();
      expect(await vault.owner()).to.equal(ZERO);
      expect(await vault.pendingOwner(), "renunciation also cleared the pending successor").to.equal(ZERO);

      // Every state-changing function in the ABI, from every principal, with value where payable.
      const probers = [admin, successor, tenant, signerA, stranger];
      const defaults = (param: ParamType, caller: string): unknown => {
        if (param.baseType === "array") return [];
        if (param.baseType === "tuple") return (param.components ?? []).map((c) => defaults(c, caller));
        if (param.baseType === "address") return caller;
        if (param.baseType.startsWith("uint") || param.baseType.startsWith("int")) return 1n;
        if (param.baseType === "bool") return false;
        if (param.baseType === "bytes32") return ethers.ZeroHash;
        return "0x";
      };
      let attempts = 0;
      frozen.interface.forEachFunction((fragment) => {
        if (fragment.stateMutability === "view" || fragment.stateMutability === "pure") return;
        attempts++;
      });
      expect(attempts, "the probe must cover the state-changing surface").to.be.greaterThan(6);

      for (const who of probers) {
        const functions: { name: string; data: string; payable: boolean }[] = [];
        frozen.interface.forEachFunction((fragment) => {
          if (fragment.stateMutability === "view" || fragment.stateMutability === "pure") return;
          const args = fragment.inputs.map((p) => defaults(p, who.address));
          functions.push({
            name: fragment.name,
            data: frozen.interface.encodeFunctionData(fragment, args),
            payable: fragment.payable,
          });
        });
        for (const fn of functions) {
          await reverts(async () =>
            (
              await who.sendTransaction({
                to: await frozen.getAddress(),
                data: fn.data,
                value: fn.payable ? 1n : 0n,
                gasLimit: 3_000_000n,
              })
            ).wait(),
          );
        }
      }

      // Nothing restored an owner, a successor or the pause, and the funds cannot leave.
      expect(await vault.paused()).to.equal(true);
      expect(await vault.owner()).to.equal(ZERO);
      expect(await vault.pendingOwner()).to.equal(ZERO);
      for (const who of [admin, successor, stranger]) {
        await expect(vault.connect(who).unpause()).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");
      }
      await expect(vault.connect(successor).acceptOwnership()).to.be.revertedWithCustomError(
        vault,
        "OwnableUnauthorizedAccount",
      );
      await expect(vault.withdraw(request, ecdsa, pq, [0, 1])).to.be.revertedWithCustomError(vault, "EnforcedPause");
      expect((await vault.getVault(tenant.address)).balance >= ethers.parseEther("1")).to.equal(true);
    });

    it("deposit and depositFor booked value while paused", async function () {
      const frozen = await deployFrozenBaseline();
      await openVault(frozen, 1n);
      const vault = frozen as unknown as WalletWallMultiSigVault;
      await (await frozen.getFunction("pause").send()).wait();

      await (await vault.connect(tenant).deposit({ value: 10n })).wait();
      await (await vault.connect(stranger).depositFor(tenant.address, { value: 20n })).wait();
      expect((await vault.getVault(tenant.address)).balance).to.equal(31n);
    });
  });
});
