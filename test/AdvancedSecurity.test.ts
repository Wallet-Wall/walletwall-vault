import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, MockMLDSAVerifier, WalletWallMultiSigVault } from "../typechain-types";
import { networkHelpers } from "./helpers/connection";

describe("Advanced Security (Phase 2)", function () {
  let vault: WalletWallVault;
  let multiSigVault: WalletWallMultiSigVault;
  let verifier: MockMLDSAVerifier;
  let owner: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let guardian3: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let newSigner: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const NEW_PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const ROTATION_TYPES = {
    RotateCredentials: [
      { name: "vaultOwner", type: "address" },
      { name: "newEcdsaSigner", type: "address" },
      { name: "newPQPublicKey", type: "bytes" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  beforeEach(async function () {
    [owner, guardian1, guardian2, guardian3, other, newSigner] = await ethers.getSigners();

    const MockVerifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await MockVerifier.deploy();

    const Vault = await ethers.getContractFactory("WalletWallVault");
    vault = await Vault.deploy(await verifier.getAddress());

    const MultiSigVault = await ethers.getContractFactory("WalletWallMultiSigVault");
    multiSigVault = await MultiSigVault.deploy(await verifier.getAddress());

    await vault.createVault(owner.address, PQ_KEY, 2); // Hybrid
  });

  // Builds the RotationAuth tuple. The current signer is the vault's current ECDSA signer
  // (owner). When `newEcdsaSigner` is a signer object it provides the new-key ECDSA
  // proof-of-possession; a plain address (e.g. the zero address) leaves it unsigned, for
  // negative cases that revert before the proof check. PQ proofs are mock-shaped blobs.
  async function signRotation(newEcdsaSigner: HardhatEthersSigner | string, newPQPublicKey: string) {
    const deadline = (await networkHelpers.time.latest()) + 3600;
    const domain = {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
    };
    const newAddr = typeof newEcdsaSigner === "string" ? newEcdsaSigner : newEcdsaSigner.address;
    const request = {
      vaultOwner: owner.address,
      newEcdsaSigner: newAddr,
      newPQPublicKey,
      nonce: Number(await vault.nonces(owner.address)),
      deadline,
    };
    const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    const auth = {
      currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, request),
      currentPqSignature: blob(),
      newEcdsaSignature:
        typeof newEcdsaSigner === "string" ? "0x" : await newEcdsaSigner.signTypedData(domain, ROTATION_TYPES, request),
      newPqSignature: blob(),
    };
    return { deadline, auth };
  }

  describe("Guardian Recovery", function () {
    it("Should allow setting guardians", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      expect(await vault.vaultGuardians(owner.address, 0)).to.equal(guardian1.address);
    });

    it("Should initiate recovery (only by a guardian)", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);

      // Should fail if initiated by non-guardian
      await expect(
        vault.connect(other).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "NotAGuardian");

      // Should succeed if initiated by guardian
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);

      const request = await vault.recoveryRequests(owner.address);
      expect(request.newEcdsaSigner).to.equal(newSigner.address);
      expect(request.exists).to.be.true;
    });

    it("Should allow guardians to support recovery", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);

      await vault.connect(guardian1).supportRecovery(owner.address);
      let request = await vault.recoveryRequests(owner.address);
      expect(request.supportCount).to.equal(1);

      await vault.connect(guardian2).supportRecovery(owner.address);
      request = await vault.recoveryRequests(owner.address);
      expect(request.supportCount).to.equal(2);
    });

    it("Should execute recovery after delay and sufficient supports", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);

      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);

      await networkHelpers.time.increase(7 * 24 * 60 * 60); // 7 days

      await vault.executeRecovery(owner.address);

      const vaultInfo = await vault.getVault(owner.address);
      expect(vaultInfo.ecdsaSigner).to.equal(newSigner.address);
      expect(vaultInfo.pqPublicKey).to.equal(NEW_PQ_KEY);
    });

    it("Should allow owner to cancel recovery", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.cancelRecovery();

      const request = await vault.recoveryRequests(owner.address);
      expect(request.exists).to.be.false;
    });
  });

  describe("Guardian Set Validation", function () {
    it("rejects an empty guardian set", async function () {
      await expect(vault.setGuardians([])).to.be.revertedWithCustomError(vault, "InvalidGuardianSet");
    });

    it("rejects a guardian set above MAX_GUARDIANS", async function () {
      const max = Number(await vault.MAX_GUARDIANS());
      const tooMany = Array.from({ length: max + 1 }, () => ethers.Wallet.createRandom().address);
      await expect(vault.setGuardians(tooMany))
        .to.be.revertedWithCustomError(vault, "TooManyGuardians")
        .withArgs(max + 1, max);
    });

    it("accepts a guardian set exactly at MAX_GUARDIANS", async function () {
      const max = Number(await vault.MAX_GUARDIANS());
      expect(max).to.equal(32);
      const exact = Array.from({ length: max }, () => ethers.Wallet.createRandom().address);
      await expect(vault.setGuardians(exact)).to.emit(vault, "GuardiansSet");
    });

    it("rejects the zero address as a guardian", async function () {
      await expect(vault.setGuardians([guardian1.address, ethers.ZeroAddress])).to.be.revertedWithCustomError(
        vault,
        "ZeroGuardian",
      );
    });

    it("rejects the vault owner as its own guardian", async function () {
      await expect(vault.setGuardians([guardian1.address, owner.address])).to.be.revertedWithCustomError(
        vault,
        "GuardianIsOwner",
      );
    });

    it("rejects duplicate guardians", async function () {
      // Without this guard, a duplicate would inflate the majority threshold above
      // the number of distinct supporters and permanently brick recovery.
      await expect(vault.setGuardians([guardian1.address, guardian2.address, guardian1.address]))
        .to.be.revertedWithCustomError(vault, "DuplicateGuardian")
        .withArgs(guardian1.address);
    });
  });

  describe("Recovery Griefing Protection", function () {
    it("blocks overwriting a live recovery request", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);

      // A second guardian cannot reset the accumulated supports by re-initiating.
      await expect(
        vault.connect(guardian3).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyExists");

      const request = await vault.recoveryRequests(owner.address);
      expect(request.supportCount).to.equal(2);
      expect(request.newEcdsaSigner).to.equal(newSigner.address);
    });

    it("allows replacing an under-supported request after its execution window elapses", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);

      await networkHelpers.time.increase(7 * 24 * 60 * 60); // window elapses without enough supports

      await vault.connect(guardian2).initiateRecovery(owner.address, other.address, NEW_PQ_KEY);
      const request = await vault.recoveryRequests(owner.address);
      expect(request.newEcdsaSigner).to.equal(other.address);
      expect(request.supportCount).to.equal(0);
    });

    it("rejects recovery credentials that would brick a hybrid vault", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);

      await expect(
        vault.connect(guardian1).initiateRecovery(owner.address, ethers.ZeroAddress, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "ZeroAddress");
      await expect(
        vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, "0x"),
      ).to.be.revertedWithCustomError(vault, "EmptyPQPublicKey");
    });

    // -----------------------------------------------------------------------
    // H4-A — majority-preserving replacement (docs/Guardian_Authority_Design.md §11).
    // Once a matured request's supportCount reaches the live guardian majority, no
    // guardian — including a would-be replacer — may erase it via initiateRecovery.
    // Under-supported matured requests remain replaceable: this is the liveness
    // property HIGH-4's fix must not regress.
    // -----------------------------------------------------------------------

    it("H4-1: a quorum-approved matured request cannot be erased by a lone dissenter, and remains executable", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address); // supportCount = 2 = required(3)

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(
        vault.connect(guardian3).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyApproved");

      const request = await vault.recoveryRequests(owner.address);
      expect(request.newEcdsaSigner).to.equal(newSigner.address);
      expect(request.supportCount).to.equal(2);
      expect(request.exists).to.be.true;

      await expect(vault.executeRecovery(owner.address)).to.not.revert(ethers);
      expect((await vault.getVault(owner.address)).ecdsaSigner).to.equal(newSigner.address);
    });

    it("H4-2/H4-13: an under-supported matured request remains replaceable, and stale support does not leak into the replacement", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address); // supportCount = 1 < required(2)

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await vault.connect(guardian2).initiateRecovery(owner.address, other.address, NEW_PQ_KEY);
      const replaced = await vault.recoveryRequests(owner.address);
      expect(replaced.newEcdsaSigner).to.equal(other.address);
      expect(replaced.supportCount).to.equal(0);

      // guardian1 supported R1; if that flag had leaked into R2 this would revert AlreadySupported.
      await vault.connect(guardian1).supportRecovery(owner.address);
      expect((await vault.recoveryRequests(owner.address)).supportCount).to.equal(1);
    });

    it("H4-3: exact odd threshold (n=3, required=2) — support==required forbids replacement", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(
        vault.connect(guardian3).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyApproved");
    });

    it("H4-4: below odd threshold (n=3, support=1) — replacement remains allowed after maturity", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(vault.connect(guardian3).initiateRecovery(owner.address, other.address, NEW_PQ_KEY)).to.not.revert(
        ethers,
      );
    });

    it("H4-5: exact even threshold (n=4, required=3) — support==required forbids replacement", async function () {
      const [, , , , , , guardian4] = await ethers.getSigners();
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address, guardian4.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);
      await vault.connect(guardian3).supportRecovery(owner.address); // supportCount = 3 = required(4)

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(
        vault.connect(guardian4).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyApproved");
    });

    it("H4-6: below even threshold (n=4, support=2) — replacement remains allowed after maturity", async function () {
      const [, , , , , , guardian4] = await ethers.getSigners();
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address, guardian4.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address); // supportCount = 2 < required(3)

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(vault.connect(guardian4).initiateRecovery(owner.address, other.address, NEW_PQ_KEY)).to.not.revert(
        ethers,
      );
    });

    it("H4-7: n=1 — the sole guardian's own quorum-approved request cannot be replaced, even by themselves", async function () {
      await vault.setGuardians([guardian1.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address); // supportCount = 1 = required(1)

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(
        vault.connect(guardian1).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyApproved");
    });

    it("H4-8: MAX_GUARDIANS (n=32, required=17) pins majority arithmetic and replacement at max size", async function () {
      const max = Number(await vault.MAX_GUARDIANS());
      expect(max).to.equal(32);
      const required = Math.floor(max / 2) + 1;
      expect(required).to.equal(17);

      // `required` guardians must actually sign transactions; the remainder only need
      // to occupy a guardian slot, matching the existing MAX_GUARDIANS fixture pattern.
      const signing = [];
      for (let i = 0; i < required + 1; i++) {
        const w = ethers.Wallet.createRandom().connect(ethers.provider);
        await owner.sendTransaction({ to: w.address, value: ethers.parseEther("1") });
        signing.push(w);
      }
      const silent = Array.from({ length: max - signing.length }, () => ethers.Wallet.createRandom().address);
      const guardians = [...signing.map((w) => w.address), ...silent];

      await vault.setGuardians(guardians);
      await vault.connect(signing[0]).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      for (let i = 0; i < required; i++) {
        await vault.connect(signing[i]).supportRecovery(owner.address);
      }
      expect((await vault.recoveryRequests(owner.address)).supportCount).to.equal(required);

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      // signing[required] is a plain, still-in-set guardian attempting to replace.
      await expect(
        vault.connect(signing[required]).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyApproved");
    });

    it("distinguishes revert reasons: quorum reached WHILE STILL LIVE reverts RecoveryAlreadyExists, never RecoveryAlreadyApproved", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address); // quorum reached, but NOT yet matured

      await expect(
        vault.connect(guardian3).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyExists");
    });

    it("H4-9: at exactly the maturity instant, a quorum-approved request cannot be replaced and remains executable", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);

      const executeAfter = (await vault.recoveryRequests(owner.address)).executeAfter;
      await networkHelpers.time.increaseTo(executeAfter);

      await expect(
        vault.connect(guardian3).initiateRecovery(owner.address, other.address, NEW_PQ_KEY),
      ).to.be.revertedWithCustomError(vault, "RecoveryAlreadyApproved");
      await expect(vault.executeRecovery(owner.address)).to.not.revert(ethers);
    });

    it("H4-10: a malicious majority remains capable of executing recovery — H4-A adds no minority veto", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, other.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await expect(vault.executeRecovery(owner.address)).to.not.revert(ethers);
      expect((await vault.getVault(owner.address)).ecdsaSigner).to.equal(other.address);
    });

    it("H4-11: owner cancellation still erases a quorum-approved matured request", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);

      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      await vault.cancelRecovery();
      expect((await vault.recoveryRequests(owner.address)).exists).to.be.false;
    });
  });

  describe("Guardian-Set Mutation vs Pending Recovery (L-F′, H4-12)", function () {
    it("a quorum-approved matured request is invalidated by setGuardians, and its support does not survive into a fresh request", async function () {
      await vault.setGuardians([guardian1.address, guardian2.address, guardian3.address]);
      await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, NEW_PQ_KEY);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);
      await networkHelpers.time.increase(7 * 24 * 60 * 60);

      // A recovery authorized under one guardian constituency must not survive into a
      // different one — even though it already reached the OLD constituency's majority.
      await vault.setGuardians([guardian1.address, guardian2.address]);
      expect((await vault.recoveryRequests(owner.address)).exists).to.be.false;

      // A fresh recovery under the NEW constituency starts clean: no leaked support,
      // and the new 2-of-2 majority applies, not the old 2-of-3.
      await vault.connect(guardian1).initiateRecovery(owner.address, other.address, NEW_PQ_KEY);
      expect((await vault.recoveryRequests(owner.address)).supportCount).to.equal(0);
      await vault.connect(guardian1).supportRecovery(owner.address);
      await vault.connect(guardian2).supportRecovery(owner.address);
      await networkHelpers.time.increase(7 * 24 * 60 * 60);
      await expect(vault.executeRecovery(owner.address)).to.not.revert(ethers);
      expect((await vault.getVault(owner.address)).ecdsaSigner).to.equal(other.address);
    });
  });

  describe("Secure Credential Rotation", function () {
    it("Should rotate credentials with valid current and new-key proofs", async function () {
      const { deadline, auth } = await signRotation(newSigner, NEW_PQ_KEY);

      await vault.rotateCredentials(owner.address, newSigner.address, NEW_PQ_KEY, deadline, auth);

      const vaultInfo = await vault.getVault(owner.address);
      expect(vaultInfo.ecdsaSigner).to.equal(newSigner.address);
      expect(vaultInfo.pqPublicKey).to.equal(NEW_PQ_KEY);
    });

    it("rejects validly signed credentials that would brick a hybrid vault", async function () {
      const zeroSigner = await signRotation(ethers.ZeroAddress, NEW_PQ_KEY);
      await expect(
        vault.rotateCredentials(owner.address, ethers.ZeroAddress, NEW_PQ_KEY, zeroSigner.deadline, zeroSigner.auth),
      ).to.be.revertedWithCustomError(vault, "ZeroAddress");

      const emptyPQ = await signRotation(newSigner, "0x");
      await expect(
        vault.rotateCredentials(owner.address, newSigner.address, "0x", emptyPQ.deadline, emptyPQ.auth),
      ).to.be.revertedWithCustomError(vault, "EmptyPQPublicKey");
    });
  });

  describe("Multi-Signature Vault", function () {
    it("Should create a multi-sig vault", async function () {
      const ecdsaSigners = [owner.address, guardian1.address];
      const pqKeys = [PQ_KEY, NEW_PQ_KEY];

      await multiSigVault.createVault(ecdsaSigners, 2, pqKeys, 2);
      const v = await multiSigVault.getVault(owner.address);
      expect(v.exists).to.be.true;
      expect(v.ecdsaThreshold).to.equal(2);
    });

    it("Should deposit and withdraw from multi-sig vault", async function () {
      const ecdsaSigners = [owner.address, guardian1.address].sort();
      const pqKeys = [PQ_KEY, NEW_PQ_KEY];

      // Re-create vault with sorted signers for easy recovery check
      const MultiSigVault = await ethers.getContractFactory("WalletWallMultiSigVault");
      multiSigVault = await MultiSigVault.deploy(await verifier.getAddress());
      await multiSigVault.connect(owner).createVault(ecdsaSigners, 2, pqKeys, 2);

      await multiSigVault.deposit({ value: ethers.parseEther("1") });

      const nonce = 0;
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const amount = ethers.parseEther("0.5");
      const recipient = other.address;

      const domain = {
        name: "WalletWallMultiSigVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await multiSigVault.getAddress(),
      };

      const types = {
        MultiSigWithdrawal: [
          { name: "vaultOwner", type: "address" },
          { name: "recipient", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      };

      const request = {
        vaultOwner: owner.address,
        recipient: recipient,
        amount: amount,
        nonce: nonce,
        deadline: deadline,
      };

      // Sign with both ECDSA signers
      const sig1 = await owner.signTypedData(domain, types, request);
      const sig2 = await guardian1.signTypedData(domain, types, request);

      // Sort signatures based on signer address to match contract expectation
      const signers = [
        { addr: owner.address, sig: sig1 },
        { addr: guardian1.address, sig: sig2 },
      ].sort((a, b) => a.addr.localeCompare(b.addr));

      const ecdsaSignatures = signers.map((s) => s.sig);

      const pqSignature1 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const pqSignature2 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const pqSignatures = [pqSignature1, pqSignature2];
      const pqKeyIndices = [0, 1];

      await multiSigVault.withdraw(request, ecdsaSignatures, pqSignatures, pqKeyIndices);

      expect(await ethers.provider.getBalance(recipient)).to.be.at.least(amount);
    });

    it("Should support p-of-q with indices", async function () {
      const ecdsaSigners = [owner.address];
      const pqKeys = [PQ_KEY, NEW_PQ_KEY, ethers.hexlify(ethers.randomBytes(1952))]; // 3 keys

      const MultiSigVault = await ethers.getContractFactory("WalletWallMultiSigVault");
      multiSigVault = await MultiSigVault.deploy(await verifier.getAddress());
      await multiSigVault.connect(owner).createVault(ecdsaSigners, 1, pqKeys, 2); // 2 of 3 PQ

      await multiSigVault.deposit({ value: ethers.parseEther("1") });

      const deadline = (await networkHelpers.time.latest()) + 3600;
      const request = {
        vaultOwner: owner.address,
        recipient: other.address,
        amount: ethers.parseEther("0.5"),
        nonce: 0,
        deadline: deadline,
      };

      const domain = {
        name: "WalletWallMultiSigVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await multiSigVault.getAddress(),
      };

      const types = {
        MultiSigWithdrawal: [
          { name: "vaultOwner", type: "address" },
          { name: "recipient", type: "address" },
          { name: "amount", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      };

      const ecdsaSignature = await owner.signTypedData(domain, types, request);

      // Use keys 0 and 2
      const pqSignature1 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      const pqSignature2 = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await multiSigVault.withdraw(request, [ecdsaSignature], [pqSignature1, pqSignature2], [0, 2]);

      expect(await ethers.provider.getBalance(other.address)).to.be.at.least(ethers.parseEther("0.5"));
    });
  });
});
