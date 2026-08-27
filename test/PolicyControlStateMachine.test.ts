import { expect } from "chai";
import { ethers, networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, MockMLDSAVerifier, PolicyControlBridge, DailySpendLimitPolicy } from "../typechain-types";
import { WITHDRAWAL_TYPES } from "./helpers/vaultHelpers";
import { NATIVE_ASSET } from "./helpers/policySubject";

/**
 * DailySpendLimitPolicy's controller/weakening-delay state machine (design doc §3-§9),
 * the load-bearing containment layer that #172's rolling ledger alone could not provide
 * — a damage limiter becomes a containment boundary only once the credential that can
 * spend cannot also instantly remove the cap that constrains it.
 *
 * This suite exercises the state machine end-to-end through the REAL PolicyControlBridge
 * (not a mock target), because the properties that matter — epoch staleness on APPLY, the
 * pause blocking an already-mature weakening, canonical-bridge-only enrolment — are only
 * meaningful when authentication is genuinely wired through.
 *
 * DailySpendAdmissionAuthority.test.ts, PolicySubjectPropagation.test.ts, and
 * DailySpendRollingWindow.test.ts remain the authority on admission/rolling/isolation and
 * are updated only for the new constructor signature — their PASSING UNCHANGED is the
 * evidence this stage did not touch #171/#172's guarantees.
 */
describe("DailySpendLimitPolicy — policy-control state machine", function () {
  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const HYBRID = 2;
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const LIMIT = ethers.parseEther("1");
  const POLICY_CONTROL_DELAY = 2 * 24 * 60 * 60;
  const POLICY_CONTROL_GRACE = 14 * 24 * 60 * 60;

  const STRENGTHEN_TYPES = {
    StrengthenLimit: [
      { name: "consumer", type: "address" },
      { name: "owner", type: "address" },
      { name: "policy", type: "address" },
      { name: "asset", type: "address" },
      { name: "newLimit", type: "uint256" },
      { name: "epoch", type: "uint64" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const PROPOSE_WEAKENING_TYPES = {
    ProposeWeakening: [
      { name: "consumer", type: "address" },
      { name: "owner", type: "address" },
      { name: "policy", type: "address" },
      { name: "asset", type: "address" },
      { name: "newLimit", type: "uint256" },
      { name: "epoch", type: "uint64" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const APPLY_WEAKENING_TYPES = {
    ApplyWeakening: [
      { name: "consumer", type: "address" },
      { name: "owner", type: "address" },
      { name: "policy", type: "address" },
      { name: "asset", type: "address" },
      { name: "epoch", type: "uint64" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const CANCEL_WEAKENING_TYPES = {
    CancelWeakening: [
      { name: "consumer", type: "address" },
      { name: "owner", type: "address" },
      { name: "policy", type: "address" },
      { name: "asset", type: "address" },
      { name: "epoch", type: "uint64" },
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
  const SET_ADMITTER_TYPES = {
    SetAdmitter: [
      { name: "consumer", type: "address" },
      { name: "owner", type: "address" },
      { name: "policy", type: "address" },
      { name: "asset", type: "address" },
      { name: "admitter", type: "address" },
      { name: "allowed", type: "bool" },
      { name: "epoch", type: "uint64" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const PROPOSE_UNENROLL_TYPES = {
    ProposeUnenrollController: [
      { name: "consumer", type: "address" },
      { name: "owner", type: "address" },
      { name: "policy", type: "address" },
      { name: "asset", type: "address" },
      { name: "epoch", type: "uint64" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const APPLY_UNENROLL_TYPES = {
    ApplyUnenrollController: [
      { name: "consumer", type: "address" },
      { name: "owner", type: "address" },
      { name: "policy", type: "address" },
      { name: "asset", type: "address" },
      { name: "epoch", type: "uint64" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let pauser: HardhatEthersSigner;
  let guardian1: HardhatEthersSigner;
  let guardian2: HardhatEthersSigner;
  let verifier: MockMLDSAVerifier;
  let vault: WalletWallVault;
  let bridge: PolicyControlBridge;
  let policy: DailySpendLimitPolicy;
  let consumer: string;

  async function bridgeDomain() {
    return {
      name: "WalletWallPolicyControlBridge",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await bridge.getAddress(),
    };
  }

  async function nextNonce() {
    return bridge.controlNonce(consumer, owner.address);
  }
  async function currentEpoch() {
    return vault.policyControlEpoch(owner.address);
  }

  async function signAndSend(
    fn:
      | "enrollController"
      | "strengthenLimit"
      | "proposeWeakening"
      | "applyWeakening"
      | "cancelWeakening"
      | "setAdmitter"
      | "proposeUnenrollController"
      | "applyUnenrollController",
    types: Record<string, Array<{ name: string; type: string }>>,
    extra: Record<string, unknown>,
    overrides: Partial<Record<string, unknown>> = {},
  ) {
    const deadline = (overrides.deadline as number) ?? (await networkHelpers.time.latest()) + 3600;
    const nonce = (overrides.nonce as bigint) ?? (await nextNonce());
    const epoch = (overrides.epoch as bigint) ?? (await currentEpoch());
    const request = {
      consumer: (overrides.consumer as string) ?? consumer,
      owner: (overrides.owner as string) ?? owner.address,
      policy: (overrides.policy as string) ?? (await policy.getAddress()),
      asset: (overrides.asset as string) ?? NATIVE_ASSET,
      ...extra,
      epoch,
      nonce,
      deadline,
    };
    const domain = await bridgeDomain();
    const ecdsaSignature = await owner.signTypedData(domain, types, request);
    const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    return (bridge as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>)[fn](
      request,
      ecdsaSignature,
      pqSignature,
    );
  }

  async function enrol() {
    return signAndSend("enrollController", ENROLL_TYPES, { controller: await bridge.getAddress() });
  }
  async function strengthen(newLimit: bigint) {
    return signAndSend("strengthenLimit", STRENGTHEN_TYPES, { newLimit });
  }
  async function proposeWeakening(newLimit: bigint) {
    return signAndSend("proposeWeakening", PROPOSE_WEAKENING_TYPES, { newLimit });
  }
  async function applyWeakening() {
    return signAndSend("applyWeakening", APPLY_WEAKENING_TYPES, {});
  }
  async function cancelWeakening() {
    return signAndSend("cancelWeakening", CANCEL_WEAKENING_TYPES, {});
  }
  async function bridgeSetAdmitter(admitter: string, allowed: boolean) {
    return signAndSend("setAdmitter", SET_ADMITTER_TYPES, { admitter, allowed });
  }
  async function proposeUnenrol(overrides: Partial<Record<string, unknown>> = {}) {
    return signAndSend("proposeUnenrollController", PROPOSE_UNENROLL_TYPES, {}, overrides);
  }
  async function applyUnenrol(overrides: Partial<Record<string, unknown>> = {}) {
    return signAndSend("applyUnenrollController", APPLY_UNENROLL_TYPES, {}, overrides);
  }

  /** Rotates the vault's credentials to `newSigner`, bumping policyControlEpoch — the
   *  recovery-equivalent event §9.8/§9.10 reason about. Returns nothing; callers read
   *  {currentEpoch} / {nextNonce} afterward exactly as they would after a real recovery. */
  async function rotateTo(newSigner: HardhatEthersSigner) {
    const deadline = (await networkHelpers.time.latest()) + 3600;
    const domain = {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: consumer,
    };
    const ROTATION_TYPES = {
      RotateCredentials: [
        { name: "vaultOwner", type: "address" },
        { name: "newEcdsaSigner", type: "address" },
        { name: "newPQPublicKey", type: "bytes" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    };
    const newPq = ethers.hexlify(ethers.randomBytes(1952));
    const req = {
      vaultOwner: owner.address,
      newEcdsaSigner: newSigner.address,
      newPQPublicKey: newPq,
      nonce: Number(await vault.nonces(owner.address)),
      deadline,
    };
    const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    await vault.rotateCredentials(owner.address, newSigner.address, newPq, deadline, {
      currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, req),
      currentPqSignature: blob(),
      newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, req),
      newPqSignature: blob(),
    });
  }

  /** Runs a full guardian-majority recovery to `newSigner` — the OTHER epoch-bumping
   *  event, with a distinct (threshold-based, not owner-signed) authorization model
   *  from {rotateTo}. Requires guardians to already be set. */
  async function recoverTo(newSigner: HardhatEthersSigner) {
    const newPq = ethers.hexlify(ethers.randomBytes(1952));
    await vault.connect(guardian1).initiateRecovery(owner.address, newSigner.address, newPq);
    await vault.connect(guardian1).supportRecovery(owner.address);
    await vault.connect(guardian2).supportRecovery(owner.address);
    await networkHelpers.time.increase(7 * 24 * 60 * 60);
    await vault.executeRecovery(owner.address);
  }

  beforeEach(async function () {
    [admin, owner, recipient, pauser, guardian1, guardian2] = await ethers.getSigners();
    const Verifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const Bridge = await ethers.getContractFactory("PolicyControlBridge");
    bridge = await Bridge.deploy(pauser.address);
    await bridge.waitForDeployment();

    const Policy = await ethers.getContractFactory("DailySpendLimitPolicy");
    policy = await Policy.deploy(await bridge.getAddress());
    await policy.waitForDeployment();

    const Vault = await ethers.getContractFactory("WalletWallVault", admin);
    vault = await Vault.deploy(await verifier.getAddress());
    await vault.waitForDeployment();
    consumer = await vault.getAddress();

    await vault.connect(admin).proposePolicyEngine(await policy.getAddress());
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyPolicyEngine();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("50") });
    await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
    await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);
  });

  // =====================================================================
  // A — STRENGTH ORDER (Path 1)
  // =====================================================================
  describe("A — Path 1: strength order determines immediate vs delayed", function () {
    it("A1: 0 -> n is immediate strengthening (arming from unrestricted)", async function () {
      // A genuinely never-armed asset, so `limit` starts at its true zero default —
      // weakening the beforeEach's already-armed NATIVE_ASSET down to 0 would itself
      // be a DELAYED transition and never actually reach 0 for this test to arm from.
      const freshAsset = ethers.Wallet.createRandom().address;
      await policy.connect(owner).setAdmitter(consumer, freshAsset, consumer, true);
      await policy.connect(owner).setDailyLimit(consumer, freshAsset, LIMIT);
      expect(await policy.dailyLimit(consumer, owner.address, freshAsset)).to.equal(LIMIT);
    });

    it("A2: n -> smaller is immediate strengthening", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT / 2n);
    });

    it("A3: n -> larger does NOT apply immediately — it creates a pending weakening", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT * 2n);
      // Not yet applied:
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("A4: n -> 0 (disarm) does NOT apply immediately — it creates a pending weakening", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("A5: a pending weakening matures after POLICY_CONTROL_DELAY and applies via applyWeakening(consumer, asset)", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("A6: applying before maturity reverts WeakeningNotReady", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      await expect(policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET)).to.be.revertedWithCustomError(
        policy,
        "WeakeningNotReady",
      );
    });

    it("A7: applying after the grace period expires reverts WeakeningExpired", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY + POLICY_CONTROL_GRACE + 1);
      await expect(policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET)).to.be.revertedWithCustomError(
        policy,
        "WeakeningExpired",
      );
    });

    it("A8: cancelWeakening clears a pending Path-1 proposal immediately", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      await policy.connect(owner).cancelWeakening(consumer, NATIVE_ASSET);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await expect(policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET)).to.be.revertedWithCustomError(
        policy,
        "NoWeakeningPending",
      );
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("A9: only one weakening may be pending at a time", async function () {
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT * 3n),
      ).to.be.revertedWithCustomError(policy, "WeakeningAlreadyPending");
    });

    it("A10: a no-op (n -> n) is neither strengthening nor weakening — design doc §3 classifies it Rejected", async function () {
      await expect(policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT)).to.be.revertedWithCustomError(
        policy,
        "NoOpTransition",
      );
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("A11: a no-op (0 -> 0) is also rejected", async function () {
      // A never-armed asset: `limit` starts at 0, so this is a genuine 0 -> 0 attempt,
      // not a second weakening proposal colliding with an already-pending one.
      const freshAsset = ethers.Wallet.createRandom().address;
      await expect(policy.connect(owner).setDailyLimit(consumer, freshAsset, 0)).to.be.revertedWithCustomError(
        policy,
        "NoOpTransition",
      );
    });
  });

  // =====================================================================
  // B — ENROLMENT (U2): signed, current-credential, one-time, immediate
  // =====================================================================
  describe("B — controller enrolment", function () {
    it("B1: a validly-signed enrolControlller call succeeds and disables Path 1", async function () {
      await enrol();
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("B2: enrolling ANY controller other than the canonical bridge is rejected (L9)", async function () {
      const rogueBridge = recipient.address; // stands in for an arbitrary address
      await expect(
        (async () => {
          const domain = await bridgeDomain();
          const request = {
            consumer,
            owner: owner.address,
            policy: await policy.getAddress(),
            asset: NATIVE_ASSET,
            controller: rogueBridge,
            epoch: await currentEpoch(),
            nonce: await nextNonce(),
            deadline: (await networkHelpers.time.latest()) + 3600,
          };
          const ecdsaSignature = await owner.signTypedData(domain, ENROLL_TYPES, request);
          const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
          return bridge.enrollController(request, ecdsaSignature, pqSignature);
        })(),
      ).to.be.revertedWithCustomError(policy, "NotCanonicalBridge");
    });

    it("B3: a DIRECT call to bridgeEnrollController, bypassing the bridge, is rejected", async function () {
      await expect(
        policy.connect(owner).bridgeEnrollController(consumer, owner.address, NATIVE_ASSET, await bridge.getAddress()),
      ).to.be.revertedWithCustomError(policy, "NotCanonicalBridge");
    });

    it("B4: enrolment is one-time — a second attempt reverts", async function () {
      await enrol();
      await expect(enrol()).to.be.revertedWithCustomError(policy, "AlreadyEnrolled");
    });
  });

  // =====================================================================
  // C — CONTROLLER-ACTIVE: Path 1 has ZERO authority (O2)
  // =====================================================================
  describe("C — once controller-active, Path 1 is fully dead", function () {
    beforeEach(async function () {
      await enrol();
    });

    it("C1: owner-direct setDailyLimit reverts, for a STRENGTHENING value too", async function () {
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("C2: owner-direct applyWeakening reverts even for a bridge-created pending", async function () {
      await proposeWeakening(0n);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await expect(policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET)).to.be.revertedWithCustomError(
        policy,
        "ControllerPathRequired",
      );
    });

    it("C3: owner-direct cancelWeakening reverts — O2, no permanent DoS lever for a compromised owner", async function () {
      await proposeWeakening(0n);
      await expect(policy.connect(owner).cancelWeakening(consumer, NATIVE_ASSET)).to.be.revertedWithCustomError(
        policy,
        "ControllerPathRequired",
      );
    });

    it("C4: the bridge, via a fresh signed intent, CAN strengthen immediately", async function () {
      await strengthen(LIMIT / 4n);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT / 4n);
    });

    it("C4b: bridgeStrengthenLimit with a no-op value reverts NoOpTransition, same as Path 1 (§3)", async function () {
      await expect(strengthen(LIMIT)).to.be.revertedWithCustomError(policy, "NoOpTransition");
    });

    it("C5: the bridge CAN propose, and later apply, a weakening", async function () {
      await proposeWeakening(LIMIT * 2n);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await applyWeakening();
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT * 2n);
    });

    it("C6: the bridge CAN cancel a pending weakening immediately", async function () {
      await proposeWeakening(0n);
      await cancelWeakening();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await expect(applyWeakening()).to.be.revertedWithCustomError(policy, "NoWeakeningPending");
    });
  });

  // =====================================================================
  // D — EPOCH STALENESS ON APPLY (§9.8): the case an implementation that only
  //     checks the epoch at PROPOSE time gets wrong.
  // =====================================================================
  describe("D — epoch staleness closes the pre-recovery weakening attack", function () {
    beforeEach(async function () {
      await enrol();
    });

    it("D1: a proposal that matures AFTER a rotation cannot be applied — StaleControlEpoch", async function () {
      await proposeWeakening(0n); // attacker, while still holding current creds

      // Recovery-equivalent: rotate credentials (bumps the epoch).
      const newSigner = recipient;
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const domain = {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: consumer,
      };
      const ROTATION_TYPES = {
        RotateCredentials: [
          { name: "vaultOwner", type: "address" },
          { name: "newEcdsaSigner", type: "address" },
          { name: "newPQPublicKey", type: "bytes" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      };
      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      const req = {
        vaultOwner: owner.address,
        newEcdsaSigner: newSigner.address,
        newPQPublicKey: newPq,
        nonce: Number(await vault.nonces(owner.address)),
        deadline,
      };
      const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      await vault.rotateCredentials(owner.address, newSigner.address, newPq, deadline, {
        currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, req),
        currentPqSignature: blob(),
        newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, req),
        newPqSignature: blob(),
      });

      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      // The attacker's OLD-epoch pending proposal is still sitting there, matured — but
      // applying it now requires a FRESH intent (§5.5), and the OLD owner key is stale.
      const domain2 = await bridgeDomain();
      const staleRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: 0, // the epoch at propose time
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const ecdsaSignature = await owner.signTypedData(domain2, APPLY_WEAKENING_TYPES, staleRequest);
      const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await expect(bridge.applyWeakening(staleRequest, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        bridge,
        "StaleControlEpoch",
      );
      // The cap survives — the pending weakening never applied.
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("D2: the POLICY's OWN epoch check rejects a stale proposal even via a FRESH, validly-signed apply (unconditional T8)", async function () {
      // D1 proved the BRIDGE's epoch check catches a stale SIGNATURE. This isolates a
      // DIFFERENT layer: the proposal ITSELF is bound to an old epoch, and this test
      // authenticates with a completely FRESH, currently-valid signature — the kind the
      // CURRENT legitimate owner could produce. The design doc's T8 is unconditional
      // (no exception carved out for who is applying), so this must still revert.
      await proposeWeakening(0n); // boundEpoch = 0 (current epoch at propose time)

      const newSigner = recipient;
      const deadline = (await networkHelpers.time.latest()) + 3600;
      const domain = {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: consumer,
      };
      const ROTATION_TYPES = {
        RotateCredentials: [
          { name: "vaultOwner", type: "address" },
          { name: "newEcdsaSigner", type: "address" },
          { name: "newPQPublicKey", type: "bytes" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      };
      const newPq = ethers.hexlify(ethers.randomBytes(1952));
      const req = {
        vaultOwner: owner.address,
        newEcdsaSigner: newSigner.address,
        newPQPublicKey: newPq,
        nonce: Number(await vault.nonces(owner.address)),
        deadline,
      };
      const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      await vault.rotateCredentials(owner.address, newSigner.address, newPq, deadline, {
        currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, req),
        currentPqSignature: blob(),
        newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, req),
        newPqSignature: blob(),
      });

      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      // FRESH intent: signed by the NEW (current) signer, at the NEW (current) epoch —
      // the bridge's own checks pass this cleanly. Only the POLICY's separate check on
      // the STORED proposal's boundEpoch can catch it now.
      const domain2 = await bridgeDomain();
      const freshRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: await currentEpoch(), // == 1, the CURRENT epoch — genuinely fresh
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const ecdsaSignature = await newSigner.signTypedData(domain2, APPLY_WEAKENING_TYPES, freshRequest);
      const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await expect(bridge.applyWeakening(freshRequest, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        policy,
        "StaleControlEpoch",
      );
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });
  });

  // =====================================================================
  // E — ONE-WAY PAUSE BLOCKS THE APPLY HALF (§9.12 — the subtle requirement)
  // =====================================================================
  describe("E — pause blocks an already-mature weakening from being applied", function () {
    it("E1: pausing after maturity but before apply prevents the weakening from ever landing", async function () {
      await enrol();
      await proposeWeakening(0n);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      await bridge.connect(pauser).pause();

      const domain = await bridgeDomain();
      const request = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: await currentEpoch(),
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const ecdsaSignature = await owner.signTypedData(domain, APPLY_WEAKENING_TYPES, request);
      const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await expect(bridge.applyWeakening(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        bridge,
        "BridgeIsPaused",
      );
      // Untouched: the stored proposal still exists, merely unreachable.
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("E2: pause blocks fresh strengthening too", async function () {
      await enrol();
      await bridge.connect(pauser).pause();
      await expect(strengthen(LIMIT / 2n)).to.be.revertedWithCustomError(bridge, "BridgeIsPaused");
    });

    it("E3: pause does not affect check() — enforcement continues at the last configured value", async function () {
      await enrol();
      await bridge.connect(pauser).pause();

      const request = {
        vaultOwner: owner.address,
        recipient: recipient.address,
        amount: LIMIT,
        nonce: 0,
        deadline: (await networkHelpers.time.latest()) + 3600,
        vaultMode: HYBRID,
      };
      const domain = {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: consumer,
      };
      const ecdsaSig = await owner.signTypedData(domain, WITHDRAWAL_TYPES, request);
      const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      await expect(vault.withdraw(request, ecdsaSig, pqSig)).to.emit(vault, "Withdrawn");
    });
  });

  // =====================================================================
  // F — ADMITTER REPAIR STAYS IMMEDIATE, EVEN CONTROLLER-ACTIVE (L5, §9.6)
  // =====================================================================
  describe("F — admitter repair is a liveness action, not a weakening", function () {
    it("F1: adding a CONTRACT admitter via the bridge is immediate, no delay, once controller-active", async function () {
      await enrol();
      // A non-owner, non-bridge admitter must still be a contract, exactly as Path 1
      // requires — the consumer (a real deployed vault) stands in for one here.
      await bridgeSetAdmitter(consumer, true);
      expect(await policy.admitter(consumer, owner.address, NATIVE_ASSET, consumer)).to.equal(true);
    });

    it("F2: self-delegating the OWNER via the bridge is exempt from the contract-code check", async function () {
      await enrol();
      await bridgeSetAdmitter(owner.address, true);
      expect(await policy.admitter(consumer, owner.address, NATIVE_ASSET, owner.address)).to.equal(true);
    });

    it("F3: delegating an arbitrary EOA (neither owner nor a contract) is still refused", async function () {
      await enrol();
      const [, , , , eoa] = await ethers.getSigners();
      await expect(bridgeSetAdmitter(eoa.address, true)).to.be.revertedWithCustomError(policy, "AdmitterNotAContract");
    });

    it("F4 (§9.6, L5): the vault's own withdrawal path is repaired by re-admitting IT — IMMEDIATE, no delay", async function () {
      // See the §9.6 erratum in the design doc: the literal "composite whose owner
      // added an always-denying module" scenario is not executable against
      // CompositePolicyEngine's real AND/fail-closed composition. This test proves the
      // strongest truthful replacement instead — and it must exercise the REAL
      // admission-path caller, not a stand-in: DailySpendLimitPolicy.check() authorizes
      // msg.sender (see _admitter[key][msg.sender] in check()), and for a genuine vault
      // withdrawal msg.sender is address(vault) itself (WalletWallVault._policySubject
      // sets subject.consumer = address(this), and the vault is the one calling
      // policyEngine.check()) — never the EOA that merely SIGNED the request. An earlier
      // version of this test authorized `owner` and called policy.check() directly as
      // owner, which proved owner could call check() but proved nothing about whether
      // vault.withdraw() itself — the actual liveness property §9.6 promises — resumes.
      await enrol();

      // The vault (`consumer`) is already the sole admitter from the outer beforeEach.
      // Add owner as a SECOND admitter first so removing the vault doesn't trip
      // LastAdmitterWhileArmed — F2 already proves the owner is exempt from the
      // contract-code check. This second admitter is scaffolding for the removal step,
      // not itself the repair: owner being an admitter is irrelevant to the vault's own
      // call path, which is exactly what this test goes on to demonstrate.
      await bridgeSetAdmitter(owner.address, true);
      await bridgeSetAdmitter(consumer, false);
      expect(await policy.admitter(consumer, owner.address, NATIVE_ASSET, consumer)).to.equal(false);

      const request = {
        vaultOwner: owner.address,
        recipient: recipient.address,
        amount: 1n,
        nonce: 0,
        deadline: (await networkHelpers.time.latest()) + 3600,
        vaultMode: HYBRID,
      };
      const withdrawalDomain = {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: consumer,
      };
      const ecdsaSig = await owner.signTypedData(withdrawalDomain, WITHDRAWAL_TYPES, request);
      const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      // The engine-path caller (the vault itself) is unauthorized: a real, validly
      // signed withdrawal reverts. The revert unwinds the whole transaction, so
      // vault.nonce is never consumed and the SAME signed request can be retried
      // verbatim once the caller is reauthorized.
      await expect(vault.withdraw(request, ecdsaSig, pqSig)).to.be.revertedWithCustomError(
        policy,
        "UnauthorizedAdmitter",
      );

      // Liveness repair: through the bridge, immediately re-admit the vault — the
      // ACTUAL admission-path caller — with no delay of any kind.
      await bridgeSetAdmitter(consumer, true);
      expect(await policy.admitter(consumer, owner.address, NATIVE_ASSET, consumer)).to.equal(true);

      // Retrying the identical signed request now succeeds, at the same timestamp,
      // proving this is a liveness repair and not a weakening.
      await expect(vault.withdraw(request, ecdsaSig, pqSig)).to.emit(vault, "Withdrawn");
    });
  });

  // =====================================================================
  // G — CONTROLLER UNENROLMENT (T15, §6.2): a WEAKENING — delayed, expiring,
  //     epoch-bound — that RE-ENABLES Path 1. controllerInitialized stays sticky
  //     forever regardless, so this policy instance can never be re-bootstrapped.
  // =====================================================================
  describe("G — controller unenrolment (T15) re-enables Path 1 but never re-arms enrolment", function () {
    beforeEach(async function () {
      await enrol();
    });

    it("G1: proposing unenrolment does not itself disable the controller — apply is still required", async function () {
      await proposeUnenrol();
      // Not yet applied: Path 1 still dead, exactly as a pending limit weakening
      // leaves the OLD limit enforced until applied.
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("G2: applying before maturity reverts WeakeningNotReady", async function () {
      await proposeUnenrol();
      await expect(applyUnenrol()).to.be.revertedWithCustomError(policy, "WeakeningNotReady");
    });

    it("G3: applying after the grace period expires reverts WeakeningExpired", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY + POLICY_CONTROL_GRACE + 1);
      await expect(applyUnenrol()).to.be.revertedWithCustomError(policy, "WeakeningExpired");
    });

    it("G4: a matured, epoch-fresh unenrolment clears the controller and RE-ENABLES Path 1 (§6.2)", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await applyUnenrol();

      // Path 1 lives again — a strengthening move now succeeds owner-direct.
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT / 2n);
    });

    it("G4b: applyWeakening (Path 1) is also usable again after unenrolment, not just setDailyLimit", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await applyUnenrol();

      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT * 2n); // n -> larger, weakening
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT * 2n);
    });

    it("G4c: cancelWeakening (Path 1) is also usable again after unenrolment", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await applyUnenrol();

      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT * 2n);
      await policy.connect(owner).cancelWeakening(consumer, NATIVE_ASSET);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await expect(policy.connect(owner).applyWeakening(consumer, NATIVE_ASSET)).to.be.revertedWithCustomError(
        policy,
        "NoWeakeningPending",
      );
    });

    it("G4d: setAdmitter (Path 1) is also usable again after unenrolment", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await applyUnenrol();

      await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, owner.address, true);
      expect(await policy.admitter(consumer, owner.address, NATIVE_ASSET, owner.address)).to.equal(true);
    });

    it("G5: after unenrolment, re-enrolling reverts AlreadyEnrolled — controllerInitialized never resets (O3)", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await applyUnenrol();

      await expect(enrol()).to.be.revertedWithCustomError(policy, "AlreadyEnrolled");
    });

    it("G6: cancelling a pending unenrolment keeps the controller active — Path 1 stays dead", async function () {
      await proposeUnenrol();
      await cancelWeakening();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      await expect(applyUnenrol()).to.be.revertedWithCustomError(policy, "NoWeakeningPending");
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("G7a: a pending LIMIT weakening blocks proposing an unenrolment (shared pending slot)", async function () {
      await proposeWeakening(LIMIT * 2n);
      await expect(proposeUnenrol()).to.be.revertedWithCustomError(policy, "WeakeningAlreadyPending");
    });

    it("G7b: a pending UNENROLMENT blocks proposing a limit weakening (shared pending slot)", async function () {
      await proposeUnenrol();
      await expect(proposeWeakening(LIMIT * 2n)).to.be.revertedWithCustomError(policy, "WeakeningAlreadyPending");
    });

    it("G8: bridgeApplyWeakening cannot complete a pending UNENROLMENT (WrongTransitionKind)", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await expect(applyWeakening()).to.be.revertedWithCustomError(policy, "WrongTransitionKind");
      // Untouched — the controller is still active, proposal still pending.
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("G9: bridgeApplyUnenrollController cannot complete a pending LIMIT weakening (WrongTransitionKind)", async function () {
      await proposeWeakening(LIMIT * 2n);
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await expect(applyUnenrol()).to.be.revertedWithCustomError(policy, "WrongTransitionKind");
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("G10: recovery before maturity stales the BRIDGE signature — mirrors §9.8/D1 for T15 (§9.10)", async function () {
      await proposeUnenrol(); // attacker/owner, while still holding current creds, epoch 0

      const newSigner = recipient;
      await rotateTo(newSigner); // recovery-equivalent: bumps the epoch to 1

      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      // The OLD stale signature (epoch 0) is submitted after the epoch moved to 1.
      const domain = await bridgeDomain();
      const staleRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: 0,
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const ecdsaSignature = await owner.signTypedData(domain, APPLY_UNENROLL_TYPES, staleRequest);
      const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await expect(
        bridge.applyUnenrollController(staleRequest, ecdsaSignature, pqSignature),
      ).to.be.revertedWithCustomError(bridge, "StaleControlEpoch");

      // §9.10: the controller SURVIVES — the compromised vaultOwner regains nothing.
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("G11: the POLICY's own boundEpoch check rejects a stale proposal even via a FRESH post-recovery signature (§9.10, mirrors D2)", async function () {
      await proposeUnenrol(); // boundEpoch = 0

      const newSigner = recipient;
      await rotateTo(newSigner); // epoch -> 1

      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      // FRESH intent: signed by the NEW (current) signer, at the NEW (current) epoch —
      // the bridge's own checks pass this cleanly. Only the POLICY's stored-proposal
      // boundEpoch check can catch it now.
      const domain = await bridgeDomain();
      const freshRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: await currentEpoch(), // == 1
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const ecdsaSignature = await newSigner.signTypedData(domain, APPLY_UNENROLL_TYPES, freshRequest);
      const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await expect(
        bridge.applyUnenrollController(freshRequest, ecdsaSignature, pqSignature),
      ).to.be.revertedWithCustomError(policy, "StaleControlEpoch");

      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("G12: pause blocks a fresh proposeUnenrollController call", async function () {
      await bridge.connect(pauser).pause();
      await expect(proposeUnenrol()).to.be.revertedWithCustomError(bridge, "BridgeIsPaused");
    });

    it("G13: pause blocks applying an already-matured unenrolment (§9.12's reasoning, mirrors E1)", async function () {
      await proposeUnenrol();
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await bridge.connect(pauser).pause();

      await expect(applyUnenrol()).to.be.revertedWithCustomError(bridge, "BridgeIsPaused");
      // Untouched — merely unreachable.
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });
  });

  // =====================================================================
  // H — RECOVERY/ROTATION PROVENANCE AND LIVENESS (§9.1, §9.2, §9.9, §9.11, §9.15)
  //     Stage 3/4 only proved STALE things fail (D1, D2, G10, G11). This group
  //     additionally proves the system stays FULLY usable afterward — a fail-safe
  //     implementation that rejected everything post-rotation would pass every
  //     existing test here and still be broken.
  // =====================================================================
  describe("H — recovery/rotation provenance and liveness", function () {
    it("H1: a consumer with no vault for the signed owner fails closed — VaultDoesNotExist (§9.11)", async function () {
      // `recipient` is a real signer but never called createVault on this vault.
      const domain = await bridgeDomain();
      const request = {
        consumer,
        owner: recipient.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        newLimit: LIMIT,
        epoch: await vault.policyControlEpoch(recipient.address),
        nonce: await bridge.controlNonce(consumer, recipient.address),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const ecdsaSignature = await recipient.signTypedData(domain, STRENGTHEN_TYPES, request);
      const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      await expect(bridge.strengthenLimit(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
        bridge,
        "VaultDoesNotExist",
      );
    });

    it("H2: rotation with NO pending weakening leaves policy state bit-identical (§9.1 CONTROL)", async function () {
      await enrol();
      const beforeLimit = await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET);
      const beforeSpent = await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET);
      const beforeCount = await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET);

      await rotateTo(recipient);

      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(beforeLimit);
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(beforeSpent);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(beforeCount);
      // The controller is still active — rotation alone never touches it.
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");
    });

    it("H3: after rotation, a FRESH weakening proposes and applies normally — liveness survives (§9.1/§9.9)", async function () {
      await enrol();
      await rotateTo(recipient);

      // signAndSend hardcodes `owner` as signer; after rotation `owner`'s ecdsaSigner IS
      // `recipient` now, so the fresh intent must be built and signed manually.
      const domain = await bridgeDomain();
      const pq = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      const proposeRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        newLimit: LIMIT * 2n,
        epoch: await currentEpoch(),
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const proposeSig = await recipient.signTypedData(domain, PROPOSE_WEAKENING_TYPES, proposeRequest);
      await expect(bridge.proposeWeakening(proposeRequest, proposeSig, pq)).to.not.revert(ethers);

      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      const applyRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: await currentEpoch(),
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const applySig = await recipient.signTypedData(domain, APPLY_WEAKENING_TYPES, applyRequest);
      await expect(bridge.applyWeakening(applyRequest, applySig, pq)).to.not.revert(ethers);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT * 2n);
    });

    it("H4: guardian recovery invalidates a pending weakening, and recovered credentials propose+apply their own (§9.2)", async function () {
      await enrol();
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await proposeWeakening(0n); // epoch 0, while credentials are still current

      // Pre-build the (soon-to-be-stale) apply intent BEFORE recovery, exactly as a
      // real attacker would — signed while `owner`'s key was still genuinely current.
      const domain = await bridgeDomain();
      const staleRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: 0,
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600 * 24 * 30,
      };
      const staleSig = await owner.signTypedData(domain, APPLY_WEAKENING_TYPES, staleRequest);
      const pq = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await recoverTo(recipient); // guardian-majority — a DIFFERENT auth model from rotation

      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);

      await expect(bridge.applyWeakening(staleRequest, staleSig, pq)).to.be.revertedWithCustomError(
        bridge,
        "StaleControlEpoch",
      );
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);

      // The attacker's proposal is still sitting there (untouched, merely unreachable) —
      // the recovered owner cancels it first, exactly as they would in practice, then
      // proposes and applies their OWN fresh weakening normally.
      const cancelRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: await currentEpoch(),
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const cancelSig = await recipient.signTypedData(domain, CANCEL_WEAKENING_TYPES, cancelRequest);
      await bridge.cancelWeakening(cancelRequest, cancelSig, pq);

      const proposeRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        newLimit: 0n,
        epoch: await currentEpoch(),
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const proposeSig = await recipient.signTypedData(domain, PROPOSE_WEAKENING_TYPES, proposeRequest);
      await bridge.proposeWeakening(proposeRequest, proposeSig, pq);

      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      const applyRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        epoch: await currentEpoch(),
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const applySig = await recipient.signTypedData(domain, APPLY_WEAKENING_TYPES, applyRequest);
      await bridge.applyWeakening(applyRequest, applySig, pq);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("H5: recovery while PRISTINE — recovered credentials CAN enrol; a pre-recovery signature cannot (§9.15)", async function () {
      // No enrol() anywhere above in this test — the subject is genuinely PRISTINE.
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);

      const domain = await bridgeDomain();
      const staleRequest = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        controller: await bridge.getAddress(),
        epoch: 0,
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600 * 24 * 30,
      };
      const staleSig = await owner.signTypedData(domain, ENROLL_TYPES, staleRequest);
      const pq = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      await recoverTo(recipient); // epoch -> 1

      await expect(bridge.enrollController(staleRequest, staleSig, pq)).to.be.revertedWithCustomError(
        bridge,
        "StaleControlEpoch",
      );

      // The RECOVERED credentials CAN enrol immediately, bound to the NEW epoch.
      const freshRequest = { ...staleRequest, epoch: await currentEpoch() };
      const freshSig = await recipient.signTypedData(domain, ENROLL_TYPES, freshRequest);
      await expect(bridge.enrollController(freshRequest, freshSig, pq)).to.not.revert(ethers);

      // Path 1 is dead now.
      await expect(
        policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT / 2n),
      ).to.be.revertedWithCustomError(policy, "ControllerPathRequired");

      // One-time: a second enrolment, freshly signed by the CURRENT signer, still reverts.
      const secondRequest = { ...freshRequest, nonce: await nextNonce() };
      const secondSig = await recipient.signTypedData(domain, ENROLL_TYPES, secondRequest);
      await expect(bridge.enrollController(secondRequest, secondSig, pq)).to.be.revertedWithCustomError(
        policy,
        "AlreadyEnrolled",
      );
    });

    it("H6: enrolling before compromise is discovered still leaves the bridge fully usable after recovery (§9.9 full sequence)", async function () {
      await vault.connect(owner).setGuardians([guardian1.address, guardian2.address]);
      await enrol(); // the "attacker" enrols the canonical bridge — harmless, §6.2

      await recoverTo(recipient); // epoch -> 1

      const domain = await bridgeDomain();
      const pq = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

      // The attacker's stale credentials can no longer do anything.
      const staleStrengthen = {
        consumer,
        owner: owner.address,
        policy: await policy.getAddress(),
        asset: NATIVE_ASSET,
        newLimit: LIMIT / 2n,
        epoch: 0,
        nonce: await nextNonce(),
        deadline: (await networkHelpers.time.latest()) + 3600,
      };
      const staleSig = await owner.signTypedData(domain, STRENGTHEN_TYPES, staleStrengthen);
      await expect(bridge.strengthenLimit(staleStrengthen, staleSig, pq)).to.be.revertedWithCustomError(
        bridge,
        "StaleControlEpoch",
      );

      // The recovered credentials CAN administer policy through the SAME bridge, normally.
      const freshStrengthen = { ...staleStrengthen, epoch: await currentEpoch() };
      const freshSig = await recipient.signTypedData(domain, STRENGTHEN_TYPES, freshStrengthen);
      await expect(bridge.strengthenLimit(freshStrengthen, freshSig, pq)).to.not.revert(ethers);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT / 2n);
    });
  });

  // =====================================================================
  // I — QUEUED WITHDRAWAL ACROSS TRANSITIONS (§9.5, L8)
  // =====================================================================
  describe("I — queued (large-tx) withdrawals interact correctly with strengthening/weakening", function () {
    const THRESHOLD = ethers.parseEther("0.5");
    const QUEUE_DELAY = 60 * 60;

    async function ethDomain() {
      return {
        name: "WalletWallVault",
        version: "1",
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: consumer,
      };
    }

    async function queue(amount: bigint) {
      const deadline = (await networkHelpers.time.latest()) + 3600 * 24;
      const req = {
        vaultOwner: owner.address,
        recipient: recipient.address,
        amount,
        nonce: 0,
        deadline,
        vaultMode: HYBRID,
      };
      const ecdsaSig = await owner.signTypedData(await ethDomain(), WITHDRAWAL_TYPES, req);
      const pqSig = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
      return vault.queueWithdrawal(req, ecdsaSig, pqSig);
    }

    beforeEach(async function () {
      await enrol();
      await vault.connect(admin).proposeLargeTxParams(THRESHOLD, QUEUE_DELAY);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyLargeTxParams();
    });

    it("I1 CASE A: strengthening mid-queue never strands or double-books the queued withdrawal", async function () {
      const amount = ethers.parseEther("0.6"); // > THRESHOLD, <= LIMIT
      await queue(amount);
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(amount);

      await strengthen(ethers.parseEther("0.8")); // 1 -> 0.8, still a valid strengthen
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("0.8"));

      await networkHelpers.time.increase(QUEUE_DELAY + 1);
      const pending = await vault.pendingWithdrawals(owner.address);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, pending.operationId)).to.not.revert(ethers);

      // Finalization is a pure revalidate() — it neither re-books nor is blocked by the
      // now-lower limit retroactively applying to an already-admitted withdrawal.
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(amount);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("0.8"));
    });

    it("I2 CASE B: a PENDING weakening never leaks into admission — the queue-time floor reads `limit`, not `pending` (the L8 trap)", async function () {
      await proposeWeakening(LIMIT * 3n); // pending — s.limit is STILL LIMIT (1 ETH)

      // Between the CURRENT limit and the PENDING one: admissible only if the engine
      // wrongly consulted `pending.newLimit` instead of the enforced `limit`.
      const amount = LIMIT + ethers.parseEther("0.5");
      await expect(queue(amount))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("I3 CASE C: a weakening applied mid-queue rewrites `limit` alone — never the ledger", async function () {
      const amount = ethers.parseEther("0.6");
      await queue(amount);
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(amount);

      await proposeWeakening(LIMIT * 2n); // 1 -> 2 ETH

      // POLICY_CONTROL_DELAY (2 days) exceeds WINDOW (24h), so by the time ANY
      // weakening can mature, the queued entry has ALREADY aged out on its own clock
      // (E1's finding, reused here) — applying the weakening must not ADDITIONALLY
      // touch the ledger beyond that ordinary, independent decay.
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);

      await applyWeakening();
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT * 2n);
      // The apply touched ONLY `limit` — the ledger is exactly as decay left it.
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await policy.remainingAllowance(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT * 2n);

      const pending = await vault.pendingWithdrawals(owner.address);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, pending.operationId)).to.not.revert(ethers);
      // Finalization (a pure revalidate()) leaves the ledger untouched too.
      expect(await policy.rollingSpent(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
      expect(await policy.activeEntryCount(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
    });
  });

  // =====================================================================
  // J — POLICY-ENGINE REPLACEMENT (§9.4, L7: no migration, ever)
  // =====================================================================
  describe("J — replacing the vault's policy engine never migrates or mutates state", function () {
    it("J1 CASE A: swapping to a DIFFERENT policy instance leaves it unarmed, uncontrolled, with no proposal", async function () {
      await enrol();
      await proposeWeakening(LIMIT * 2n); // leave a pending weakening in P

      const Policy2 = await ethers.getContractFactory("DailySpendLimitPolicy");
      const policy2 = await Policy2.deploy(await bridge.getAddress());
      await policy2.waitForDeployment();

      await vault.connect(admin).proposePolicyEngine(await policy2.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyPolicyEngine();

      // P2 starts genuinely PRISTINE — not armed, no controller, nothing pending.
      expect(await policy2.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(0n);
      await policy2.connect(owner).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
      await expect(policy2.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT)).to.not.revert(ethers);

      // Engine replacement is a vault-governance action, wholly independent of the
      // credential lifecycle — it never touches the epoch.
      expect(await vault.policyControlEpoch(owner.address)).to.equal(0n);

      // P's own state — including the now-abandoned pending proposal — is untouched.
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
    });

    it("J2 CASE B: swapping to a composite that wraps the SAME instance leaves its pending proposal intact — it lives in P, not in the wiring", async function () {
      await enrol();
      await proposeWeakening(LIMIT * 2n);

      const Composite = await ethers.getContractFactory("CompositePolicyEngine", admin);
      const composite = await Composite.deploy();
      await composite.waitForDeployment();
      await composite.connect(admin).addModule(await policy.getAddress());

      await vault.connect(admin).proposePolicyEngine(await composite.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await vault.connect(admin).applyPolicyEngine();

      // P's proposal survives being wrapped — apply it DIRECTLY against P, exactly as
      // if nothing had changed, since the vault's engine pointer never touched P itself.
      await networkHelpers.time.increase(POLICY_CONTROL_DELAY);
      await applyWeakening();
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT * 2n);
    });
  });
});
