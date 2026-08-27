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
 *真 meaningful when authentication is genuinely wired through.
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

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let pauser: HardhatEthersSigner;
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
      | "setAdmitter",
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

  beforeEach(async function () {
    [admin, owner, recipient, pauser] = await ethers.getSigners();
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
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, 0);
      await policy.connect(owner).setAdmitter(consumer, NATIVE_ASSET, consumer, true);
      await policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
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

    it("A10: a no-op (n -> n) is neither strengthening nor weakening — it is simply a no-op", async function () {
      await expect(policy.connect(owner).setDailyLimit(consumer, NATIVE_ASSET, LIMIT)).to.not.revert(ethers);
      expect(await policy.dailyLimit(consumer, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
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
  });
});
