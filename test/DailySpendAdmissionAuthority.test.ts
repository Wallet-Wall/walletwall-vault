import { expect } from "chai";
import { ethers } from "./helpers/connection";
import { networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import {
  WalletWallVault,
  StablecoinVaultSimulator,
  MockUSDC,
  MockMLDSAVerifier,
  CompositePolicyEngine,
  DailySpendLimitPolicy,
  DailySpendPoisonerMock,
  FakeVaultMock,
} from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";
import {
  makeBuildRequest as makeSimBuildRequest,
  makeSignWithdrawal as makeSimSignWithdrawal,
} from "./helpers/simulatorHelpers";
import { NATIVE_ASSET } from "./helpers/policySubject";

/**
 * Regression suite for the DailySpendLimitPolicy ADMISSION AUTHORITY model.
 *
 * Background: PR #152 split the policy interface into admission (`check`, MAY mutate)
 * and finalization revalidation (`revalidate`, view / STATICCALL, never re-books). That
 * split fixed WHEN accounting is booked; it did not establish WHO may cause a booking.
 * `check` was `external`, mutated `_windowStart[vaultOwner]` / `_windowSpent[vaultOwner]`,
 * and derived that accounting key from its `vaultOwner` CALLDATA ARGUMENT while reading
 * `msg.sender` nowhere.
 *
 * These tests began life as characterization of that bug. On the base commit all of
 * A–E passed while ASSERTING THE ATTACK SUCCEEDED: an arbitrary EOA or contract could
 * burn any armed vault owner's entire daily allowance — directly or laundered through
 * CompositePolicyEngine — moving no funds, owning no vault, for well under 80k gas, and
 * renewably once per window. They now pin the FIXED model:
 *
 *   - booking requires `_admitter[subjectKey][msg.sender]`, a delegation only the
 *     subject's OWNER can write (both setters force msg.sender into the subject's
 *     owner slot, the same authority root as setDailyLimit);
 *   - the PolicySubject argument only selects which delegation list is consulted, and
 *     authority granted for one (consumer, owner, asset) confers nothing for another;
 *   - the gate holds at EVERY hop: CompositePolicyEngine carries the matching
 *     `admissionCaller` gate, without which it relays the same attack to the module,
 *     PLUS a `subject.consumer == msg.sender` binding so a registered consumer cannot
 *     impersonate a different one;
 *   - `revalidate` stays ungated, `pure`, and non-booking — PR #152's split is intact.
 *
 * UPDATED BY POLICY-SUBJECT PROPAGATION. Three cases changed meaning rather than
 * merely changing shape, and each says so at its own site:
 *   - A8 now splits into "honest subject reaches only its own bucket" and "spoofed
 *     consumer is refused";
 *   - C3 dies one hop earlier, at the composite's consumer binding;
 *   - C7 previously pinned an ACCEPTED weakness (a composite owner could burn a
 *     delegating tenant's allowance). That is now structurally impossible, so C7
 *     asserts its absence and C7b states the residual composite-owner power exactly,
 *     so the improvement is not over-read.
 *
 * Base: origin/main 5792975d4db331156845de72addbae95d079c0f8 (includes merged PR #152).
 */
describe("Daily-spend admission authority (regression)", function () {
  let vault: WalletWallVault;
  let verifier: MockMLDSAVerifier;
  let composite: CompositePolicyEngine;
  let dailyPolicy: DailySpendLimitPolicy;
  let poisoner: DailySpendPoisonerMock;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let attacker: HardhatEthersSigner;
  let victim2: HardhatEthersSigner;

  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  // Deliberately shorter than WINDOW: a timelock >= WINDOW would roll the spend window
  // during the delay, which would mask whether finalization re-books (F2).
  const LARGE_TX_DELAY = 6 * 60 * 60;
  const WINDOW = 24 * 60 * 60;
  const DEPOSIT = ethers.parseEther("20");
  const THRESHOLD = ethers.parseEther("1");
  const LARGE_AMOUNT = ethers.parseEther("2");
  const LIMIT = ethers.parseEther("5");

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  /// The ETH vault's address, cached in beforeEach. This suite's default consumer.
  let vaultAddress: string;

  /** The subject the ETH vault mints for `o`: (vault, o, native ETH). */
  const subj = (o: string) => ({ consumer: vaultAddress, owner: o, asset: NATIVE_ASSET });
  /** Remaining allowance for `o` under the ETH vault's native subject. */
  const allowanceOf = (o: string) => dailyPolicy.remainingAllowance(vaultAddress, o, NATIVE_ASSET);
  /** Whether `caller` is delegated for `o`'s ETH-vault subject. */
  const admitterOf = (o: string, caller: string) => dailyPolicy.admitter(vaultAddress, o, NATIVE_ASSET, caller);

  async function setPolicyEngine(engine: string) {
    await vault.connect(admin).proposePolicyEngine(engine);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyPolicyEngine();
  }

  async function enableLargeTx(delay = LARGE_TX_DELAY) {
    await vault.connect(admin).proposeLargeTxParams(THRESHOLD, delay);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyLargeTxParams();
  }

  /** The canonical direct wiring: owner delegates to the vault, then arms the limit. */
  async function armViaVault(limit = LIMIT) {
    await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
    await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, limit);
    await setPolicyEngine(await dailyPolicy.getAddress());
  }

  /** Immediate (sub-threshold) withdrawal from `owner`'s vault. */
  async function withdrawSmall(amount: bigint, nonce?: number) {
    const req = await buildRequest({ recipient: recipient.address, amount, nonce });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    return vault.connect(other).withdraw(req, ecdsaSig, pqSig);
  }

  async function queueLarge(amount = LARGE_AMOUNT, nonce?: number) {
    const req = await buildRequest({ recipient: recipient.address, amount, nonce });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
    return { req, operationId: await vault.hashWithdrawal(req) };
  }

  beforeEach(async function () {
    [admin, owner, recipient, other, attacker, victim2] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    vaultAddress = await vault.getAddress();
    composite = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();
    const bridge = await (await ethers.getContractFactory("PolicyControlBridge", admin)).deploy(admin.address);
    dailyPolicy = await (
      await ethers.getContractFactory("DailySpendLimitPolicy", admin)
    ).deploy(await bridge.getAddress());
    poisoner = await (await ethers.getContractFactory("DailySpendPoisonerMock", attacker)).deploy();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, 2);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  // =========================================================================
  // A — DIRECT-CALL POISONING IS REFUSED
  // =========================================================================
  describe("A — direct-call poisoning by an unrelated caller", function () {
    beforeEach(async function () {
      await armViaVault();
    });

    it("A1: the attacker neither owns nor controls the victim's vault", async function () {
      expect(await vault.owner()).to.equal(admin.address);
      expect((await vault.getVault(owner.address)).ecdsaSigner).to.equal(owner.address);
      expect((await vault.getVault(attacker.address)).exists).to.equal(false);
      await expect(vault.connect(attacker).proposePolicyEngine(ethers.ZeroAddress))
        .to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount")
        .withArgs(attacker.address);
      expect(await admitterOf(owner.address, attacker.address)).to.equal(false);
    });

    it("A2: an arbitrary EOA calling check() is REFUSED and consumes nothing", async function () {
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);

      await expect(
        dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, ethers.parseEther("3"), 0n),
      )
        .to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter")
        .withArgs(attacker.address, vaultAddress, owner.address, NATIVE_ASSET);

      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("A3: the refusal is a REVERT, not a silent denial — even for a static probe", async function () {
      // An authority failure must stay distinguishable from a policy decision. A denial
      // would return (false, "daily limit exceeded"); a misconfiguration reverts.
      await expect(
        dailyPolicy.connect(attacker).check.staticCall(subj(owner.address), attacker.address, LIMIT, 0n),
      ).to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter");
    });

    it("A4: the victim's subsequent withdrawal still succeeds (no residual damage)", async function () {
      await expect(dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, LIMIT, 0n)).to.revert(
        ethers,
      );
      await expect(withdrawSmall(ethers.parseEther("0.5"))).to.not.revert(ethers);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - ethers.parseEther("0.5"));
    });

    it("A5: the QUEUED (large-tx) admission path is likewise unaffected", async function () {
      await enableLargeTx();
      await expect(dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, LIMIT, 0n)).to.revert(
        ethers,
      );

      const req = await buildRequest({ recipient: recipient.address, amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await expect(vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig)).to.emit(vault, "WithdrawalQueued");
    });

    it("A7: an arbitrary CONTRACT caller is refused exactly as an EOA is", async function () {
      await expect(
        poisoner
          .connect(attacker)
          .poison(
            await dailyPolicy.getAddress(),
            vaultAddress,
            owner.address,
            NATIVE_ASSET,
            attacker.address,
            LIMIT,
            0n,
          ),
      ).to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter");

      expect(await poisoner.callCount()).to.equal(0n);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("A8: a contract that merely CLAIMS to be a vault reaches only its OWN subject", async function () {
      // Authority is an explicit registration, never a property inferred from the caller's
      // own claims — a caller that answers `policyEngine()`/`owner()` proves nothing.
      //
      // Under subject propagation this splits into two distinct refusals, and BOTH
      // matter. Asserting only one would leave the other silently untested.
      const fake: FakeVaultMock = await (
        await ethers.getContractFactory("FakeVaultMock", attacker)
      ).deploy(await dailyPolicy.getAddress());
      const fakeAddress = await fake.getAddress();

      // (i) Minting an HONEST subject (consumer = itself, as a real vault does) lands on
      // a bucket keyed to the fake, which nobody armed. It is therefore an inert no-op:
      // it does not revert, and — the part that matters — it consumes nothing of the
      // victim's allowance, because it never addressed the victim's bucket at all.
      await expect(
        fake.connect(attacker).admit(owner.address, NATIVE_ASSET, attacker.address, LIMIT, 0n),
      ).to.not.revert(ethers);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
      expect(await dailyPolicy.remainingAllowance(fakeAddress, owner.address, NATIVE_ASSET)).to.equal(
        ethers.MaxUint256,
      );

      // (ii) SPOOFING the real vault as `consumer` does address the victim's bucket — and
      // is refused, because the delegation for that subject names the vault, not this
      // contract. Naming a consumer never confers that consumer's authority.
      await expect(
        fake.connect(attacker).admitAs(vaultAddress, owner.address, NATIVE_ASSET, attacker.address, LIMIT, 0n),
      )
        .to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter")
        .withArgs(fakeAddress, vaultAddress, owner.address, NATIVE_ASSET);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("A9: supplying the REAL vault address as an argument does not confer its authority", async function () {
      // The vault address appears only as calldata here; authority is msg.sender.
      await expect(dailyPolicy.connect(attacker).check(subj(owner.address), await vault.getAddress(), LIMIT, DEPOSIT))
        .to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter")
        .withArgs(attacker.address, vaultAddress, owner.address, NATIVE_ASSET);
    });

    it("A9b: supplying ANOTHER vault's address as an argument is equally powerless", async function () {
      const otherVault = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await verifier.getAddress());

      await expect(
        dailyPolicy.connect(attacker).check(subj(owner.address), await otherVault.getAddress(), LIMIT, 0n),
      ).to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter");
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("A10: an owner with NO limit set needs no delegation and is never locked out", async function () {
      // The gate sits after the `limit == 0` short-circuit, so the unarmed majority
      // require no configuration — and have nothing to poison in the first place.
      expect(await allowanceOf(victim2.address)).to.equal(ethers.MaxUint256);
      await expect(
        dailyPolicy.connect(attacker).check(subj(victim2.address), attacker.address, LIMIT, 0n),
      ).to.not.revert(ethers);
      expect(await allowanceOf(victim2.address)).to.equal(ethers.MaxUint256);
    });
  });

  // =========================================================================
  // B — REPEATED ATTEMPTS, AND THE NEAR-MAX-LIMIT ESCALATION
  // =========================================================================
  describe("B — repeated attempts and accounting integrity", function () {
    beforeEach(async function () {
      await armViaVault();
    });

    it("B1: five repeated attack attempts leave the allowance exactly untouched", async function () {
      const step = ethers.parseEther("1");
      for (let i = 0; i < 5; i++) {
        await expect(dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, step, 0n)).to.revert(
          ethers,
        );
      }
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("B4: distinct armed victims are each protected independently", async function () {
      await dailyPolicy.connect(victim2).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      await dailyPolicy.connect(victim2).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);

      await expect(dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, LIMIT, 0n)).to.revert(
        ethers,
      );
      await expect(dailyPolicy.connect(attacker).check(subj(victim2.address), attacker.address, LIMIT, 0n)).to.revert(
        ethers,
      );
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
      expect(await allowanceOf(victim2.address)).to.equal(LIMIT);
    });

    it("B5: the near-max-limit PANIC escalation is foreclosed", async function () {
      // `0` means unrestricted, so an owner reaching for "effectively unlimited" may set
      // a near-max limit instead. There the denial branch is unreachable, so on the base
      // commit an attacker could book _windowSpent to the ceiling and make every later
      // admission revert on the CHECKED ADD — Panic(0x11), not a policy denial. The gate
      // sits before the first storage read, so no such value can be planted.
      await dailyPolicy.connect(victim2).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      await dailyPolicy.connect(victim2).setDailyLimit(vaultAddress, NATIVE_ASSET, ethers.MaxUint256);

      await expect(
        dailyPolicy.connect(attacker).check(subj(victim2.address), attacker.address, ethers.MaxUint256, 0n),
      ).to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter");

      expect(await allowanceOf(victim2.address)).to.equal(ethers.MaxUint256);
    });
  });

  // =========================================================================
  // C — COMPOSITE-MEDIATED PATH
  // =========================================================================
  describe("C — composite-mediated admission", function () {
    beforeEach(async function () {
      await composite.connect(admin).addModule(await dailyPolicy.getAddress());
      // Under composition the module observes the COMPOSITE as msg.sender, so that is
      // what the owner delegates to; the composite's admin registers the vault in turn.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await composite.getAddress(), true);
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);
      await composite.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
      await setPolicyEngine(await composite.getAddress());
    });

    it("C1: CompositePolicyEngine.check() refuses an unregistered caller", async function () {
      await expect(
        dailyPolicy.connect(attacker).check.staticCall(subj(owner.address), attacker.address, LIMIT, 0n),
      ).to.revert(ethers);
      await expect(composite.connect(attacker).check(subj(owner.address), attacker.address, LIMIT, 0n))
        .to.be.revertedWithCustomError(composite, "UnauthorizedAdmissionCaller")
        .withArgs(attacker.address);
    });

    it("C2: the composite can no longer be used to launder the attack into the module", async function () {
      await expect(composite.connect(attacker).check(subj(owner.address), attacker.address, LIMIT, 0n)).to.revert(
        ethers,
      );
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
      await expect(withdrawSmall(ethers.parseEther("0.5"))).to.not.revert(ethers);
    });

    it("C3: an attacker's OWN composite cannot borrow the victim's delegation", async function () {
      // The attacker fully controls a second composite — they can register themselves on
      // it and install the real module. Two routes exist and both are closed.
      const evil = await (await ethers.getContractFactory("CompositePolicyEngine", attacker)).deploy();
      const evilAddress = await evil.getAddress();
      const poisonerAddress = await poisoner.getAddress();
      await evil.connect(attacker).addModule(await dailyPolicy.getAddress());
      await evil.connect(attacker).setAdmissionCaller(poisonerAddress, true);

      // (i) Naming the VICTIM'S vault as consumer is rejected by the evil composite's own
      // consumer binding — a composite relays only for the caller that IS the consumer,
      // and the poisoner is not the vault. The attack dies one hop earlier than before.
      await expect(
        poisoner
          .connect(attacker)
          .poison(evilAddress, vaultAddress, owner.address, NATIVE_ASSET, attacker.address, LIMIT, 0n),
      )
        .to.be.revertedWithCustomError(evil, "SubjectConsumerMismatch")
        .withArgs(vaultAddress, poisonerAddress);

      // (ii) Being HONEST about the consumer gets through the composite but lands on the
      // poisoner's own unarmed bucket — never the victim's.
      await expect(
        poisoner
          .connect(attacker)
          .poison(evilAddress, poisonerAddress, owner.address, NATIVE_ASSET, attacker.address, LIMIT, 0n),
      ).to.not.revert(ethers);

      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("C4: the module registered in the composite is still refused on a DIRECT call", async function () {
      await expect(dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, LIMIT, 0n)).to.revert(
        ethers,
      );
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("C5: the LEGITIMATE vault -> composite -> module path books exactly once", async function () {
      const amount = ethers.parseEther("0.5");
      await expect(withdrawSmall(amount)).to.emit(vault, "Withdrawn");
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - amount);
    });

    it("C7: TRADE-OFF RETIRED — a registered relay can no longer burn the tenant's vault allowance", async function () {
      // PREVIOUSLY AN ACCEPTED WEAKNESS, NOW STRUCTURALLY CLOSED.
      //
      // Before subject propagation this test asserted the attack SUCCEEDED: delegation is
      // transitive, so a tenant delegating to a composite inherited that composite's
      // access control, and its owner could register an arbitrary code-bearing relay
      // which then burned the tenant's whole allowance. It was documented as an accepted
      // denial-class trade-off.
      //
      // The consumer binding removes it. A relay reaching the composite must name ITSELF
      // as `subject.consumer`, so it can only ever address a bucket keyed to the relay —
      // and no tenant arms such a bucket. The tenant's real bucket, (vault, owner, ETH),
      // is now reachable only by the vault itself.
      const poisonerAddress = await poisoner.getAddress();
      const compositeAddress = await composite.getAddress();
      await composite.connect(admin).setAdmissionCaller(poisonerAddress, true);

      // Route 1: claim the tenant's vault as consumer — refused by the binding.
      await expect(
        poisoner
          .connect(attacker)
          .poison(compositeAddress, vaultAddress, owner.address, NATIVE_ASSET, attacker.address, LIMIT, 0n),
      )
        .to.be.revertedWithCustomError(composite, "SubjectConsumerMismatch")
        .withArgs(vaultAddress, poisonerAddress);

      // Route 2: be honest — reaches the module, but against the relay's own bucket.
      await poisoner
        .connect(attacker)
        .poison(compositeAddress, poisonerAddress, owner.address, NATIVE_ASSET, attacker.address, LIMIT, 0n);

      // The tenant's allowance is intact under BOTH routes, and their withdrawals work.
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
      await expect(withdrawSmall(ethers.parseEther("0.5"))).to.not.revert(ethers);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - ethers.parseEther("0.5"));
    });

    it("C7b: the composite owner RETAINS its unescapable denial powers (scope of C7 stated exactly)", async function () {
      // C7 must not be read as "the composite owner is now harmless". Adding a denying
      // module is still instant, still unilateral, and still blocks the tenant — that
      // authority was never the thing subject propagation removed. What changed is only
      // that the owner can no longer reach the tenant's ACCOUNTING. Stating the residual
      // power explicitly keeps C7 an honest claim rather than an over-read one.
      const denier = await (await ethers.getContractFactory("SanctionsListPolicy", admin)).deploy();
      await denier.connect(admin).addToSanctionsList(recipient.address);
      await composite.connect(admin).addModule(await denier.getAddress());

      await expect(withdrawSmall(ethers.parseEther("0.5")))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("recipient is sanctioned");

      // Denial only — the tenant's allowance was never touched.
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("C8: an UNREGISTERED relay gets nowhere, even pointed at the legitimate composite", async function () {
      // The control for C7: without the composite owner's registration the same relay is
      // refused at the composite hop, so C7 is about that registration, not about the relay.
      await expect(
        poisoner
          .connect(attacker)
          .poison(await composite.getAddress(), vaultAddress, owner.address, NATIVE_ASSET, attacker.address, LIMIT, 0n),
      ).to.be.revertedWithCustomError(composite, "UnauthorizedAdmissionCaller");
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
    });

    it("C6: composite revalidate() stays UNGATED so settlement never fails on authority", async function () {
      // revalidate is view and mutates nothing; gating it would break the vaults'
      // fail-closed settlement revalidation for every caller.
      const [ok, reason] = await composite
        .connect(attacker)
        .revalidate(subj(owner.address), recipient.address, LIMIT * 100n, 0n);
      expect(ok).to.equal(true);
      expect(reason).to.equal("");
    });
  });

  // =========================================================================
  // D — CROSS-VAULT / CROSS-ASSET IDENTITY
  // =========================================================================
  describe("D — cross-vault and cross-asset identity", function () {
    let sim: StablecoinVaultSimulator;
    let token: MockUSDC;
    const MUSDC = (n: number) => BigInt(n) * 1_000_000n;

    beforeEach(async function () {
      token = await (await ethers.getContractFactory("MockUSDC")).deploy();
      sim = await (
        await ethers.getContractFactory("StablecoinVaultSimulator", admin)
      ).deploy(await token.getAddress(), await verifier.getAddress());

      await sim.connect(owner).createVault(owner.address, PQ_KEY, 2);
      await token.connect(owner).mint(owner.address, MUSDC(500));
      await token.connect(owner).approve(await sim.getAddress(), MUSDC(500));
      await sim.connect(owner).deposit(MUSDC(500));
    });

    it("D1: delegation is per (subject, caller) — one vault's grant does not cover another", async function () {
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);

      expect(await admitterOf(owner.address, await vault.getAddress())).to.equal(true);
      expect(await admitterOf(owner.address, await sim.getAddress())).to.equal(false);
      // A different subject's grant is likewise irrelevant to this subject.
      expect(await admitterOf(victim2.address, await vault.getAddress())).to.equal(false);
    });

    it("D2: two DELEGATED vaults now hold INDEPENDENT spend windows (previously shared)", async function () {
      // INVERTED BY THIS PR. Before subject propagation, accounting was keyed on the
      // vaultOwner alone and carried no consumer or asset dimension, so ONE policy
      // instance wired into both vaults shared a single accumulator across
      // incommensurable units (wei vs 6-decimal token base units). This test asserted
      // exactly that collapse. It now asserts its absence.
      const simAddress = await sim.getAddress();
      const tokenAddress = await token.getAddress();
      const simLimit = MUSDC(400);

      // Arm BOTH subjects for the same owner: the ETH vault and the token simulator.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);
      await dailyPolicy.connect(owner).setAdmitter(simAddress, tokenAddress, simAddress, true);
      await dailyPolicy.connect(owner).setDailyLimit(simAddress, tokenAddress, simLimit);

      await sim.connect(admin).proposePolicyEngine(await dailyPolicy.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPolicyEngine();
      await setPolicyEngine(await dailyPolicy.getAddress());

      const simAllowance = () => dailyPolicy.remainingAllowance(simAddress, owner.address, tokenAddress);

      // Spend token units through the simulator.
      const simBuild = makeSimBuildRequest(owner, { recipient: recipient.address, amount: MUSDC(100) });
      const simSign = makeSimSignWithdrawal(sim, owner);
      const req = await simBuild({ recipient: recipient.address, amount: MUSDC(100) });
      const { ecdsaSig, pqSig } = await simSign(req);
      await sim.connect(other).withdraw(req, ecdsaSig, pqSig);

      // Only the token subject moved. The ETH subject is untouched — no shared scalar.
      expect(await simAllowance()).to.equal(simLimit - MUSDC(100));
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);

      // And the reverse: spending ETH does not consume the token allowance.
      await withdrawSmall(ethers.parseEther("1"));
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - ethers.parseEther("1"));
      expect(await simAllowance()).to.equal(simLimit - MUSDC(100));
    });

    it("D3: an attacker can no longer poison the ETH surface to block a STABLECOIN admission", async function () {
      const simAddress = await sim.getAddress();
      const tokenAddress = await token.getAddress();
      const sharedLimit = MUSDC(400);
      await dailyPolicy.connect(owner).setAdmitter(simAddress, tokenAddress, simAddress, true);
      await dailyPolicy.connect(owner).setDailyLimit(simAddress, tokenAddress, sharedLimit);
      await sim.connect(admin).proposePolicyEngine(await dailyPolicy.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPolicyEngine();

      await expect(
        dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, sharedLimit, 0n),
      ).to.not.revert(ethers); // ETH subject is unarmed, so this is an inert no-op…

      // …and, crucially, the attacker cannot reach the ARMED token subject either.
      await expect(
        dailyPolicy
          .connect(attacker)
          .check(
            { consumer: simAddress, owner: owner.address, asset: tokenAddress },
            attacker.address,
            sharedLimit,
            0n,
          ),
      ).to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter");

      const simBuild = makeSimBuildRequest(owner, { recipient: recipient.address, amount: MUSDC(100) });
      const simSign = makeSimSignWithdrawal(sim, owner);
      const req = await simBuild({ recipient: recipient.address, amount: MUSDC(100) });
      const { ecdsaSig, pqSig } = await simSign(req);
      await expect(sim.connect(other).withdraw(req, ecdsaSig, pqSig)).to.emit(sim, "Withdrawn");
    });
  });

  // =========================================================================
  // E — WINDOW SEMANTICS (a true rolling 24h ledger)
  //     Unchanged for the legitimate path: a single spend still exhausts the cap and
  //     still recovers a full WINDOW later, because one entry expires exactly a WINDOW
  //     after itself. The rolling matrix is test/DailySpendRollingWindow.test.ts.
  // =========================================================================
  describe("E — window semantics for the authorized path", function () {
    beforeEach(async function () {
      await armViaVault();
    });

    it("E1: a legitimately exhausted window still denies — cleanly, not by revert", async function () {
      await withdrawSmall(LIMIT);
      expect(await allowanceOf(owner.address)).to.equal(0n);
      await expect(withdrawSmall(ethers.parseEther("0.5"), 1))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("E2: allowance recovers exactly at start + WINDOW", async function () {
      await withdrawSmall(LIMIT);
      const spentAt = await networkHelpers.time.latest();

      await networkHelpers.time.setNextBlockTimestamp(spentAt + WINDOW - 1);
      await networkHelpers.mine();
      expect(await allowanceOf(owner.address)).to.equal(0n);

      await networkHelpers.time.setNextBlockTimestamp(spentAt + WINDOW);
      await networkHelpers.mine();
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);
      await expect(withdrawSmall(ethers.parseEther("0.5"), 1)).to.not.revert(ethers);
    });

    it("E3: an attacker cannot re-open or re-exhaust the window at any point in the cycle", async function () {
      for (let day = 0; day < 3; day++) {
        await expect(dailyPolicy.connect(attacker).check(subj(owner.address), attacker.address, LIMIT, 0n)).to.revert(
          ethers,
        );
        expect(await allowanceOf(owner.address)).to.equal(LIMIT);
        await networkHelpers.time.increase(WINDOW);
      }
    });
  });

  // =========================================================================
  // F — LEGITIMATE-PATH CONTROLS (must remain green through any remediation)
  // =========================================================================
  describe("F — legitimate-path controls", function () {
    beforeEach(async function () {
      await armViaVault();
    });

    it("F1: a legitimate immediate withdrawal books EXACTLY once", async function () {
      const amount = ethers.parseEther("0.5");
      await withdrawSmall(amount);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - amount);
    });

    it("F2: queueing books once and finalization does NOT re-book", async function () {
      await enableLargeTx();
      const { operationId } = await queueLarge();
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - LARGE_AMOUNT);

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await vault.connect(owner).finalizeWithdrawal(owner.address, operationId);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - LARGE_AMOUNT);
    });

    it("F3: revalidate() is ungated, non-mutating, and allows unconditionally", async function () {
      await withdrawSmall(ethers.parseEther("0.5"));
      const before = await allowanceOf(owner.address);
      // Called by a completely unauthorized address — settlement must never depend on
      // admission authority, or a revoked delegation would strand queued withdrawals.
      const [ok, reason] = await dailyPolicy
        .connect(attacker)
        .revalidate(subj(owner.address), recipient.address, LIMIT * 100n, 0n);
      expect(ok).to.equal(true);
      expect(reason).to.equal("");
      expect(await allowanceOf(owner.address)).to.equal(before);
    });

    it("F3b: revalidate() survives STATICCALL — it performs no write at all", async function () {
      // The vault invokes revalidate through a `view` interface, i.e. under STATICCALL.
      // Reproduce that constraint exactly: any SSTORE would make this revert.
      const iface = dailyPolicy.interface;
      const data = iface.encodeFunctionData("revalidate", [subj(owner.address), recipient.address, LIMIT, DEPOSIT]);
      const raw = await ethers.provider.call({ to: await dailyPolicy.getAddress(), data });
      const [ok, reason] = iface.decodeFunctionResult("revalidate", raw);
      expect(ok).to.equal(true);
      expect(reason).to.equal("");
    });

    it("F4: cancellation does NOT release booked allowance (documented invariant)", async function () {
      await enableLargeTx();
      const { operationId } = await queueLarge();
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - LARGE_AMOUNT);

      await vault.connect(owner).cancelPendingWithdrawal(operationId);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - LARGE_AMOUNT);
    });

    it("F5: re-queueing after cancellation books AGAIN (documented invariant)", async function () {
      await enableLargeTx();
      const { operationId } = await queueLarge();
      await vault.connect(owner).cancelPendingWithdrawal(operationId);

      const nonce = Number((await vault.getVault(owner.address)).nonce);
      const req = await buildRequest({ recipient: recipient.address, amount: LARGE_AMOUNT, nonce });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);

      expect(await allowanceOf(owner.address)).to.equal(LIMIT - LARGE_AMOUNT * 2n);
    });

    it("F6: an exactly-at-limit admission is permitted and lands on zero", async function () {
      await withdrawSmall(LIMIT - ethers.parseEther("0.5"), 0);
      expect(await allowanceOf(owner.address)).to.equal(ethers.parseEther("0.5"));
      await withdrawSmall(ethers.parseEther("0.5"), 1);
      expect(await allowanceOf(owner.address)).to.equal(0n);
    });

    it("F7: one wei beyond the limit is denied", async function () {
      await withdrawSmall(LIMIT - ethers.parseEther("0.5"), 0);
      const req = await buildRequest({
        recipient: recipient.address,
        amount: ethers.parseEther("0.5") + 1n,
        nonce: 1,
      });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await expect(vault.connect(other).withdraw(req, ecdsaSig, pqSig))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs("daily limit exceeded");
    });

    it("F8: a reverted outer withdrawal rolls the booking back", async function () {
      const rejector = await (await ethers.getContractFactory("RejectEther", admin)).deploy();
      const before = await allowanceOf(owner.address);

      const req = await buildRequest({
        recipient: await rejector.getAddress(),
        amount: ethers.parseEther("0.5"),
      });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await expect(vault.connect(other).withdraw(req, ecdsaSig, pqSig)).to.be.revertedWithCustomError(
        vault,
        "TransferFailed",
      );
      expect(await allowanceOf(owner.address)).to.equal(before);
    });

    it("F9: STANDALONE use survives — a self-delegating owner may drive check() directly", async function () {
      const standaloneBridge = await (
        await ethers.getContractFactory("PolicyControlBridge", admin)
      ).deploy(admin.address);
      const standalone = await (
        await ethers.getContractFactory("DailySpendLimitPolicy", admin)
      ).deploy(await standaloneBridge.getAddress());
      await standalone.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, owner.address, true);
      await standalone.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);

      await standalone.connect(owner).check(subj(owner.address), recipient.address, ethers.parseEther("2"), 0n);
      expect(await standalone.remainingAllowance(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(
        LIMIT - ethers.parseEther("2"),
      );

      // Self-delegation grants nobody else anything.
      await expect(
        standalone.connect(attacker).check(subj(owner.address), attacker.address, 1n, 0n),
      ).to.be.revertedWithCustomError(standalone, "UnauthorizedAdmitter");
    });
  });

  // =========================================================================
  // G — AUTHORITY CONFIGURATION SEMANTICS
  // =========================================================================
  describe("G — delegation configuration", function () {
    it("G1: only the SUBJECT can write its own delegation list", async function () {
      // There is no setter that takes a subject; msg.sender IS the subject. An attacker
      // delegating to themselves only ever writes their own (empty, unread) list.
      await dailyPolicy.connect(attacker).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      expect(await admitterOf(attacker.address, await vault.getAddress())).to.equal(true);
      expect(await admitterOf(owner.address, await vault.getAddress())).to.equal(false);
    });

    it("G2: arming a limit with no admitter is refused at CONFIGURATION time", async function () {
      await expect(dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT))
        .to.be.revertedWithCustomError(dailyPolicy, "NoAdmitterConfigured")
        .withArgs(vaultAddress, owner.address, NATIVE_ASSET);
    });

    it("G3: disarming to 0 is always permitted — the escape hatch is never blocked", async function () {
      // Arm first — G2 already proved arming with no admitter is refused; the claim
      // under test is that DISARMING carries no such liveness precondition.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, owner.address, true);
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);

      // Disarming (n -> 0) is a WEAKENING under v0.13.0 — delayed, not immediate — but
      // neither the proposal nor its eventual application is ever blocked by
      // NoAdmitterConfigured or any other liveness guard; those gate STRENGTHENING only.
      await expect(dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, 0)).to.not.revert(ethers);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await expect(dailyPolicy.connect(owner).applyWeakening(vaultAddress, NATIVE_ASSET)).to.not.revert(ethers);
      expect(await dailyPolicy.dailyLimit(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("G4: the zero address cannot be delegated to", async function () {
      await expect(
        dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, ethers.ZeroAddress, true),
      ).to.be.revertedWithCustomError(dailyPolicy, "ZeroAdmitter");
    });

    it("G5: a code-less (EOA) delegate is refused; self-delegation is allowed", async function () {
      await expect(dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, attacker.address, true))
        .to.be.revertedWithCustomError(dailyPolicy, "AdmitterNotAContract")
        .withArgs(attacker.address);

      await expect(
        dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, owner.address, true),
      ).to.not.revert(ethers);
    });

    it("G6: revoking the LAST admitter while armed is refused (self-brick guard)", async function () {
      await armViaVault();
      await expect(dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await vault.getAddress(), false))
        .to.be.revertedWithCustomError(dailyPolicy, "LastAdmitterWhileArmed")
        .withArgs(vaultAddress, owner.address, NATIVE_ASSET);

      // Disarm first, then revoke — the documented order. Under v0.13.0's
      // policy-control authority, disarming (n -> 0) is a delayed WEAKENING, not an
      // immediate change — it must mature and be separately applied before the
      // subsequent revoke sees limit == 0.
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, 0);
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await dailyPolicy.connect(owner).applyWeakening(vaultAddress, NATIVE_ASSET);
      await expect(
        dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await vault.getAddress(), false),
      ).to.not.revert(ethers);
      expect(await dailyPolicy.admitterCount(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("G7: rotating between two admitters never trips the self-brick guard", async function () {
      await armViaVault();
      const second = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await verifier.getAddress());

      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await second.getAddress(), true);
      expect(await dailyPolicy.admitterCount(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(2n);
      await expect(
        dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await vault.getAddress(), false),
      ).to.not.revert(ethers);
      expect(await dailyPolicy.admitterCount(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(1n);
    });

    it("G8: setAdmitter is idempotent and keeps admitterCount exact", async function () {
      const v = await vault.getAddress();
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, true);
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, true);
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, true);
      expect(await dailyPolicy.admitterCount(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(1n);

      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, false);
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, false);
      expect(await dailyPolicy.admitterCount(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("G9: revoking a delegation takes effect immediately on the next admission", async function () {
      await armViaVault();
      await expect(withdrawSmall(ethers.parseEther("0.5"))).to.not.revert(ethers);

      // Add a second admitter so the last-admitter guard does not apply, then revoke
      // the vault's own delegation.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, owner.address, true);
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await vault.getAddress(), false);

      await expect(withdrawSmall(ethers.parseEther("0.5"), 1)).to.be.revertedWithCustomError(
        dailyPolicy,
        "UnauthorizedAdmitter",
      );
    });

    it("G10: the composite refuses zero, self, and code-less admission callers", async function () {
      await expect(composite.connect(admin).setAdmissionCaller(ethers.ZeroAddress, true)).to.be.revertedWithCustomError(
        composite,
        "ZeroModuleAddress",
      );
      await expect(
        composite.connect(admin).setAdmissionCaller(await composite.getAddress(), true),
      ).to.be.revertedWithCustomError(composite, "SelfModule");
      await expect(composite.connect(admin).setAdmissionCaller(attacker.address, true))
        .to.be.revertedWithCustomError(composite, "NoCode")
        .withArgs(attacker.address);
    });

    it("G12: INVARIANT — an armed subject always has at least one admitter", async function () {
      // Two guards jointly establish this, and every route into the forbidden state is
      // refused. The invariant is what makes a 'permissive when unconfigured' gate an
      // equivalent mutation rather than a hole: that state cannot be reached.
      const v = await vault.getAddress();

      // Route 1 — arm first, delegate later. Refused by the arming guard.
      await expect(
        dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT),
      ).to.be.revertedWithCustomError(dailyPolicy, "NoAdmitterConfigured");

      // Route 2 — delegate, arm, then revoke back to zero. Refused by the self-brick guard.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, true);
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);
      await expect(
        dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, false),
      ).to.be.revertedWithCustomError(dailyPolicy, "LastAdmitterWhileArmed");

      // Route 3 — grow to two, then revoke both. The second revocation is refused.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, owner.address, true);
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, v, false);
      expect(await dailyPolicy.admitterCount(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(1n);
      await expect(
        dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, owner.address, false),
      ).to.be.revertedWithCustomError(dailyPolicy, "LastAdmitterWhileArmed");

      // The invariant held throughout.
      expect(await dailyPolicy.dailyLimit(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(LIMIT);
      expect(await dailyPolicy.admitterCount(vaultAddress, owner.address, NATIVE_ASSET)).to.be.greaterThanOrEqual(1n);
    });

    it("G13: an engine ROTATION invalidates a delegation, and one tenant tx restores it", async function () {
      // Rotating to a new intermediary that still routes to the same module changes the
      // msg.sender the module observes, so the tenant's existing delegation stops matching.
      await armViaVault();
      await expect(withdrawSmall(ethers.parseEther("0.5"))).to.not.revert(ethers);

      const relay = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();
      await relay.connect(admin).addModule(await dailyPolicy.getAddress());
      await relay.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
      await setPolicyEngine(await relay.getAddress());

      // The tenant delegated to the vault, not to the relay — admissions now fail closed.
      await expect(withdrawSmall(ethers.parseEther("0.5"), 1)).to.be.revertedWithCustomError(
        dailyPolicy,
        "UnauthorizedAdmitter",
      );

      // Recovery is ONE permissionless transaction the tenant sends themselves.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await relay.getAddress(), true);
      await expect(withdrawSmall(ethers.parseEther("0.5"), 1)).to.not.revert(ethers);
    });

    it("G14: a rotation cannot strand an ALREADY-QUEUED withdrawal", async function () {
      // Settlement uses the ungated `revalidate`, so a delegation that no longer matches
      // blocks new admissions but never traps a withdrawal that was already admitted.
      await armViaVault();
      await enableLargeTx();
      const { operationId } = await queueLarge();

      const relay = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();
      await relay.connect(admin).addModule(await dailyPolicy.getAddress());
      await relay.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
      await setPolicyEngine(await relay.getAddress());

      await networkHelpers.time.increase(LARGE_TX_DELAY);
      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId)).to.emit(
        vault,
        "WithdrawalFinalized",
      );
    });

    it("G11: only the composite OWNER may register an admission caller", async function () {
      await expect(composite.connect(attacker).setAdmissionCaller(await vault.getAddress(), true))
        .to.be.revertedWithCustomError(composite, "OwnableUnauthorizedAccount")
        .withArgs(attacker.address);
    });

    it("G15: setAdmissionCaller grant/revoke emit AdmissionCallerSet with the right args", async function () {
      const v = await vault.getAddress();
      await expect(composite.connect(admin).setAdmissionCaller(v, true))
        .to.emit(composite, "AdmissionCallerSet")
        .withArgs(v, true);
      await expect(composite.connect(admin).setAdmissionCaller(v, false))
        .to.emit(composite, "AdmissionCallerSet")
        .withArgs(v, false);
    });

    it("G16: revoking a composite admission caller takes effect immediately — mirrors G9 at the composite hop", async function () {
      // Same shape as G9 (module-level revoke), one hop further out: a consumer that
      // was legitimately registered, then de-registered, must be refused exactly like
      // one that was never registered — setAdmissionCaller is not additive-only.
      await composite.connect(admin).addModule(await dailyPolicy.getAddress());
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, await composite.getAddress(), true);
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);
      await composite.connect(admin).setAdmissionCaller(await vault.getAddress(), true);
      await setPolicyEngine(await composite.getAddress());

      await expect(withdrawSmall(ethers.parseEther("0.5"))).to.not.revert(ethers);

      await composite.connect(admin).setAdmissionCaller(await vault.getAddress(), false);

      await expect(withdrawSmall(ethers.parseEther("0.5"), 1))
        .to.be.revertedWithCustomError(composite, "UnauthorizedAdmissionCaller")
        .withArgs(await vault.getAddress());
      // No partial effect: the denied attempt did not book against the allowance.
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - ethers.parseEther("0.5"));
    });
  });

  // =========================================================================
  // H — OPERATIONAL INTEGRATION: MISCONFIGURATION FAILS LOUD, NOT SILENT
  // =========================================================================
  describe("H — misconfigured wiring fails loud at the real vault boundary", function () {
    it("H1: a vault never delegated as admitter has EVERY real withdrawal blocked, not silently permitted", async function () {
      // Arm the limit through a throwaway admitter so configuration succeeds, then wire
      // the policy into the vault WITHOUT ever delegating the vault itself. This is the
      // exact operator mistake the split creates a new failure mode for: forgetting
      // setAdmitter after wiring a stateful policy in. It must fail CLOSED (block
      // withdrawals) and ATTRIBUTABLY (the real custom error, not a generic revert or a
      // silent bypass) — never fail OPEN.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, owner.address, true);
      await dailyPolicy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, LIMIT);
      await setPolicyEngine(await dailyPolicy.getAddress());

      await expect(withdrawSmall(ethers.parseEther("0.5")))
        .to.be.revertedWithCustomError(dailyPolicy, "UnauthorizedAdmitter")
        .withArgs(await vault.getAddress(), vaultAddress, owner.address, NATIVE_ASSET);
      expect(await allowanceOf(owner.address)).to.equal(LIMIT);

      // Wiring the missing delegation heals it immediately — this is a misconfiguration,
      // not a design dead end.
      await dailyPolicy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      await expect(withdrawSmall(ethers.parseEther("0.5"))).to.emit(vault, "Withdrawn");
      expect(await allowanceOf(owner.address)).to.equal(LIMIT - ethers.parseEther("0.5"));
    });
  });
});
