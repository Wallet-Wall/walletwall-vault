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
  SubjectRecordingPolicyMock,
  DailySpendPoisonerMock,
} from "../typechain-types";
import { makeBuildRequest, makeSignWithdrawal } from "./helpers/vaultHelpers";
import {
  makeBuildRequest as makeSimBuildRequest,
  makeSignWithdrawal as makeSimSignWithdrawal,
} from "./helpers/simulatorHelpers";
import { NATIVE_ASSET } from "./helpers/policySubject";

/**
 * POLICY SUBJECT PROPAGATION — the trust-boundary regression suite.
 *
 * The claim under test:
 *
 *   Every policy evaluation carries an explicit (consumer, owner, asset) subject
 *   constructed by the trusted vault execution path; CompositePolicyEngine preserves
 *   that subject exactly; and DailySpendLimitPolicy cannot mix spend across different
 *   consumers or assets.
 *
 * WHY A RECORDING PROBE RATHER THAN EQUALITY ASSERTIONS. A test that builds the
 * expected subject itself and compares it to what a policy returns is comparing two
 * values derived from the SAME test inputs; a composite that quietly rewrote a field
 * could still satisfy it if the test rebuilt the subject the same wrong way. The probe
 * ({SubjectRecordingPolicyMock}) instead reports the bytes that genuinely crossed the
 * module boundary, and records `msg.sender` alongside them. `msg.sender` is the field
 * that MUST differ between the direct and composite paths, so it doubles as proof that
 * the composite hop actually happened rather than being silently bypassed.
 *
 * Scope note: the tumbling-vs-rolling TIME semantics are deliberately unchanged and are
 * covered by test/DailySpendWindowSemantics.test.ts.
 */
describe("Policy subject propagation (trust boundary)", function () {
  const GOVERNANCE_DELAY = 2 * 24 * 60 * 60;
  const LARGE_TX_DELAY = 6 * 60 * 60;
  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const HYBRID = 2;
  const DEPOSIT = ethers.parseEther("20");
  const THRESHOLD = ethers.parseEther("1");
  const LARGE_AMOUNT = ethers.parseEther("2");
  const MUSDC = (n: number) => BigInt(n) * 1_000_000n;

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let recipient: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let attacker: HardhatEthersSigner;

  let verifier: MockMLDSAVerifier;
  let vault: WalletWallVault;
  let vaultAddress: string;
  let probe: SubjectRecordingPolicyMock;
  let composite: CompositePolicyEngine;
  let policy: DailySpendLimitPolicy;

  let buildRequest: ReturnType<typeof makeBuildRequest>;
  let signWithdrawal: ReturnType<typeof makeSignWithdrawal>;

  async function setEngine(v: WalletWallVault, engine: string) {
    await v.connect(admin).proposePolicyEngine(engine);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await v.connect(admin).applyPolicyEngine();
  }

  async function enableLargeTx(delay = LARGE_TX_DELAY) {
    await vault.connect(admin).proposeLargeTxParams(THRESHOLD, delay);
    await networkHelpers.time.increase(GOVERNANCE_DELAY);
    await vault.connect(admin).applyLargeTxParams();
  }

  async function withdrawSmall(amount = ethers.parseEther("0.5"), nonce?: number) {
    const req = await buildRequest({ recipient: recipient.address, amount, nonce });
    const { ecdsaSig, pqSig } = await signWithdrawal(req);
    return vault.connect(other).withdraw(req, ecdsaSig, pqSig);
  }

  /** Everything the probe observed on its most recent {check}. */
  async function observed() {
    return {
      consumer: await probe.lastConsumer(),
      owner: await probe.lastOwner(),
      asset: await probe.lastAsset(),
      caller: await probe.lastCaller(),
      recipient: await probe.lastRecipient(),
      amount: await probe.lastAmount(),
      vaultBalance: await probe.lastVaultBalance(),
      calls: await probe.checkCalls(),
    };
  }

  beforeEach(async function () {
    [admin, owner, recipient, other, attacker] = await ethers.getSigners();

    verifier = await (await ethers.getContractFactory("MockMLDSAVerifier", admin)).deploy();
    vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await verifier.getAddress());
    vaultAddress = await vault.getAddress();
    probe = await (await ethers.getContractFactory("SubjectRecordingPolicyMock", admin)).deploy();
    composite = await (await ethers.getContractFactory("CompositePolicyEngine", admin)).deploy();
    policy = await (await ethers.getContractFactory("DailySpendLimitPolicy", admin)).deploy();

    await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID);
    await vault.connect(owner).deposit({ value: DEPOSIT });

    buildRequest = makeBuildRequest(owner, { recipient: recipient.address, amount: LARGE_AMOUNT });
    signWithdrawal = makeSignWithdrawal(vault, owner);
  });

  // =========================================================================
  // A — DIRECT PATH IDENTITY
  // =========================================================================
  describe("A — the subject a vault mints on the direct path", function () {
    it("A1: WalletWallVault mints (this vault, authenticated owner, address(0))", async function () {
      await setEngine(vault, await probe.getAddress());
      await withdrawSmall();

      const seen = await observed();
      expect(seen.calls).to.equal(1n);
      expect(seen.consumer).to.equal(vaultAddress);
      expect(seen.owner).to.equal(owner.address);
      expect(seen.asset).to.equal(ethers.ZeroAddress);
      // The direct path's caller IS the consumer — no relay in between.
      expect(seen.caller).to.equal(vaultAddress);
    });

    it("A2: `owner` is the SIGNATURE-authenticated vault owner, never msg.sender", async function () {
      // `other` relays a request signed by `owner`. Relay is permissionless, so if the
      // subject took msg.sender the module would see the relayer. It must see the signer.
      await setEngine(vault, await probe.getAddress());
      const req = await buildRequest({ recipient: recipient.address, amount: ethers.parseEther("0.5") });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await vault.connect(attacker).withdraw(req, ecdsaSig, pqSig);

      const seen = await observed();
      expect(seen.owner).to.equal(owner.address);
      expect(seen.owner).to.not.equal(attacker.address);
      expect(seen.caller).to.equal(vaultAddress);
    });

    it("A3: the QUEUED admission path mints the identical subject", async function () {
      await setEngine(vault, await probe.getAddress());
      await enableLargeTx();
      const req = await buildRequest({ recipient: recipient.address, amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);

      const seen = await observed();
      expect(seen.consumer).to.equal(vaultAddress);
      expect(seen.owner).to.equal(owner.address);
      expect(seen.asset).to.equal(ethers.ZeroAddress);
      expect(seen.amount).to.equal(LARGE_AMOUNT);
    });

    it("A4: StablecoinVaultSimulator mints (this simulator, owner, immutable token)", async function () {
      const token: MockUSDC = await (await ethers.getContractFactory("MockUSDC")).deploy();
      const sim: StablecoinVaultSimulator = await (
        await ethers.getContractFactory("StablecoinVaultSimulator", admin)
      ).deploy(await token.getAddress(), await verifier.getAddress());

      await sim.connect(owner).createVault(owner.address, PQ_KEY, HYBRID);
      await token.connect(owner).mint(owner.address, MUSDC(500));
      await token.connect(owner).approve(await sim.getAddress(), MUSDC(500));
      await sim.connect(owner).deposit(MUSDC(500));

      await sim.connect(admin).proposePolicyEngine(await probe.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPolicyEngine();

      const simBuild = makeSimBuildRequest(owner, { recipient: recipient.address, amount: MUSDC(100) });
      const simSign = makeSimSignWithdrawal(sim, owner);
      const req = await simBuild({ recipient: recipient.address, amount: MUSDC(100) });
      const { ecdsaSig, pqSig } = await simSign(req);
      await sim.connect(other).withdraw(req, ecdsaSig, pqSig);

      const seen = await observed();
      expect(seen.consumer).to.equal(await sim.getAddress());
      expect(seen.owner).to.equal(owner.address);
      expect(seen.asset).to.equal(await token.getAddress());
      expect(seen.asset).to.not.equal(ethers.ZeroAddress); // never collides with native ETH
      expect(seen.amount).to.equal(MUSDC(100));
    });

    it("A5: two vault CONTRACTS mint distinguishable subjects for the same owner", async function () {
      const vaultB = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await verifier.getAddress());
      await vaultB.connect(owner).createVault(owner.address, PQ_KEY, HYBRID);
      await vaultB.connect(owner).deposit({ value: DEPOSIT });

      await setEngine(vault, await probe.getAddress());
      await setEngine(vaultB, await probe.getAddress());

      await withdrawSmall();
      expect((await observed()).consumer).to.equal(vaultAddress);

      const reqB = {
        vaultOwner: owner.address,
        recipient: recipient.address,
        amount: ethers.parseEther("0.5"),
        nonce: 0,
        deadline: (await networkHelpers.time.latest()) + 3600,
        vaultMode: HYBRID,
      };
      const sigB = await makeSignWithdrawal(vaultB, owner)(reqB);
      await vaultB.connect(other).withdraw(reqB, sigB.ecdsaSig, sigB.pqSig);
      expect((await observed()).consumer).to.equal(await vaultB.getAddress());
    });
  });

  // =========================================================================
  // B — COMPOSITE PRESERVES THE SUBJECT EXACTLY
  // =========================================================================
  describe("B — CompositePolicyEngine relays the subject unchanged", function () {
    beforeEach(async function () {
      await composite.connect(admin).addModule(await probe.getAddress());
      await composite.connect(admin).setAdmissionCaller(vaultAddress, true);
      await setEngine(vault, await composite.getAddress());
    });

    it("B1: subject_out == subject_in at the module boundary, while msg.sender CHANGES", async function () {
      await withdrawSmall();
      const seen = await observed();

      // Every subject field survives the hop untouched…
      expect(seen.consumer).to.equal(vaultAddress);
      expect(seen.owner).to.equal(owner.address);
      expect(seen.asset).to.equal(ethers.ZeroAddress);

      // …and the hop demonstrably happened: the module's caller is the COMPOSITE.
      // Without this the assertions above would also pass on a direct wiring, so the
      // test would not be exercising the relay at all.
      expect(seen.caller).to.equal(await composite.getAddress());
      expect(seen.caller).to.not.equal(vaultAddress);
    });

    it("B2: the composite does NOT substitute address(this) for subject.consumer", async function () {
      // The single most likely regression: a composite that "helpfully" re-mints the
      // subject from its own context. Asserted as an explicit inequality so the failure
      // message names the defect.
      await withdrawSmall();
      const seen = await observed();
      expect(seen.consumer).to.not.equal(await composite.getAddress());
      expect(seen.consumer).to.equal(vaultAddress);
    });

    it("B3: the composite does NOT zero the asset dimension", async function () {
      // For the ETH vault address(0) is the CORRECT asset, so a dropped-asset bug is
      // invisible here. Run the check through the token simulator, where the correct
      // value is non-zero and an erasure would show up.
      const token: MockUSDC = await (await ethers.getContractFactory("MockUSDC")).deploy();
      const sim: StablecoinVaultSimulator = await (
        await ethers.getContractFactory("StablecoinVaultSimulator", admin)
      ).deploy(await token.getAddress(), await verifier.getAddress());

      await sim.connect(owner).createVault(owner.address, PQ_KEY, HYBRID);
      await token.connect(owner).mint(owner.address, MUSDC(500));
      await token.connect(owner).approve(await sim.getAddress(), MUSDC(500));
      await sim.connect(owner).deposit(MUSDC(500));

      await composite.connect(admin).setAdmissionCaller(await sim.getAddress(), true);
      await sim.connect(admin).proposePolicyEngine(await composite.getAddress());
      await networkHelpers.time.increase(GOVERNANCE_DELAY);
      await sim.connect(admin).applyPolicyEngine();

      const simBuild = makeSimBuildRequest(owner, { recipient: recipient.address, amount: MUSDC(100) });
      const simSign = makeSimSignWithdrawal(sim, owner);
      const req = await simBuild({ recipient: recipient.address, amount: MUSDC(100) });
      const { ecdsaSig, pqSig } = await simSign(req);
      await sim.connect(other).withdraw(req, ecdsaSig, pqSig);

      const seen = await observed();
      expect(seen.asset).to.equal(await token.getAddress());
      expect(seen.asset).to.not.equal(ethers.ZeroAddress);
      expect(seen.consumer).to.equal(await sim.getAddress());
      expect(seen.caller).to.equal(await composite.getAddress());
    });

    it("B4: the composite relays the subject to EVERY module, not just the first", async function () {
      const probe2: SubjectRecordingPolicyMock = await (
        await ethers.getContractFactory("SubjectRecordingPolicyMock", admin)
      ).deploy();
      await composite.connect(admin).addModule(await probe2.getAddress());

      await withdrawSmall();

      for (const p of [probe, probe2]) {
        expect(await p.checkCalls()).to.equal(1n);
        expect(await p.lastConsumer()).to.equal(vaultAddress);
        expect(await p.lastOwner()).to.equal(owner.address);
        expect(await p.lastAsset()).to.equal(ethers.ZeroAddress);
      }
    });

    it("B5: REVALIDATION carries the same subject as admission", async function () {
      // revalidate is view, so the probe cannot record. It encodes the subject it saw
      // into its denial reason, which the vault surfaces verbatim as PolicyViolation.
      await enableLargeTx();
      const req = await buildRequest({ recipient: recipient.address, amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
      const operationId = await vault.hashWithdrawal(req);

      await probe.setDenyOnRevalidate(true);
      await networkHelpers.time.increase(LARGE_TX_DELAY);

      const expected = [
        "subject",
        vaultAddress.slice(2).toLowerCase(),
        owner.address.slice(2).toLowerCase(),
        ethers.ZeroAddress.slice(2).toLowerCase(),
      ].join(":");

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyViolation")
        .withArgs(expected);
    });

    it("B6: a stale subject cannot be reused — a second withdrawal re-mints from live state", async function () {
      await withdrawSmall(ethers.parseEther("0.5"), 0);
      const first = await observed();

      // A different tenant on the SAME vault must produce a different subject, proving
      // the vault does not cache or reuse whatever it built last time.
      await vault.connect(attacker).createVault(attacker.address, PQ_KEY, HYBRID);
      await vault.connect(attacker).deposit({ value: ethers.parseEther("5") });
      const req = {
        vaultOwner: attacker.address,
        recipient: recipient.address,
        amount: ethers.parseEther("0.5"),
        nonce: 0,
        deadline: (await networkHelpers.time.latest()) + 3600,
        vaultMode: HYBRID,
      };
      const sig = await makeSignWithdrawal(vault, attacker)(req);
      await vault.connect(other).withdraw(req, sig.ecdsaSig, sig.pqSig);

      const second = await observed();
      expect(second.owner).to.equal(attacker.address);
      expect(second.owner).to.not.equal(first.owner);
      expect(second.consumer).to.equal(first.consumer); // same vault, correctly
    });
  });

  // =========================================================================
  // C — SPOOFING IS REFUSED
  // =========================================================================
  describe("C — a caller cannot choose someone else's subject", function () {
    let poisoner: DailySpendPoisonerMock;

    beforeEach(async function () {
      poisoner = await (await ethers.getContractFactory("DailySpendPoisonerMock", attacker)).deploy();
      await policy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      await policy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, ethers.parseEther("5"));
      await setEngine(vault, await policy.getAddress());
    });

    it("C1: SPOOFED CONSUMER — spend cannot be booked under another consumer", async function () {
      const poisonerAddress = await poisoner.getAddress();
      // The relay names the tenant's real vault as consumer. The delegation for that
      // subject names the VAULT, so the relay is refused.
      await expect(
        poisoner
          .connect(attacker)
          .poison(
            await policy.getAddress(),
            vaultAddress,
            owner.address,
            NATIVE_ASSET,
            attacker.address,
            ethers.parseEther("5"),
            0n,
          ),
      )
        .to.be.revertedWithCustomError(policy, "UnauthorizedAdmitter")
        .withArgs(poisonerAddress, vaultAddress, owner.address, NATIVE_ASSET);

      expect(await policy.remainingAllowance(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(
        ethers.parseEther("5"),
      );
    });

    it("C2: SPOOFED ASSET — claiming a different asset reaches a different, unarmed bucket", async function () {
      const token: MockUSDC = await (await ethers.getContractFactory("MockUSDC")).deploy();
      const tokenAddress = await token.getAddress();

      // The owner armed only (vault, owner, ETH). Naming a token asset addresses a
      // bucket that was never armed, so no allowance can be escaped or consumed there…
      await poisoner
        .connect(attacker)
        .poison(
          await policy.getAddress(),
          vaultAddress,
          owner.address,
          tokenAddress,
          attacker.address,
          ethers.parseEther("5"),
          0n,
        );

      // …and the ARMED ETH bucket is untouched by that call.
      expect(await policy.remainingAllowance(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(
        ethers.parseEther("5"),
      );

      // Nor can a spoofed asset be used to ESCAPE an armed cap: the real vault always
      // mints address(0), so the tenant's ETH withdrawals still consume the ETH bucket.
      await withdrawSmall(ethers.parseEther("1"));
      expect(await policy.remainingAllowance(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(
        ethers.parseEther("4"),
      );
    });

    it("C3: SPOOFED OWNER — naming another tenant does not reach their bucket", async function () {
      await policy.connect(attacker).setAdmitter(vaultAddress, NATIVE_ASSET, await poisoner.getAddress(), true);
      await policy.connect(attacker).setDailyLimit(vaultAddress, NATIVE_ASSET, ethers.parseEther("5"));

      // The poisoner IS delegated — but only for the attacker's own subject. Presenting
      // the victim's owner address selects the victim's delegation list, which the
      // poisoner is absent from.
      await expect(
        poisoner
          .connect(attacker)
          .poison(
            await policy.getAddress(),
            vaultAddress,
            owner.address,
            NATIVE_ASSET,
            attacker.address,
            ethers.parseEther("5"),
            0n,
          ),
      ).to.be.revertedWithCustomError(policy, "UnauthorizedAdmitter");

      expect(await policy.remainingAllowance(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(
        ethers.parseEther("5"),
      );
    });

    it("C4: the composite refuses a registered consumer that claims to be a DIFFERENT consumer", async function () {
      const vaultB = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await verifier.getAddress());
      const poisonerAddress = await poisoner.getAddress();
      await composite.connect(admin).addModule(await policy.getAddress());
      // Both the relay and vault B are legitimately registered consumers…
      await composite.connect(admin).setAdmissionCaller(poisonerAddress, true);
      await composite.connect(admin).setAdmissionCaller(await vaultB.getAddress(), true);

      // …but registration is not permission to impersonate. The relay naming vault B is
      // refused by the consumer binding, before any module is reached.
      await expect(
        poisoner
          .connect(attacker)
          .poison(
            await composite.getAddress(),
            await vaultB.getAddress(),
            owner.address,
            NATIVE_ASSET,
            attacker.address,
            1n,
            0n,
          ),
      )
        .to.be.revertedWithCustomError(composite, "SubjectConsumerMismatch")
        .withArgs(await vaultB.getAddress(), poisonerAddress);
    });
  });

  // =========================================================================
  // D — DELEGATION ISOLATION
  // =========================================================================
  describe("D — admission delegation is per subject", function () {
    it("D1: authority for one subject does not authorize another", async function () {
      const vaultB = await (
        await ethers.getContractFactory("WalletWallVault", admin)
      ).deploy(await verifier.getAddress());
      const b = await vaultB.getAddress();
      const token: MockUSDC = await (await ethers.getContractFactory("MockUSDC")).deploy();
      const tokenAddress = await token.getAddress();

      await policy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);

      // Same delegate, different consumer → not authorized.
      expect(await policy.admitter(b, owner.address, NATIVE_ASSET, vaultAddress)).to.equal(false);
      // Same consumer + delegate, different asset → not authorized.
      expect(await policy.admitter(vaultAddress, owner.address, tokenAddress, vaultAddress)).to.equal(false);
      // Same consumer + asset + delegate, different owner → not authorized.
      expect(await policy.admitter(vaultAddress, attacker.address, NATIVE_ASSET, vaultAddress)).to.equal(false);
      // The one that WAS granted.
      expect(await policy.admitter(vaultAddress, owner.address, NATIVE_ASSET, vaultAddress)).to.equal(true);
    });

    it("D2: only the subject's OWNER can write its delegation — msg.sender fills the owner slot", async function () {
      // The attacker calls the setter naming the victim's vault as consumer. There is no
      // owner parameter to supply, so the write lands on the ATTACKER'S subject.
      await policy.connect(attacker).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);

      expect(await policy.admitter(vaultAddress, attacker.address, NATIVE_ASSET, vaultAddress)).to.equal(true);
      expect(await policy.admitter(vaultAddress, owner.address, NATIVE_ASSET, vaultAddress)).to.equal(false);
    });

    it("D3: arming a limit is likewise owner-slotted and per subject", async function () {
      await policy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true);
      await policy.connect(owner).setDailyLimit(vaultAddress, NATIVE_ASSET, ethers.parseEther("3"));

      expect(await policy.dailyLimit(vaultAddress, owner.address, NATIVE_ASSET)).to.equal(ethers.parseEther("3"));
      expect(await policy.dailyLimit(vaultAddress, attacker.address, NATIVE_ASSET)).to.equal(0n);
    });

    it("D4: a subject with no originating consumer is refused at configuration time", async function () {
      // address(0) can never be a consumer — no vault has that address — so a bucket
      // keyed there would be permanently unreachable and would give a false sense of
      // being capped. The ASSET may be address(0): that is native ETH.
      await expect(
        policy.connect(owner).setAdmitter(ethers.ZeroAddress, NATIVE_ASSET, vaultAddress, true),
      ).to.be.revertedWithCustomError(policy, "ZeroConsumer");
      await expect(
        policy.connect(owner).setDailyLimit(ethers.ZeroAddress, NATIVE_ASSET, 1n),
      ).to.be.revertedWithCustomError(policy, "ZeroConsumer");

      // The asymmetry: a zero ASSET is accepted, because it is meaningful.
      await expect(policy.connect(owner).setAdmitter(vaultAddress, NATIVE_ASSET, vaultAddress, true)).to.not.revert(
        ethers,
      );
    });
  });

  // =========================================================================
  // E — SUBJECT KEYING
  // =========================================================================
  describe("E — subjectKey binds all three fields unambiguously", function () {
    it("E1: the key equals keccak256(abi.encode(consumer, owner, asset))", async function () {
      const a = ethers.Wallet.createRandom().address;
      const b = ethers.Wallet.createRandom().address;
      const c = ethers.Wallet.createRandom().address;

      const expected = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["address", "address", "address"], [a, b, c]),
      );
      expect(await policy.subjectKey({ consumer: a, owner: b, asset: c })).to.equal(expected);
    });

    it("E2: EXACT FIELD SEPARATION — permuting the fields yields distinct keys", async function () {
      const a = ethers.Wallet.createRandom().address;
      const b = ethers.Wallet.createRandom().address;
      const c = ethers.Wallet.createRandom().address;

      const permutations: [string, string, string][] = [
        [a, b, c],
        [a, c, b],
        [b, a, c],
        [b, c, a],
        [c, a, b],
        [c, b, a],
      ];
      const keys = await Promise.all(
        permutations.map(([consumer, owner_, asset]) => policy.subjectKey({ consumer, owner: owner_, asset })),
      );
      expect(new Set(keys).size).to.equal(permutations.length);
    });

    it("E3: no field can be shifted into another — abi.encode pads to fixed width", async function () {
      // The classic packed-concatenation hazard: with a variable-width encoding, moving
      // characters across a field boundary can collide. Fixed 32-byte padding forecloses
      // it. Demonstrated on adjacent-value addresses, where a packed scheme is weakest.
      const zero = ethers.ZeroAddress;
      const one = "0x" + "00".repeat(19) + "01";
      const k1 = await policy.subjectKey({ consumer: one, owner: zero, asset: zero });
      const k2 = await policy.subjectKey({ consumer: zero, owner: one, asset: zero });
      const k3 = await policy.subjectKey({ consumer: zero, owner: zero, asset: one });
      expect(new Set([k1, k2, k3]).size).to.equal(3);
    });
  });

  // =========================================================================
  // F — NO SUBJECTLESS LEGACY PATH
  // =========================================================================
  describe("F — a pre-subject engine fails closed in both directions", function () {
    it("F1: admission reverts rather than silently allowing", async function () {
      const legacy = await (await ethers.getContractFactory("SubjectlessLegacyPolicyMock", admin)).deploy();
      await setEngine(vault, await legacy.getAddress());

      // The vault emits check((address,address,address),address,uint256,uint256); the
      // legacy engine only answers check(address,address,uint256,uint256). The dispatcher
      // finds no match and reverts, so the withdrawal cannot proceed.
      await expect(withdrawSmall()).to.revert(ethers);
    });

    it("F2: settlement reports PolicyEngineUnavailable rather than granting", async function () {
      const legacy = await (await ethers.getContractFactory("SubjectlessLegacyPolicyMock", admin)).deploy();

      // Queue with NO engine, then install the legacy one as the current engine so the
      // failure surfaces at revalidation rather than at admission.
      await enableLargeTx();
      const req = await buildRequest({ recipient: recipient.address, amount: LARGE_AMOUNT });
      const { ecdsaSig, pqSig } = await signWithdrawal(req);
      await vault.connect(other).queueWithdrawal(req, ecdsaSig, pqSig);
      const operationId = await vault.hashWithdrawal(req);

      await setEngine(vault, await legacy.getAddress());
      await networkHelpers.time.increase(LARGE_TX_DELAY);

      await expect(vault.connect(owner).finalizeWithdrawal(owner.address, operationId))
        .to.be.revertedWithCustomError(vault, "PolicyEngineUnavailable")
        .withArgs(await legacy.getAddress());

      // Fail-closed, not fund-trapping: the ungated escape still works.
      await expect(vault.connect(owner).cancelPendingWithdrawal(operationId)).to.not.revert(ethers);
    });
  });
});
