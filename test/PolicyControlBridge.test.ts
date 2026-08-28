import { expect } from "chai";
import { ethers, networkHelpers } from "./helpers/connection";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { WalletWallVault, MockMLDSAVerifier, PolicyControlBridge, PolicyControlTargetMock } from "../typechain-types";

/**
 * PolicyControlBridge — the canonical authentication layer for the v0.13.0 policy-control
 * authority lane (design doc §5, §6, §6.3).
 *
 * This suite proves the CORE pipeline shared by every bridge action, exercised through
 * enrollController (the first and most safety-critical action, per U2): EIP-712 domain
 * binding, a dedicated (consumer, owner) nonce independent of the withdrawal nonce,
 * deadline enforcement, epoch binding against the vault's CURRENT policyControlEpoch, and
 * dual ECDSA/PQ signature verification against the vault's CURRENT credentials (read live,
 * never cached) — reusing the vault's OWN configured pqVerifier, per the corrected L6.
 *
 * The EnrollController struct here includes `asset`, unlike the doc's illustrative sketch,
 * to stay consistent with every other action and with SpendState's own per-(consumer,
 * owner, asset) granularity — see the PR description for why that's a deliberate
 * conservative correction rather than a redesign.
 */
describe("PolicyControlBridge — core authentication pipeline", function () {
  const PQ_KEY = ethers.hexlify(ethers.randomBytes(1952));
  const HYBRID = 2;
  const NATIVE_ASSET = ethers.ZeroAddress;

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

  let admin: HardhatEthersSigner;
  let owner: HardhatEthersSigner;
  let attacker: HardhatEthersSigner;
  let newSigner: HardhatEthersSigner;
  let verifier: MockMLDSAVerifier;
  let vault: WalletWallVault;
  let bridge: PolicyControlBridge;
  let target: PolicyControlTargetMock;
  let pauser: HardhatEthersSigner;

  async function bridgeDomain() {
    return {
      name: "WalletWallPolicyControlBridge",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await bridge.getAddress(),
    };
  }

  /** Builds a validly-signed EnrollController intent for `owner`, current credentials. */
  async function signEnroll(overrides: Partial<Record<string, unknown>> = {}) {
    const deadline = (overrides.deadline as number) ?? (await networkHelpers.time.latest()) + 3600;
    const nonce = (overrides.nonce as bigint) ?? (await bridge.controlNonce(await vault.getAddress(), owner.address));
    const epoch = (overrides.epoch as bigint) ?? (await vault.policyControlEpoch(owner.address));
    const request = {
      consumer: (overrides.consumer as string) ?? (await vault.getAddress()),
      owner: (overrides.owner as string) ?? owner.address,
      policy: (overrides.policy as string) ?? (await target.getAddress()),
      asset: (overrides.asset as string) ?? NATIVE_ASSET,
      controller: (overrides.controller as string) ?? (await bridge.getAddress()),
      epoch,
      nonce,
      deadline,
    };
    const domain = await bridgeDomain();
    const signer = (overrides.signer as HardhatEthersSigner) ?? owner;
    const ecdsaSignature = await signer.signTypedData(domain, ENROLL_TYPES, request);
    const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    return { request, ecdsaSignature, pqSignature, deadline };
  }

  beforeEach(async function () {
    [admin, owner, attacker, newSigner, pauser] = await ethers.getSigners();
    const Verifier = await ethers.getContractFactory("MockMLDSAVerifier");
    verifier = await Verifier.deploy();
    await verifier.waitForDeployment();

    const Vault = await ethers.getContractFactory("WalletWallVault", admin);
    vault = await Vault.deploy(await verifier.getAddress());
    await vault.waitForDeployment();
    await vault.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

    const Bridge = await ethers.getContractFactory("PolicyControlBridge");
    bridge = await Bridge.deploy(pauser.address);
    await bridge.waitForDeployment();

    const Target = await ethers.getContractFactory("PolicyControlTargetMock");
    target = await Target.deploy();
    await target.waitForDeployment();
  });

  it("constructor: a zero emergencyPauser reverts ZeroEmergencyPauser — zero would permanently remove the L11 circuit breaker", async function () {
    const Bridge = await ethers.getContractFactory("PolicyControlBridge");
    await expect(Bridge.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(Bridge, "ZeroEmergencyPauser");
  });

  it("constructor: a real (EOA) emergencyPauser deploys successfully — it is never called as a contract, so no code-length check applies", async function () {
    const Bridge = await ethers.getContractFactory("PolicyControlBridge");
    await expect(Bridge.deploy(pauser.address)).to.not.revert(ethers);
  });

  it("forwards a validly-signed enrollController intent to the named policy", async function () {
    const { request, ecdsaSignature, pqSignature } = await signEnroll();
    await bridge.enrollController(request, ecdsaSignature, pqSignature);

    expect(await target.callCount()).to.equal(1n);
    expect(await target.lastCaller()).to.equal(await bridge.getAddress());
    expect(await target.lastConsumer()).to.equal(await vault.getAddress());
    expect(await target.lastOwner()).to.equal(owner.address);
    expect(await target.lastAsset()).to.equal(NATIVE_ASSET);
    expect(await target.lastController()).to.equal(await bridge.getAddress());
  });

  it("consumes the (consumer, owner) nonce on success", async function () {
    const before = await bridge.controlNonce(await vault.getAddress(), owner.address);
    const { request, ecdsaSignature, pqSignature } = await signEnroll();
    await bridge.enrollController(request, ecdsaSignature, pqSignature);
    expect(await bridge.controlNonce(await vault.getAddress(), owner.address)).to.equal(before + 1n);
  });

  it("REPLAY: the same signed intent cannot be submitted twice (M7)", async function () {
    const { request, ecdsaSignature, pqSignature } = await signEnroll();
    await bridge.enrollController(request, ecdsaSignature, pqSignature);
    await expect(bridge.enrollController(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "InvalidNonce",
    );
  });

  it("an intent signed but never submitted consumes no nonce (§10.6)", async function () {
    await signEnroll(); // signed, never submitted
    expect(await bridge.controlNonce(await vault.getAddress(), owner.address)).to.equal(0n);
  });

  it("DEADLINE: an expired intent is refused", async function () {
    const past = (await networkHelpers.time.latest()) - 10;
    const { request, ecdsaSignature, pqSignature } = await signEnroll({ deadline: past });
    await expect(bridge.enrollController(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "IntentExpired",
    );
  });

  it("CROSS-CONSUMER: a signature is bound to its consumer and cannot be replayed against another (M8)", async function () {
    const Vault2 = await ethers.getContractFactory("WalletWallVault", admin);
    const vault2 = await Vault2.deploy(await verifier.getAddress());
    await vault2.waitForDeployment();
    await vault2.connect(owner).createVault(owner.address, PQ_KEY, HYBRID, { value: ethers.parseEther("10") });

    // Signed for vault2, but the request's consumer field is what's actually hashed —
    // an attacker cannot simply relabel it, because that changes the digest.
    const { request, ecdsaSignature, pqSignature } = await signEnroll({ consumer: await vault2.getAddress() });
    const forged = { ...request, consumer: await vault.getAddress() };

    await expect(bridge.enrollController(forged, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "InvalidEcdsaSignature",
    );
  });

  it("CROSS-POLICY: a signature is bound to its named policy target", async function () {
    const Target2 = await ethers.getContractFactory("PolicyControlTargetMock");
    const target2 = await Target2.deploy();
    await target2.waitForDeployment();

    const { request, ecdsaSignature, pqSignature } = await signEnroll({ policy: await target2.getAddress() });
    const forged = { ...request, policy: await target.getAddress() };

    await expect(bridge.enrollController(forged, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "InvalidEcdsaSignature",
    );
  });

  it("STALE SIGNER: a signature from a non-current ecdsaSigner is refused", async function () {
    const { request, pqSignature } = await signEnroll();
    const wrongSignature = await attacker.signTypedData(await bridgeDomain(), ENROLL_TYPES, request);
    await expect(bridge.enrollController(request, wrongSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "InvalidEcdsaSignature",
    );
  });

  it("READS CREDENTIALS LIVE: rotating after signing invalidates the intent (via the epoch gate)", async function () {
    // Sign now (while `owner` is current), THEN rotate credentials before submitting.
    // Rotation bumps BOTH the signer and the epoch, so this exercises both gates at
    // once; the epoch check fires first (see the dedicated STALE EPOCH test below for
    // the case that isolates the epoch gate from signature recovery).
    const { request, ecdsaSignature, pqSignature } = await signEnroll();

    const deadline = (await networkHelpers.time.latest()) + 3600;
    const domain = {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
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
    const rotationReq = {
      vaultOwner: owner.address,
      newEcdsaSigner: newSigner.address,
      newPQPublicKey: newPq,
      nonce: Number(await vault.nonces(owner.address)),
      deadline,
    };
    const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    await vault.rotateCredentials(owner.address, newSigner.address, newPq, deadline, {
      currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, rotationReq),
      currentPqSignature: blob(),
      newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, rotationReq),
      newPqSignature: blob(),
    });

    // The intent was signed before rotation; it now fails on BOTH grounds that would
    // independently catch this — a stale signer AND a stale epoch. The epoch gate runs
    // first in this implementation, so that is the error surfaced here.
    await expect(bridge.enrollController(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "StaleControlEpoch",
    );
  });

  it("STALE EPOCH: a correctly-signed-but-outdated epoch is refused even by the NEW signer (§9.8)", async function () {
    // Build the intent, sign it with the CURRENT (soon-to-be-old) owner, at the CURRENT
    // epoch — then rotate, then attempt to submit. This proves the epoch check closes the
    // gap independent of signature-recovery: a stale epoch is refused on its own.
    const requestFields = await signEnroll();

    const deadline = (await networkHelpers.time.latest()) + 3600;
    const domain = {
      name: "WalletWallVault",
      version: "1",
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await vault.getAddress(),
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
    const rotationReq = {
      vaultOwner: owner.address,
      newEcdsaSigner: newSigner.address,
      newPQPublicKey: newPq,
      nonce: Number(await vault.nonces(owner.address)),
      deadline,
    };
    const blob = () => ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));
    await vault.rotateCredentials(owner.address, newSigner.address, newPq, deadline, {
      currentEcdsaSignature: await owner.signTypedData(domain, ROTATION_TYPES, rotationReq),
      currentPqSignature: blob(),
      newEcdsaSignature: await newSigner.signTypedData(domain, ROTATION_TYPES, rotationReq),
      newPqSignature: blob(),
    });

    // Have the NEW signer re-sign the SAME logical request but keep the OLD (now stale)
    // epoch value baked in, simulating a signature that was crafted just before rotation.
    const domain2 = await bridgeDomain();
    const staleRequest = {
      ...requestFields.request,
      nonce: await bridge.controlNonce(await vault.getAddress(), owner.address),
    };
    const ecdsaSignature = await newSigner.signTypedData(domain2, ENROLL_TYPES, staleRequest);
    const pqSignature = ethers.hexlify(ethers.concat(["0x01", ethers.randomBytes(3308)]));

    await expect(bridge.enrollController(staleRequest, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "StaleControlEpoch",
    );
  });

  it("PAUSE: pauser may pause; blocks all further enrollController calls", async function () {
    await bridge.connect(pauser).pause();
    const { request, ecdsaSignature, pqSignature } = await signEnroll();
    await expect(bridge.enrollController(request, ecdsaSignature, pqSignature)).to.be.revertedWithCustomError(
      bridge,
      "BridgeIsPaused",
    );
  });

  it("PAUSE emits the BridgeRetired event", async function () {
    await expect(bridge.connect(pauser).pause()).to.emit(bridge, "BridgeRetired");
  });

  it("PAUSE: only the configured pauser may pause, not the vault admin or anyone else", async function () {
    await expect(bridge.connect(admin).pause()).to.be.revertedWithCustomError(bridge, "NotPauser");
    await expect(bridge.connect(owner).pause()).to.be.revertedWithCustomError(bridge, "NotPauser");
  });

  it("PAUSE: is one-way — no callable path returns paused to false (M13)", async function () {
    await bridge.connect(pauser).pause();
    expect(await bridge.paused()).to.equal(true);
    const iface = bridge.interface;
    const hasUnpause = iface.fragments.some((f) => f.type === "function" && "name" in f && f.name === "unpause");
    expect(hasUnpause).to.equal(false);
  });

  it("PAUSE: is idempotent-safe to call once, and a second call is refused rather than silently no-op", async function () {
    await bridge.connect(pauser).pause();
    await expect(bridge.connect(pauser).pause()).to.be.revertedWithCustomError(bridge, "AlreadyPaused");
  });
});
