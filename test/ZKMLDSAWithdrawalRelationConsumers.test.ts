import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import { ethers, networkHelpers } from "./helpers/connection";
import { WITHDRAWAL_TYPES, withdrawalDomain } from "./helpers/vaultHelpers";
import { ProverClient } from "../scripts/prover-client";

/**
 * The withdrawal relation through every PQ consumer of a ZKMLDSAVerifier: WalletWallVault withdrawals
 * (PqOnly, the Hybrid PQ leg, queued large withdrawals), credential rotation, the PQ threshold of
 * WalletWallMultiSigVault and PolicyControlBridge authentication.
 *
 * Which journals a program commits — and so which proofs can exist — comes from the real guest program
 * sources, run natively by `guest-native-execute` (zkvm/relation-tests). `ProgramBoundMockSP1Verifier`
 * then verifies a proof only for a (program vkey, journal) pair a program execution produced, so each
 * consumer sees exactly the proofs a prover could have made. The vkeys are labelled test identities.
 *
 * Forged routes use every stdin layout a prover could choose, including the message/context fields of
 * the pre-remediation guest. If the withdrawal program ever accepted one, the resulting proof is
 * registered and submitted, and the consumer must still refuse it; the program must also refuse every
 * layout outright. The attacker holds whatever classical signature the mode needs and PQ signatures the
 * key made over other messages, never the PQ secret key.
 *
 * Needs the executor: `cargo build --locked --manifest-path zkvm/relation-tests/Cargo.toml --bin
 * guest-native-execute`, then set SP1_RELATION_EXECUTOR to the binary. Skipped locally without it;
 * required in CI.
 */
const configuredExecutor = process.env.SP1_RELATION_EXECUTOR;
const executor =
  configuredExecutor === undefined
    ? undefined
    : isAbsolute(configuredExecutor)
      ? configuredExecutor
      : resolve(configuredExecutor);
const requiredInCi = process.env.CI === "true";

type ExecutionResult = { accepted: boolean; publicValues?: string; reason?: string; committed?: string };

function runProgram(request: object): ExecutionResult {
  if (executor === undefined) throw new Error("SP1_RELATION_EXECUTOR is not set");
  const dir = mkdtempSync(join(tmpdir(), "relation-exec-"));
  try {
    const requestPath = join(dir, "request.json");
    writeFileSync(requestPath, JSON.stringify(request));
    const result = spawnSync(executor, [requestPath], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    if (result.error) throw new Error(`failed to launch ${executor}: ${result.error.message}`);
    if (result.status !== 0) throw new Error(`guest-native-execute exited ${result.status}: ${result.stderr}`);
    return JSON.parse(result.stdout) as ExecutionResult;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** bincode 1 (the encoding `SP1Stdin::write` uses): u64 little-endian lengths, raw fixed arrays. */
function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function bincodeBytes(bytes: Uint8Array): Uint8Array {
  return ethers.getBytes(ethers.concat([u64le(BigInt(bytes.length)), bytes]));
}

function acvpStdin(publicKey: Uint8Array, message: Uint8Array, context: Uint8Array, signature: Uint8Array) {
  return ethers.concat([
    bincodeBytes(publicKey),
    bincodeBytes(message),
    bincodeBytes(context),
    bincodeBytes(signature),
  ]);
}

describe("ZKMLDSAVerifier consumers: the withdrawal relation through the vault, MultiSig and PolicyControlBridge", function () {
  const ECDSA_ONLY = 0;
  const PQ_ONLY = 1;
  const HYBRID = 2;
  const WITHDRAWAL_PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("test identity: mldsa65-withdrawal program"));
  const ACVP_PROGRAM_VKEY = ethers.keccak256(ethers.toUtf8Bytes("test identity: mldsa65-acvp program"));
  const ROTATE_TYPES = {
    RotateCredentials: [
      { name: "vaultOwner", type: "address" },
      { name: "newEcdsaSigner", type: "address" },
      { name: "newPQPublicKey", type: "bytes" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const MULTISIG_TYPES = {
    MultiSigWithdrawal: [
      { name: "vaultOwner", type: "address" },
      { name: "recipient", type: "address" },
      { name: "amount", type: "uint256" },
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

  let sp1: any;
  let vault: any;
  let admin: any;
  let owner: any;
  let attacker: any;
  let recipient: any;
  let pauser: any;
  let chainId: bigint;
  let verifierAddress: string;

  before(function () {
    if (executor === undefined) {
      if (requiredInCi) {
        throw new Error(
          "SP1_RELATION_EXECUTOR must point at guest-native-execute in CI " +
            "(cargo build --locked --manifest-path zkvm/relation-tests/Cargo.toml --bin guest-native-execute)",
        );
      }
      this.skip();
    }
    if (!existsSync(executor!)) throw new Error(`${executor} not found`);
  });

  beforeEach(async function () {
    [admin, owner, attacker, recipient, pauser] = await ethers.getSigners();
    sp1 = await (await ethers.getContractFactory("ProgramBoundMockSP1Verifier")).deploy();
    const zkVerifier = await (
      await ethers.getContractFactory("ZKMLDSAVerifier")
    ).deploy(await sp1.getAddress(), WITHDRAWAL_PROGRAM_VKEY);
    vault = await (await ethers.getContractFactory("WalletWallVault", admin)).deploy(await zkVerifier.getAddress());
    chainId = (await ethers.provider.getNetwork()).chainId;
    verifierAddress = await zkVerifier.getAddress();
  });

  async function openVault(mode: number) {
    const pq = ml_dsa65.keygen();
    await vault.connect(owner).createVault(mode === PQ_ONLY ? ethers.ZeroAddress : owner.address, pq.publicKey, mode);
    await vault.connect(owner).deposit({ value: ethers.parseEther("10") });
    return pq;
  }

  async function withdrawalRequest(to: string, amount: bigint, mode: number) {
    const request = {
      vaultOwner: owner.address,
      recipient: to,
      amount,
      nonce: await vault.nonces(owner.address),
      deadline: (await networkHelpers.time.latest()) + 3600,
      vaultMode: mode,
    };
    const digest = ethers.TypedDataEncoder.hash(await withdrawalDomain(vault), WITHDRAWAL_TYPES, request);
    expect(await vault.hashWithdrawal(request)).to.equal(digest);
    return { request, digest };
  }

  const signPq = (message: string, secretKey: Uint8Array, context?: Uint8Array) =>
    ml_dsa65.sign(ethers.getBytes(message), secretKey, context === undefined ? {} : { context });

  const payloadFor = (publicValues: string) =>
    ethers.AbiCoder.defaultAbiCoder().encode(["bytes", "bytes"], [publicValues, "0x01"]);

  function honestWithdrawalExecution(digest: string, publicKey: Uint8Array, signature: Uint8Array) {
    return runProgram({
      program: "withdrawal",
      honest: {
        withdrawalDigest: digest,
        publicKey: ethers.hexlify(publicKey),
        signature: ethers.hexlify(signature),
        chainId: Number(chainId),
        verifierAddress,
      },
    });
  }

  /** A proof of an accepted withdrawal-program execution: registered, then encoded for the consumer. */
  async function provenWithdrawalPayload(label: string, result: ExecutionResult) {
    expect(result.accepted, `${label}: ${result.reason}`).to.equal(true);
    await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, result.publicValues);
    return payloadFor(result.publicValues!);
  }

  /**
   * Every stdin layout a prover could use to pass (digest, key, signature) plus an extra message and
   * context. If the withdrawal program accepts a layout, a proof of it exists: register and submit it,
   * and the consumer must still refuse (with `refusal`, by default the vault's InvalidPQSignature).
   * Finally require that the program refused every layout.
   */
  async function expectNoForgedPqAuthorization(
    label: string,
    digest: string,
    publicKey: Uint8Array,
    signature: Uint8Array,
    extra: { message: Uint8Array; context: Uint8Array },
    submit: (pqPayload: string) => Promise<unknown>,
    refusal: { contract: any; error: string } = { contract: vault, error: "InvalidPQSignature" },
  ) {
    const fields = ethers.getBytes(
      ethers.concat([digest, bincodeBytes(publicKey), bincodeBytes(signature), u64le(chainId), verifierAddress]),
    );
    const message = bincodeBytes(extra.message);
    const context = bincodeBytes(extra.context);
    const layouts: [string, string[]][] = [
      ["the five withdrawal fields", [ethers.hexlify(fields)]],
      ["the fields + message/context trailer", [ethers.concat([fields, message, context])]],
      ["the fields + message trailer", [ethers.concat([fields, message])]],
      ["the fields + context trailer", [ethers.concat([fields, context])]],
      ["the fields + mode 1 (u8) + message/context trailer", [ethers.concat([fields, "0x01", message, context])]],
      [
        "the fields + mode 1 (u32 enum tag) + message/context trailer",
        [ethers.concat([fields, "0x01000000", message, context])],
      ],
      ["message/context as extra buffers", [ethers.hexlify(fields), ethers.hexlify(message), ethers.hexlify(context)]],
    ];
    const accepted: string[] = [];
    for (const [layout, stdin] of layouts) {
      const result = runProgram({ program: "withdrawal", stdin });
      if (!result.accepted) {
        expect(result.committed, `${label}, ${layout}: a rejected run must commit nothing`).to.equal("0x");
        continue;
      }
      accepted.push(layout);
      await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, result.publicValues);
      try {
        await expect(submit(payloadFor(result.publicValues!))).to.be.revertedWithCustomError(
          refusal.contract,
          refusal.error,
        );
      } catch (error) {
        throw new Error(
          `${label}: the withdrawal program accepted "${layout}" and the consumer did not refuse the resulting ` +
            `proof with ${refusal.error} (${(error as Error).message})`,
        );
      }
    }
    expect(accepted, `${label}: the withdrawal program accepted a PQ authorization its key never signed`).to.deep.equal(
      [],
    );
  }

  async function rotationFor(newPublicKey: Uint8Array) {
    const deadline = (await networkHelpers.time.latest()) + 3600;
    const rotation = {
      vaultOwner: owner.address,
      newEcdsaSigner: ethers.ZeroAddress,
      newPQPublicKey: ethers.hexlify(newPublicKey),
      nonce: await vault.nonces(owner.address),
      deadline,
    };
    const digest = ethers.TypedDataEncoder.hash(await withdrawalDomain(vault), ROTATE_TYPES, rotation);
    return { deadline, digest };
  }

  async function enableLargeWithdrawals(threshold: bigint, delay: number) {
    await vault.connect(admin).proposeLargeTxParams(threshold, delay);
    await networkHelpers.time.increase(Number(await vault.LARGE_TX_PARAMS_UPDATE_DELAY()) + 1);
    await vault.connect(admin).applyLargeTxParams();
  }

  async function openMultiSig() {
    const multiSig = await (await ethers.getContractFactory("WalletWallMultiSigVault", admin)).deploy(verifierAddress);
    const pq = ml_dsa65.keygen();
    await multiSig.connect(owner).createVault([owner.address], 1, [pq.publicKey], 1);
    await multiSig.connect(owner).deposit({ value: ethers.parseEther("10") });
    return { multiSig, pq };
  }

  async function multiSigWithdrawal(multiSig: any, to: string, amount: bigint) {
    const request = {
      vaultOwner: owner.address,
      recipient: to,
      amount,
      nonce: (await multiSig.getVault(owner.address)).nonce,
      deadline: (await networkHelpers.time.latest()) + 3600,
    };
    const domain = {
      name: "WalletWallMultiSigVault",
      version: "1",
      chainId,
      verifyingContract: await multiSig.getAddress(),
    };
    return {
      request,
      digest: ethers.TypedDataEncoder.hash(domain, MULTISIG_TYPES, request),
      ecdsa: await owner.signTypedData(domain, MULTISIG_TYPES, request),
    };
  }

  async function openBridge() {
    const bridge = await (await ethers.getContractFactory("PolicyControlBridge")).deploy(pauser.address);
    const target = await (await ethers.getContractFactory("PolicyControlTargetMock")).deploy();
    return { bridge, target };
  }

  async function enrollmentFor(bridge: any, target: any) {
    const intent = {
      consumer: await vault.getAddress(),
      owner: owner.address,
      policy: await target.getAddress(),
      asset: ethers.ZeroAddress,
      controller: await bridge.getAddress(),
      epoch: await vault.policyControlEpoch(owner.address),
      nonce: await bridge.controlNonce(await vault.getAddress(), owner.address),
      deadline: (await networkHelpers.time.latest()) + 3600,
    };
    const domain = {
      name: "WalletWallPolicyControlBridge",
      version: "1",
      chainId,
      verifyingContract: await bridge.getAddress(),
    };
    return { intent, digest: ethers.TypedDataEncoder.hash(domain, ENROLL_TYPES, intent) };
  }

  // ---------------------------------------------------------------------------------------------
  // Positive controls
  // ---------------------------------------------------------------------------------------------

  it("control: an honest PqOnly withdrawal proven by the withdrawal program is paid", async function () {
    const pq = await openVault(PQ_ONLY);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), PQ_ONLY);
    const payload = await provenWithdrawalPayload(
      "withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signPq(a.digest, pq.secretKey)),
    );
    await expect(vault.connect(attacker).withdraw(a.request, "0x", payload)).to.emit(vault, "Withdrawn");
  });

  it("control: an honest Hybrid withdrawal with both legs is paid", async function () {
    const pq = await openVault(HYBRID);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), HYBRID);
    const ecdsa = await owner.signTypedData(await withdrawalDomain(vault), WITHDRAWAL_TYPES, a.request);
    const payload = await provenWithdrawalPayload(
      "withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signPq(a.digest, pq.secretKey)),
    );
    await expect(vault.connect(attacker).withdraw(a.request, ecdsa, payload)).to.emit(vault, "Withdrawn");
  });

  it("control: an EcdsaOnly withdrawal never consults the PQ verifier", async function () {
    await vault.connect(owner).createVault(owner.address, "0x", ECDSA_ONLY, { value: ethers.parseEther("1") });
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), ECDSA_ONLY);
    const ecdsa = await owner.signTypedData(await withdrawalDomain(vault), WITHDRAWAL_TYPES, a.request);
    // Nothing is proven under any program vkey and no PQ payload is sent.
    await expect(vault.connect(attacker).withdraw(a.request, ecdsa, "0x")).to.emit(vault, "Withdrawn");
  });

  it("control: an honest credential rotation proven by the withdrawal program succeeds", async function () {
    const pq = await openVault(PQ_ONLY);
    const next = ml_dsa65.keygen();
    const rotation = await rotationFor(next.publicKey);
    const current = await provenWithdrawalPayload(
      "current key",
      honestWithdrawalExecution(rotation.digest, pq.publicKey, signPq(rotation.digest, pq.secretKey)),
    );
    const proofOfPossession = await provenWithdrawalPayload(
      "new key",
      honestWithdrawalExecution(rotation.digest, next.publicKey, signPq(rotation.digest, next.secretKey)),
    );
    await expect(
      vault.connect(owner).rotateCredentials(owner.address, ethers.ZeroAddress, next.publicKey, rotation.deadline, {
        currentEcdsaSignature: "0x",
        currentPqSignature: current,
        newEcdsaSignature: "0x",
        newPqSignature: proofOfPossession,
      }),
    ).to.emit(vault, "CredentialsRotated");
  });

  it("control: a queued PqOnly withdrawal can be finalized only by the vault owner", async function () {
    // Queueing consumes the nonce and reserves the amount, but only the owner can finalize (or cancel):
    // a PQ authorization accepted for the queue alone does not move funds to its recipient.
    const pq = await openVault(PQ_ONLY);
    await enableLargeWithdrawals(ethers.parseEther("2"), 3600);
    const b = await withdrawalRequest(recipient.address, ethers.parseEther("5"), PQ_ONLY);
    const payload = await provenWithdrawalPayload(
      "queued withdrawal B",
      honestWithdrawalExecution(b.digest, pq.publicKey, signPq(b.digest, pq.secretKey)),
    );
    await expect(vault.connect(attacker).queueWithdrawal(b.request, "0x", payload)).to.emit(vault, "WithdrawalQueued");
    await networkHelpers.time.increase(3601);
    await expect(vault.connect(attacker).finalizeWithdrawal(owner.address, b.digest)).to.be.revertedWithCustomError(
      vault,
      "NotPendingWithdrawalOwner",
    );
    await expect(vault.connect(owner).finalizeWithdrawal(owner.address, b.digest)).to.not.revert(ethers);
  });

  it("control: an honest MultiSig withdrawal meeting both thresholds is paid", async function () {
    const { multiSig, pq } = await openMultiSig();
    const a = await multiSigWithdrawal(multiSig, recipient.address, ethers.parseEther("1"));
    const payload = await provenWithdrawalPayload(
      "MultiSig withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signPq(a.digest, pq.secretKey)),
    );
    await expect(multiSig.connect(attacker).withdraw(a.request, [a.ecdsa], [payload], [0])).to.emit(
      multiSig,
      "Withdrawn",
    );
  });

  it("control: an honest PqOnly policy-control enrolment is authenticated and forwarded", async function () {
    const pq = await openVault(PQ_ONLY);
    const { bridge, target } = await openBridge();
    const enrolment = await enrollmentFor(bridge, target);
    const payload = await provenWithdrawalPayload(
      "enrolment",
      honestWithdrawalExecution(enrolment.digest, pq.publicKey, signPq(enrolment.digest, pq.secretKey)),
    );
    await bridge.connect(attacker).enrollController(enrolment.intent, "0x", payload);
    expect(await target.callCount()).to.equal(1n);
  });

  // ---------------------------------------------------------------------------------------------
  // Forged PQ authorizations
  // ---------------------------------------------------------------------------------------------

  it("binding (PqOnly): one observed withdrawal signature cannot authorize a different withdrawal", async function () {
    const pq = await openVault(PQ_ONLY);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), PQ_ONLY);
    const signatureA = signPq(a.digest, pq.secretKey);
    const payloadA = await provenWithdrawalPayload(
      "withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signatureA),
    );
    await vault.connect(owner).withdraw(a.request, "0x", payloadA);

    // Whoever built or saw A's proof holds signatureA, but never the secret key.
    const b = await withdrawalRequest(attacker.address, ethers.parseEther("9"), PQ_ONLY);
    await expect(vault.connect(attacker).withdraw(b.request, "0x", payloadA)).to.be.revertedWithCustomError(
      vault,
      "InvalidPQSignature",
    );
    await expectNoForgedPqAuthorization(
      "PqOnly withdrawal B from A's signature",
      b.digest,
      pq.publicKey,
      signatureA,
      { message: ethers.getBytes(a.digest), context: new Uint8Array() },
      (pqPayload) => vault.connect(attacker).withdraw(b.request, "0x", pqPayload),
    );
  });

  it("binding (PqOnly): a signature made under another ML-DSA context cannot authorize a withdrawal", async function () {
    const pq = await openVault(PQ_ONLY);
    const b = await withdrawalRequest(attacker.address, ethers.parseEther("10"), PQ_ONLY);
    const context = ethers.toUtf8Bytes("another-protocol/v1");
    const foreign = signPq(b.digest, pq.secretKey, context);
    expect(ml_dsa65.verify(foreign, ethers.getBytes(b.digest), pq.publicKey)).to.equal(false);
    await expectNoForgedPqAuthorization(
      "PqOnly withdrawal B under a foreign context",
      b.digest,
      pq.publicKey,
      foreign,
      { message: new Uint8Array(), context },
      (pqPayload) => vault.connect(attacker).withdraw(b.request, "0x", pqPayload),
    );
  });

  it("binding (Hybrid): the PQ leg cannot be met without a PQ signature over the withdrawal", async function () {
    const pq = await openVault(HYBRID);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), HYBRID);
    const signatureA = signPq(a.digest, pq.secretKey);
    const payloadA = await provenWithdrawalPayload(
      "withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signatureA),
    );

    // B carries a valid classical leg: the ECDSA key is the one the PQ leg exists to back up.
    const b = await withdrawalRequest(attacker.address, ethers.parseEther("10"), HYBRID);
    const ecdsaB = await owner.signTypedData(await withdrawalDomain(vault), WITHDRAWAL_TYPES, b.request);
    await expect(vault.connect(attacker).withdraw(b.request, ecdsaB, payloadA)).to.be.revertedWithCustomError(
      vault,
      "InvalidPQSignature",
    );
    await expectNoForgedPqAuthorization(
      "Hybrid PQ leg for B from A's signature",
      b.digest,
      pq.publicKey,
      signatureA,
      { message: ethers.getBytes(a.digest), context: new Uint8Array() },
      (pqPayload) => vault.connect(attacker).withdraw(b.request, ecdsaB, pqPayload),
    );
  });

  it("binding (rotation): a withdrawal signature cannot authorize a credential rotation", async function () {
    const pq = await openVault(PQ_ONLY);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), PQ_ONLY);
    const signatureA = signPq(a.digest, pq.secretKey);
    const payloadA = await provenWithdrawalPayload(
      "withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signatureA),
    );

    const attackerPq = ml_dsa65.keygen();
    const rotation = await rotationFor(attackerPq.publicKey);
    const attackerProof = await provenWithdrawalPayload(
      "attacker key proof of possession",
      honestWithdrawalExecution(rotation.digest, attackerPq.publicKey, signPq(rotation.digest, attackerPq.secretKey)),
    );
    const rotate = (currentPqSignature: string) =>
      vault
        .connect(attacker)
        .rotateCredentials(owner.address, ethers.ZeroAddress, attackerPq.publicKey, rotation.deadline, {
          currentEcdsaSignature: "0x",
          currentPqSignature,
          newEcdsaSignature: "0x",
          newPqSignature: attackerProof,
        });

    await expect(rotate(payloadA)).to.be.revertedWithCustomError(vault, "InvalidPQSignature");
    await expectNoForgedPqAuthorization(
      "rotation to the attacker's key from A's withdrawal signature",
      rotation.digest,
      pq.publicKey,
      signatureA,
      { message: ethers.getBytes(a.digest), context: new Uint8Array() },
      rotate,
    );
  });

  it("binding (queued): one observed withdrawal signature cannot queue a different large withdrawal", async function () {
    const pq = await openVault(PQ_ONLY);
    await enableLargeWithdrawals(ethers.parseEther("2"), 3600);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), PQ_ONLY);
    const signatureA = signPq(a.digest, pq.secretKey);
    const payloadA = await provenWithdrawalPayload(
      "withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signatureA),
    );
    await vault.connect(owner).withdraw(a.request, "0x", payloadA);

    const b = await withdrawalRequest(attacker.address, ethers.parseEther("9"), PQ_ONLY);
    const queue = (pqPayload: string) => vault.connect(attacker).queueWithdrawal(b.request, "0x", pqPayload);
    await expect(queue(payloadA)).to.be.revertedWithCustomError(vault, "InvalidPQSignature");
    await expectNoForgedPqAuthorization(
      "queued withdrawal B from A's signature",
      b.digest,
      pq.publicKey,
      signatureA,
      { message: ethers.getBytes(a.digest), context: new Uint8Array() },
      queue,
    );
  });

  it("binding (MultiSig): the PQ threshold cannot be met from a signature over another withdrawal", async function () {
    const { multiSig, pq } = await openMultiSig();
    const a = await multiSigWithdrawal(multiSig, recipient.address, ethers.parseEther("1"));
    const signatureA = signPq(a.digest, pq.secretKey);
    const payloadA = await provenWithdrawalPayload(
      "MultiSig withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signatureA),
    );
    await multiSig.connect(owner).withdraw(a.request, [a.ecdsa], [payloadA], [0]);

    // B meets the ECDSA threshold; only the PQ threshold stands between it and payment.
    const b = await multiSigWithdrawal(multiSig, attacker.address, ethers.parseEther("9"));
    const submit = (pqPayload: string) => multiSig.connect(attacker).withdraw(b.request, [b.ecdsa], [pqPayload], [0]);
    await expect(submit(payloadA)).to.be.revertedWithCustomError(multiSig, "InvalidSignature");
    await expectNoForgedPqAuthorization(
      "MultiSig PQ threshold for B from A's signature",
      b.digest,
      pq.publicKey,
      signatureA,
      { message: ethers.getBytes(a.digest), context: new Uint8Array() },
      submit,
      { contract: multiSig, error: "InvalidSignature" },
    );
  });

  it("binding (PolicyControlBridge): a withdrawal signature cannot authenticate a policy-control enrolment", async function () {
    const pq = await openVault(PQ_ONLY);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), PQ_ONLY);
    const signatureA = signPq(a.digest, pq.secretKey);
    const payloadA = await provenWithdrawalPayload(
      "withdrawal A",
      honestWithdrawalExecution(a.digest, pq.publicKey, signatureA),
    );

    const { bridge, target } = await openBridge();
    const enrolment = await enrollmentFor(bridge, target);
    const enroll = (pqSignature: string) =>
      bridge.connect(attacker).enrollController(enrolment.intent, "0x", pqSignature);
    await expect(enroll(payloadA)).to.be.revertedWithCustomError(bridge, "InvalidPQSignature");
    await expectNoForgedPqAuthorization(
      "policy-control enrolment from A's withdrawal signature",
      enrolment.digest,
      pq.publicKey,
      signatureA,
      { message: ethers.getBytes(a.digest), context: new Uint8Array() },
      enroll,
      { contract: bridge, error: "InvalidPQSignature" },
    );
    expect(await target.callCount()).to.equal(0n);
  });

  // ---------------------------------------------------------------------------------------------
  // Program identity
  // ---------------------------------------------------------------------------------------------

  it("isolation: a proof of the ACVP program cannot pay a withdrawal, even over a withdrawal-shaped journal", async function () {
    const pq = await openVault(PQ_ONLY);
    const a = await withdrawalRequest(recipient.address, ethers.parseEther("1"), PQ_ONLY);
    const signatureA = signPq(a.digest, pq.secretKey);

    // The ACVP program accepts A's signature as a sigVer case (empty context) and commits its own journal.
    const acvp = runProgram({
      program: "acvp",
      stdin: [acvpStdin(pq.publicKey, ethers.getBytes(a.digest), new Uint8Array(), signatureA)],
    });
    expect(acvp.accepted, acvp.reason).to.equal(true);
    await sp1.setProven(ACVP_PROGRAM_VKEY, acvp.publicValues);
    await expect(
      vault.connect(attacker).withdraw(a.request, "0x", payloadFor(acvp.publicValues!)),
    ).to.be.revertedWithCustomError(vault, "InvalidPQSignature");

    // A withdrawal-shaped journal is worthless under the ACVP program's identity...
    const honest = honestWithdrawalExecution(a.digest, pq.publicKey, signatureA);
    expect(honest.accepted, honest.reason).to.equal(true);
    expect(honest.publicValues).to.equal(
      ProverClient.encodePublicValues(a.digest, pq.publicKey, signatureA, chainId, verifierAddress),
    );
    await sp1.setProven(ACVP_PROGRAM_VKEY, honest.publicValues);
    await expect(
      vault.connect(attacker).withdraw(a.request, "0x", payloadFor(honest.publicValues!)),
    ).to.be.revertedWithCustomError(vault, "InvalidPQSignature");

    // ...and pays only once the withdrawal program itself has proven it (positive control).
    await sp1.setProven(WITHDRAWAL_PROGRAM_VKEY, honest.publicValues);
    await expect(vault.connect(attacker).withdraw(a.request, "0x", payloadFor(honest.publicValues!))).to.emit(
      vault,
      "Withdrawn",
    );
  });
});
