/**
 * EXPERIMENTAL PROTOTYPE — SD-6 / SD-7 EVIDENCE LEDGER, VERDICTS MOVED.
 *
 * Every test here was written against the PARENT commit
 * (`security/vnext-sd3-sd4-authentication-satisfiability` @ a70de68) and
 * REPRODUCED the defect it names. They are INVERTED IN PLACE rather than
 * deleted, so the record of what the kernel used to do survives alongside the
 * proof that it no longer does — and so a regression cannot land quietly while
 * `AUTHORITY.md` still calls the outcome unreachable.
 *
 * WHAT CHANGED
 *   `I-COMMITMENT-EXHIBITED-AT-ADMISSION` — every accepted transition that
 *   writes a NON-ZERO `pqPublicKeyHash` must exhibit a preimage of the value
 *   being written; where the governing floor already mandates PQ, that preimage
 *   must also carry the declared key length. Three writers, one rule:
 *   `initialize`, `rotateCredential`, `executeRecovery`.
 *
 * WHAT DID NOT CHANGE, AND IS RECORDED HERE RATHER THAN OMITTED
 *   SD-5 is untouched. An exhibit proves possession of a preimage; it says
 *   nothing about that preimage being a well-formed key of any scheme, and
 *   nothing at all about `pqSignatureLength`, which no commitment anywhere in
 *   this kernel binds. The one-byte-shape capture is still reachable — now with
 *   an exhibited one-byte key instead of an unattested one. That is a
 *   MIN_PQ_LENGTH question, and the tests that prove it are kept below with
 *   their verdicts UNCHANGED.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  floorTuple,
  keyOf,
  pqHash,
  pqKeyBytes,
  sign,
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";

const KERNEL_GEN = 1n;
const abi = ethers.AbiCoder.defaultAbiCoder();

const bytesOfLength = (n: number, tag: string): string => {
  if (n === 0) return "0x";
  let out = "";
  let i = 0;
  while (out.length < n * 2) {
    out += ethers.id(`${tag}-${i}`).slice(2);
    i += 1;
  }
  return "0x" + out.slice(0, n * 2);
};

interface RotateOpts {
  newCred: ethers.SigningKey;
  newPqKeyHash: string;
  newPqKey?: string;
  newPqPop?: string;
  cred?: ethers.SigningKey;
  popKey?: ethers.SigningKey;
}

async function rotate(w: World, o: RotateOpts): Promise<ethers.ContractTransactionResponse> {
  const floor = await liveFloor(w);
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const pop = (await w.vault.credentialPossessionDigest(addrOf(o.newCred), o.newPqKeyHash)) as string;
  const digest = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.ROTATE,
    authorityGeneration: credGen,
    params: ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(o.newCred), o.newPqKeyHash])),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.rotateCredential(
    {
      newSigner: addrOf(o.newCred),
      newPqKeyHash: o.newPqKeyHash,
      newPqKey: o.newPqKey ?? "0x",
      newEcdsaPop: sign(o.popKey ?? o.newCred, pop),
      newPqPop: o.newPqPop ?? "0x",
    },
    nonce,
    FAR_DEADLINE,
    sign(o.cred ?? w.credKey, digest),
    floor.requirePq ? sign(w.pqKey, digest) : "0x",
    floor.requirePq ? pqKeyBytes(w.pqKey) : "0x",
  );
}

async function liveFloor(w: World): Promise<Floor> {
  const f = await w.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

async function declare(
  w: World,
  floor: Floor,
  opts: { pqKey?: string; cred?: ethers.SigningKey } = {},
): Promise<ethers.ContractTransactionResponse> {
  const cred = opts.cred ?? w.credKey;
  const current = await liveFloor(w);
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credGen,
    params: ethers.keccak256(
      abi.encode(["address", "tuple(bool,uint16,uint32,uint32)"], [w.verifiers.honest, floorTuple(floor)]),
    ),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.setVerifier(
    w.verifiers.honest,
    floorTuple(floor),
    nonce,
    FAR_DEADLINE,
    sign(cred, d),
    current.requirePq ? sign(w.pqKey, d) : "0x",
    opts.pqKey ?? "0x",
  );
}

async function canSpend(w: World): Promise<boolean> {
  const floor = await liveFloor(w);
  const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.SPEND,
    authorityGeneration: credGen,
    params: spendParams(w.recipient, 1n),
    domain: DOMAIN.SPEND,
    nonce,
    deadline: FAR_DEADLINE,
  });
  try {
    const tx = await w.vault.execute(
      w.recipient, 1n, nonce, FAR_DEADLINE,
      sign(w.credKey, d),
      floor.requirePq ? sign(w.pqKey, d) : "0x",
      floor.requirePq ? pqKeyBytes(w.pqKey) : "0x",
    );
    await tx.wait();
    return true;
  } catch {
    return false;
  }
}

async function deployGenesis(
  w: World,
  over: Record<string, unknown>,
  salt: string,
  pqKey: string,
): Promise<{ ok: true; vault: ethers.Contract } | { ok: false; error: string }> {
  const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
  const genesis = {
    signer: addrOf(w.credKey),
    pqKeyHash: pqHash(w.pqKey),
    verifier: w.verifiers.honest,
    threshold: w.threshold,
    guardians: w.guardians,
    guardianIsContract: w.guardianIsContract,
    floor: floorTuple({ requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 }),
    ...over,
  };
  try {
    const predicted: string = await factory.predictVault(salt, genesis);
    await (await factory.deployVault(salt, genesis, pqKey)).wait();
    return { ok: true, vault: await ethers.getContractAt("VaultKernelPrototype", predicted, w.deployer) };
  } catch (e) {
    return { ok: false, error: String((e as Error).message ?? e) };
  }
}

// =======================================================================
// SD-6 — REMEDIATED. Each title records the sustaining claim; each body now
// asserts the refusal.
// =======================================================================
describe("SD-6 — REMEDIATED: rotateCredential no longer admits an unattested commitment", () => {
  it("SUSTAINING CLAIM, still true: the authority is the SOLE ECDSA credential; an outsider cannot", async () => {
    const w = await deployWorld({ label: "sd6r-authority", ecdsaOnlyFloor: true });
    const stranger = keyOf("sd6r-stranger");
    const target = keyOf("sd6r-target");

    // POSITIVE CONTROL — the real credential succeeds, WITH the exhibit.
    expect(
      (await (await rotate(w, {
        newCred: target, newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(target),
      })).wait())?.status,
    ).to.equal(1);

    const w2 = await deployWorld({ label: "sd6r-authority-2", ecdsaOnlyFloor: true });
    expect((await liveFloor(w2)).requirePq, "born ECDSA-only").to.equal(false);
    const nonce = (await w2.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
    const pop = (await w2.vault.credentialPossessionDigest(addrOf(target), pqHash(target))) as string;
    const digest = digestOf({
      chainId: w2.chainId, vault: w2.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.ROTATE, authorityGeneration: 1n,
      params: ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(target), pqHash(target)])),
      domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
    });
    await expect(
      w2.vault.rotateCredential(
        {
          newSigner: addrOf(target), newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(target),
          newEcdsaPop: sign(target, pop), newPqPop: "0x",
        },
        nonce, FAR_DEADLINE, sign(stranger, digest), "0x", "0x",
      ),
    ).to.be.revertedWithCustomError(w2.vault, "BadSignature");
  });

  it("VERDICT MOVED — an ARBITRARY non-zero commitment with no preimage is now REFUSED", async () => {
    const w = await deployWorld({ label: "sd6r-arbitrary", ecdsaOnlyFloor: true });
    const target = keyOf("sd6r-arbitrary-target");
    const poison = ethers.id("no preimage of this will ever be exhibited");

    await expect(
      rotate(w, { newCred: target, newPqKeyHash: poison, newPqKey: "0x", newPqPop: "0x" }),
      "SD-6: this call SUCCEEDED on the parent and wrote `poison` to storage",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    expect(await w.vault.pqPublicKeyHash(), "storage untouched").to.equal(ethers.ZeroHash);
    expect(await w.vault.ecdsaSigner(), "the whole transition is refused, not partially applied")
      .to.equal(addrOf(w.credKey));
  });

  it("VERDICT MOVED — the exhibit is no longer ignored: wrong length and wrong value both REFUSED", async () => {
    const w = await deployWorld({ label: "sd6r-ignored", ecdsaOnlyFloor: true });
    const a = keyOf("sd6r-ignored-a");
    const other = keyOf("sd6r-ignored-other");
    const poison = ethers.id("still no preimage");

    await expect(
      rotate(w, { newCred: a, newPqKeyHash: poison, newPqKey: bytesOfLength(7, "junk") }),
      "a 7-byte exhibit that hashes to nothing related — accepted on the parent",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
    await expect(
      rotate(w, { newCred: a, newPqKeyHash: poison, newPqKey: pqKeyBytes(other) }),
      "a CORRECT-LENGTH exhibit of the WRONG key — accepted on the parent",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");
  });

  it("UNCHANGED: zero stays admissible, and repeated exhibited rotations still work", async () => {
    const w = await deployWorld({ label: "sd6r-shapes", ecdsaOnlyFloor: true });
    const k1 = keyOf("sd6r-shapes-1");
    const k2 = keyOf("sd6r-shapes-2");
    const k3 = keyOf("sd6r-shapes-3");

    await (await rotate(w, { newCred: k1, newPqKeyHash: ethers.ZeroHash })).wait();
    expect(await w.vault.pqPublicKeyHash(), "zero is NOT a commitment").to.equal(ethers.ZeroHash);
    await (await rotate(w, { cred: k1, newCred: k2, newPqKeyHash: pqHash(k2), newPqKey: pqKeyBytes(k2) })).wait();
    await (await rotate(w, { cred: k2, newCred: k3, newPqKeyHash: pqHash(k3), newPqKey: pqKeyBytes(k3) })).wait();
    expect(await w.vault.pqPublicKeyHash()).to.equal(pqHash(k3));
    expect((await w.vault.credentialGeneration()) as bigint).to.equal(4n);
  });

  it("THE CONSEQUENCE THAT MOTIVATED THE FIX: a commitment that cannot satisfy the declaring edge cannot be installed", async () => {
    // On the parent this sequence installed an unexhibitable commitment and the
    // vault could then NEVER adopt PQ. The first step is now refused, so the
    // dead end is unreachable rather than merely repairable.
    const w = await deployWorld({ label: "sd6r-declare-dead", ecdsaOnlyFloor: true });
    const target = keyOf("sd6r-declare-dead-target");
    await expect(
      rotate(w, { newCred: target, newPqKeyHash: ethers.id("unexhibitable") }),
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // POSITIVE CONTROL — the honest adoption path is intact end to end.
    const good = keyOf("sd6r-declare-live-good");
    await (await rotate(w, { newCred: good, newPqKeyHash: pqHash(good), newPqKey: pqKeyBytes(good) })).wait();
    expect(
      (await (await declare({ ...w, credKey: good } as World,
        { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
        { pqKey: pqKeyBytes(good), cred: good })).wait())?.status,
    ).to.equal(1);
    expect((await liveFloor(w)).requirePq, "PQ is now mandatory").to.equal(true);
  });

  it("UNCHANGED: the cut is 1 before and 1 after — the fix gains no authority for anyone", async () => {
    const w = await deployWorld({ label: "sd6r-cut", ecdsaOnlyFloor: true });
    expect(await canSpend(w), "cut 1 BEFORE").to.equal(true);
    const target = keyOf("sd6r-cut-target");
    await (await rotate(w, { newCred: target, newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(target) })).wait();
    expect(await canSpend({ ...w, credKey: target } as World), "cut 1 AFTER").to.equal(true);
  });

  it("SD-5 REMAINS SUSTAINED — the shape capture survives, now with an EXHIBITED one-byte key", async () => {
    // THE HONEST BOUNDARY OF THIS REMEDIATION. SD-6 was the mechanism by which
    // a cut-1 root planted the commitment; closing it removes the UNATTESTED
    // plant and nothing else. An attacker who simply holds a one-byte "key"
    // exhibits it and reaches the identical permanent end state.
    const w = await deployWorld({ label: "sd6r-shape-capture", ecdsaOnlyFloor: true });
    const target = keyOf("sd6r-shape-capture-target");
    const oneByte = "0xaa";

    await expect(
      rotate(w, { newCred: target, newPqKeyHash: ethers.keccak256(oneByte), newPqKey: "0x" }),
      "the UNATTESTED plant is closed",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    await (
      await rotate(w, { newCred: target, newPqKeyHash: ethers.keccak256(oneByte), newPqKey: oneByte })
    ).wait();
    expect(
      (await (await declare({ ...w, credKey: target } as World,
        { requirePq: true, pqParamLevel: 65535, pqPublicKeyLength: 1, pqSignatureLength: 1 },
        { pqKey: oneByte, cred: target })).wait())?.status,
      "SD-5: still reachable, and still permanent",
    ).to.equal(1);
    const f = await liveFloor(w);
    expect(f.pqPublicKeyLength).to.equal(1);
    expect(f.pqSignatureLength).to.equal(1);
  });

  it("UNCHANGED: rotation during an ACTIVE recovery is permitted and does not disturb the request", async () => {
    const w = await deployWorld({ label: "sd6r-during-recovery", ecdsaOnlyFloor: true });
    const proposed = keyOf("sd6r-during-recovery-proposed");
    const gNonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER, authorityGeneration: 1n,
      params: ethers.keccak256(
        abi.encode(["address", "bytes32", "address"], [addrOf(proposed), pqHash(proposed), w.verifiers.honest]),
      ),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(proposed), pqHash(proposed), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      }, gNonce, FAR_DEADLINE)
    ).wait();
    expect((await w.vault.recovery())[7], "recovery active").to.equal(true);

    const target = keyOf("sd6r-during-recovery-target");
    await (await rotate(w, { newCred: target, newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(target) })).wait();
    expect((await w.vault.recovery())[7], "still active — rotation does not cancel it").to.equal(true);
  });

  it("VERDICT MOVED — GUARDIAN RECOVERY is bound by the same rule, and the remedy still completes", async () => {
    const w = await deployWorld({ label: "sd6r-quorum", ecdsaOnlyFloor: true });
    const fresh = keyOf("sd6r-quorum-fresh");
    const gNonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER, authorityGeneration: 1n,
      params: ethers.keccak256(
        abi.encode(["address", "bytes32", "address"], [addrOf(fresh), pqHash(fresh), w.verifiers.honest]),
      ),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(fresh), pqHash(fresh), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      }, gNonce, FAR_DEADLINE)
    ).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;

    await expect(
      w.vault.executeRecovery({
        newSigner: addrOf(fresh), newPqKeyHash: pqHash(fresh), newPqKey: "0x",
        newEcdsaPop: sign(fresh, pop), newPqPop: "0x",
      }),
      "the recovery twin of SD-6, also closed",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(fresh), newPqKeyHash: pqHash(fresh), newPqKey: pqKeyBytes(fresh),
        newEcdsaPop: sign(fresh, pop), newPqPop: "0x",
      })
    ).wait();
    expect(await w.vault.pqPublicKeyHash(), "the remedy path is preserved").to.equal(pqHash(fresh));
  });
});

// =======================================================================
// SD-7 — REMEDIATED for the structural class, with the residual declared.
// =======================================================================
describe("SD-7 — REMEDIATED: initialize no longer admits a structurally unsatisfiable genesis", () => {
  it("POSITIVE CONTROL: a legitimate PQ-mandatory genesis deploys and can spend", async () => {
    const w = await deployWorld({ label: "sd7r-control" });
    expect((await w.vault.securityFloor())[0]).to.equal(true);
    expect(await canSpend(w)).to.equal(true);
  });

  it("UNCHANGED: requirePq WITH a zero commitment is refused (the pre-existing check survives)", async () => {
    const w = await deployWorld({ label: "sd7r-zero" });
    const r = await deployGenesis(w, { pqKeyHash: ethers.ZeroHash }, ethers.id("sd7r-zero-salt"), "0x");
    expect(r.ok).to.equal(false);
  });

  it("VERDICT MOVED — an arbitrary non-zero commitment with NO preimage is now REFUSED", async () => {
    const w = await deployWorld({ label: "sd7r-nopreimage" });
    const r = await deployGenesis(
      w, { pqKeyHash: ethers.id("genesis with no preimage") }, ethers.id("sd7r-np-salt"), "0x",
    );
    expect(r.ok, "admitted on the parent; refused now").to.equal(false);
  });

  it("VERDICT MOVED — a 48-byte key under a 32-byte declared shape is now REFUSED", async () => {
    const w = await deployWorld({ label: "sd7r-mismatch" });
    const key48 = bytesOfLength(48, "sd7r-key48");
    const r = await deployGenesis(
      w, { pqKeyHash: ethers.keccak256(key48) }, ethers.id("sd7r-mm-salt"), key48,
    );
    expect(r.ok, "the recorded SD-7 reproduction, closed").to.equal(false);
  });

  it("VERDICT MOVED — a DORMANT genesis carrying an unattested latent commitment is now REFUSED", async () => {
    const w = await deployWorld({ label: "sd7r-dormant" });
    const r = await deployGenesis(
      w,
      {
        pqKeyHash: ethers.id("latent"),
        floor: floorTuple({ requirePq: false, pqParamLevel: 0, pqPublicKeyLength: 0, pqSignatureLength: 0 }),
      },
      ethers.id("sd7r-dormant-salt"),
      "0x",
    );
    expect(r.ok, "a latent commitment is still a commitment").to.equal(false);
  });

  it("RESIDUAL, DECLARED: correct-length garbage still yields a vault BORN unable to authorise", async () => {
    // THE BOUNDARY OF THE GENESIS FIX, stated as an executable fact rather than
    // a caveat in prose. An exhibit proves knowledge of a preimage; it cannot
    // prove the bytes are a well-formed key of the verifier's scheme, and the
    // only party who could judge that is a verifier THE DEPLOYER CHOOSES in the
    // same transaction — self-certification, rejected for the same reason
    // `I-DECLARATION-EXHIBITED` has no signature leg. A deployer determined to
    // build a dead vault still can; what is closed is the CONTRADICTORY genesis
    // a well-intentioned deployer reaches by accident.
    const w = await deployWorld({ label: "sd7r-residual" });
    const garbage = bytesOfLength(32, "sd7r-garbage-not-a-real-key");
    const r = await deployGenesis(
      w, { pqKeyHash: ethers.keccak256(garbage) }, ethers.id("sd7r-residual-salt"), garbage,
    );
    expect(r.ok, "admitted: the exhibit is consistent, the key is not real").to.equal(true);
    if (!r.ok) return;
    await w.deployer.sendTransaction({ to: await r.vault.getAddress(), value: ethers.parseEther("1") });
    const nonce = (await r.vault.nonces(DOMAIN.SPEND)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: await r.vault.getAddress(), kernelGeneration: KERNEL_GEN,
      actionType: ACTION.SPEND, authorityGeneration: 1n,
      params: spendParams(w.recipient, 1n), domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
    });
    await expect(
      r.vault.execute(w.recipient, 1n, nonce, FAR_DEADLINE, sign(w.credKey, d), sign(w.pqKey, d), garbage),
      "the honest verifier refuses: born dead, and no admission check could have seen it",
    ).to.be.revertedWithCustomError(r.vault, "VerifierDenied");
  });

  it("ESCAPABLE AT k, still: a guardian quorum recovers such a vault", async () => {
    const w = await deployWorld({ label: "sd7r-escape" });
    const garbage = bytesOfLength(32, "sd7r-escape-garbage");
    const r = await deployGenesis(
      w, { pqKeyHash: ethers.keccak256(garbage) }, ethers.id("sd7r-escape-salt"), garbage,
    );
    expect(r.ok).to.equal(true);
    if (!r.ok) return;
    await w.deployer.sendTransaction({ to: await r.vault.getAddress(), value: ethers.parseEther("1") });

    const fresh = keyOf("sd7r-escape-fresh");
    const gNonce = (await r.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId, vault: await r.vault.getAddress(), kernelGeneration: KERNEL_GEN,
      actionType: ACTION.RECOVER, authorityGeneration: 1n,
      params: ethers.keccak256(
        abi.encode(["address", "bytes32", "address"], [addrOf(fresh), pqHash(fresh), w.verifiers.honest]),
      ),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await r.vault.initiateRecovery(addrOf(fresh), pqHash(fresh), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      }, gNonce, FAR_DEADLINE)
    ).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await r.vault.recoveryPossessionDigest()) as string;
    await (
      await r.vault.executeRecovery({
        newSigner: addrOf(fresh), newPqKeyHash: pqHash(fresh), newPqKey: pqKeyBytes(fresh),
        newEcdsaPop: sign(fresh, pop), newPqPop: sign(fresh, pop),
      })
    ).wait();
    expect(await r.vault.pqPublicKeyHash()).to.equal(pqHash(fresh));
  });

  it("UNCHANGED: the credential cannot repair a born-dead vault — rotation needs the dead conjunct", async () => {
    const w = await deployWorld({ label: "sd7r-repair" });
    const garbage = bytesOfLength(32, "sd7r-repair-garbage");
    const r = await deployGenesis(
      w, { pqKeyHash: ethers.keccak256(garbage) }, ethers.id("sd7r-repair-salt"), garbage,
    );
    expect(r.ok).to.equal(true);
    if (!r.ok) return;
    const target = keyOf("sd7r-repair-target");
    const nonce = (await r.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
    const pop = (await r.vault.credentialPossessionDigest(addrOf(target), pqHash(target))) as string;
    const digest = digestOf({
      chainId: w.chainId, vault: await r.vault.getAddress(), kernelGeneration: KERNEL_GEN,
      actionType: ACTION.ROTATE, authorityGeneration: 1n,
      params: ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(target), pqHash(target)])),
      domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
    });
    await expect(
      r.vault.rotateCredential(
        {
          newSigner: addrOf(target), newPqKeyHash: pqHash(target), newPqKey: pqKeyBytes(target),
          newEcdsaPop: sign(target, pop), newPqPop: sign(target, pop),
        },
        nonce, FAR_DEADLINE, sign(w.credKey, digest), sign(w.pqKey, digest), garbage,
      ),
    ).to.be.revertedWithCustomError(r.vault, "VerifierDenied");
  });

  it("SD-7 x SD-5, UNCHANGED: genesis still reaches the permanently vacuous shape at cut 0", async () => {
    const w = await deployWorld({ label: "sd7r-vacuous" });
    const oneByte = "0xaa";
    const r = await deployGenesis(
      w,
      {
        pqKeyHash: ethers.keccak256(oneByte),
        floor: floorTuple({ requirePq: true, pqParamLevel: 65535, pqPublicKeyLength: 1, pqSignatureLength: 1 }),
      },
      ethers.id("sd7r-vacuous-salt"),
      oneByte,
    );
    expect(r.ok, "SD-5 is not an admission question and is untouched").to.equal(true);
    if (!r.ok) return;
    const f = await r.vault.securityFloor();
    expect(f[2]).to.equal(1);
    expect(f[3]).to.equal(1);
  });

  it("UNCHANGED: the maximum legal shape is still deployable when genuinely exhibited", async () => {
    const w = await deployWorld({ label: "sd7r-max" });
    const big = bytesOfLength(65535, "sd7r-max-key");
    const r = await deployGenesis(
      w,
      {
        pqKeyHash: ethers.keccak256(big),
        floor: floorTuple({ requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 65535, pqSignatureLength: 65535 }),
      },
      ethers.id("sd7r-max-salt"),
      big,
    );
    expect(r.ok, "the exhibit is not a new magnitude bound").to.equal(true);
  });

  it("STEALTH VARIANT, UNCHANGED: a commitment may still be replaced with the signer apparently unchanged", async () => {
    // Recorded because it was found while re-deriving and is not closed by this
    // lane: `_installCredential` does not require `newSigner` to differ from the
    // incumbent, so an observatory watching `ecdsaSigner` alone sees nothing.
    // What IS now true is that the replacement must be attested.
    const w = await deployWorld({ label: "sd6r-stealth", ecdsaOnlyFloor: true });
    const before = await w.vault.ecdsaSigner();
    const planted = keyOf("sd6r-stealth-planted");
    await (
      await rotate(w, { newCred: w.credKey, newPqKeyHash: pqHash(planted), newPqKey: pqKeyBytes(planted) })
    ).wait();
    expect(await w.vault.ecdsaSigner(), "signer unchanged").to.equal(before);
    expect(await w.vault.pqPublicKeyHash(), "commitment replaced").to.equal(pqHash(planted));
    expect((await w.vault.credentialGeneration()) as bigint, "only the generation betrays it").to.equal(2n);
  });
});
