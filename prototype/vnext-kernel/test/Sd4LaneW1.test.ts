/**
 * EXPERIMENTAL PROTOTYPE — LANE W1: EXPIRY BOUNDARY CORRECTION.
 *
 * Lane W froze the kernel's own reading of recovery expiry — live while
 * `now <= expiresAt`. This lane tests the cross-artifact reconciliation that
 * supersedes it, and every premise was verified firsthand:
 *
 *   MODEL, uniformly:  expiry is `>=`  (vaultVNextModel.ts:696 containment,
 *                      :1031 & :1040 recovery, :1358 containment window)
 *                      deadline is `>` (:1140 migration) — a DIFFERENT concept.
 *   KERNEL:            containment `>= containedUntil` -> NORMAL   (:691)
 *                      deadline    `>  deadline`       -> Expired  (:665)
 *                      recovery    `>  expiresAt`      -> Expired  (:1228)  <- the outlier
 *   #179:              silent. Its only `expiresAt` (:755) is containment's,
 *                      and it says only that the value is set once and immovable.
 *
 * So the kernel already distinguishes an inclusive DEADLINE from an exclusive
 * EXPIRY for containment, and breaks its own rule for recovery alone. No
 * refutation from authority exists. The frozen rule is therefore:
 *
 *     effectiveLive(r, t) := r.active && t < r.expiresAt
 *     LIVE_WINDOW = [executableAt, expiresAt)
 *     t == expiresAt  =>  expired
 *
 * Every probe below asserts the ACTUAL mined block timestamp of the transaction
 * that exercised the boundary, never a wall-clock point the transaction did not
 * execute at.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { VERIFIER_32_64_SOURCE, buildLaneWHalfOpen, compileAuxContract } from "./sd4-candidate-kernels.js";
import { R, abi, at, cancel, declare, guardianDigest, quorum } from "./sd4-harness.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  pqKeyBytes,
  sign,
  type Floor,
  type World,
} from "../stateful/world.js";

const QCANCEL_TAG = ethers.id("QUORUM_CANCEL_RECOVERY");
type Kernel = { abi: unknown[]; bytecode: string };
let K: Kernel;
let V64: Kernel;

before(function () {
  this.timeout(900_000);
  K = buildLaneWHalfOpen();
  V64 = compileAuxContract("EcdsaBackedVerifier64", VERIFIER_32_64_SOURCE);
});

async function deployV64(w: World): Promise<string> {
  const f = new ethers.ContractFactory(V64.abi as ethers.InterfaceAbi, V64.bytecode, w.deployer);
  const c = await f.deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

async function propose(w: World, v: ethers.Contract, signer: string, hash: string, verifier: string) {
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [signer, hash, verifier]));
  const { digest, nonce } = await guardianDigest(w, v, params);
  return v.initiateRecovery(signer, hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE);
}

async function quorumCancel(w: World, v: ethers.Contract) {
  const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);
  return v.cancelRecoveryByQuorum(quorum(w, digest), nonce, FAR_DEADLINE);
}

/** The block timestamp a transaction ACTUALLY executed at. */
async function minedAt(tx: ethers.ContractTransactionResponse): Promise<bigint> {
  const rec = await tx.wait();
  return BigInt((await ethers.provider.getBlock(rec!.blockNumber))!.timestamp);
}

const latest = async (): Promise<bigint> => BigInt((await ethers.provider.getBlock("latest"))!.timestamp);

async function bindMigration(w: World, v: ethers.Contract) {
  const dest = { vault: w.destination, codeHash: ethers.id("w1-dest"), generation: 2n };
  const nonce = (await v.nonces(DOMAIN.MIGRATION)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: (await v.guardianGeneration()) as bigint,
    params: ethers.keccak256(abi.encode(["address", "bytes32", "uint64"], [dest.vault, dest.codeHash, dest.generation])),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.bindMigration(dest, quorum(w, d), nonce, FAR_DEADLINE, sign(w.credKey, d));
}

interface Cred {
  nominee: ethers.SigningKey;
  pqNominee: ethers.SigningKey;
  key32: string;
  hash: string;
}
const mkCred = (tag: string): Cred => {
  const nominee = keyOf(`${tag}-s`);
  const pqNominee = keyOf(`${tag}-p`);
  const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
  return { nominee, pqNominee, key32, hash: ethers.keccak256(key32) };
};

/** Execute the live request for `c` at a `sigLen`-byte floor, then spend. */
async function executeAndSpend(w: World, v: ethers.Contract, c: Cred, sigLen: 64 | 65) {
  const pop = (await v.recoveryPossessionDigest()) as string;
  const pqPop = sigLen === 64 ? ethers.dataSlice(sign(c.pqNominee, pop), 0, 64) : sign(c.pqNominee, pop);
  await (
    await v.executeRecovery({
      newSigner: addrOf(c.nominee),
      newPqKeyHash: c.hash,
      newPqKey: c.key32,
      newEcdsaPop: sign(c.nominee, pop),
      newPqPop: pqPop,
    })
  ).wait();
  const sNonce = (await v.nonces(DOMAIN.SPEND)) as bigint;
  const sd = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.SPEND,
    authorityGeneration: (await v.credentialGeneration()) as bigint,
    params: ethers.keccak256(abi.encode(["address", "uint256"], [w.recipient, 1n])),
    domain: DOMAIN.SPEND,
    nonce: sNonce,
    deadline: FAR_DEADLINE,
  });
  const pqSig = sigLen === 64 ? ethers.dataSlice(sign(c.pqNominee, sd), 0, 64) : sign(c.pqNominee, sd);
  await (await v.execute(w.recipient, 1n, sNonce, FAR_DEADLINE, sign(c.nominee, sd), pqSig, c.key32)).wait();
  expect(await v.ecdsaSigner(), "recovered credential spends").to.equal(addrOf(c.nominee));
}

describe("SD-4 lane W1 — recovery expiry boundary correction", () => {
  // ===================================================================
  // 2 — the exact boundary probes
  // ===================================================================

  it("E-1 at expiresAt-1: live, cancellable, budget unchanged, fresh recovery completes", async function () {
    this.timeout(600_000);
    const w = await deployWorld({ label: "w1-em1", implOverride: K });
    const v = at(w, K);
    const c = mkCred("w1-em1");
    await (await propose(w, v, addrOf(c.nominee), c.hash, w.verifiers.honest)).wait();
    const E = (await v.recovery())[R.EXPIRES_AT] as bigint;

    // The cancellation must LAND at E-1, so the preceding block sits below it.
    await networkHelpers.time.increaseTo(Number(E - 2n));
    expect(await v.effectiveLiveRecovery(), "live at E-2").to.equal(true);
    await networkHelpers.time.setNextBlockTimestamp(Number(E - 1n));
    const tCancel = await minedAt(await quorumCancel(w, v));
    expect(tCancel, "cancellation executed at exactly expiresAt-1").to.equal(E - 1n);
    // Its success IS the liveness assertion: cancelRecoveryByQuorum requires
    // effectiveLiveRecovery(), evaluated in the block it executed in.
    expect(await v.recoveryChallengesUsed(), "budget unchanged").to.equal(0n);

    const c2 = mkCred("w1-em1-fresh");
    const tInit = await minedAt(await propose(w, v, addrOf(c2.nominee), c2.hash, w.verifiers.honest));
    const r = await v.recovery();
    expect((r[R.EXECUTABLE_AT] as bigint) - tInit, "full ordinary delay").to.equal(BigInt(7 * DAY));
    expect((r[R.EXPIRES_AT] as bigint) - tInit, "full ordinary expiry").to.equal(BigInt(21 * DAY));

    await networkHelpers.time.increase(7 * DAY + 1);
    await executeAndSpend(w, v, c2, 65);
  });

  for (const [label, delta] of [
    ["E0 at expiresAt", 0n],
    ["E+1 at expiresAt+1", 1n],
  ] as [string, bigint][]) {
    it(`${label}: expired — zero execution, zero cancellation target, zero blocking; fresh initiation is not overwrite`, async function () {
      this.timeout(600_000);
      const w = await deployWorld({ label: `w1-${label.slice(0, 3)}`, implOverride: K });
      const v = at(w, K);
      const c = mkCred(`w1-${label.slice(0, 3)}`);
      await (await propose(w, v, addrOf(c.nominee), c.hash, w.verifiers.honest)).wait();
      const E = (await v.recovery())[R.EXPIRES_AT] as bigint;

      // Mine a block AT the probe instant so every view below reads it.
      await networkHelpers.time.increaseTo(Number(E + delta));
      expect(await latest(), "probe block timestamp").to.equal(E + delta);
      expect(await v.effectiveLiveRecovery(), "effectively expired").to.equal(false);
      expect((await v.recovery())[R.ACTIVE], "stale byte still set — carries nothing").to.equal(true);

      // zero execution authority
      const pop = (await v.recoveryPossessionDigest()) as string;
      await expect(
        v.executeRecovery({
          newSigner: addrOf(c.nominee),
          newPqKeyHash: c.hash,
          newPqKey: c.key32,
          newEcdsaPop: sign(c.nominee, pop),
          newPqPop: sign(c.pqNominee, pop),
        }),
      ).to.be.revertedWithCustomError(v, "Expired");

      // zero cancellation-target authority, both principals, and NO epoch consumed
      await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "NoRecovery");
      await expect(quorumCancel(w, v)).to.be.revertedWithCustomError(v, "NoRecovery");
      expect(await v.recoveryChallengesUsed(), "a refused challenge consumes nothing").to.equal(0n);

      // zero blocking effect on migration — measured on a SEPARATE world so the
      // fresh-initiation path below is not pre-empted by MIGRATION_ONLY.
      {
        const w2 = await deployWorld({ label: `w1-${label.slice(0, 3)}-mig`, implOverride: K });
        const v2 = at(w2, K);
        const cc = mkCred(`w1-${label.slice(0, 3)}-mig`);
        await (await propose(w2, v2, addrOf(cc.nominee), cc.hash, w2.verifiers.honest)).wait();
        const E2 = (await v2.recovery())[R.EXPIRES_AT] as bigint;
        await networkHelpers.time.increaseTo(Number(E2 + delta));
        const tBind = await minedAt(await bindMigration(w2, v2));
        expect(tBind >= E2 + delta, "bound at or after the probe instant").to.equal(true);
        expect(await v2.effectiveSafeState(), "MIGRATION_ONLY with no sweeper").to.equal(3n);
      }

      // zero blocking effect on fresh initiation — and it is NOT overwrite: the
      // guard that refuses a LIVE request (`BadState`) does not fire.
      const c2 = mkCred(`w1-${label.slice(0, 3)}-fresh`);
      const tInit = await minedAt(await propose(w, v, addrOf(c2.nominee), c2.hash, w.verifiers.honest));
      expect(tInit >= E + delta, "initiated at or after the probe instant").to.equal(true);
      const r = await v.recovery();
      expect(r[R.SIGNER], "fresh request installed").to.equal(addrOf(c2.nominee));
      expect((r[R.EXECUTABLE_AT] as bigint) - tInit, "own delay").to.equal(BigInt(7 * DAY));
      expect((r[R.EXPIRES_AT] as bigint) - tInit, "own expiry").to.equal(BigInt(21 * DAY));

      await networkHelpers.time.increase(7 * DAY + 1);
      await executeAndSpend(w, v, c2, 65);
    });
  }

  // ===================================================================
  // 3 — identical-material recovery still resets: authority, not bytes
  // ===================================================================

  it("3 identical-material recovery resets the epoch — the boundary is the authority transition", async function () {
    this.timeout(600_000);
    const w = await deployWorld({ label: "w1-ident", implOverride: K });
    const v = at(w, K);
    const c = mkCred("w1-ident");

    // Install c by a first recovery, then spend one challenge as c.
    await (await propose(w, v, addrOf(c.nominee), c.hash, w.verifiers.honest)).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    await executeAndSpend(w, v, c, 65);
    await (await propose(w, v, addrOf(keyOf("w1-ident-x")), ethers.keccak256(abi.encode(["address"], [addrOf(keyOf("w1-ident-y"))])), w.verifiers.honest)).wait();
    await (await cancel(w, v, c.nominee)).wait();
    expect(await v.recoveryChallengesUsed()).to.equal(1n);

    // Recover to BYTE-IDENTICAL material. The bytes do not change; the
    // recovery authority was exercised. The epoch follows the authority.
    await (await propose(w, v, addrOf(c.nominee), c.hash, w.verifiers.honest)).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    await executeAndSpend(w, v, c, 65);
    expect(await v.recoveryChallengesUsed(), "reset on identical material").to.equal(0n);
  });

  // ===================================================================
  // 4 — SD-4 at the corrected boundary, the two-path remedy
  // ===================================================================

  it("4 SD-4 two-path remedy across seven timings, each landing at its asserted instant", async function () {
    this.timeout(2_400_000);
    const rows: string[] = [];

    const timings: [string, (t0: bigint, E: bigint) => bigint | null][] = [
      ["t0", () => null],
      ["t0+7d", (t0) => t0 + BigInt(7 * DAY)],
      ["t0+14d", (t0) => t0 + BigInt(14 * DAY)],
      ["t0+20d", (t0) => t0 + BigInt(20 * DAY)],
      ["expiresAt-1", (_t0, E) => E - 1n],
      ["expiresAt", (_t0, E) => E],
      ["expiresAt+1", (_t0, E) => E + 1n],
    ];

    for (const [label, pick] of timings) {
      const w = await deployWorld({
        label: `w1-sd4-${label}`.replace(/[+\-]/g, "_"),
        ecdsaOnlyFloor: true,
        commitPqKeyOnEcdsaOnlyFloor: true,
        implOverride: K,
      });
      const v = at(w, K);
      const v64 = await deployV64(w);
      const c = mkCred(`w1-sd4-${label}`);

      await (await propose(w, v, addrOf(c.nominee), c.hash, w.verifiers.honest)).wait();
      const r0 = await v.recovery();
      const E = r0[R.EXPIRES_AT] as bigint;
      const t0 = (r0[R.EXECUTABLE_AT] as bigint) - BigInt(7 * DAY);

      // SD-4 kills the approved request.
      const floor: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 };
      await (await declare(w, v, w.credKey, w.verifiers.honest, floor, pqKeyBytes(w.pqKey))).wait();
      const floorAfterDeclare = await v.securityFloor();

      const target = pick(t0, E);
      if (target !== null) await networkHelpers.time.setNextBlockTimestamp(Number(target));

      // THE TWO-PATH REMEDY, decided by the FROZEN rule, not by the stored flag.
      const liveAtTarget = target === null ? true : target < E;
      let tFirst: bigint;
      let path: string;
      if (liveAtTarget) {
        tFirst = await minedAt(await quorumCancel(w, v));
        path = "live: quorum cancel + fresh initiate";
        expect((await v.recovery())[R.ACTIVE], "explicit terminal transition").to.equal(false);
      } else {
        // No cancellation required — and none is POSSIBLE: the target is gone.
        await expect(quorumCancel(w, v)).to.be.revertedWithCustomError(v, "NoRecovery");
        path = "expired: fresh initiate directly";
        tFirst = 0n;
      }
      const tInit = await minedAt(await propose(w, v, addrOf(c.nominee), c.hash, v64));
      if (target !== null && liveAtTarget) expect(tFirst, `${label}: remedy landed at its instant`).to.equal(target);
      if (target !== null && !liveAtTarget) expect(tInit >= target, `${label}: initiated at/after`).to.equal(true);

      const r1 = await v.recovery();
      expect(await v.securityFloor(), `${label}: remedy touched no floor`).to.deep.equal(floorAfterDeclare);
      expect((r1[R.EXECUTABLE_AT] as bigint) - tInit, `${label}: fresh full delay`).to.equal(BigInt(7 * DAY));
      expect((r1[R.EXPIRES_AT] as bigint) - tInit, `${label}: fresh full expiry`).to.equal(BigInt(21 * DAY));
      expect(await v.recoveryChallengesUsed(), `${label}: budget preserved`).to.equal(0n);
      expect(r1[R.GUARDIAN_GEN], `${label}: generation correct`).to.equal(1n);

      await networkHelpers.time.increase(7 * DAY + 1);
      await executeAndSpend(w, v, c, 64);
      rows.push(`${label.padEnd(12)} ${path.padEnd(38)} spent`);
    }
    console.log("\n      SD-4 two-path remedy:\n      " + rows.join("\n      ") + "\n");
  });
});
