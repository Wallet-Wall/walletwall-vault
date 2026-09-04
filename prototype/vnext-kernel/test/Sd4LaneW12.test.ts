/**
 * EXPERIMENTAL PROTOTYPE — LANE W1.2: RECOVERY STATE MINIMALITY CHALLENGE.
 *
 * Challenges one assumption W/W1 introduced: that semantic independence of the
 * challenge epoch REQUIRES physically moving `challengesUsed` out of
 * `RecoveryRequest`. Two kernels are compiled in memory and driven through
 * identical histories:
 *
 *   SEP — W1's frozen candidate: standalone `recoveryChallengesUsed`, one reset
 *         site, struct field abandoned.
 *   COL — the challenger: struct, layout and `recovery()` getter untouched;
 *         the field is redefined as epoch-scoped; the existing `delete` on
 *         successful execution is the reset boundary.
 *
 * Every history snapshots the same externally meaningful state on both and
 * requires deep equality. Any difference is the witness that separation is
 * required. None was found.
 *
 * Part D attacks guardian-cancel replay without assuming a request identifier,
 * and finds the existing DOMAIN_GUARDIAN nonce serialisation sufficient.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { buildLaneWColocated, buildLaneWHalfOpen } from "./sd4-candidate-kernels.js";
import { R, abi, at, cancel, guardianDigest, quorum } from "./sd4-harness.js";
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
  type World,
} from "../stateful/world.js";

const QCANCEL_TAG = ethers.id("QUORUM_CANCEL_RECOVERY");
type Kernel = { abi: unknown[]; bytecode: string };
const K: Record<"sep" | "col", Kernel> = {} as never;

before(function () {
  this.timeout(900_000);
  K.sep = buildLaneWHalfOpen();
  K.col = buildLaneWColocated();
});

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

async function propose(w: World, v: ethers.Contract, c: Cred) {
  const params = ethers.keccak256(
    abi.encode(["address", "bytes32", "address"], [addrOf(c.nominee), c.hash, w.verifiers.honest]),
  );
  const { digest, nonce } = await guardianDigest(w, v, params);
  return v.initiateRecovery(addrOf(c.nominee), c.hash, w.verifiers.honest, quorum(w, digest), nonce, FAR_DEADLINE);
}

async function quorumCancel(w: World, v: ethers.Contract) {
  const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);
  return v.cancelRecoveryByQuorum(quorum(w, digest), nonce, FAR_DEADLINE);
}

async function execute(w: World, v: ethers.Contract, c: Cred) {
  const pop = (await v.recoveryPossessionDigest()) as string;
  return v.executeRecovery({
    newSigner: addrOf(c.nominee),
    newPqKeyHash: c.hash,
    newPqKey: c.key32,
    newEcdsaPop: sign(c.nominee, pop),
    newPqPop: sign(c.pqNominee, pop),
  });
}

async function rotateInPlace(w: World, v: ethers.Contract, credKey: ethers.SigningKey, pqKey: ethers.SigningKey) {
  const nonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await v.credentialGeneration()) as bigint;
  const hash = (await v.pqPublicKeyHash()) as string;
  const signer = addrOf(credKey);
  const pqBytes = abi.encode(["address"], [addrOf(pqKey)]);
  const pop = (await v.credentialPossessionDigest(signer, hash)) as string;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.ROTATE,
    authorityGeneration: gen,
    params: ethers.keccak256(abi.encode(["address", "bytes32"], [signer, hash])),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.rotateCredential(
    { newSigner: signer, newPqKeyHash: hash, newPqKey: pqBytes, newEcdsaPop: sign(credKey, pop), newPqPop: sign(pqKey, pop) },
    nonce,
    FAR_DEADLINE,
    sign(credKey, d),
    sign(pqKey, d),
    pqBytes,
  );
}

async function setGuardiansSame(w: World, v: ethers.Contract) {
  const commitment = (await v.rosterCommitment(w.threshold, w.guardians, w.guardianIsContract)) as string;
  const nonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.SET_GUARDIANS,
    authorityGeneration: (await v.guardianGeneration()) as bigint,
    params: commitment,
    domain: DOMAIN.GUARDIAN,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.setGuardians(w.threshold, w.guardians, w.guardianIsContract, quorum(w, d), nonce, FAR_DEADLINE);
}

/** Every externally meaningful fact about recovery state, read the same way on both kernels. */
interface Snap {
  used: bigint;
  active: boolean;
  live: boolean;
  signer: string;
  credGen: bigint;
  guardGen: bigint;
  canChallenge: string;
  canQuorumCancel: string;
  canInitiate: string;
  canBindMigration: string;
}

const outcome = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return "OK";
  } catch (e) {
    const m = String((e as Error).message);
    const named = m.match(/custom error '(\w+)/);
    if (named) return named[1];
    const sel = m.match(/0x[0-9a-f]{8}/);
    const map: Record<string, string> = {
      "0xc993b993": "NoRecovery",
      "0x8523b62a": "BadState",
      "0xe9505ced": "ChallengeExhausted",
      "0x203d82d8": "Expired",
      "0x085de625": "TooEarly",
      "0xd79e824a": "QuorumNotMet",
      "0x4bd574ec": "BadNonce",
      "0xaeb053e3": "BadRoster",
    };
    return sel && map[sel[0]] ? map[sel[0]] : "REVERT";
  }
};

async function snap(kind: "sep" | "col", w: World, v: ethers.Contract, credKey: ethers.SigningKey): Promise<Snap> {
  const r = await v.recovery();
  const used = kind === "sep" ? ((await v.recoveryChallengesUsed()) as bigint) : (r[R.CHALLENGES] as bigint);

  // Static calls: "would it succeed?" without mutating anything.
  const cNonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const cd = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.RECOVER,
    authorityGeneration: (await v.credentialGeneration()) as bigint,
    params: ethers.id("CANCEL"),
    domain: DOMAIN.CREDENTIAL,
    nonce: cNonce,
    deadline: FAR_DEADLINE,
  });
  const gq = await guardianDigest(w, v, QCANCEL_TAG);
  const probe = mkCred("snap-probe");
  const ip = ethers.keccak256(
    abi.encode(["address", "bytes32", "address"], [addrOf(probe.nominee), probe.hash, w.verifiers.honest]),
  );
  const gi = await guardianDigest(w, v, ip);
  const dest = { vault: w.destination, codeHash: ethers.id("snap-dest"), generation: 2n };
  const mNonce = (await v.nonces(DOMAIN.MIGRATION)) as bigint;
  const md = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: (await v.guardianGeneration()) as bigint,
    params: ethers.keccak256(abi.encode(["address", "bytes32", "uint64"], [dest.vault, dest.codeHash, dest.generation])),
    domain: DOMAIN.MIGRATION,
    nonce: mNonce,
    deadline: FAR_DEADLINE,
  });

  return {
    used,
    active: r[R.ACTIVE] as boolean,
    live: (await v.effectiveLiveRecovery()) as boolean,
    // `deployWorld` seeds the ORIGINAL credential from the world label, which
    // necessarily differs between the `-sep` and `-col` worlds. Normalise it to
    // a symbol so only a genuine authority change can make the two differ; a
    // recovered-to nominee is label-independent and compares raw.
    signer: ((await v.ecdsaSigner()) as string) === addrOf(w.credKey) ? "ORIGINAL" : ((await v.ecdsaSigner()) as string),
    credGen: (await v.credentialGeneration()) as bigint,
    guardGen: (await v.guardianGeneration()) as bigint,
    canChallenge: await outcome(v.cancelRecovery.staticCall(cNonce, FAR_DEADLINE, sign(credKey, cd))),
    canQuorumCancel: await outcome(v.cancelRecoveryByQuorum.staticCall(quorum(w, gq.digest), gq.nonce, FAR_DEADLINE)),
    canInitiate: await outcome(
      v.initiateRecovery.staticCall(
        addrOf(probe.nominee),
        probe.hash,
        w.verifiers.honest,
        quorum(w, gi.digest),
        gi.nonce,
        FAR_DEADLINE,
      ),
    ),
    canBindMigration: await outcome(
      v.bindMigration.staticCall(dest, quorum(w, md), mNonce, FAR_DEADLINE, sign(credKey, md)),
    ),
  };
}

/**
 * Run one scripted history on BOTH kernels, snapshotting after every step, and
 * require the two snapshot sequences to be deeply equal. The script receives a
 * small driver so it is written once and executed twice.
 */
async function history(
  name: string,
  script: (d: {
    w: World;
    v: ethers.Contract;
    cred: { key: ethers.SigningKey; pq: ethers.SigningKey };
    take: () => Promise<void>;
  }) => Promise<void>,
): Promise<Snap[][]> {
  const out: Snap[][] = [];
  for (const kind of ["sep", "col"] as const) {
    const w = await deployWorld({ label: `w12-${name}-${kind}`, implOverride: K[kind] });
    const v = at(w, K[kind]);
    const cred = { key: w.credKey, pq: w.pqKey };
    const snaps: Snap[] = [];
    await script({
      w,
      v,
      cred,
      take: async () => {
        snaps.push(await snap(kind, w, v, cred.key));
      },
    });
    out.push(snaps);
  }
  return out;
}

const same = (name: string, [a, b]: Snap[][]) => {
  expect(a.length, `${name}: same number of observations`).to.equal(b.length);
  for (let i = 0; i < a.length; i++) expect(a[i], `${name}: step ${i}`).to.deep.equal(b[i]);
};

describe("SD-4 lane W1.2 — recovery state minimality", () => {
  // ===================================================================
  // 0 — the unmodified kernel resets on execute, as a side effect of delete
  // ===================================================================

  it("0 unmodified kernel: challenge → carry-forward → execute deletes → reads zero", async function () {
    this.timeout(300_000);
    const w = await deployWorld({ label: "w12-0" });
    const c = mkCred("w12-0");
    await (await propose(w, w.vault, c)).wait();
    await (await cancel(w, w.vault, w.credKey)).wait();
    expect((await w.vault.recovery())[R.CHALLENGES], "incremented by challenge").to.equal(1n);
    await (await propose(w, w.vault, c)).wait();
    expect((await w.vault.recovery())[R.CHALLENGES], "carried forward by initiation (:1177)").to.equal(1n);
    await networkHelpers.time.increase(7 * DAY + 1);
    await (await execute(w, w.vault, c)).wait();
    expect((await w.vault.recovery())[R.CHALLENGES], "zero after `delete recovery` (:1240)").to.equal(0n);
  });

  // ===================================================================
  // A — nine histories, two representations, deep equality
  // ===================================================================

  it("A1 challenge → re-initiate", async function () {
    this.timeout(600_000);
    same(
      "A1",
      await history("a1", async ({ w, v, cred, take }) => {
        await (await propose(w, v, mkCred("a1"))).wait();
        await take();
        await (await cancel(w, v, cred.key)).wait();
        await take();
        await (await propose(w, v, mkCred("a1"))).wait();
        await take();
      }),
    );
  });

  it("A2 challenge × limit → expire → re-initiate", async function () {
    this.timeout(600_000);
    same(
      "A2",
      await history("a2", async ({ w, v, cred, take }) => {
        for (let i = 0; i < 2; i++) {
          await (await propose(w, v, mkCred("a2"))).wait();
          await (await cancel(w, v, cred.key)).wait();
        }
        await (await propose(w, v, mkCred("a2"))).wait();
        await take();
        const E = (await v.recovery())[R.EXPIRES_AT] as bigint;
        await networkHelpers.time.increaseTo(Number(E));
        await take();
        await (await propose(w, v, mkCred("a2b"))).wait();
        await take();
      }),
    );
  });

  it("A3 challenge × limit → quorum cancel → re-initiate", async function () {
    this.timeout(600_000);
    same(
      "A3",
      await history("a3", async ({ w, v, cred, take }) => {
        for (let i = 0; i < 2; i++) {
          await (await propose(w, v, mkCred("a3"))).wait();
          await (await cancel(w, v, cred.key)).wait();
        }
        await (await propose(w, v, mkCred("a3"))).wait();
        await take();
        await (await quorumCancel(w, v)).wait();
        await take();
        await (await propose(w, v, mkCred("a3b"))).wait();
        await take();
      }),
    );
  });

  it("A4 challenge × limit → ordinary rotation → re-initiate", async function () {
    this.timeout(600_000);
    same(
      "A4",
      await history("a4", async ({ w, v, cred, take }) => {
        for (let i = 0; i < 2; i++) {
          await (await propose(w, v, mkCred("a4"))).wait();
          await (await cancel(w, v, cred.key)).wait();
        }
        await take();
        await (await rotateInPlace(w, v, cred.key, cred.pq)).wait();
        await take();
        await (await propose(w, v, mkCred("a4"))).wait();
        await take();
      }),
    );
  });

  it("A5 challenge × limit → successful recovery → new recovery", async function () {
    this.timeout(600_000);
    same(
      "A5",
      await history("a5", async ({ w, v, cred, take }) => {
        for (let i = 0; i < 2; i++) {
          await (await propose(w, v, mkCred("a5"))).wait();
          await (await cancel(w, v, cred.key)).wait();
        }
        const c = mkCred("a5-new");
        await (await propose(w, v, c)).wait();
        await take();
        await networkHelpers.time.increase(7 * DAY + 1);
        await (await execute(w, v, c)).wait();
        cred.key = c.nominee;
        cred.pq = c.pqNominee;
        await take();
        await (await propose(w, v, mkCred("a5-after"))).wait();
        await take();
      }),
    );
  });

  it("A6 successful recovery to identical material → new recovery", async function () {
    this.timeout(600_000);
    same(
      "A6",
      await history("a6", async ({ w, v, cred, take }) => {
        const c = mkCred("a6");
        await (await propose(w, v, c)).wait();
        await networkHelpers.time.increase(7 * DAY + 1);
        await (await execute(w, v, c)).wait();
        cred.key = c.nominee;
        cred.pq = c.pqNominee;
        await (await propose(w, v, mkCred("a6-x"))).wait();
        await (await cancel(w, v, cred.key)).wait();
        await take();
        // identical material, second recovery
        await (await propose(w, v, c)).wait();
        await networkHelpers.time.increase(7 * DAY + 1);
        await (await execute(w, v, c)).wait();
        await take();
        await (await propose(w, v, mkCred("a6-y"))).wait();
        await take();
      }),
    );
  });

  it("A7 expiry with no subsequent transaction — effective liveness only", async function () {
    this.timeout(600_000);
    same(
      "A7",
      await history("a7", async ({ w, v, cred, take }) => {
        await (await propose(w, v, mkCred("a7"))).wait();
        await (await cancel(w, v, cred.key)).wait();
        await (await propose(w, v, mkCred("a7"))).wait();
        const E = (await v.recovery())[R.EXPIRES_AT] as bigint;
        await networkHelpers.time.increaseTo(Number(E - 1n));
        await take();
        await networkHelpers.time.increaseTo(Number(E));
        await take();
        await networkHelpers.time.increaseTo(Number(E + BigInt(30 * DAY)));
        await take();
      }),
    );
  });

  it("A8 repeated expiry / re-initiation cycles", async function () {
    this.timeout(900_000);
    same(
      "A8",
      await history("a8", async ({ w, v, cred, take }) => {
        await (await propose(w, v, mkCred("a8"))).wait();
        await (await cancel(w, v, cred.key)).wait();
        for (let i = 0; i < 3; i++) {
          await (await propose(w, v, mkCred(`a8-${i}`))).wait();
          const E = (await v.recovery())[R.EXPIRES_AT] as bigint;
          await networkHelpers.time.increaseTo(Number(E));
          await take();
        }
      }),
    );
  });

  it("A9 guardian-set change with a live request — observed identically, SD-10 not absorbed", async function () {
    this.timeout(600_000);
    same(
      "A9",
      await history("a9", async ({ w, v, cred, take }) => {
        await (await propose(w, v, mkCred("a9"))).wait();
        await (await cancel(w, v, cred.key)).wait();
        await (await propose(w, v, mkCred("a9"))).wait();
        await take();
        await (await setGuardiansSame(w, v)).wait();
        await take();
      }),
    );
  });

  // ===================================================================
  // D — stale guardian cancellation, no request identifier assumed
  // ===================================================================

  describe("D stale CANCEL(R1) against R2, on the co-located kernel", () => {
    /** Pre-sign a quorum cancellation at an EXPLICIT nonce and hold it. */
    async function presignCancel(w: World, v: ethers.Contract, nonce: bigint) {
      const d = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.RECOVER,
        authorityGeneration: (await v.guardianGeneration()) as bigint,
        params: QCANCEL_TAG,
        domain: DOMAIN.GUARDIAN,
        nonce,
        deadline: FAR_DEADLINE,
      });
      return { proof: quorum(w, d), nonce };
    }

    for (const [how, terminate] of [
      ["credential challenge", async (w: World, v: ethers.Contract) => (await cancel(w, v, w.credKey)).wait()],
      [
        "expiry",
        async (_w: World, v: ethers.Contract) => {
          const E = (await v.recovery())[R.EXPIRES_AT] as bigint;
          await networkHelpers.time.increaseTo(Number(E));
        },
      ],
      [
        "successful recovery",
        async (w: World, v: ethers.Contract) => {
          await networkHelpers.time.increase(7 * DAY + 1);
          await (await execute(w, v, mkCred("d-r1"))).wait();
        },
      ],
    ] as [string, (w: World, v: ethers.Contract) => Promise<unknown>][]) {
      it(`R1 ends by ${how}: stale cancel finds no target before R2, and a dead nonce after`, async function () {
        this.timeout(600_000);
        const w = await deployWorld({ label: `w12-d-${how.slice(0, 4)}`, implOverride: K.col });
        const v = at(w, K.col);

        await (await propose(w, v, mkCred("d-r1"))).wait();
        const N1 = (await v.nonces(DOMAIN.GUARDIAN)) as bigint; // = N+1
        const stale = await presignCancel(w, v, N1);

        await terminate(w, v);

        // BEFORE R2: no live target. The nonce is NOT consumed by the revert.
        await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
          v,
          "NoRecovery",
        );
        expect(await v.nonces(DOMAIN.GUARDIAN), "revert consumes nothing").to.equal(N1);

        // R2's initiation necessarily consumes N+1 before R2 exists.
        await (await propose(w, v, mkCred("d-r2"))).wait();
        expect(await v.nonces(DOMAIN.GUARDIAN), "initiation consumed the stale nonce").to.equal(N1 + 1n);

        // AFTER R2: the stale cancellation is dead by nonce serialisation alone.
        await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
          v,
          "BadNonce",
        );
        expect((await v.recovery())[R.ACTIVE], "R2 untouched").to.equal(true);
      });
    }

    it("another guardian-domain action between R1 and R2 kills the stale cancel", async function () {
      this.timeout(600_000);
      const w = await deployWorld({ label: "w12-d-mid", implOverride: K.col });
      const v = at(w, K.col);
      await (await propose(w, v, mkCred("d-mid"))).wait();
      const stale = await presignCancel(w, v, (await v.nonces(DOMAIN.GUARDIAN)) as bigint);
      await (await cancel(w, v, w.credKey)).wait();
      // setGuardians consumes a guardian nonce AND bumps the generation the
      // digest binds — the stale cancel is dead twice over.
      await (await setGuardiansSame(w, v)).wait();
      await (await propose(w, v, mkCred("d-mid2"))).wait();
      // QuorumNotMet, not BadNonce — and the ORDER is the finding: the digest
      // binds `guardianGeneration`, `_requireQuorum` runs before `_consume`, so
      // the generation binding kills the stale cancel before the nonce is even
      // examined. Two independent mechanisms; either alone would suffice.
      await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
        v,
        "QuorumNotMet",
      );
    });

    it("same block, both orders: the stale cancel never reaches R2", async function () {
      this.timeout(600_000);
      for (const order of ["cancel-first", "initiate-first"]) {
        const w = await deployWorld({ label: `w12-d-${order}`, implOverride: K.col });
        const v = at(w, K.col);
        await (await propose(w, v, mkCred("d-sb"))).wait();
        const stale = await presignCancel(w, v, (await v.nonces(DOMAIN.GUARDIAN)) as bigint);
        await (await cancel(w, v, w.credKey)).wait();

        const r2 = mkCred("d-sb2");
        const ip = ethers.keccak256(
          abi.encode(["address", "bytes32", "address"], [addrOf(r2.nominee), r2.hash, w.verifiers.honest]),
        );
        const gi = await guardianDigest(w, v, ip);

        await ethers.provider.send("evm_setAutomine", [false]);
        const txs: Promise<ethers.ContractTransactionResponse>[] = [];
        const sendCancel = () => v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE, { gasLimit: 500_000 });
        const sendInit = () =>
          v.initiateRecovery(addrOf(r2.nominee), r2.hash, w.verifiers.honest, quorum(w, gi.digest), gi.nonce, FAR_DEADLINE, {
            gasLimit: 800_000,
          });
        if (order === "cancel-first") txs.push(sendCancel(), sendInit());
        else txs.push(sendInit(), sendCancel());
        const sent = await Promise.all(txs);
        await networkHelpers.mine();
        await ethers.provider.send("evm_setAutomine", [true]);

        const receipts = await Promise.all(sent.map((t) => ethers.provider.getTransactionReceipt(t.hash)));
        const statuses = receipts.map((r) => r?.status);
        // Exactly one succeeds — the initiation — and R2 is live and untouched.
        expect(statuses.filter((s) => s === 1).length, `${order}: one success`).to.equal(1);
        expect((await v.recovery())[R.SIGNER], `${order}: R2 installed`).to.equal(addrOf(r2.nominee));
        expect((await v.recovery())[R.ACTIVE], `${order}: R2 live`).to.equal(true);
      }
    });

    it("failed R2 initiation: the stale cancel still has no target and consumes nothing", async function () {
      this.timeout(600_000);
      const w = await deployWorld({ label: "w12-d-fail", implOverride: K.col });
      const v = at(w, K.col);
      await (await propose(w, v, mkCred("d-fail"))).wait();
      const N1 = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      const stale = await presignCancel(w, v, N1);
      await (await cancel(w, v, w.credKey)).wait();

      // R2 fails at initiation (zero verifier) — its nonce is NOT consumed.
      const bad = mkCred("d-fail2");
      const ip = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [addrOf(bad.nominee), bad.hash, ethers.ZeroAddress]));
      const gi = await guardianDigest(w, v, ip);
      await expect(
        v.initiateRecovery(addrOf(bad.nominee), bad.hash, ethers.ZeroAddress, quorum(w, gi.digest), gi.nonce, FAR_DEADLINE),
      ).to.be.revertedWithCustomError(v, "ZeroAddress");
      expect(await v.nonces(DOMAIN.GUARDIAN)).to.equal(N1);

      // The stale cancel is now nonce-VALID — and still finds no live request.
      await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
        v,
        "NoRecovery",
      );
      expect(await v.nonces(DOMAIN.GUARDIAN), "still unconsumed").to.equal(N1);
    });
  });
});
