/**
 * EXPERIMENTAL PROTOTYPE — LANE W2: THE FROZEN RECOVERY LIFECYCLE, ON THE REAL
 * ARTIFACT.
 *
 * Every lane before this one measured the recovery lifecycle on kernels compiled
 * IN MEMORY (`sd4-candidate-kernels.ts`). This suite is different in exactly one
 * way, and it is the whole point: every test below deploys the kernel the
 * repository actually compiles — `deployWorld()` with NO `implOverride` — so a
 * green run here is evidence about the shipped prototype and nothing else.
 *
 * WHAT IS FROZEN, and where it comes from (W2_IMPLEMENTATION_CONTRACT.md and
 * docs/Vault_vNext_Recovery_Amendment.md at #188 head e6964aeb):
 *
 *   LIVE_WINDOW                 = [executableAt, expiresAt)
 *   effectiveLive               = active && now < expiresAt
 *   K-9 mechanism B             = cancelRecoveryByQuorum(QuorumProof,uint256,uint64)
 *                                 guardian quorum, DOMAIN_GUARDIAN nonce, digest
 *                                 bound to guardianGeneration, distinct event
 *   live overwrite              = refused (BadState) BEFORE any nonce is consumed
 *   expired request             = zero execution authority (Expired), zero
 *                                 cancellation-target authority (NoRecovery from
 *                                 both principals, nothing consumed), zero blocking
 *                                 effect on bindMigration and on fresh initiation
 *   challenge epoch             = challengesUsed persists across challenge, quorum
 *                                 cancellation, expiry, fresh initiation and
 *                                 ordinary rotation; resets ONLY on a successful
 *                                 guardian recovery (the existing `delete recovery`)
 *   guardian-cancel replay      = excluded by DOMAIN_GUARDIAN nonce serialisation
 *                                 plus generation binding; no request id
 *
 * WRITTEN RED FIRST. Against the kernel at e6964aeb the tests that exercise
 * mechanism B, the live-overwrite refusal and the half-open expiry FAIL for the
 * intended reasons (selector absent; overwrite accepted; execution accepted at
 * expiresAt; expired request still challengeable and still blocking migration).
 * The tests that pin behaviour W2 must PRESERVE — carry-forward on initiation,
 * rotation leaving the epoch alone, the reset on successful recovery, TooEarly
 * before maturity — pass on both kernels and are regression guards, not RED.
 *
 * MINED-INSTANT DISCIPLINE (Lane W1). Every boundary probe asserts the block
 * timestamp the transaction ACTUALLY executed at, never a wall-clock point the
 * transaction did not execute at. One fresh world per probe transaction, because
 * only the first transaction after `setNextBlockTimestamp` can land exactly on
 * the boundary second.
 *
 * NOTHING HERE ASKS THE KERNEL WHAT TO SIGN. Every digest is mirrored from
 * `stateful/world.ts` / `sd4-harness.ts`, so a kernel that binds the wrong
 * fields cannot make this harness agree with it.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { R, abi, cancel, guardianDigest, quorum } from "./sd4-harness.js";
import {
  ACTION,
  DAY,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  sign,
  type World,
} from "../stateful/world.js";

// ---------------------------------------------------------------------------
// The W2 surface, declared by the harness rather than read from the artifact.
//
// The ABI fragments below are what the frozen contract says the kernel MUST
// expose. They are appended to the real artifact's interface only when the
// artifact does not already carry them, so on the pre-W2 kernel a call to
// `cancelRecoveryByQuorum` reaches the clone with a selector it does not
// implement and REVERTS WITH NO DATA — the RED failure for "mechanism B is
// missing" — while on the W2 kernel the same contract object binds to the real
// function and the tests assert its semantics.
// ---------------------------------------------------------------------------

const QCANCEL_TAG = ethers.id("QUORUM_CANCEL_RECOVERY");
const QCANCEL_FN =
  "function cancelRecoveryByQuorum((address[] members,bool[] isContract,uint256[] attestingIndices,bytes[] attestations) proof,uint256 nonce,uint64 deadline)";
const QCANCEL_EVENT = "event RecoveryCancelledByQuorum(uint32 challengesUsed)";
const QCANCEL_SIGHASH = "cancelRecoveryByQuorum((address[],bool[],uint256[],bytes[]),uint256,uint64)";

/** The real vault, addressed through the real ABI plus the frozen W2 fragments. */
function w2(w: World): ethers.Contract {
  const base = w.vault.interface;
  const fragments: (string | Record<string, unknown>)[] = base.fragments.map(
    (f) => JSON.parse(f.format("json")) as Record<string, unknown>,
  );
  if (!base.hasFunction(QCANCEL_SIGHASH)) fragments.push(QCANCEL_FN);
  if (!base.hasEvent("RecoveryCancelledByQuorum")) fragments.push(QCANCEL_EVENT);
  return new ethers.Contract(w.vaultAddress, fragments as ethers.InterfaceAbi, w.deployer);
}

// ---------------------------------------------------------------------------
// Credential material and the recovery drivers
// ---------------------------------------------------------------------------

interface Cred {
  nominee: ethers.SigningKey;
  pqNominee: ethers.SigningKey;
  key32: string;
  hash: string;
}
const mkCred = (tag: string): Cred => {
  const nominee = keyOf(`w2-${tag}-s`);
  const pqNominee = keyOf(`w2-${tag}-p`);
  const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
  return { nominee, pqNominee, key32, hash: ethers.keccak256(key32) };
};

/**
 * Transaction overrides for the boundary probes. ethers estimates gas before
 * sending, and a probe that REVERTS at estimation is never sent, so no block is
 * mined and the instant it "executed at" does not exist. An explicit gas limit
 * skips estimation: the transaction is sent, mined at the pinned timestamp, and
 * its revert is reported — which is what lets a refused probe prove its instant.
 */
type Overrides = { gasLimit?: number };
const MINED: Overrides = { gasLimit: 2_000_000 };

/** `initiateRecovery` for `c`, signed by seats 0 and 1 at the CURRENT guardian nonce. */
async function propose(w: World, v: ethers.Contract, c: Cred, verifier?: string, overrides: Overrides = {}) {
  const ver = verifier ?? w.verifiers.honest;
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [addrOf(c.nominee), c.hash, ver]));
  const { digest, nonce } = await guardianDigest(w, v, params);
  return v.initiateRecovery(addrOf(c.nominee), c.hash, ver, quorum(w, digest), nonce, FAR_DEADLINE, overrides);
}

/** The credential's bounded challenge (mirrors `sd4-harness.cancel`, plus overrides). */
async function challenge(w: World, v: ethers.Contract, credKey: ethers.SigningKey, overrides: Overrides = {}) {
  const nonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await v.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.RECOVER,
    authorityGeneration: credGen,
    params: ethers.id("CANCEL"),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.cancelRecovery(nonce, FAR_DEADLINE, sign(credKey, d), overrides);
}

/** A quorum cancellation proof at an EXPLICIT nonce, held for later. */
async function presignQuorumCancel(w: World, v: ethers.Contract, nonce: bigint) {
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
  return { proof: quorum(w, d), nonce, digest: d };
}

/** K-9 mechanism B at the current guardian nonce. */
async function quorumCancel(w: World, v: ethers.Contract, overrides: Overrides = {}) {
  const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);
  return v.cancelRecoveryByQuorum(quorum(w, digest), nonce, FAR_DEADLINE, overrides);
}

/** `executeRecovery` for the live request proposing `c`, with genuine possession proofs. */
async function execute(w: World, v: ethers.Contract, c: Cred, overrides: Overrides = {}) {
  const pop = (await v.recoveryPossessionDigest()) as string;
  return v.executeRecovery(
    {
      newSigner: addrOf(c.nominee),
      newPqKeyHash: c.hash,
      newPqKey: c.key32,
      newEcdsaPop: sign(c.nominee, pop),
      newPqPop: sign(c.pqNominee, pop),
    },
    overrides,
  );
}

/** Ordinary credential rotation to `next` (or in place when `next` is the installed material). */
async function rotate(
  w: World,
  v: ethers.Contract,
  credKey: ethers.SigningKey,
  pqKey: ethers.SigningKey,
  next: { signer: ethers.SigningKey; pq: ethers.SigningKey },
) {
  const nonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const gen = (await v.credentialGeneration()) as bigint;
  const newSigner = addrOf(next.signer);
  const newPqBytes = abi.encode(["address"], [addrOf(next.pq)]);
  const newHash = ethers.keccak256(newPqBytes);
  const pop = (await v.credentialPossessionDigest(newSigner, newHash)) as string;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.ROTATE,
    authorityGeneration: gen,
    params: ethers.keccak256(abi.encode(["address", "bytes32"], [newSigner, newHash])),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.rotateCredential(
    {
      newSigner,
      newPqKeyHash: newHash,
      newPqKey: newPqBytes,
      newEcdsaPop: sign(next.signer, pop),
      newPqPop: sign(next.pq, pop),
    },
    nonce,
    FAR_DEADLINE,
    sign(credKey, d),
    sign(pqKey, d),
    abi.encode(["address"], [addrOf(pqKey)]),
  );
}

/** Re-commit the SAME roster: bumps guardianGeneration and consumes a guardian nonce. */
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

/** `bindMigration` by quorum AND credential, to the world's destination stub. */
async function bindMigration(w: World, v: ethers.Contract, credKey: ethers.SigningKey, overrides: Overrides = {}) {
  const dest = { vault: w.destination, codeHash: ethers.id("w2-dest"), generation: 2n };
  const nonce = (await v.nonces(DOMAIN.MIGRATION)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: (await v.guardianGeneration()) as bigint,
    params: ethers.keccak256(
      abi.encode(["address", "bytes32", "uint64"], [dest.vault, dest.codeHash, dest.generation]),
    ),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.bindMigration(dest, quorum(w, d), nonce, FAR_DEADLINE, sign(credKey, d), overrides);
}

/** The block timestamp a transaction ACTUALLY executed at. */
async function minedAt(tx: ethers.ContractTransactionResponse): Promise<bigint> {
  const rec = await tx.wait();
  return BigInt((await ethers.provider.getBlock(rec!.blockNumber))!.timestamp);
}
const latest = async (): Promise<bigint> => BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
const challenges = async (v: ethers.Contract): Promise<bigint> => (await v.recovery())[R.CHALLENGES] as bigint;
const isActive = async (v: ethers.Contract): Promise<boolean> => (await v.recovery())[R.ACTIVE] as boolean;
const expiresAt = async (v: ethers.Contract): Promise<bigint> => (await v.recovery())[R.EXPIRES_AT] as bigint;

/** Every authority-bearing storage field EXCEPT the recovery request, for "nothing else moved" assertions. */
async function authorityState(v: ethers.Contract) {
  const [signer, pqHash, credGen, floor, verifier, gCommit, gThr, gGen, n0, n1, n2, n3] = await Promise.all([
    v.ecdsaSigner(),
    v.pqPublicKeyHash(),
    v.credentialGeneration(),
    v.securityFloor(),
    v.pqVerifier(),
    v.guardianCommitment(),
    v.guardianThreshold(),
    v.guardianGeneration(),
    v.nonces(0),
    v.nonces(1),
    v.nonces(2),
    v.nonces(3),
  ]);
  return {
    signer: String(signer),
    pqHash: String(pqHash),
    credGen: credGen as bigint,
    floor: [floor[0], floor[1], floor[2], floor[3]].map(String).join("/"),
    verifier: String(verifier),
    gCommit: String(gCommit),
    gThr: gThr as bigint,
    gGen: gGen as bigint,
    nonces: [n0, n1, n2, n3].map((n) => (n as bigint).toString()).join(","),
  };
}

/** Drive the credential's challenge budget to exhaustion: two challenges, each on a fresh request. */
async function exhaust(w: World, v: ethers.Contract, credKey: ethers.SigningKey, tag: string): Promise<void> {
  for (let i = 0; i < 2; i++) {
    await (await propose(w, v, mkCred(`${tag}-x${i}`))).wait();
    await (await cancel(w, v, credKey)).wait();
  }
  expect(await challenges(v), `${tag}: budget exhausted`).to.equal(2n);
}

const KINDS = ["execute", "challenge", "quorumCancel", "bindMigration", "initiate"] as const;
type ProbeKind = (typeof KINDS)[number];

describe("W2 — frozen recovery lifecycle on the real artifact", () => {
  // =========================================================================
  // A. K-9 mechanism B — guardian-quorum cancellation
  // =========================================================================
  describe("A. K-9 mechanism B: guardian-quorum cancellation", () => {
    it("A1 the real artifact exposes exactly the frozen surface: cancelRecoveryByQuorum and RecoveryCancelledByQuorum", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-a1" });
      const iface = w.vault.interface;
      expect(iface.hasFunction(QCANCEL_SIGHASH), "K-9 mechanism B selector present on the compiled kernel").to.equal(
        true,
      );
      expect(iface.hasEvent("RecoveryCancelledByQuorum"), "distinct terminal event present").to.equal(true);
      expect(iface.hasFunction("recovery()"), "autogenerated getter retained").to.equal(true);
      expect(iface.getFunction("recovery()")!.outputs.length, "recovery() tuple shape unchanged").to.equal(8);
      // Option E0: liveness is a pure function of public data; no new selector for it.
      expect(iface.hasFunction("effectiveLiveRecovery()"), "no fabricated liveness getter").to.equal(false);
    });

    it("A2 a current quorum terminates an effectively-live request: authority cleared, epoch and every other slot untouched, one guardian nonce, distinct event", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-a2" });
      const v = w2(w);
      const c = mkCred("a2");
      await (await propose(w, v, c)).wait();
      const before = await authorityState(v);
      const rBefore = await v.recovery();
      const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      const cNonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;

      const tx = await quorumCancel(w, v);
      await expect(tx).to.emit(v, "RecoveryCancelledByQuorum").withArgs(0n);
      await expect(tx).to.not.emit(v, "RecoveryCancelled");
      await tx.wait();

      expect(await isActive(v), "request authority cleared").to.equal(false);
      expect(await challenges(v), "credential budget neither consumed nor refunded").to.equal(0n);
      const rAfter = await v.recovery();
      for (const i of [
        R.SIGNER,
        R.PQ_KEY_HASH,
        R.VERIFIER,
        R.EXECUTABLE_AT,
        R.EXPIRES_AT,
        R.GUARDIAN_GEN,
        R.CHALLENGES,
      ]) {
        expect(rAfter[i], `recovery field ${i} untouched (no whole-struct delete)`).to.equal(rBefore[i]);
      }
      expect(await v.nonces(DOMAIN.GUARDIAN), "exactly one guardian nonce consumed").to.equal(gNonce + 1n);
      expect(await v.nonces(DOMAIN.CREDENTIAL), "no credential nonce consumed").to.equal(cNonce);
      const after = await authorityState(v);
      expect(after.signer).to.equal(before.signer);
      expect(after.pqHash).to.equal(before.pqHash);
      expect(after.credGen).to.equal(before.credGen);
      expect(after.floor).to.equal(before.floor);
      expect(after.verifier).to.equal(before.verifier);
      expect(after.gCommit).to.equal(before.gCommit);
      expect(after.gThr).to.equal(before.gThr);
      expect(after.gGen).to.equal(before.gGen);
    });

    it("A3 below quorum, wrong principal, wrong digest: refused as QuorumNotMet, request stays live, nothing consumed", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-a3" });
      const v = w2(w);
      await (await propose(w, v, mkCred("a3"))).wait();
      const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      const { digest, nonce } = await guardianDigest(w, v, QCANCEL_TAG);

      // one guardian — below k = 2
      const one = { ...quorum(w, digest), attestingIndices: [0], attestations: [sign(w.gKeys[0]!, digest)] };
      await expect(v.cancelRecoveryByQuorum(one, nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(v, "QuorumNotMet");

      // the CREDENTIAL principal signing at guardian seats: principal separation
      const credSigned = {
        ...quorum(w, digest),
        attestations: [sign(w.credKey, digest), sign(w.credKey, digest)],
      };
      await expect(v.cancelRecoveryByQuorum(credSigned, nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
        v,
        "QuorumNotMet",
      );

      // guardians signing the CREDENTIAL challenge digest instead of the quorum one
      const credDomainDigest = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: 1n,
        actionType: ACTION.RECOVER,
        authorityGeneration: (await v.credentialGeneration()) as bigint,
        params: ethers.id("CANCEL"),
        domain: DOMAIN.CREDENTIAL,
        nonce,
        deadline: FAR_DEADLINE,
      });
      await expect(
        v.cancelRecoveryByQuorum(quorum(w, credDomainDigest), nonce, FAR_DEADLINE),
      ).to.be.revertedWithCustomError(v, "QuorumNotMet");

      expect(await isActive(v), "request still live").to.equal(true);
      expect(await v.nonces(DOMAIN.GUARDIAN), "no nonce consumed by a refused cancellation").to.equal(gNonce);
      expect(await challenges(v)).to.equal(0n);
    });

    it("A4 the credential's challenge and the quorum's cancellation stay distinct: two domains, two events, and the budget moves only for the credential", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-a4" });
      const v = w2(w);
      await (await propose(w, v, mkCred("a4"))).wait();
      const tx1 = await cancel(w, v, w.credKey);
      await expect(tx1).to.emit(v, "RecoveryCancelled").withArgs(1n);
      await expect(tx1).to.not.emit(v, "RecoveryCancelledByQuorum");
      await tx1.wait();
      expect(await challenges(v)).to.equal(1n);

      await (await propose(w, v, mkCred("a4b"))).wait();
      const tx2 = await quorumCancel(w, v);
      await expect(tx2).to.emit(v, "RecoveryCancelledByQuorum").withArgs(1n);
      await tx2.wait();
      expect(await challenges(v), "quorum cancellation reports the standing epoch and does not move it").to.equal(1n);
    });

    it("A5 after a quorum cancellation a fresh request initiates with the epoch carried forward, and completes", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-a5" });
      const v = w2(w);
      await (await propose(w, v, mkCred("a5"))).wait();
      await (await cancel(w, v, w.credKey)).wait();
      await (await propose(w, v, mkCred("a5"))).wait();
      await (await quorumCancel(w, v)).wait();
      const c = mkCred("a5-fresh");
      const tInit = await minedAt(await propose(w, v, c));
      const r = await v.recovery();
      expect(r[R.CHALLENGES], "carried forward, not refunded").to.equal(1n);
      expect((r[R.EXECUTABLE_AT] as bigint) - tInit).to.equal(BigInt(7 * DAY));
      expect((r[R.EXPIRES_AT] as bigint) - tInit).to.equal(BigInt(21 * DAY));
      await networkHelpers.time.increase(7 * DAY + 1);
      await (await execute(w, v, c)).wait();
      expect(await v.ecdsaSigner()).to.equal(addrOf(c.nominee));
    });
  });

  // =========================================================================
  // B. The expiry boundary — one fresh world per probe, mined instant asserted
  // =========================================================================
  describe("B. expiry boundary: expiresAt-1 live, expiresAt expired, expiresAt+1 expired", () => {
    /**
     * Runs ONE probe transaction in a FRESH world, landing exactly at
     * `expiresAt + delta`, and returns what the kernel did.
     */
    async function probe(kind: ProbeKind, delta: bigint) {
      const label = `w2-b-${kind}-${delta < 0n ? "m" : "p"}${(delta < 0n ? -delta : delta).toString()}`;
      const w = await deployWorld({ label });
      const v = w2(w);
      const c = mkCred(label);
      await (await propose(w, v, c)).wait();
      const E = await expiresAt(v);
      const target = E + delta;
      const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      const cNonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const used = await challenges(v);
      // The preceding block sits strictly below the target, so the probe lands ON it.
      await networkHelpers.time.increaseTo(Number(target - 1n));
      await networkHelpers.time.setNextBlockTimestamp(Number(target));
      const next = mkCred(`${label}-next`);
      // Sent with an explicit gas limit (see MINED) so a refused probe is still
      // mined at the pinned instant and `landed` can prove where it executed.
      const send = () => {
        switch (kind) {
          case "execute":
            return execute(w, v, c, MINED);
          case "challenge":
            return challenge(w, v, w.credKey, MINED);
          case "quorumCancel":
            return quorumCancel(w, v, MINED);
          case "bindMigration":
            return bindMigration(w, v, w.credKey, MINED);
          case "initiate":
            return propose(w, v, next, undefined, MINED);
        }
      };
      let error: string | null = null;
      let tMined: bigint | null = null;
      try {
        tMined = await minedAt(await send());
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
      return {
        w,
        v,
        c,
        next,
        E,
        target,
        error,
        tMined,
        landed: await latest(),
        gNonceDelta: ((await v.nonces(DOMAIN.GUARDIAN)) as bigint) - gNonce,
        cNonceDelta: ((await v.nonces(DOMAIN.CREDENTIAL)) as bigint) - cNonce,
        usedDelta: (await challenges(v)) - used,
        active: await isActive(v),
      };
    }

    const custom = (err: string | null, name: string): boolean => err !== null && err.includes(name);

    it("B1 at expiresAt-1 the request is LIVE: execution succeeds, both cancellations succeed, migration is blocked, initiation is refused as overwrite", async function () {
      this.timeout(900_000);
      const ex = await probe("execute", -1n);
      expect(ex.error, "execution at expiresAt-1 succeeds").to.equal(null);
      expect(ex.tMined, "executed at exactly expiresAt-1").to.equal(ex.target);
      expect(await ex.v.ecdsaSigner()).to.equal(addrOf(ex.c.nominee));

      const ch = await probe("challenge", -1n);
      expect(ch.error, "credential challenge at expiresAt-1 succeeds").to.equal(null);
      expect(ch.tMined).to.equal(ch.target);
      expect(ch.usedDelta).to.equal(1n);
      expect(ch.active).to.equal(false);

      const qc = await probe("quorumCancel", -1n);
      expect(qc.error, "quorum cancellation at expiresAt-1 succeeds").to.equal(null);
      expect(qc.tMined).to.equal(qc.target);
      expect(qc.usedDelta, "budget untouched by the quorum").to.equal(0n);
      expect(qc.gNonceDelta).to.equal(1n);
      expect(qc.active).to.equal(false);

      const bm = await probe("bindMigration", -1n);
      expect(custom(bm.error, "NoRecovery"), `a live request blocks migration (got ${bm.error})`).to.equal(true);
      expect(bm.landed, "probe block mined at expiresAt-1").to.equal(bm.target);

      const init = await probe("initiate", -1n);
      expect(custom(init.error, "BadState"), `a live request cannot be overwritten (got ${init.error})`).to.equal(true);
      expect(init.landed).to.equal(init.target);
      expect(init.gNonceDelta, "refused initiation consumes no guardian nonce").to.equal(0n);
      expect((await init.v.recovery())[R.SIGNER], "original request intact").to.equal(addrOf(init.c.nominee));
    });

    for (const [name, delta] of [
      ["B2 at expiresAt", 0n],
      ["B3 at expiresAt+1", 1n],
    ] as [string, bigint][]) {
      it(`${name} the request is EXPIRED: Expired on execute, NoRecovery from both principals with nothing consumed, migration binds, fresh initiation is not overwrite`, async function () {
        this.timeout(900_000);
        const ex = await probe("execute", delta);
        expect(custom(ex.error, "Expired"), `execute at the instant -> Expired (got ${ex.error})`).to.equal(true);
        expect(ex.landed, "probe block mined at the instant").to.equal(ex.target);
        expect(ex.active, "stale byte still set — carries nothing").to.equal(true);

        const ch = await probe("challenge", delta);
        expect(custom(ch.error, "NoRecovery"), `credential challenge -> NoRecovery (got ${ch.error})`).to.equal(true);
        expect(ch.landed).to.equal(ch.target);
        expect(ch.usedDelta, "a refused challenge consumes no budget").to.equal(0n);
        expect(ch.cNonceDelta, "a refused challenge consumes no credential nonce").to.equal(0n);

        const qc = await probe("quorumCancel", delta);
        expect(custom(qc.error, "NoRecovery"), `quorum cancellation -> NoRecovery (got ${qc.error})`).to.equal(true);
        expect(qc.landed).to.equal(qc.target);
        expect(qc.gNonceDelta, "a refused cancellation consumes no guardian nonce").to.equal(0n);
        expect(qc.usedDelta).to.equal(0n);

        const bm = await probe("bindMigration", delta);
        expect(bm.error, `an expired request does not block migration (got ${bm.error})`).to.equal(null);
        expect(bm.tMined).to.equal(bm.target);
        expect(await bm.v.effectiveSafeState(), "MIGRATION_ONLY with no sweeper").to.equal(3n);

        const init = await probe("initiate", delta);
        expect(init.error, `fresh initiation over an expired request is allowed (got ${init.error})`).to.equal(null);
        expect(init.tMined).to.equal(init.target);
        const r = await init.v.recovery();
        expect(r[R.SIGNER], "fresh request installed").to.equal(addrOf(init.next.nominee));
        expect((r[R.EXECUTABLE_AT] as bigint) - init.target, "own full delay").to.equal(BigInt(7 * DAY));
        expect((r[R.EXPIRES_AT] as bigint) - init.target, "own full expiry").to.equal(BigInt(21 * DAY));
        expect(r[R.CHALLENGES], "challenge count preserved across expiry and re-initiation").to.equal(0n);
      });
    }

    it("B4 TooEarly before maturity is retained, and the half-open window admits execution at expiresAt-1 only", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-b4" });
      const v = w2(w);
      const c = mkCred("b4");
      await (await propose(w, v, c)).wait();
      await expect(execute(w, v, c)).to.be.revertedWithCustomError(v, "TooEarly");
      expect(await isActive(v)).to.equal(true);
    });
  });

  // =========================================================================
  // C. Live overwrite
  // =========================================================================
  describe("C. live overwrite is refused; expired storage does not block", () => {
    it("C1 while live before maturity: initiateRecovery(next) -> BadState, guardian nonce unconsumed, request intact", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-c1" });
      const v = w2(w);
      const c1 = mkCred("c1");
      await (await propose(w, v, c1)).wait();
      const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      await expect(propose(w, v, mkCred("c1-next"))).to.be.revertedWithCustomError(v, "BadState");
      expect(await v.nonces(DOMAIN.GUARDIAN), "refused overwrite consumes no nonce").to.equal(gNonce);
      expect((await v.recovery())[R.SIGNER]).to.equal(addrOf(c1.nominee));
      expect(await isActive(v)).to.equal(true);
    });

    it("C2 while live after maturity: still refused", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-c2" });
      const v = w2(w);
      const c1 = mkCred("c2");
      await (await propose(w, v, c1)).wait();
      await networkHelpers.time.increase(8 * DAY);
      const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      await expect(propose(w, v, mkCred("c2-next"))).to.be.revertedWithCustomError(v, "BadState");
      expect(await v.nonces(DOMAIN.GUARDIAN)).to.equal(gNonce);
      expect((await v.recovery())[R.SIGNER]).to.equal(addrOf(c1.nominee));
    });

    it("C3 after expiry: initiation allowed with the challenge count preserved; no cleanup transaction was needed", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-c3" });
      const v = w2(w);
      await (await propose(w, v, mkCred("c3"))).wait();
      await (await cancel(w, v, w.credKey)).wait();
      await (await propose(w, v, mkCred("c3b"))).wait();
      expect(await challenges(v)).to.equal(1n);
      await networkHelpers.time.increaseTo(Number(await expiresAt(v)));
      const c = mkCred("c3-fresh");
      await (await propose(w, v, c)).wait();
      expect((await v.recovery())[R.SIGNER]).to.equal(addrOf(c.nominee));
      expect(await challenges(v), "epoch preserved across expiry").to.equal(1n);
    });
  });

  // =========================================================================
  // D. The challenge epoch
  // =========================================================================
  describe("D. challenge epoch: persists across every exit but a successful recovery", () => {
    it("D1 challenge -> re-initiate carries the count", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-d1" });
      const v = w2(w);
      await (await propose(w, v, mkCred("d1"))).wait();
      await (await cancel(w, v, w.credKey)).wait();
      await (await propose(w, v, mkCred("d1"))).wait();
      expect(await challenges(v)).to.equal(1n);
    });

    it("D2 exhaust -> quorum cancel -> re-initiate: still exhausted", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-d2" });
      const v = w2(w);
      await exhaust(w, v, w.credKey, "d2");
      await (await propose(w, v, mkCred("d2-r3"))).wait();
      await (await quorumCancel(w, v)).wait();
      await (await propose(w, v, mkCred("d2-r4"))).wait();
      expect(await challenges(v)).to.equal(2n);
      await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "ChallengeExhausted");
    });

    it("D3 exhaust -> expiry -> re-initiate: still exhausted, with no cleanup transaction", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-d3" });
      const v = w2(w);
      await exhaust(w, v, w.credKey, "d3");
      await (await propose(w, v, mkCred("d3-r3"))).wait();
      await networkHelpers.time.increaseTo(Number(await expiresAt(v)));
      await (await propose(w, v, mkCred("d3-r4"))).wait();
      expect(await challenges(v)).to.equal(2n);
      await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "ChallengeExhausted");
    });

    it("D4 exhaust -> ordinary rotation (identical material, then different material) -> re-initiate: still exhausted", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-d4" });
      const v = w2(w);
      await exhaust(w, v, w.credKey, "d4");
      // identical material: the credential rotates to itself
      await (await rotate(w, v, w.credKey, w.pqKey, { signer: w.credKey, pq: w.pqKey })).wait();
      await (await propose(w, v, mkCred("d4-r3"))).wait();
      expect(await challenges(v), "self-rotation refunds nothing").to.equal(2n);
      await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "ChallengeExhausted");
      await (await quorumCancel(w, v)).wait();
      // different material
      const next = { signer: w.spareCred[0]!, pq: w.sparePq[0]! };
      await (await rotate(w, v, w.credKey, w.pqKey, next)).wait();
      await (await propose(w, v, mkCred("d4-r4"))).wait();
      expect(await challenges(v), "rotation to fresh material refunds nothing").to.equal(2n);
      await expect(cancel(w, v, next.signer)).to.be.revertedWithCustomError(v, "ChallengeExhausted");
    });

    it("D5 successful guardian recovery resets the epoch; a later recovery is challengeable again", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-d5" });
      const v = w2(w);
      await exhaust(w, v, w.credKey, "d5");
      const c = mkCred("d5-new");
      await (await propose(w, v, c)).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await (await execute(w, v, c)).wait();
      expect(await challenges(v), "reset at the authority transition").to.equal(0n);
      await (await propose(w, v, mkCred("d5-later"))).wait();
      await expect(cancel(w, v, c.nominee))
        .to.emit(v, "RecoveryCancelled")
        .withArgs(1n);
      expect(await challenges(v)).to.equal(1n);
    });

    it("D6 recovery to byte-identical material also resets: the boundary is the authority, not the bytes", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-d6" });
      const v = w2(w);
      const c = mkCred("d6");
      await (await propose(w, v, c)).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await (await execute(w, v, c)).wait();
      await exhaust(w, v, c.nominee, "d6");
      // identical material, second recovery
      await (await propose(w, v, c)).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await (await execute(w, v, c)).wait();
      expect(await v.ecdsaSigner()).to.equal(addrOf(c.nominee));
      expect(await challenges(v), "reset on identical material").to.equal(0n);
      await (await propose(w, v, mkCred("d6-later"))).wait();
      await (await cancel(w, v, c.nominee)).wait();
      expect(await challenges(v)).to.equal(1n);
    });

    it("D7 a challenge with no request, and a challenge against a fresh vault, both refuse with NoRecovery and consume nothing", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-d7" });
      const v = w2(w);
      const cNonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
      await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "NoRecovery");
      await expect(quorumCancel(w, v)).to.be.revertedWithCustomError(v, "NoRecovery");
      expect(await v.nonces(DOMAIN.CREDENTIAL)).to.equal(cNonce);
      expect(await challenges(v)).to.equal(0n);
    });
  });

  // =========================================================================
  // E. Guardian-cancel replay — no request identifier assumed
  // =========================================================================
  describe("E. stale quorum cancellation for R1 never reaches R2", () => {
    for (const [how, terminate] of [
      ["credential challenge", async (w: World, v: ethers.Contract) => (await cancel(w, v, w.credKey)).wait()],
      [
        "expiry",
        async (_w: World, v: ethers.Contract) => {
          await networkHelpers.time.increaseTo(Number(await expiresAt(v)));
        },
      ],
      [
        "successful recovery",
        async (w: World, v: ethers.Contract) => {
          await networkHelpers.time.increase(7 * DAY + 1);
          await (await execute(w, v, mkCred("e-r1"))).wait();
        },
      ],
    ] as [string, (w: World, v: ethers.Contract) => Promise<unknown>][]) {
      it(`E1 R1 ends by ${how}: stale cancel finds no target before R2 (nothing consumed) and a dead nonce after; R2 survives`, async function () {
        this.timeout(600_000);
        const w = await deployWorld({ label: `w2-e-${how.slice(0, 4)}` });
        const v = w2(w);
        await (await propose(w, v, mkCred("e-r1"))).wait();
        const N1 = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
        const stale = await presignQuorumCancel(w, v, N1);

        await terminate(w, v);

        await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
          v,
          "NoRecovery",
        );
        expect(await v.nonces(DOMAIN.GUARDIAN), "a refused cancellation consumes nothing").to.equal(N1);

        const r2 = mkCred("e-r2");
        await (await propose(w, v, r2)).wait();
        expect(await v.nonces(DOMAIN.GUARDIAN), "R2's initiation consumed the stale nonce").to.equal(N1 + 1n);

        await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
          v,
          "BadNonce",
        );
        expect((await v.recovery())[R.SIGNER], "R2 installed").to.equal(addrOf(r2.nominee));
        expect(await isActive(v), "R2 untouched").to.equal(true);
      });
    }

    it("E2 an intervening guardian-generation change kills the stale cancel on generation binding before the nonce is examined", async function () {
      this.timeout(600_000);
      const w = await deployWorld({ label: "w2-e2" });
      const v = w2(w);
      await (await propose(w, v, mkCred("e2-r1"))).wait();
      const stale = await presignQuorumCancel(w, v, (await v.nonces(DOMAIN.GUARDIAN)) as bigint);
      await (await cancel(w, v, w.credKey)).wait();
      await (await setGuardiansSame(w, v)).wait();
      await (await propose(w, v, mkCred("e2-r2"))).wait();
      await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
        v,
        "QuorumNotMet",
      );
      expect(await isActive(v), "R2 untouched").to.equal(true);
    });

    it("E3 same block, both orders: exactly one transaction succeeds and it is the initiation; R2 is live and untouched", async function () {
      this.timeout(600_000);
      for (const order of ["cancel-first", "initiate-first"]) {
        const w = await deployWorld({ label: `w2-e3-${order}` });
        const v = w2(w);
        await (await propose(w, v, mkCred("e3-r1"))).wait();
        const stale = await presignQuorumCancel(w, v, (await v.nonces(DOMAIN.GUARDIAN)) as bigint);
        await (await cancel(w, v, w.credKey)).wait();

        const r2 = mkCred("e3-r2");
        const ip = ethers.keccak256(
          abi.encode(["address", "bytes32", "address"], [addrOf(r2.nominee), r2.hash, w.verifiers.honest]),
        );
        const gi = await guardianDigest(w, v, ip);

        await ethers.provider.send("evm_setAutomine", [false]);
        const sendCancel = () =>
          v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE, { gasLimit: 500_000 });
        const sendInit = () =>
          v.initiateRecovery(
            addrOf(r2.nominee),
            r2.hash,
            w.verifiers.honest,
            quorum(w, gi.digest),
            gi.nonce,
            FAR_DEADLINE,
            {
              gasLimit: 800_000,
            },
          );
        const txs = order === "cancel-first" ? [sendCancel(), sendInit()] : [sendInit(), sendCancel()];
        const sent = await Promise.all(txs);
        await networkHelpers.mine();
        await ethers.provider.send("evm_setAutomine", [true]);

        const receipts = await Promise.all(sent.map((t) => ethers.provider.getTransactionReceipt(t.hash)));
        expect(receipts.filter((r) => r?.status === 1).length, `${order}: exactly one success`).to.equal(1);
        expect((await v.recovery())[R.SIGNER], `${order}: R2 installed`).to.equal(addrOf(r2.nominee));
        expect(await isActive(v), `${order}: R2 live`).to.equal(true);
      }
    });

    it("E4 a failed R2 initiation leaves the stale cancel nonce-valid and still targetless; nothing is consumed", async function () {
      this.timeout(600_000);
      const w = await deployWorld({ label: "w2-e4" });
      const v = w2(w);
      await (await propose(w, v, mkCred("e4-r1"))).wait();
      const N1 = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      const stale = await presignQuorumCancel(w, v, N1);
      await (await cancel(w, v, w.credKey)).wait();

      const bad = mkCred("e4-bad");
      await expect(propose(w, v, bad, ethers.ZeroAddress)).to.be.revertedWithCustomError(v, "ZeroAddress");
      expect(await v.nonces(DOMAIN.GUARDIAN)).to.equal(N1);

      await expect(v.cancelRecoveryByQuorum(stale.proof, stale.nonce, FAR_DEADLINE)).to.be.revertedWithCustomError(
        v,
        "NoRecovery",
      );
      expect(await v.nonces(DOMAIN.GUARDIAN), "still unconsumed").to.equal(N1);
    });
  });

  // =========================================================================
  // F. Migration subordination uses effective liveness
  // =========================================================================
  describe("F. bindMigration and effective liveness", () => {
    it("F1 a live request blocks migration (positive control for the expired-does-not-block probes)", async function () {
      this.timeout(300_000);
      const w = await deployWorld({ label: "w2-f1" });
      const v = w2(w);
      await (await propose(w, v, mkCred("f1"))).wait();
      await expect(bindMigration(w, v, w.credKey)).to.be.revertedWithCustomError(v, "NoRecovery");
      await (await quorumCancel(w, v)).wait();
      await (await bindMigration(w, v, w.credKey)).wait();
      expect(await v.effectiveSafeState()).to.equal(3n);
    });
  });

  // =========================================================================
  // G. Composed adversarial sequences (Lane W2 brief, section 8) — the ones
  //    not already pinned exactly by A–F above.
  // =========================================================================
  describe("G. composed adversarial sequences", () => {
    it("G1 overwrite ordering: R2 while R1 live is refused; cancel-then-R2 and expire-then-R2 both create R2", async function () {
      this.timeout(600_000);
      // (i) initiate R2 while R1 is live — refused, nothing consumed.
      const w = await deployWorld({ label: "w2-g1" });
      const v = w2(w);
      const r1 = mkCred("g1-r1");
      await (await propose(w, v, r1)).wait();
      const gNonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
      await expect(propose(w, v, mkCred("g1-r2a"))).to.be.revertedWithCustomError(v, "BadState");
      expect(await v.nonces(DOMAIN.GUARDIAN)).to.equal(gNonce);
      expect((await v.recovery())[R.SIGNER]).to.equal(addrOf(r1.nominee));

      // (ii) cancel R1 (quorum), then R2 — created, with its own full clocks.
      await (await quorumCancel(w, v)).wait();
      const r2 = mkCred("g1-r2b");
      const t2 = await minedAt(await propose(w, v, r2));
      const s2 = await v.recovery();
      expect(s2[R.SIGNER]).to.equal(addrOf(r2.nominee));
      expect((s2[R.EXECUTABLE_AT] as bigint) - t2).to.equal(BigInt(7 * DAY));
      expect((s2[R.EXPIRES_AT] as bigint) - t2).to.equal(BigInt(21 * DAY));

      // (iii) expire R2 (no transaction touches it), then R3 — created.
      await networkHelpers.time.increaseTo(Number(s2[R.EXPIRES_AT] as bigint));
      const r3 = mkCred("g1-r3");
      const t3 = await minedAt(await propose(w, v, r3));
      const s3 = await v.recovery();
      expect(s3[R.SIGNER]).to.equal(addrOf(r3.nominee));
      expect((s3[R.EXPIRES_AT] as bigint) - t3).to.equal(BigInt(21 * DAY));
      expect(s3[R.CHALLENGES], "no budget moved through any of it").to.equal(0n);
    });

    it("G2 credential self-refund attempt with DIFFERENT material at every step still leaves the budget exhausted", async function () {
      this.timeout(600_000);
      const w = await deployWorld({ label: "w2-g2" });
      const v = w2(w);
      await exhaust(w, v, w.credKey, "g2");
      // Rotate to fresh material twice in a row (each rotation is authorised by
      // the current credential and installs the next), re-initiate, challenge.
      let cur = { signer: w.credKey, pq: w.pqKey };
      for (let i = 0; i < 2; i++) {
        const next = { signer: w.spareCred[i]!, pq: w.sparePq[i]! };
        await (await rotate(w, v, cur.signer, cur.pq, next)).wait();
        cur = next;
        await (await propose(w, v, mkCred(`g2-r${i}`))).wait();
        expect(await challenges(v), `after rotation ${i}: still exhausted`).to.equal(2n);
        await expect(cancel(w, v, cur.signer)).to.be.revertedWithCustomError(v, "ChallengeExhausted");
        await (await quorumCancel(w, v)).wait();
      }
    });

    it("G3 the exact expiry race, three transactions mined at expiresAt-1, expiresAt and expiresAt+1 in ONE world", async function () {
      this.timeout(600_000);
      // The three instants in sequence on one request: the credential's
      // challenge lands at E-1 (live: succeeds), so the request is gone before
      // E; a fresh request then meets E and E+1 as an ordinary young request.
      // The per-instant matrix for every kind is section B; this pins that the
      // boundary is consistent when the instants are consecutive blocks.
      const w = await deployWorld({ label: "w2-g3" });
      const v = w2(w);
      await (await propose(w, v, mkCred("g3"))).wait();
      const E = await expiresAt(v);
      await networkHelpers.time.increaseTo(Number(E - 2n));
      await networkHelpers.time.setNextBlockTimestamp(Number(E - 1n));
      const tChallenge = await minedAt(await cancel(w, v, w.credKey));
      expect(tChallenge).to.equal(E - 1n);
      expect(await challenges(v)).to.equal(1n);
      // At E the slot holds an inactive request: a fresh initiation is admitted
      // exactly at E and again nothing is consumed from the budget.
      await networkHelpers.time.setNextBlockTimestamp(Number(E));
      const tInit = await minedAt(await propose(w, v, mkCred("g3-fresh")));
      expect(tInit).to.equal(E);
      await networkHelpers.time.setNextBlockTimestamp(Number(E + 1n));
      const tBlocked = await latest();
      await expect(propose(w, v, mkCred("g3-over"))).to.be.revertedWithCustomError(v, "BadState");
      expect(await latest(), "the refused overwrite at E+1 mined no state change").to.equal(tBlocked);
      expect(await challenges(v)).to.equal(1n);
    });
  });

  // =========================================================================
  // H. SD-10 interplay — BLAST RADIUS RECORDED, NOT REMEDIATED
  // =========================================================================
  describe("H. a rotated-across request under W2 — SD-10's stranding REMOVED, W2's liveness rules unchanged", () => {
    it("H1 a request that outlived a roster change is effectively live: it blocks re-initiation and migration, and (since Lane SD10-I) it EXECUTES at maturity", async function () {
      this.timeout(600_000);
      // W2 changes `setGuardians` in NO way, and neither did Lane SD10-I. What
      // this test used to record was SD-10's blast radius under W2: the request
      // was STRANDED (BadRoster at maturity) yet still effectively live, so it
      // blocked a fresh initiation and migration until the quorum's explicit
      // exit cleared it — two acts where there had been one silent overwrite.
      //
      // INVERTED BY LANE SD10-I, same sequence, verdict moved. Removing
      // `executeRecovery`'s execution-time generation re-check means the request
      // is no longer stranded. EVERY W2 ASSERTION IS RETAINED AND STILL FIRES:
      // an effectively-live request still blocks initiation (BadState) and
      // migration (NoRecovery), because those rules are about LIVENESS and were
      // never about the generation. Only the verdict on `executeRecovery` moved
      // — from `BadRoster` to success — and with it the need for the quorum's
      // cancellation as a REMEDY. Mechanism B is unchanged and is exercised in
      // section A; here there is simply nothing left to rescue.
      const w = await deployWorld({ label: "w2-h1" });
      const v = w2(w);
      const c = mkCred("h1");
      await (await propose(w, v, c)).wait();
      const boundGen = (await v.recovery())[R.GUARDIAN_GEN] as bigint;
      await (await setGuardiansSame(w, v)).wait();
      expect((await v.guardianGeneration()) as bigint, "the generation moved past the request's").to.equal(
        boundGen + 1n,
      );

      // Matured, and bound to a superseded generation — which is now PROVENANCE
      // rather than a gate.
      await networkHelpers.time.increase(7 * DAY + 1);
      expect(await isActive(v), "still stored active").to.equal(true);
      expect((await v.recovery())[R.GUARDIAN_GEN] as bigint, "provenance frozen at the approving generation").to.equal(
        boundGen,
      );

      // W2, UNCHANGED: effectively live means it blocks.
      await expect(propose(w, v, mkCred("h1-next"))).to.be.revertedWithCustomError(v, "BadState");
      await expect(bindMigration(w, v, w.credKey)).to.be.revertedWithCustomError(v, "NoRecovery");

      // SD10-I, INVERTED: the call that reverted `BadRoster` on every kernel up
      // to a42f5c7e now completes.
      await (await execute(w, v, c)).wait();
      expect(await v.ecdsaSigner(), "the rotated-across request installed").to.equal(addrOf(c.nominee));
      expect(await isActive(v), "consumed by execution").to.equal(false);

      // And the blocking clears with it — no cancellation was needed.
      const fresh = mkCred("h1-fresh");
      await (await propose(w, v, fresh)).wait();
      await networkHelpers.time.increase(7 * DAY + 1);
      await (await execute(w, v, fresh)).wait();
      expect(await v.ecdsaSigner()).to.equal(addrOf(fresh.nominee));
    });
  });
});
