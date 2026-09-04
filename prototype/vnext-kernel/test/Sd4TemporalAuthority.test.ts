/**
 * EXPERIMENTAL PROTOTYPE — LANE T: THE AXIS THE ROUND-3 BATTERY DID NOT PRICE.
 *
 * Round 3 adjudicated every candidate against AUTHORITY.md section 3, whose
 * rows are MINIMUM COMPROMISE CUTS — a census of WHO must be compromised to
 * reach a state. G-PRIME left every row where it found it, and round 3 read
 * "cut unchanged" as the safety verdict.
 *
 * A cut census is structurally blind to WHEN. Two designs with identical cuts
 * can differ completely in how long the values an attacker installs are visible
 * before they take effect, and this lane measures that second quantity.
 *
 * WHY VISIBILITY IS LOAD-BEARING HERE, derived from source rather than assumed:
 *
 *   - `setGuardians` is QUORUM-gated (DOMAIN_GUARDIAN, `_requireQuorum`), so the
 *     credential cannot rotate out a compromised roster.
 *   - `rotateCredential` does NOT defeat a pending recovery: `executeRecovery`
 *     measures against `r.proposedSigner`/`r.proposedPqKeyHash`, by design.
 *   - therefore `cancelRecovery` is the credential's ONLY remedy, and
 *     `initiateRecovery` carries `challengesUsed: recovery.challengesUsed`
 *     FORWARD across episodes. Only `delete recovery` on a SUCCESSFUL execute
 *     resets it.
 *
 * So the credential holds CHALLENGE_LIMIT cancels for the LIFETIME of the
 * vault, not per episode. A remedy that scarce is spent on what the payload
 * LOOKS like — which makes the coincidence between the payload a defender
 * inspects and the payload that executes a security property in its own right.
 * T0 establishes all of this on the UNMODIFIED kernel before any candidate is
 * judged, because an attack without a positive control measures nothing.
 *
 * THE MALICIOUSNESS PREDICATE IS THE KERNEL'S, NOT A STORY. A payload naming
 * the honest verifier installs a real two-factor credential; a payload naming
 * `alwaysTrue` collapses the PQ conjunct, so the signer's ECDSA key spends
 * alone. That is AUTHORITY.md section 3's "Silent crypto downgrade" row, and it
 * makes `proposedVerifier == alwaysTrue` an objective inspection criterion.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  buildCandidateGPrime,
  buildCandidateGPrimeClamped,
  buildCandidateGPrimeDelay,
  buildCandidateGPrimeNotice,
  buildCandidateGPrimeReset,
} from "./sd4-candidate-kernels.js";
import { R, abi, at, bytesOfLength, cancel, guardianDigest, pqPub, proposeStd, quorum, spend } from "./sd4-harness.js";
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

const RATIFY_TAG = ethers.id("RATIFY_RECOVERY_COMMITMENT");
const POP_TAG = ethers.id("INCOMING_CREDENTIAL_POSSESSION");
const PQ_BLOB = bytesOfLength(65, "lane-t-pq-blob");

type Kernel = { abi: unknown[]; bytecode: string };
const LADDER: Record<string, Kernel> = {};

before(function () {
  this.timeout(900_000);
  LADDER.atomic = buildCandidateGPrime();
  LADDER.notice = buildCandidateGPrimeNotice();
  LADDER.delay = buildCandidateGPrimeDelay();
  LADDER.reset = buildCandidateGPrimeReset();
  LADDER.clamped = buildCandidateGPrimeClamped();
});

/** A PQ-MANDATING vault: floor {requirePq, 32, 65}, born under the honest verifier. */
const pqWorld = (label: string, impl?: Kernel) => deployWorld({ label, implOverride: impl });

const ratifyParams = (hash: string, verifier: string, signer: string, executableAt: bigint): string =>
  ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "address", "address", "uint64"],
      [RATIFY_TAG, hash, verifier, signer, executableAt],
    ),
  );

async function ratify(
  w: World,
  v: ethers.Contract,
  hash: string,
  verifier: string,
): Promise<ethers.ContractTransactionResponse> {
  const r = await v.recovery();
  const { digest, nonce } = await guardianDigest(
    w,
    v,
    ratifyParams(hash, verifier, r[R.SIGNER] as string, r[R.EXECUTABLE_AT] as bigint),
  );
  return v.ratifyRecoveryCommitment(hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE);
}

/** `recoveryPossessionDigest()` recomputed OFF-CHAIN, for the state a not-yet-mined ratify will leave. */
const popDigestFor = (w: World, signer: string, hash: string, verifier: string, gen: bigint, execAt: bigint): string =>
  ethers.keccak256(
    abi.encode(
      ["bytes32", "uint256", "address", "uint64", "address", "bytes32", "address", "uint64", "uint64"],
      [POP_TAG, w.chainId, w.vaultAddress, 1n, signer, hash, verifier, gen, execAt],
    ),
  );

/**
 * `pqKey` is required only where the execution must SUCCEED against the HONEST
 * verifier, which demands a real possession proof. Against `alwaysTrue`, and on
 * every path that reverts before `_requireIncomingPossession`, the junk blob is
 * sufficient and says so.
 */
const execChange = (
  nominee: ethers.SigningKey,
  hash: string,
  key32: string,
  pop: string,
  pqKey?: ethers.SigningKey,
) => ({
  newSigner: addrOf(nominee),
  newPqKeyHash: hash,
  newPqKey: key32,
  newEcdsaPop: sign(nominee, pop),
  newPqPop: pqKey ? sign(pqKey, pop) : PQ_BLOB,
});

const stamp = async (tx: ethers.ContractTransactionResponse): Promise<bigint> => {
  const rec = await tx.wait();
  const blk = await ethers.provider.getBlock(rec!.blockNumber);
  return BigInt(blk!.timestamp);
};

/** The credential holder's inspection: the ONE thing that makes a payload a downgrade. */
const looksLikeDowngrade = (verifier: string, w: World): boolean =>
  verifier.toLowerCase() === w.verifiers.alwaysTrue.toLowerCase();

describe("SD-4 lane T — temporal authority, the axis a minimum-cut census cannot see", () => {
  // ===================================================================
  // T0 — POSITIVE CONTROL. Unmodified kernel. Does the notice window carry
  // a live remedy at all, and how scarce is it?
  // ===================================================================

  it("T0a POSITIVE CONTROL — the notice window carries a REAL remedy on the unmodified kernel", async function () {
    this.timeout(180_000);
    const w = await pqWorld("t0a");
    const nominee = keyOf("t0a-nominee");
    const key32 = bytesOfLength(32, "t0a-key");

    // A compromised quorum proposes a DOWNGRADE payload. It is on-chain and
    // inspectable from the moment `initiateRecovery` returns.
    await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key32), w.verifiers.alwaysTrue);
    const posted = (await w.vault.recovery())[R.VERIFIER] as string;
    expect(looksLikeDowngrade(posted, w), "the executing payload is visible at t0").to.equal(true);

    // The credential holder inspects, sees the downgrade, and spends a cancel.
    await (await cancel(w, w.vault, w.credKey)).wait();
    expect((await w.vault.recovery())[R.ACTIVE], "defeated").to.equal(false);

    // At the original maturity there is nothing to execute...
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await expect(
      w.vault.executeRecovery(execChange(nominee, ethers.keccak256(key32), key32, pop)),
      "the remedy is real, not cosmetic",
    ).to.be.revertedWithCustomError(w.vault, "NoRecovery");

    // ...and the vault still spends under its ORIGINAL two-factor credential.
    await (await spend(w, w.vault, w.credKey, w.pqKey, pqKeyBytes(w.pqKey))).wait();
  });

  it("T0b POSITIVE CONTROL — the remedy is a LIFETIME budget of 2, not 2 per episode", async function () {
    this.timeout(180_000);
    const w = await pqWorld("t0b");
    const nominee = keyOf("t0b-nominee");
    const hash = ethers.keccak256(bytesOfLength(32, "t0b-key"));

    // `initiateRecovery` copies `challengesUsed` FORWARD (line 1177), so a fresh
    // episode does NOT refund the credential's veto.
    for (let episode = 1; episode <= 2; episode++) {
      await proposeStd(w, w.vault, addrOf(nominee), hash, w.verifiers.alwaysTrue);
      await (await cancel(w, w.vault, w.credKey)).wait();
      expect((await w.vault.recovery())[R.CHALLENGES], `after episode ${episode}`).to.equal(BigInt(episode));
    }

    // Third episode: the credential can no longer object AT ALL, and the
    // downgrade executes over its head.
    await proposeStd(w, w.vault, addrOf(nominee), hash, w.verifiers.alwaysTrue);
    await expect(cancel(w, w.vault, w.credKey), "budget is per-VAULT").to.be.revertedWithCustomError(
      w.vault,
      "ChallengeExhausted",
    );
    expect(await w.vault.CHALLENGE_LIMIT()).to.equal(2n);
  });

  it("T0c POSITIVE CONTROL — cancelRecovery is the credential's ONLY remedy", async function () {
    this.timeout(180_000);
    const w = await pqWorld("t0c");
    const nominee = keyOf("t0c-nominee");
    const key32 = bytesOfLength(32, "t0c-key");
    await proposeStd(w, w.vault, addrOf(nominee), ethers.keccak256(key32), w.verifiers.alwaysTrue);

    // The credential cannot rotate the roster out from under the request:
    // `setGuardians` demands DOMAIN_GUARDIAN quorum, which it does not hold.
    const roster = await w.vault.guardianCommitment();
    const empty = { members: [], isContract: [], attestingIndices: [], attestations: [] };
    await expect(
      w.vault.setGuardians(1n, [addrOf(w.credKey)], [false], empty, 0n, FAR_DEADLINE),
      "no credential path bumps guardianGeneration",
    ).to.be.revert(ethers);
    expect(await w.vault.guardianCommitment(), "roster unmoved").to.equal(roster);

    // And the recovery remains fully executable, confirming no other credential
    // action defuses it — which is exactly why recovery exists.
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await (await w.vault.executeRecovery(execChange(nominee, ethers.keccak256(key32), key32, pop))).wait();
    expect(await w.vault.pqVerifier(), "downgrade landed").to.equal(w.verifiers.alwaysTrue);
  });

  // ===================================================================
  // T1/T2 — THE ATTACK. Plain G-PRIME.
  // ===================================================================

  it("T1 PAYLOAD-AGING — G-PRIME(atomic) ages a BENIGN payload and executes a DIFFERENT one", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t1", LADDER.atomic);
    const v = at(w, LADDER.atomic);
    const nominee = keyOf("t1-nominee");
    const key32 = bytesOfLength(32, "t1-key");
    const hash = ethers.keccak256(key32);

    // t0 — a payload that PASSES inspection: real two-factor, honest verifier.
    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    expect(looksLikeDowngrade((await v.recovery())[R.VERIFIER] as string, w), "inspects clean").to.equal(false);

    // The credential holder inspects and correctly declines to spend one of its
    // two lifetime cancels on a legitimate-looking recovery.
    expect((await v.recovery())[R.CHALLENGES], "veto unspent").to.equal(0n);

    await networkHelpers.time.increase(7 * DAY + 1);

    // t7 — the payload is replaced with the downgrade, then executed.
    const tRatify = await stamp(await ratify(w, v, hash, w.verifiers.alwaysTrue));
    const pop = (await v.recoveryPossessionDigest()) as string;
    const tExec = await stamp(await v.executeRecovery(execChange(nominee, hash, key32, pop)));

    expect(await v.pqVerifier(), "downgraded").to.equal(w.verifiers.alwaysTrue);

    // THE MEASUREMENT. Notice on the payload that actually executed.
    expect(tExec - tRatify, "guaranteed notice on the EXECUTING payload, in seconds").to.be.lessThanOrEqual(2n);

    // And the downgrade is REAL, not nominal: the nominee spends using a PQ
    // "signature" from a key unrelated to anything the vault ever committed to.
    // The second factor still has to be PRESENT (the floor's length check is
    // structural and survives), but it no longer has to be ANYONE'S.
    await (await spend(w, v, nominee, keyOf("t1-unrelated-key"), key32)).wait();
  });

  it("T2 SAME-BLOCK — ratification and execution compose atomically, so a 2-tx API is not notice", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t2", LADDER.atomic);
    const v = at(w, LADDER.atomic);
    const nominee = keyOf("t2-nominee");
    const key32 = bytesOfLength(32, "t2-key");
    const hash = ethers.keccak256(key32);

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);

    const r = await v.recovery();
    const execAt = r[R.EXECUTABLE_AT] as bigint;
    const gen = r[R.GUARDIAN_GEN] as bigint;
    // The possession digest binds the POST-ratify verifier, so it is computed
    // off-chain for a state no block has yet observed.
    const pop = popDigestFor(w, addrOf(nominee), hash, w.verifiers.alwaysTrue, gen, execAt);

    await ethers.provider.send("evm_setAutomine", [false]);
    const txR = await ratify(w, v, hash, w.verifiers.alwaysTrue);
    const txE = await v.executeRecovery(execChange(nominee, hash, key32, pop));
    await networkHelpers.mine();
    await ethers.provider.send("evm_setAutomine", [true]);

    const recR = await txR.wait();
    const recE = await txE.wait();
    expect(recE!.blockNumber, "SAME BLOCK — no observer could interpose").to.equal(recR!.blockNumber);
    expect(await v.pqVerifier(), "downgraded within one block").to.equal(w.verifiers.alwaysTrue);
  });

  // ===================================================================
  // T3–T6 — the accounting attacks. These G-PRIME should SURVIVE.
  // ===================================================================

  it("T3 STALE RATIFICATION REPLAY — an attestation for episode R1 does not bind R2", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t3", LADDER.atomic);
    const v = at(w, LADDER.atomic);
    const nominee = keyOf("t3-nominee");
    const hash = ethers.keccak256(bytesOfLength(32, "t3-key"));

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    const r1 = await v.recovery();
    const staleParams = ratifyParams(hash, w.verifiers.alwaysTrue, r1[R.SIGNER] as string, r1[R.EXECUTABLE_AT] as bigint);
    const stale = await guardianDigest(w, v, staleParams);

    // R1 dies, R2 is opened at a different timestamp -> different executableAt.
    await (await cancel(w, v, w.credKey)).wait();
    await networkHelpers.time.increase(DAY);
    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    expect((await v.recovery())[R.EXECUTABLE_AT], "R2 matures later").to.not.equal(r1[R.EXECUTABLE_AT]);

    // QuorumNotMet, not BadRoster, and the distinction is the POINT: the
    // ratification digest is recomputed from the LIVE `r.executableAt`, so a
    // stale attestation does not merely fail a roster equality check — it
    // recovers to different addresses entirely and never counts as support.
    // The binding is cryptographic, not a comparison that could be forgotten.
    await expect(
      v.ratifyRecoveryCommitment(hash, w.verifiers.alwaysTrue, quorum(w, stale.digest), stale.nonce, FAR_DEADLINE),
      "the attestation binds the episode it was written for",
    ).to.be.revertedWithCustomError(v, "QuorumNotMet");
  });

  it("T4 GUARDIAN-GENERATION REPLAY — a roster change invalidates a ratified request", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t4", LADDER.atomic);
    const v = at(w, LADDER.atomic);
    const nominee = keyOf("t4-nominee");
    const key32 = bytesOfLength(32, "t4-key");
    const hash = ethers.keccak256(key32);

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);
    await (await ratify(w, v, hash, w.verifiers.alwaysTrue)).wait();

    // An honest quorum act that bumps the generation. Re-setting the IDENTICAL
    // roster still increments `guardianGeneration` (setGuardians line 1051),
    // which is the cleanest possible way to isolate the generation check.
    const members = w.guardians;
    const isContract = w.guardianIsContract;
    const commitment = (await v.rosterCommitment(w.threshold, members, isContract)) as string;
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
    await (await v.setGuardians(w.threshold, members, isContract, quorum(w, d), nonce, FAR_DEADLINE)).wait();

    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(
      v.executeRecovery(execChange(nominee, hash, key32, pop)),
      "ratification does not survive the roster it was drawn from",
    ).to.be.revertedWithCustomError(v, "BadRoster");
  });

  it("T5 CHALLENGE ACCOUNTING — ratification neither refunds nor consumes the credential's veto", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t5", LADDER.atomic);
    const v = at(w, LADDER.atomic);
    const nominee = keyOf("t5-nominee");
    const hash = ethers.keccak256(bytesOfLength(32, "t5-key"));

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(1n);

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await (await ratify(w, v, hash, w.verifiers.alwaysTrue)).wait();
    expect((await v.recovery())[R.CHALLENGES], "ratification is not a refund").to.equal(1n);

    // Exactly one cancel remains, then exhaustion — identical to the unmodified
    // schedule, so no budget was manufactured either.
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.CHALLENGES]).to.equal(2n);
    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await expect(cancel(w, v, w.credKey)).to.be.revertedWithCustomError(v, "ChallengeExhausted");
  });

  it("T6 EXPIRY LAUNDERING — a dead episode cannot be revived by ratifying it", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t6", LADDER.atomic);
    const v = at(w, LADDER.atomic);
    const nominee = keyOf("t6-nominee");
    const key32 = bytesOfLength(32, "t6-key");
    const hash = ethers.keccak256(key32);

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await networkHelpers.time.increase(22 * DAY);

    await expect(ratify(w, v, hash, w.verifiers.alwaysTrue), "ratify is gated on expiry").to.be.revertedWithCustomError(
      v,
      "Expired",
    );
    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(v.executeRecovery(execChange(nominee, hash, key32, pop))).to.be.revertedWithCustomError(v, "Expired");

    // The pre-existing residue, unchanged by G-PRIME and re-recorded here: an
    // EXPIRED episode never clears `active`. G-PRIME neither causes nor repairs it.
    expect((await v.recovery())[R.ACTIVE], "stranded true, as on the unmodified kernel").to.equal(true);
  });

  // ===================================================================
  // T7–T10 — the ladder.
  // ===================================================================

  it("T7 TIMER LAUNDERING — each rung writes exactly the timers it claims, and no others", async function () {
    this.timeout(600_000);
    const seen: Record<string, { execDelta: bigint; expiryMoved: boolean }> = {};

    for (const rung of ["atomic", "delay", "reset"]) {
      const w = await pqWorld(`t7-${rung}`, LADDER[rung]);
      const v = at(w, LADDER[rung]);
      const nominee = keyOf(`t7-${rung}-nominee`);
      const hash = ethers.keccak256(bytesOfLength(32, `t7-${rung}-key`));

      await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
      const before = await v.recovery();
      await networkHelpers.time.increase(7 * DAY + 1);
      const tR = await stamp(await ratify(w, v, hash, w.verifiers.alwaysTrue));
      const after = await v.recovery();

      seen[rung] = {
        execDelta: (after[R.EXECUTABLE_AT] as bigint) - tR,
        expiryMoved: (after[R.EXPIRES_AT] as bigint) !== (before[R.EXPIRES_AT] as bigint),
      };
      expect(seen[rung].expiryMoved, `${rung} must never extend the episode's life`).to.equal(false);
    }

    // atomic: maturity already passed and is not rewritten -> negative delta.
    expect(seen.atomic.execDelta, "atomic grants nothing").to.be.lessThanOrEqual(0n);
    expect(seen.delay.execDelta, "delay grants RATIFICATION_DELAY").to.equal(BigInt(3 * DAY));
    expect(seen.reset.execDelta, "reset grants RECOVERY_DELAY").to.equal(BigInt(7 * DAY));
  });

  it("T7b HAZARD — on delay and reset, a LATE ratification can push maturity past expiry", async function () {
    this.timeout(600_000);
    for (const rung of ["delay", "reset"]) {
      const w = await pqWorld(`t7b-${rung}`, LADDER[rung]);
      const v = at(w, LADDER[rung]);
      const nominee = keyOf(`t7b-${rung}-nominee`);
      const key32 = bytesOfLength(32, `t7b-${rung}-key`);
      const hash = ethers.keccak256(key32);

      await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
      // Late in the execution window, but still legally ratifiable.
      await networkHelpers.time.increase(20 * DAY);
      await (await ratify(w, v, hash, w.verifiers.honest)).wait();

      const r = await v.recovery();
      expect(
        (r[R.EXECUTABLE_AT] as bigint) > (r[R.EXPIRES_AT] as bigint),
        `${rung}: maturity now beyond expiry`,
      ).to.equal(true);

      // The episode is now unexecutable at EVERY future time, and the window is
      // closed from BOTH sides — which is what makes it empty rather than
      // merely late. Before the new maturity the guard is TooEarly...
      await networkHelpers.time.increase(2 * DAY);
      const popEarly = (await v.recoveryPossessionDigest()) as string;
      await expect(
        v.executeRecovery(execChange(nominee, hash, key32, popEarly)),
        `${rung}: closed from below`,
      ).to.be.revertedWithCustomError(v, "TooEarly");

      // ...and once maturity finally arrives, expiry has long since passed.
      await networkHelpers.time.increase(6 * DAY);
      const popLate = (await v.recoveryPossessionDigest()) as string;
      await expect(
        v.executeRecovery(execChange(nominee, hash, key32, popLate)),
        `${rung}: closed from above — self-inflicted dead episode`,
      ).to.be.revertedWithCustomError(v, "Expired");
    }
  });

  it("T8 SIGNER IMMUTABILITY — no rung of the ladder makes the principal amendable", async function () {
    this.timeout(120_000);
    for (const rung of Object.keys(LADDER)) {
      const frag = new ethers.Interface(LADDER[rung].abi as ethers.InterfaceAbi).getFunction(
        "ratifyRecoveryCommitment",
      );
      expect(
        frag?.inputs.map((i) => i.name),
        `${rung}: no calldata shape can carry a signer`,
      ).to.deep.equal(["newPqKeyHash", "newVerifier", "proof", "nonce", "deadline"]);
    }
  });

  it("T9 CAPABILITY DELTA — the floor is never written by any rung, and only executableAt moves", async function () {
    this.timeout(600_000);
    for (const rung of ["atomic", "delay", "reset"]) {
      const w = await pqWorld(`t9-${rung}`, LADDER[rung]);
      const v = at(w, LADDER[rung]);
      const nominee = keyOf(`t9-${rung}-nominee`);
      const hash = ethers.keccak256(bytesOfLength(32, `t9-${rung}-key`));

      await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
      const floorBefore = await v.securityFloor();
      const signerBefore = await v.ecdsaSigner();
      const genBefore = await v.credentialGeneration();

      await networkHelpers.time.increase(7 * DAY + 1);
      await (await ratify(w, v, hash, w.verifiers.alwaysTrue)).wait();

      // I-FLOOR-SHAPE-IMMUTABLE: this is the exact assertion design E failed.
      expect(await v.securityFloor(), `${rung}: floor untouched`).to.deep.equal(floorBefore);
      expect(await v.ecdsaSigner(), `${rung}: live credential untouched`).to.equal(signerBefore);
      expect(await v.credentialGeneration(), `${rung}: no installation happened`).to.equal(genBefore);
      expect((await v.recovery())[R.SIGNER], `${rung}: principal untouched`).to.equal(addrOf(nominee));
    }
  });

  it("T10 THE VERDICT — only delay and reset restore the coincidence a defender needs", async function () {
    this.timeout(900_000);
    const measured: Record<string, bigint> = {};

    for (const rung of ["atomic", "notice", "delay", "reset"]) {
      const w = await pqWorld(`t10-${rung}`, LADDER[rung]);
      const v = at(w, LADDER[rung]);
      const nominee = keyOf(`t10-${rung}-nominee`);
      const key32 = bytesOfLength(32, `t10-${rung}-key`);
      const hash = ethers.keccak256(key32);

      await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);

      // The adversary's best move on each rung: ratify as LATE as that rung
      // permits, which is what makes this a guarantee and not an average.
      if (rung === "notice") {
        // `notice` forbids ratifying at or after maturity, so the adversary
        // takes maturity-minus-one-second instead.
        await networkHelpers.time.increase(7 * DAY - 2);
      } else {
        await networkHelpers.time.increase(7 * DAY + 1);
      }

      const tR = await stamp(await ratify(w, v, hash, w.verifiers.alwaysTrue));
      const execAt = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
      measured[rung] = execAt > tR ? execAt - tR : 0n;
    }

    expect(measured.atomic, "atomic: no notice").to.equal(0n);
    expect(measured.notice, "notice: 'before maturity' is unbounded below — MY OWN round-3 fix, killed").to.be.lessThan(
      BigInt(60),
    );
    expect(measured.delay, "delay: a real guarantee").to.equal(BigInt(3 * DAY));
    expect(measured.reset, "reset: the full original assurance").to.equal(BigInt(7 * DAY));
  });

  it("T10b THE PROPERTY THAT MATTERS — under delay, the veto re-opens on the TRUE payload", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t10b", LADDER.delay);
    const v = at(w, LADDER.delay);
    const nominee = keyOf("t10b-nominee");
    const key32 = bytesOfLength(32, "t10b-key");
    const hash = ethers.keccak256(key32);

    // Same attack as T1: age a clean payload, swap at maturity.
    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);
    await (await ratify(w, v, hash, w.verifiers.alwaysTrue)).wait();

    // The downgrade is now BOTH on-chain and not yet executable.
    expect(looksLikeDowngrade((await v.recovery())[R.VERIFIER] as string, w), "now visible").to.equal(true);
    const pop0 = (await v.recoveryPossessionDigest()) as string;
    await expect(
      v.executeRecovery(execChange(nominee, hash, key32, pop0)),
      "and not yet executable",
    ).to.be.revertedWithCustomError(v, "TooEarly");

    // So the credential's ONE remedy applies to the payload that would actually
    // execute — which is precisely what T1 showed plain G-PRIME destroys.
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.ACTIVE], "defeated on the true payload").to.equal(false);
    await (await spend(w, v, w.credKey, w.pqKey, pqKeyBytes(w.pqKey))).wait();
  });

  // ===================================================================
  // T11 — the clamp, which exists only because T7b measured the fix
  // introducing a dead episode with no adversary present.
  // ===================================================================

  it("T11a CLAMP — a ratification that could not itself age is REFUSED, not installed", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t11a", LADDER.clamped);
    const v = at(w, LADDER.clamped);
    const nominee = keyOf("t11a-nominee");
    // A REAL incoming PQ credential: this is the only test in the lane whose
    // execution must succeed against the HONEST verifier, so the second factor
    // has to actually exist rather than merely be the right length.
    const pqNominee = keyOf("t11a-nominee-pq");
    const key32 = pqPub(pqNominee);
    const hash = ethers.keccak256(key32);

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    const execAtBefore = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
    await networkHelpers.time.increase(20 * DAY);

    await expect(
      ratify(w, v, hash, w.verifiers.alwaysTrue),
      "the amendment cannot fit in the episode's remaining life",
    ).to.be.revertedWithCustomError(v, "Expired");

    // AND THE APPROVED EPISODE SURVIVES INTACT — this is what T7b's rungs
    // destroyed. The quorum's original, inspected payload is still executable
    // on its original schedule, and the refusal cost nothing.
    const r = await v.recovery();
    expect(r[R.EXECUTABLE_AT], "schedule untouched by the refusal").to.equal(execAtBefore);
    expect(r[R.VERIFIER], "payload untouched by the refusal").to.equal(w.verifiers.honest);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await (await v.executeRecovery(execChange(nominee, hash, key32, pop, pqNominee))).wait();
    expect(await v.pqVerifier(), "the honest payload the credential inspected").to.equal(w.verifiers.honest);
  });

  it("T11b CLAMP — an in-window amendment still earns the full notice guarantee", async function () {
    this.timeout(240_000);
    const w = await pqWorld("t11b", LADDER.clamped);
    const v = at(w, LADDER.clamped);
    const nominee = keyOf("t11b-nominee");
    const key32 = bytesOfLength(32, "t11b-key");
    const hash = ethers.keccak256(key32);

    await proposeStd(w, v, addrOf(nominee), hash, w.verifiers.honest);
    await networkHelpers.time.increase(7 * DAY + 1);

    const tR = await stamp(await ratify(w, v, hash, w.verifiers.alwaysTrue));
    const execAt = (await v.recovery())[R.EXECUTABLE_AT] as bigint;
    expect(execAt - tR, "clamping did not cost the guarantee").to.equal(BigInt(3 * DAY));

    // The downgrade is visible, not yet executable, and vetoable — the three
    // properties together are what "notice" actually means.
    expect(looksLikeDowngrade((await v.recovery())[R.VERIFIER] as string, w)).to.equal(true);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(v.executeRecovery(execChange(nominee, hash, key32, pop))).to.be.revertedWithCustomError(v, "TooEarly");
    await (await cancel(w, v, w.credKey)).wait();
    expect((await v.recovery())[R.ACTIVE], "vetoed on the payload that would have run").to.equal(false);
    await (await spend(w, v, w.credKey, w.pqKey, pqKeyBytes(w.pqKey))).wait();
  });
});
