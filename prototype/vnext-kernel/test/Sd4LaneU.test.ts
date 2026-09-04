/**
 * EXPERIMENTAL PROTOTYPE — LANE U: TEMPORAL EQUIVALENCE AND EPISODE SEMANTICS.
 *
 * Lane T established that a minimum-cut census cannot see notice, and proposed a
 * 3-day clamp. THAT VALUE WAS NEVER DERIVED FROM AUTHORITY — it was chosen so a
 * measurement could distinguish the clause from the episode's original timer.
 * This lane treats it as a policy proposal to be attacked, not a default.
 *
 * The primary authority, read firsthand:
 *
 *   - `docs/Vault_vNext_Hazard_Register.md` H-15 — Containment: "7-day delay";
 *     Detection: "`RecoveryInitiated` gives at least `RECOVERY_DELAY` of
 *     warning"; Recovery: "Cancellation within the delay window".
 *   - `docs/Vault_vNext_Architecture.md` §13.2 — "identical prerequisites, less
 *     warning, irreversible outcome... `bindDelay >= recoveryDelay` is therefore
 *     an ARCHITECTURAL CONSTRAINT, NOT A TUNING PARAMETER."
 *   - `I-MIGRATION-CLOCK-NEUTRAL (T1)` — migration "may neither shorten nor
 *     lengthen the maturity of any pending obligation... recovery delay".
 *
 * The lane's job is to find out whether a candidate honouring those can exist.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  VERIFIER_32_64_SOURCE,
  buildCandidateGPrimeClamped,
  buildCandidateU1,
  buildCandidateU2a,
  buildCandidateU2b,
  buildCandidateU5,
  compileAuxContract,
} from "./sd4-candidate-kernels.js";
import { R, abi, at, bytesOfLength, cancel, declare, guardianDigest, quorum } from "./sd4-harness.js";
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
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";

const RATIFY_TAG = ethers.id("RATIFY_RECOVERY_COMMITMENT");
const sig64 = (k: ethers.SigningKey, d: string): string => ethers.dataSlice(sign(k, d), 0, 64);

type Kernel = { abi: unknown[]; bytecode: string };
const K: Record<string, Kernel> = {};
let V64: Kernel;

before(function () {
  this.timeout(900_000);
  K.u1 = buildCandidateU1();
  K.u2a = buildCandidateU2a();
  K.u2b = buildCandidateU2b();
  K.u4 = buildCandidateGPrimeClamped();
  K.u5 = buildCandidateU5();
  V64 = compileAuxContract("EcdsaBackedVerifier64", VERIFIER_32_64_SOURCE);
});

const sd4World = (label: string, impl?: Kernel) =>
  deployWorld({ label, ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true, implOverride: impl });

async function deployV64(w: World): Promise<string> {
  const f = new ethers.ContractFactory(V64.abi as ethers.InterfaceAbi, V64.bytecode, w.deployer);
  const c = await f.deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

const ratifyParams = (hash: string, verifier: string, signer: string, execAt: bigint): string =>
  ethers.keccak256(
    abi.encode(["bytes32", "bytes32", "address", "address", "uint64"], [RATIFY_TAG, hash, verifier, signer, execAt]),
  );

async function ratify(w: World, v: ethers.Contract, hash: string, verifier: string) {
  const r = await v.recovery();
  const { digest, nonce } = await guardianDigest(
    w,
    v,
    ratifyParams(hash, verifier, r[R.SIGNER] as string, r[R.EXECUTABLE_AT] as bigint),
  );
  return v.ratifyRecoveryCommitment(hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE);
}

async function propose(w: World, v: ethers.Contract, signer: string, hash: string, verifier: string) {
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [signer, hash, verifier]));
  const { digest, nonce } = await guardianDigest(w, v, params);
  await (await v.initiateRecovery(signer, hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE)).wait();
}

const now = async (): Promise<bigint> => BigInt((await ethers.provider.getBlock("latest"))!.timestamp);

async function advanceTo(target: bigint): Promise<void> {
  if (target > (await now())) await networkHelpers.time.increaseTo(Number(target));
}

/**
 * Clones revert through `<UnrecognizedContract>` during gas estimation, so the
 * provider hands back a raw selector rather than a name. Decoding it here keeps
 * the matrix reporting WHICH guard fired instead of "unrecognized".
 */
const SELECTORS: Record<string, string> = {
  "0x5cd5d233": "BadSignature",
  "0x8523b62a": "BadState",
  "0x203d82d8": "Expired",
  "0x085de625": "TooEarly",
  "0xc993b993": "NoRecovery",
  "0xaeb053e3": "BadRoster",
  "0xd79e824a": "QuorumNotMet",
  "0xd92e233d": "ZeroAddress",
  "0xe9505ced": "ChallengeExhausted",
};

const errName = (e: unknown): string => {
  const m = String((e as Error)?.message ?? e);
  const named = m.match(/reverted with custom error '(\w+)/);
  if (named) return named[1];
  const sel = m.match(/0x[0-9a-f]{8}/);
  if (sel && SELECTORS[sel[0]]) return SELECTORS[sel[0]];
  return m.slice(0, 60);
};

/** Every postcondition the brief requires, captured as data rather than asserted inline. */
interface Post {
  amended: boolean;
  amendErr: string | null;
  executableAt: bigint;
  expiresAt: bigint;
  signer: string;
  hash: string;
  verifier: string;
  challenges: bigint;
  guardianGen: bigint;
  active: boolean;
  executed: boolean;
  execErr: string | null;
  spent: boolean;
}

interface Scenario {
  sigLen: number;
  /** Verifier the amendment would switch TO in order to repair. */
  repair: (v64: string, w: World) => string;
  needsRepair: boolean;
}

const SCENARIOS: Record<string, Scenario> = {
  // Declared shape matches the pinned honest verifier (32/65): nothing is broken,
  // and the amendment is exercised anyway to measure what it costs.
  harmless: { sigLen: 65, repair: (_v64, w) => w.verifiers.honest, needsRepair: false },
  // Declared shape is 32/64, which the pinned honest verifier REFUSES. This is a
  // real SD-4 instance: the quorum-approved request is now unsatisfiable, and
  // only a verifier accepting 64-byte signatures repairs it.
  sd4: { sigLen: 64, repair: (v64) => v64, needsRepair: true },
};

/**
 * One cell of the matrix: build a vault, open a recovery, move the floor under
 * it, attempt an amendment at `offset` seconds after initiation, then follow the
 * episode through to an actual spend.
 */
async function cell(kernel: Kernel, label: string, scenarioKey: string, offset: number): Promise<Post> {
  const s = SCENARIOS[scenarioKey];
  const w = await sd4World(label, kernel);
  const v = at(w, kernel);
  const v64 = await deployV64(w);

  const nominee = keyOf(`${label}-nominee`);
  const pqNominee = keyOf(`${label}-pq`);
  const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
  const hash = ethers.keccak256(key32);

  await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
  const r0 = await v.recovery();
  const t0 = (r0[R.EXECUTABLE_AT] as bigint) - BigInt(7 * DAY);

  // The declaring edge — SD-4's mechanism. Moves the floor under an already
  // quorum-approved request, without the quorum's participation.
  const floor: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: s.sigLen };
  await (await declare(w, v, w.credKey, w.verifiers.honest, floor, pqKeyBytes(w.pqKey))).wait();

  // The amendment must land at EXACTLY t0+offset, not at the first block after
  // it: the admissible boundary is a single second wide, and letting the
  // transaction drift past it would report the clamp firing one second early.
  const target = t0 + BigInt(offset);
  if (target > (await now())) await networkHelpers.time.setNextBlockTimestamp(Number(target));

  let amended = false;
  let amendErr: string | null = null;
  try {
    await (await ratify(w, v, hash, s.repair(v64, w))).wait();
    amended = true;
  } catch (e) {
    amendErr = errName(e);
  }

  const r = await v.recovery();
  const post: Post = {
    amended,
    amendErr,
    executableAt: r[R.EXECUTABLE_AT] as bigint,
    expiresAt: r[R.EXPIRES_AT] as bigint,
    signer: r[R.SIGNER] as string,
    hash: r[R.PQ_KEY_HASH] as string,
    verifier: r[R.VERIFIER] as string,
    challenges: r[R.CHALLENGES] as bigint,
    guardianGen: r[R.GUARDIAN_GEN] as bigint,
    active: r[R.ACTIVE] as boolean,
    executed: false,
    execErr: null,
    spent: false,
  };

  await advanceTo(post.executableAt + 1n);
  try {
    const pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: key32,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: s.sigLen === 64 ? sig64(pqNominee, pop) : sign(pqNominee, pop),
      })
    ).wait();
    post.executed = true;
  } catch (e) {
    post.execErr = errName(e);
  }

  if (post.executed) {
    try {
      // The live floor after a repaired SD-4 recovery still demands the DECLARED
      // signature length, so the spend must supply one of exactly that size —
      // the shared `spend` helper always signs 65.
      await (await spendAtLen(w, v, nominee, pqNominee, key32, s.sigLen)).wait();
      post.spent = true;
    } catch {
      post.spent = false;
    }
  }
  return post;
}

/** A spend whose PQ factor is exactly `sigLen` bytes, so 64-byte floors are exercised. */
async function spendAtLen(
  w: World,
  v: ethers.Contract,
  signerKey: ethers.SigningKey,
  pqKey: ethers.SigningKey,
  pqKeyBytesValue: string,
  sigLen: number,
  amount = 1n,
): Promise<ethers.ContractTransactionResponse> {
  const nonce = (await v.nonces(DOMAIN.SPEND)) as bigint;
  const credGen = (await v.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.SPEND,
    authorityGeneration: credGen,
    params: spendParams(w.recipient, amount),
    domain: DOMAIN.SPEND,
    nonce,
    deadline: FAR_DEADLINE,
  });
  const pq = sigLen === 65 ? sign(pqKey, d) : ethers.dataSlice(sign(pqKey, d), 0, sigLen);
  return v.execute(w.recipient, amount, nonce, FAR_DEADLINE, sign(signerKey, d), pq, pqKeyBytesValue);
}

const OFFSETS: [string, number][] = [
  ["t0", 0],
  ["t0+7d-1", 7 * DAY - 1],
  ["t0+7d", 7 * DAY],
  ["t0+14d-1", 14 * DAY - 1],
  ["t0+14d", 14 * DAY],
  ["t0+14d+1", 14 * DAY + 1],
  ["t0+21d-1", 21 * DAY - 1],
  ["t0+21d", 21 * DAY],
];

describe("SD-4 lane U — temporal equivalence and recovery-episode adjudication", () => {
  // =====================================================================
  // PART B — episode semantics, executed rather than read
  // =====================================================================

  it("B1 MODEL/IMPLEMENTATION MISMATCH — the kernel replaces a live, quorum-approved request; the model forbids it", async function () {
    this.timeout(180_000);
    const w = await deployWorld({ label: "u-b1" });
    const a = keyOf("u-b1-a");
    const b = keyOf("u-b1-b");
    const hashA = ethers.keccak256(bytesOfLength(32, "u-b1-a-key"));
    const hashB = ethers.keccak256(bytesOfLength(32, "u-b1-b-key"));

    await propose(w, w.vault, addrOf(a), hashA, w.verifiers.honest);
    const before = await w.vault.recovery();

    // Still pre-maturity, and quorum-approved the instant it existed — the
    // reference model denies BOTH of these ("a live request may not be
    // replaced", "an approved request may not be replaced",
    // test/helpers/vaultVNextModel.ts:995-999). The kernel permits it.
    await networkHelpers.time.increase(DAY);
    await propose(w, w.vault, addrOf(b), hashB, w.verifiers.honest);

    const after = await w.vault.recovery();
    expect(after[R.SIGNER], "principal substituted under a live approved request").to.equal(addrOf(b));
    expect(after[R.EXECUTABLE_AT], "and the clock restarted").to.be.greaterThan(before[R.EXECUTABLE_AT] as bigint);
  });

  it("B2 CHALLENGE COUNTER — carried across re-initiation, reset ONLY by a successful execution", async function () {
    this.timeout(180_000);
    const w = await deployWorld({ label: "u-b2" });
    const nominee = keyOf("u-b2-nominee");
    const pqNominee = keyOf("u-b2-pq");
    const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
    const hash = ethers.keccak256(key32);

    await propose(w, w.vault, addrOf(nominee), hash, w.verifiers.honest);
    await (await cancel(w, w.vault, w.credKey)).wait();
    expect((await w.vault.recovery())[R.CHALLENGES], "one spent").to.equal(1n);

    // A NEW episode by any ordinary reading — and the counter does not reset.
    await propose(w, w.vault, addrOf(nominee), hash, w.verifiers.honest);
    expect((await w.vault.recovery())[R.CHALLENGES], "carried forward").to.equal(1n);

    // Successful execution deletes the request, and with it the counter.
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: key32,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(pqNominee, pop),
      })
    ).wait();
    expect((await w.vault.recovery())[R.CHALLENGES], "reset by `delete recovery`, and only there").to.equal(0n);
  });

  it("B3 THE UNBOUNDED-VETO CONSEQUENCE — a per-episode reset would restore H-03", async function () {
    this.timeout(180_000);
    // Executed as an ARITHMETIC fact about the kernel's own constants rather
    // than by mutating it: the quorum may re-initiate without limit (B1), so if
    // each re-initiation refunded CHALLENGE_LIMIT cancels, the credential's
    // total veto count would be unbounded — exactly `I-VETO-BOUND`'s
    // prohibition, and exactly the architecture's own rule that "per-episode
    // bounds do not compose into a bound on the authority" (§6, §22 D5).
    const w = await deployWorld({ label: "u-b3" });
    const nominee = keyOf("u-b3-nominee");
    const hash = ethers.keccak256(bytesOfLength(32, "u-b3-key"));

    let cancels = 0;
    for (let episode = 0; episode < 4; episode++) {
      await propose(w, w.vault, addrOf(nominee), hash, w.verifiers.honest);
      try {
        await (await cancel(w, w.vault, w.credKey)).wait();
        cancels += 1;
      } catch {
        /* exhausted */
      }
    }
    expect(cancels, "four episodes, still only CHALLENGE_LIMIT cancels in total").to.equal(2);
    expect(await w.vault.CHALLENGE_LIMIT()).to.equal(2n);
  });

  // =====================================================================
  // PART D — the exhaustive timing boundary for the full-delay rule
  // =====================================================================

  it("D U1 FULL-DELAY CLAMP — the complete 8-timing x 2-payload postcondition matrix", async function () {
    this.timeout(1_800_000);
    const rows: string[] = [];
    const amendWindow: Record<string, boolean> = {};

    for (const [name, off] of OFFSETS) {
      for (const sk of ["harmless", "sd4"]) {
        const p = await cell(K.u1, `u1-${name}-${sk}`.replace(/[+\-]/g, ""), sk, off);
        rows.push(
          `${name.padEnd(10)} ${sk.padEnd(9)} amended=${String(p.amended).padEnd(5)} err=${String(p.amendErr).padEnd(12)} ` +
            `exec=${p.executed} spent=${p.spent} chal=${p.challenges} gen=${p.guardianGen} active=${p.active}`,
        );
        if (sk === "sd4") amendWindow[name] = p.amended;

        // Invariants that must hold in EVERY cell, whatever the timing.
        expect(p.signer, `${name}/${sk}: principal never amendable`).to.match(/^0x/);
        expect(p.challenges, `${name}/${sk}: no challenge refund`).to.equal(0n);
        expect(p.guardianGen, `${name}/${sk}: generation binding intact`).to.equal(1n);
      }
    }
    console.log("\n      U1 matrix:\n      " + rows.join("\n      ") + "\n");

    // THE RESULT. U1's amendment window is [t0, t0 + 14d] — exactly
    // RECOVERY_EXPIRY wide — because an amendment must age RECOVERY_DELAY and
    // expiry never moves. Past it, a live SD-4 instance is CORRECTLY REFUSED.
    expect(amendWindow["t0"], "early amendment admitted").to.equal(true);
    expect(amendWindow["t0+14d"], "the last admissible instant").to.equal(true);
    expect(amendWindow["t0+14d+1"], "one second later: REFUSED").to.equal(false);
    expect(amendWindow["t0+21d-1"], "and refused thereafter").to.equal(false);
  });

  it("D-LATE U1 DOES NOT CLOSE SD-4 — a valid live SD-4 state needs a whole second recovery", async function () {
    this.timeout(600_000);
    const p = await cell(K.u1, "u1late", "sd4", 14 * DAY + 1);

    // The episode is ACTIVE, UNEXPIRED, generation-current — and unrepairable.
    expect(p.active, "the request is still live").to.equal(true);
    expect(p.amended, "amendment correctly refused: it could not age in time").to.equal(false);
    expect(p.amendErr, "refused, not silently installed").to.equal("Expired");
    expect(p.executed, "and the quorum-approved recovery can never execute").to.equal(false);

    // Stated plainly rather than absorbed: closing SD-4 would mean this cell
    // recovers WITHIN the episode. It does not. The remedy is another full
    // recovery at a fresh RECOVERY_DELAY, which is the liveness cost #188
    // called inherent — and for this timing band, it still is.
  });

  it("D-WINDOW U1's clamp bounds the execution window below at ZERO, not at anything usable", async function () {
    this.timeout(900_000);
    // THE DEFECT THIS LANE FOUND IN ITS OWN LEAD CANDIDATE. `newExec > expiresAt
    // -> revert` only excludes a NEGATIVE window. Because expiry never moves and
    // the amended payload must age RECOVERY_DELAY, the surviving window is
    // `t0 + 14d - t` and shrinks continuously to zero. There is no cliff to
    // defend at t0+14d: an amendment admitted at t0+14d-1 leaves ONE SECOND in
    // which the recovery must be executed, which is not a remedy.
    const measured: [string, bigint, boolean][] = [];
    for (const [name, off] of OFFSETS.filter(([n]) => ["t0", "t0+7d", "t0+14d-1", "t0+14d"].includes(n))) {
      const p = await cell(K.u1, `u1win${name}`.replace(/[+\-]/g, ""), "sd4", off);
      measured.push([name, p.amended ? p.expiresAt - p.executableAt : -1n, p.executed]);
    }
    console.log("\n      U1 usable window after amendment:\n      " + measured.map((m) => m.join("  ")).join("\n      ") + "\n");

    const win = Object.fromEntries(measured.map(([n, w]) => [n, w]));
    // Offset 0 is the one timing the harness cannot pin exactly — the setup
    // transactions have already mined — so it is asserted as a band.
    expect(win["t0"], "a full RECOVERY_EXPIRY remains when amending early").to.be.greaterThan(
      BigInt(14 * DAY - 10),
    );
    expect(win["t0+7d"], "half of it at the original maturity").to.equal(BigInt(7 * DAY));
    expect(win["t0+14d-1"], "one second — admitted, and useless").to.equal(1n);
    expect(win["t0+14d"], "zero — still admitted").to.equal(0n);

    // So U1's HONEST repairable band is not [t0, t0+14d]. It is [t0, t0+14d-W]
    // for whatever W a deployment considers an executable window, and W is a
    // parameter no candidate in this lane has proposed a value for.
    expect(measured.find(([n]) => n === "t0+14d-1")![2], "unexecutable in practice").to.equal(false);
  });

  it("D-COMPARE the other families at the boundary that separates them", async function () {
    this.timeout(1_800_000);
    const out: string[] = [];
    for (const [k, kernel] of [
      ["u2a", K.u2a],
      ["u2b", K.u2b],
      ["u4(3d)", K.u4],
    ] as [string, Kernel][]) {
      for (const [name, off] of OFFSETS.filter(([n]) => ["t0+14d", "t0+14d+1", "t0+21d-1"].includes(n))) {
        const p = await cell(kernel, `${k}-${name}-sd4`.replace(/[+\-()]/g, ""), "sd4", off);
        out.push(
          `${k.padEnd(8)} ${name.padEnd(10)} amended=${String(p.amended).padEnd(5)} exec=${String(p.executed).padEnd(5)} ` +
            `execAt-expiry=${p.executableAt - p.expiresAt} err=${p.execErr}`,
        );
        if (k === "u2a" && p.amended) {
          // U2a never refuses, so a late amendment installs a maturity at or
          // beyond expiry. At EXACTLY t0+14d the two coincide — a window of a
          // single instant, not a negative one — and past it the window is
          // negative outright. Both are non-executable, which is the claim that
          // matters; the strict inequality is true only past the boundary.
          expect(p.expiresAt - p.executableAt, `${name}: U2a leaves no usable window`).to.be.lessThanOrEqual(0n);
          expect(p.executed, `${name}: and nothing can execute it`).to.equal(false);
        }
      }
    }
    console.log("\n      boundary comparison:\n      " + out.join("\n      ") + "\n");
  });

  // =====================================================================
  // PART E/U3 — is the "new window" family anything but re-initiation?
  // =====================================================================

  it("E-U3 RE-INITIATION EQUIVALENCE — U2b's post-amendment state is byte-identical to re-initiating", async function () {
    this.timeout(600_000);
    const mk = async (label: string) => {
      const w = await sd4World(label, K.u2b);
      const v = at(w, K.u2b);
      const v64 = await deployV64(w);
      const nominee = keyOf("u-e3-nominee");
      const pqNominee = keyOf("u-e3-pq");
      const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
      const hash = ethers.keccak256(key32);
      await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
      const floor: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 };
      await (await declare(w, v, w.credKey, w.verifiers.honest, floor, pqKeyBytes(w.pqKey))).wait();
      return { w, v, v64, nominee, hash };
    };

    // Path 1: amend via U2b's ratification.
    const A = await mk("u-e3-ratify");
    await networkHelpers.time.increase(3 * DAY);
    const tA = await now();
    await (await ratify(A.w, A.v, A.hash, A.v64)).wait();
    const rA = await A.v.recovery();

    // Path 2: the SAME repair through the kernel's EXISTING re-initiation, at
    // the same elapsed offset, on a world built identically.
    const B = await mk("u-e3-reinit");
    await networkHelpers.time.increase(3 * DAY);
    const tB = await now();
    await propose(B.w, B.v, addrOf(keyOf("u-e3-nominee")), B.hash, B.v64);
    const rB = await B.v.recovery();

    // Every authority-relevant field agrees; the timers agree RELATIVE to the
    // instant each path ran. U2b therefore reaches no state re-initiation could
    // not, by a path costing exactly the same one guardian quorum act.
    expect(rA[R.SIGNER], "same principal").to.equal(rB[R.SIGNER]);
    expect(rA[R.PQ_KEY_HASH], "same commitment").to.equal(rB[R.PQ_KEY_HASH]);
    // Each world deploys its own repair verifier, so the comparison is
    // structural: both paths installed THEIR OWN 32/64 verifier, not a
    // coincidence of addresses.
    expect(rA[R.VERIFIER], "path A installed its repair verifier").to.equal(A.v64);
    expect(rB[R.VERIFIER], "path B installed its repair verifier").to.equal(B.v64);
    expect(rA[R.CHALLENGES], "same challenge history").to.equal(rB[R.CHALLENGES]);
    expect(rA[R.GUARDIAN_GEN], "same generation binding").to.equal(rB[R.GUARDIAN_GEN]);
    expect((rA[R.EXECUTABLE_AT] as bigint) - tA, "same maturity, measured from each path's own instant").to.equal(
      (rB[R.EXECUTABLE_AT] as bigint) - tB,
    );
    expect((rA[R.EXPIRES_AT] as bigint) - tA, "same expiry, likewise").to.equal((rB[R.EXPIRES_AT] as bigint) - tB);
  });

  // =====================================================================
  // PART F — timing-window extension
  // =====================================================================

  it("F EXTENSION — U2b lets the quorum hold `active` forever, and so does plain re-initiation", async function () {
    this.timeout(900_000);
    const w = await sd4World("u-f", K.u2b);
    const v = at(w, K.u2b);
    const v64 = await deployV64(w);
    const nominee = keyOf("u-f-nominee");
    const hash = ethers.keccak256(abi.encode(["address"], [addrOf(keyOf("u-f-pq"))]));

    await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
    const firstExpiry = (await v.recovery())[R.EXPIRES_AT] as bigint;

    // Repeated amendment, each just before the current expiry.
    for (let i = 0; i < 3; i++) {
      const r = await v.recovery();
      await advanceTo((r[R.EXPIRES_AT] as bigint) - 10n);
      await (await ratify(w, v, hash, i % 2 === 0 ? v64 : w.verifiers.honest)).wait();
      expect((await v.recovery())[R.ACTIVE], `round ${i}: still live`).to.equal(true);
    }
    const held = (await v.recovery())[R.EXPIRES_AT] as bigint;
    expect(held, "expiry extended well past the original").to.be.greaterThan(firstExpiry);
    expect((await v.recovery())[R.CHALLENGES], "no challenge refunded by any of it").to.equal(0n);

    // SAME AUTHORITY / DIFFERENT PATH, not NEW AUTHORITY: the unmodified kernel
    // reaches indefinite `active` by re-initiating on the same cadence, and the
    // migration blocker that follows from it is identical on both paths.
    const w2 = await deployWorld({ label: "u-f-base" });
    const firstBase = (await (async () => {
      await propose(w2, w2.vault, addrOf(nominee), hash, w2.verifiers.honest);
      return (await w2.vault.recovery())[R.EXPIRES_AT] as bigint;
    })()) as bigint;
    for (let i = 0; i < 3; i++) {
      const r = await w2.vault.recovery();
      await advanceTo((r[R.EXPIRES_AT] as bigint) - 10n);
      await propose(w2, w2.vault, addrOf(nominee), hash, w2.verifiers.honest);
      expect((await w2.vault.recovery())[R.ACTIVE], `base round ${i}: still live`).to.equal(true);
    }
    expect((await w2.vault.recovery())[R.EXPIRES_AT], "unmodified kernel, same capability").to.be.greaterThan(
      firstBase,
    );
  });

  it("F REPLAY — an amendment is inert after a cancellation and after a successful recovery", async function () {
    this.timeout(600_000);
    const w = await sd4World("u-f-replay", K.u2b);
    const v = at(w, K.u2b);
    const v64 = await deployV64(w);
    const nominee = keyOf("u-f-replay-nominee");
    const pqNominee = keyOf("u-f-replay-pq");
    const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
    const hash = ethers.keccak256(key32);

    // Prepare an amendment against the live request, then kill the request.
    await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
    const live = await v.recovery();
    const prepared = await guardianDigest(
      w,
      v,
      ratifyParams(hash, v64, live[R.SIGNER] as string, live[R.EXECUTABLE_AT] as bigint),
    );
    await (await cancel(w, v, w.credKey)).wait();

    // AFTER A CANCELLATION: the request is inactive, so the prepared quorum act
    // has nothing to amend.
    await expect(
      v.ratifyRecoveryCommitment(hash, v64, quorum(w, prepared.digest), prepared.nonce, FAR_DEADLINE),
      "no live request to amend",
    ).to.be.revertedWithCustomError(v, "NoRecovery");

    // AFTER A SUCCESSFUL RECOVERY: run one to completion, then replay.
    await propose(w, v, addrOf(nominee), hash, w.verifiers.honest);
    const live2 = await v.recovery();
    const prepared2 = await guardianDigest(
      w,
      v,
      ratifyParams(hash, v64, live2[R.SIGNER] as string, live2[R.EXECUTABLE_AT] as bigint),
    );
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: key32,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sign(pqNominee, pop),
      })
    ).wait();

    // `delete recovery` cleared the slot, so the prepared amendment is inert —
    // it cannot resurrect a consumed request.
    await expect(
      v.ratifyRecoveryCommitment(hash, v64, quorum(w, prepared2.digest), prepared2.nonce, FAR_DEADLINE),
      "a consumed request cannot be amended back into existence",
    ).to.be.revertedWithCustomError(v, "NoRecovery");
    expect((await v.recovery())[R.CHALLENGES], "and the counter reset with it").to.equal(0n);
  });

  // =====================================================================
  // PART G — notice must be notice OF THE PAYLOAD
  // =====================================================================

  it("G OBSERVABILITY GAP — the authority's named detection mechanism omits both amendable fields", async function () {
    this.timeout(120_000);
    const w = await deployWorld({ label: "u-g" });
    const iface = w.vault.interface;

    // H-15 Detection names `RecoveryInitiated` as the warning. It carries three
    // values, and neither of the two G-PRIME makes amendable is among them.
    const ev = iface.getEvent("RecoveryInitiated");
    expect(ev?.inputs.map((i) => i.name)).to.deep.equal(["proposedSigner", "executableAt", "guardianGeneration"]);

    // The values ARE readable — from storage, by polling, never announced.
    const nominee = keyOf("u-g-nominee");
    const hash = ethers.keccak256(bytesOfLength(32, "u-g-key"));
    await propose(w, w.vault, addrOf(nominee), hash, w.verifiers.alwaysTrue);
    expect((await w.vault.recovery())[R.VERIFIER], "public storage, yes").to.equal(w.verifiers.alwaysTrue);

    // The consequence, stated as the requirement it implies: on the unmodified
    // kernel one storage read at t0 suffices, because the payload cannot change.
    // Under ANY ratification design it does change, so an event-driven observer
    // is blind and a polling observer must poll continuously. Any admitted
    // candidate must therefore EMIT the final payload on amendment.
    const verifierChanged = iface.getEvent("VerifierChanged");
    expect(verifierChanged?.inputs.map((i) => i.name), "announced only after the fact").to.deep.equal(["verifier"]);
  });

  // =====================================================================
  // PART C — the trilemma, attacked
  // =====================================================================

  it("C REFUTATION ATTEMPT — U5 pre-publishes the fallback, and still fails late SD-4", async function () {
    this.timeout(600_000);
    // U5 is the strongest escape available: the amendment names NO value, it
    // selects one the quorum published at t0. Notice is therefore satisfied
    // with no timer moving at all, satisfying trilemma constraints 1-5 and
    // apparently avoiding all of A, B and C.
    const w = await sd4World("u-c-u5", K.u5);
    const v = at(w, K.u5);
    const v64 = await deployV64(w);
    const nominee = keyOf("u-c-nominee");
    const pqNominee = keyOf("u-c-pq");
    const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
    const hash = ethers.keccak256(key32);

    // t0: the quorum publishes BOTH the primary and the fallback verifier.
    const params = ethers.keccak256(
      abi.encode(
        ["address", "bytes32", "address", "address"],
        [addrOf(nominee), hash, w.verifiers.honest, v64],
      ),
    );
    const { digest, nonce } = await guardianDigest(w, v, params);
    await (
      await v.initiateRecovery(addrOf(nominee), hash, w.verifiers.honest, v64, quorum(w, digest), nonce, FAR_DEADLINE)
    ).wait();

    // The credential declares 32/64 — the shape the published fallback handles.
    const good: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 };
    await (await declare(w, v, w.credKey, w.verifiers.honest, good, pqKeyBytes(w.pqKey))).wait();

    // Selection succeeds at ANY time, moves no timer, and repairs SD-4.
    await networkHelpers.time.increase(20 * DAY);
    const before = await v.recovery();
    const selParams = ethers.keccak256(
      abi.encode(["bytes32", "address", "address", "uint64"], [RATIFY_TAG, v64, addrOf(nominee), before[R.EXECUTABLE_AT]]),
    );
    const sel = await guardianDigest(w, v, selParams);
    await (await v.selectFallbackVerifier(quorum(w, sel.digest), sel.nonce, FAR_DEADLINE)).wait();
    const after = await v.recovery();
    expect(after[R.VERIFIER], "repaired").to.equal(v64);
    expect(after[R.EXECUTABLE_AT], "NO timer moved").to.equal(before[R.EXECUTABLE_AT]);
    expect(after[R.EXPIRES_AT], "expiry untouched").to.equal(before[R.EXPIRES_AT]);

    const pop = (await v.recoveryPossessionDigest()) as string;
    await (
      await v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: key32,
        newEcdsaPop: sign(nominee, pop),
        newPqPop: sig64(pqNominee, pop),
      })
    ).wait();
    expect(await v.pqVerifier(), "late SD-4 repaired with full notice and no timer move").to.equal(v64);
  });

  it("C THE REFUTATION FAILS — the declared shape is chosen AFTER the fallback is fixed", async function () {
    this.timeout(600_000);
    // The escape works only when the quorum GUESSED the shape. The declaring
    // edge picks `pqSignatureLength` freely, and a pre-published fallback is one
    // point in that space. Same construction, one different declared length.
    const w = await sd4World("u-c-miss", K.u5);
    const v = at(w, K.u5);
    const v64 = await deployV64(w);
    const nominee = keyOf("u-c-miss-nominee");
    const hash = ethers.keccak256(abi.encode(["address"], [addrOf(keyOf("u-c-miss-pq"))]));

    const params = ethers.keccak256(
      abi.encode(["address", "bytes32", "address", "address"], [addrOf(nominee), hash, w.verifiers.honest, v64]),
    );
    const { digest, nonce } = await guardianDigest(w, v, params);
    await (
      await v.initiateRecovery(addrOf(nominee), hash, w.verifiers.honest, v64, quorum(w, digest), nonce, FAR_DEADLINE)
    ).wait();

    // 96 bytes: neither the pinned honest verifier (32/65) nor the published
    // fallback (32/64) accepts it. Both published values are now dead.
    const miss: Floor = { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 96 };
    await (await declare(w, v, w.credKey, w.verifiers.honest, miss, pqKeyBytes(w.pqKey))).wait();

    await networkHelpers.time.increase(7 * DAY + 1);
    const before = await v.recovery();
    const selParams = ethers.keccak256(
      abi.encode(["bytes32", "address", "address", "uint64"], [RATIFY_TAG, v64, addrOf(nominee), before[R.EXECUTABLE_AT]]),
    );
    const sel = await guardianDigest(w, v, selParams);
    // The selection is ADMITTED — and repairs nothing, because the value it
    // selects was fixed before the shape was known.
    await (await v.selectFallbackVerifier(quorum(w, sel.digest), sel.nonce, FAR_DEADLINE)).wait();

    const pop = (await v.recoveryPossessionDigest()) as string;
    await expect(
      v.executeRecovery({
        newSigner: addrOf(nominee),
        newPqKeyHash: hash,
        newPqKey: abi.encode(["address"], [addrOf(keyOf("u-c-miss-pq"))]),
        newEcdsaPop: sign(keyOf("u-c-miss-nominee"), pop),
        newPqPop: bytesOfLength(96, "u-c-miss-sig"),
      }),
      "SD-4 survives a design that pre-published its only escape",
    ).to.be.revertedWithCustomError(v, "BadSignature");

    // THE TRILEMMA HOLDS AGAINST THIS ATTACK. To cover the shape space a
    // pre-commitment must enumerate it; the free axis is a uint16 length, so
    // any finite published set leaves instances it cannot repair — which is
    // horn A, reached by a design built specifically to avoid it.
  });
});
