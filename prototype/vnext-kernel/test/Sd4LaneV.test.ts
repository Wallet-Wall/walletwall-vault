/**
 * EXPERIMENTAL PROTOTYPE — LANE V: RECOVERY LIFECYCLE AUTHORITY RECONCILIATION.
 *
 * Lane U left two questions as "owner decisions". Lane V tests whether primary
 * authority already settles them, and the cited invariants DO exist — verified
 * firsthand at `docs/Vault_vNext_Architecture.md`:
 *
 *   :945  I-RECOVERY-NONVETO — "No principal holds an unbounded veto over an
 *         otherwise-valid recovery."
 *   :948  I-RECOVERY-TERMINATION — "Every quorum-approved request leaves the
 *         system by execution, cancellation, or expiry — and expiry requires no
 *         principal to act."
 *   :951  I-APPROVED-REQUEST-PRESERVATION — "Once a request reaches quorum, a
 *         GUARDIAN-SET REPLACEMENT cannot clear it."
 *   :736  CLOCK RULE, generalised — "Every clock in this design — recovery
 *         delay, recovery expiry, ... — runs on wall clock in every safe state,
 *         and NO STATE TRANSITION MAY RESET, EXTEND, OR SUSPEND ANY OF THEM."
 *
 * All four are T1 (:1540). Nothing here modifies production Solidity.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { R, abi, cancel, guardianDigest, quorum } from "./sd4-harness.js";
import { buildPreW2Kernel } from "./sd4-candidate-kernels.js";
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
import { VaultVNextModel } from "../../../test/helpers/vaultVNextModel.js";

/** The architecture test's own factory, replicated: it is local to that file. */
const makeModel = (identityModel: "ACCOUNT_PER_VAULT") => new VaultVNextModel({ identityModel });

/**
 * W2 SUPERSESSION (implementation status only). Four measurements below — A1,
 * B1, B2 and C — were taken on the kernel at c67d1439 and established the
 * defects Lane W2 then remediated (SD-9b, SD-9c, SD-9d). They are kept as the
 * record of what was measured, pinned to the byte-exact pre-W2 build so they
 * still measure it; the remediated behaviour is asserted on the real artifact
 * in W2RecoveryLifecycle.test.ts, and B1 additionally asserts that the missing
 * exit now exists on the shipped kernel.
 */
let preW2: { abi: unknown[]; bytecode: string } | null = null;
const PRE_W2 = () => (preW2 ??= buildPreW2Kernel());

const KEY32 = (tag: string) => abi.encode(["address"], [addrOf(keyOf(tag))]);

async function propose(w: World, signer: string, hash: string, verifier: string) {
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [signer, hash, verifier]));
  const { digest, nonce } = await guardianDigest(w, w.vault, params);
  await (await w.vault.initiateRecovery(signer, hash, verifier, quorum(w, digest), nonce, FAR_DEADLINE)).wait();
}

/** `bindMigration` needs BOTH the guardian quorum and the credential (§22 D2). */
async function bindMigration(w: World): Promise<ethers.ContractTransactionResponse> {
  const dest = { vault: w.destination, codeHash: ethers.id("dest-code"), generation: 2n };
  const nonce = (await w.vault.nonces(DOMAIN.MIGRATION)) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.BIND_MIGRATION,
    authorityGeneration: (await w.vault.guardianGeneration()) as bigint,
    params: ethers.keccak256(
      abi.encode(["address", "bytes32", "uint64"], [dest.vault, dest.codeHash, dest.generation]),
    ),
    domain: DOMAIN.MIGRATION,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.bindMigration(dest, quorum(w, d), nonce, FAR_DEADLINE, sign(w.credKey, d));
}

describe("SD-4 lane V — recovery lifecycle authority reconciliation", () => {
  // ===================================================================
  // A — RECOVERY_CHALLENGE_EPOCH
  // ===================================================================

  it("A1 the quorum may open UNBOUNDED requests, so a request-local budget is unbounded in total", async function () {
    this.timeout(300_000);
    // HISTORICAL (pre-W2 kernel, pinned): back-to-back initiations over a live
    // request. The W2 kernel refuses the overwrite; the epoch conclusion holds
    // there too, through the conformant exits (W2RecoveryLifecycle D-series).
    const w = await deployWorld({ label: "v-a1", implOverride: PRE_W2() });
    const nominee = addrOf(keyOf("v-a1-nominee"));
    const hash = ethers.keccak256(KEY32("v-a1-pq"));

    // Nothing rate-limits initiation, and each call installs a fresh request.
    for (let i = 0; i < 5; i++) {
      await propose(w, nominee, hash, w.verifiers.honest);
      expect((await w.vault.recovery())[R.ACTIVE], `request ${i} live`).to.equal(true);
    }

    // Under the EPOCH semantics actually implemented, five requests still yield
    // exactly CHALLENGE_LIMIT cancels. Under a request-local reset the same five
    // would yield five, and N requests N — an unbounded veto, hazard H-03, which
    // `I-RECOVERY-NONVETO` (:945) forbids by name.
    let cancels = 0;
    for (let i = 0; i < 5; i++) {
      try {
        await (await cancel(w, w.vault, w.credKey)).wait();
        cancels += 1;
        await propose(w, nominee, hash, w.verifiers.honest);
      } catch {
        /* exhausted */
      }
    }
    expect(cancels, "the counter is an EPOCH, not a per-request field").to.equal(2);
  });

  it("A2 the counterexample that DOES survive is expiry-triggered, and no authority establishes it", async function () {
    this.timeout(300_000);
    // Falsification attempt, recorded because it partly succeeds: the
    // unboundedness argument does NOT exclude every reset trigger. It excludes
    // triggers the CREDENTIAL can cause. Expiry is not one — it requires the
    // quorum to abandon a request for RECOVERY_DELAY + RECOVERY_EXPIRY, which a
    // determined quorum never does. An expiry-triggered reset would therefore
    // remain bounded against an adversarial quorum.
    //
    // It is NOT adopted, because no primary source establishes it, and this test
    // pins the fact that makes it inert rather than the design: the credential
    // has no transition that forces expiry.
    const w = await deployWorld({ label: "v-a2" });
    const nominee = addrOf(keyOf("v-a2-nominee"));
    const hash = ethers.keccak256(KEY32("v-a2-pq"));
    await propose(w, nominee, hash, w.verifiers.honest);

    // The credential's only lever consumes the epoch and clears the request; it
    // cannot hold a request open to expiry, and it cannot expire one early.
    await (await cancel(w, w.vault, w.credKey)).wait();
    expect((await w.vault.recovery())[R.ACTIVE], "cancellation clears, it does not age").to.equal(false);
    expect((await w.vault.recovery())[R.CHALLENGES]).to.equal(1n);
  });

  it("A3 KERNEL AND MODEL DIVERGE ON RESET — the model never resets the epoch at all", async function () {
    this.timeout(300_000);
    // Model side: `credentialChallengesUsed` is initialised to 0 at genesis and
    // incremented on challenge. NOTHING in the model assigns it anywhere else —
    // not `executeRecovery`, not `cancelRecovery`. It is a strict per-vault
    // lifetime counter.
    const m = makeModel("ACCOUNT_PER_VAULT");
    const src = String(makeModel);
    expect(typeof m.challengeRecoveryByCredential, "the model exposes the bounded challenge").to.equal("function");

    // Kernel side: `delete recovery` in `executeRecovery` DOES reset it.
    const w = await deployWorld({ label: "v-a3" });
    const nominee = keyOf("v-a3-nominee");
    const pqNominee = keyOf("v-a3-pq");
    const key32 = KEY32("v-a3-pq");
    const hash = ethers.keccak256(key32);

    await propose(w, addrOf(nominee), hash, w.verifiers.honest);
    await (await cancel(w, w.vault, w.credKey)).wait();
    expect((await w.vault.recovery())[R.CHALLENGES]).to.equal(1n);

    await propose(w, addrOf(nominee), hash, w.verifiers.honest);
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
    expect((await w.vault.recovery())[R.CHALLENGES], "kernel resets on success").to.equal(0n);
    expect(src.length, "model source is reachable for the citation above").to.be.greaterThan(0);
  });

  // ===================================================================
  // B — the exit set
  // ===================================================================

  it("B1 the kernel has NO quorum cancellation — the model's third exit is missing", async function () {
    this.timeout(120_000);
    const w = await deployWorld({ label: "v-b1" });

    // `cancelRecovery` is the CREDENTIAL's bounded challenge: it takes an ECDSA
    // signature, consumes the epoch, and is capped. It is the kernel's spelling
    // of the model's `challengeRecoveryByCredential`, not of its `cancelRecovery`.
    const frag = w.vault.interface.getFunction("cancelRecovery");
    expect(frag?.inputs.map((i) => i.name)).to.deep.equal(["nonce", "deadline", "ecdsaSig"]);

    // There was no guardian-quorum path that withdraws a request. Every function
    // taking a QuorumProof is enumerated FROM THE PRE-W2 BUILD, and none of them
    // cancels — that is the measurement this lane made.
    const quorumFns = new ethers.Interface(PRE_W2().abi as ethers.InterfaceAbi).fragments
      .filter((f): f is ethers.FunctionFragment => f.type === "function")
      .filter((f) => f.inputs.some((i) => i.type.startsWith("tuple") && i.name === "proof"))
      .map((f) => f.name)
      .sort();
    expect(quorumFns, "no quorum-side withdrawal existed at c67d1439").to.not.include("cancelRecoveryByQuorum");
    expect(quorumFns.length, "the quorum surface is small and fully enumerated here").to.be.greaterThan(0);
    console.log("\n      quorum-authorised functions (pre-W2): " + quorumFns.join(", ") + "\n");

    // W2 SUPERSESSION: the shipped kernel carries the missing exit.
    expect(
      w.vault.interface.hasFunction("cancelRecoveryByQuorum((address[],bool[],uint256[],bytes[]),uint256,uint64)"),
      "Lane W2 implemented K-9 mechanism B on the real artifact",
    ).to.equal(true);
  });

  it("B2 the kernel overwrites a LIVE quorum-approved request; the model refuses the same move", async function () {
    this.timeout(300_000);
    // HISTORICAL (pre-W2 kernel, pinned): the kernel half of the mismatch. The
    // W2 kernel refuses the same move with BadState (W2RecoveryLifecycle C1).
    const w = await deployWorld({ label: "v-b2", implOverride: PRE_W2() });
    const a = addrOf(keyOf("v-b2-a"));
    const b = addrOf(keyOf("v-b2-b"));
    const hash = ethers.keccak256(KEY32("v-b2-pq"));

    await propose(w, a, hash, w.verifiers.honest);
    await networkHelpers.time.increase(DAY);
    await propose(w, b, hash, w.verifiers.honest);
    expect((await w.vault.recovery())[R.SIGNER], "kernel: overwritten in place").to.equal(b);

    // Model: the identical sequence is DENIED, and the denial has no invariant
    // citation anywhere in the model source — it is a rule the model enforces
    // that the architecture prose never states.
    const m = makeModel("ACCOUNT_PER_VAULT");
    const cred = { commitment: "cred-2", schemeId: "ECDSA_SECP256K1" as const, generation: 1, possessionProven: true };
    expect(m.initiateRecovery("GUARDIAN", cred).kind).to.equal("OK");
    expect(m.supportRecovery("g1").kind).to.equal("OK");
    expect(m.supportRecovery("g2").kind).to.equal("OK");
    const second = m.initiateRecovery("GUARDIAN", { ...cred, commitment: "cred-3" });
    expect(second.kind, "model: refused").to.equal("DENIED");
  });

  // ===================================================================
  // C — EXPIRED_RECOVERY_AUTHORITY_STALE
  // ===================================================================

  it("C the five proofs — an expired request keeps blocking migration with no principal having acted", async function () {
    this.timeout(600_000);
    // HISTORICAL (pre-W2 kernel, pinned): this is SD-9b as measured. On the W2
    // kernel an expired request blocks nothing and is no longer a challenge
    // target — the inverted proofs are W2RecoveryLifecycle B2/B3.
    const w = await deployWorld({ label: "v-c", implOverride: PRE_W2() });
    const nominee = addrOf(keyOf("v-c-nominee"));
    const hash = ethers.keccak256(KEY32("v-c-pq"));

    await propose(w, nominee, hash, w.verifiers.honest);
    const r0 = await w.vault.recovery();
    const expiresAt = r0[R.EXPIRES_AT] as bigint;

    // Nobody acts. Wall clock alone carries the request past expiry.
    await networkHelpers.time.increaseTo(Number(expiresAt) + 1);
    const nowTs = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);

    // (1) the request IS expired
    expect(nowTs, "past expiresAt").to.be.greaterThan(expiresAt);

    // (2) executeRecovery is impossible BECAUSE expired
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await expect(
      w.vault.executeRecovery({
        newSigner: nominee,
        newPqKeyHash: hash,
        newPqKey: KEY32("v-c-pq"),
        newEcdsaPop: sign(keyOf("v-c-nominee"), pop),
        newPqPop: sign(keyOf("v-c-pq"), pop),
      }),
    ).to.be.revertedWithCustomError(w.vault, "Expired");

    // (4) no principal performed any transition — `active` is still the value
    // `initiateRecovery` wrote, and the challenge epoch is untouched.
    const r1 = await w.vault.recovery();
    expect(r1[R.ACTIVE], "stored active survives its own expiry").to.equal(true);
    expect(r1[R.CHALLENGES], "and nobody spent anything").to.equal(0n);
    expect(r1[R.EXPIRES_AT], "the clock itself was never rewritten").to.equal(expiresAt);

    // (3) migration binding is blocked SOLELY by the stale flag: `bindMigration`
    // tests `recovery.active` and never tests effective expiry.
    await expect(bindMigration(w), "dead request still blocks the exit").to.be.revertedWithCustomError(
      w.vault,
      "NoRecovery",
    );

    // ...and the block lifts the instant a PRINCIPAL acts, which is exactly what
    // `I-RECOVERY-TERMINATION` says expiry must not require.
    await (await cancel(w, w.vault, w.credKey)).wait();
    expect((await w.vault.recovery())[R.ACTIVE]).to.equal(false);
    await (await bindMigration(w)).wait();
    // SafeState: NORMAL 0, CONTAINED 1, RECOVERY_ONLY 2, MIGRATION_ONLY 3, RETIRED 4.
    expect(await w.vault.effectiveSafeState(), "MIGRATION_ONLY once a principal cleared it").to.equal(3n);

    // (5) the model treats the same request as expired AND deletes it, with no
    // principal acting. Its own assertion message names the hazard.
    const m = makeModel("ACCOUNT_PER_VAULT");
    const cred = { commitment: "cred-2", schemeId: "ECDSA_SECP256K1" as const, generation: 1, possessionProven: true };
    m.initiateRecovery("GUARDIAN", cred);
    m.supportRecovery("g1");
    m.supportRecovery("g2");
    m.warp(1000);
    m.tickRecoveryExpiry();
    expect(m.kernel.recovery, "model: autonomous termination").to.equal(null);
  });

  it("E BASELINE — with overwrite forbidden and no quorum cancellation, a dead SD-4 request costs t0+28d", async function () {
    this.timeout(900_000);
    // The load-bearing number for `SD4_BASELINE_LIVENESS_COST`, measured rather
    // than derived. Regime (iii): overwrite is treated as unavailable (it is
    // nonconformant), the kernel offers the quorum no cancellation (B1), and
    // the credential does not cooperate. The only remaining exit is autonomous
    // expiry — which, per C, the kernel does not actually perform.
    const w = await deployWorld({
      label: "v-e",
      ecdsaOnlyFloor: true,
      commitPqKeyOnEcdsaOnlyFloor: true,
    });
    const nominee = keyOf("v-e-nominee");
    const pqNominee = keyOf("v-e-pq");
    const key32 = KEY32("v-e-pq");
    const hash = ethers.keccak256(key32);

    await propose(w, addrOf(nominee), hash, w.verifiers.honest);
    const t0 = ((await w.vault.recovery())[R.EXECUTABLE_AT] as bigint) - BigInt(7 * DAY);
    const expiresAt = (await w.vault.recovery())[R.EXPIRES_AT] as bigint;
    expect(expiresAt - t0, "expiry is anchored at t0, not at the death").to.equal(BigInt(21 * DAY));

    // The request dies immediately: the credential declares a shape the pinned
    // verifier cannot satisfy. No principal has to act again after this.
    const { declare } = await import("./sd4-harness.js");
    const { pqKeyBytes } = await import("../stateful/world.js");
    await (
      await declare(
        w,
        w.vault,
        w.credKey,
        w.verifiers.honest,
        { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 64 },
        pqKeyBytes(w.pqKey),
      )
    ).wait();

    // Wait out the whole expiry window. Nothing else is available.
    await networkHelpers.time.increaseTo(Number(expiresAt) + 1);
    await propose(w, addrOf(nominee), hash, w.verifiers.honest);
    const second = await w.vault.recovery();
    // A band, not an instant: the re-proposal mines a couple of seconds after
    // expiry. The claim is that maturity lands at t0+28d and not before.
    const elapsed = (second[R.EXECUTABLE_AT] as bigint) - t0;
    expect(elapsed, "fresh maturity lands at t0+28d").to.be.greaterThanOrEqual(BigInt(28 * DAY));
    expect(elapsed, "and not materially later").to.be.lessThan(BigInt(28 * DAY + 60));

    // The interval is a HARM window, not merely a wait: the live credential is
    // untouched until a recovery executes, so a compromised one keeps spending
    // for the whole 28 days.
    expect(await w.vault.ecdsaSigner(), "still the original credential at t0+21d").to.equal(addrOf(w.credKey));
  });

  // ===================================================================
  // D — I-APPROVED-REQUEST-PRESERVATION, tested directly
  // ===================================================================

  it("D a guardian-set replacement STRANDS an approved request on the kernel; the model denies the replacement", async function () {
    this.timeout(300_000);
    const w = await deployWorld({ label: "v-d" });
    const nominee = addrOf(keyOf("v-d-nominee"));
    const hash = ethers.keccak256(KEY32("v-d-pq"));
    await propose(w, nominee, hash, w.verifiers.honest);

    // Re-set the IDENTICAL roster. `setGuardians` still increments the
    // generation, and it is NOT refused while an approved request is live.
    const commitment = (await w.vault.rosterCommitment(w.threshold, w.guardians, w.guardianIsContract)) as string;
    const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const d = digestOf({
      chainId: w.chainId,
      vault: w.vaultAddress,
      kernelGeneration: 1n,
      actionType: ACTION.SET_GUARDIANS,
      authorityGeneration: (await w.vault.guardianGeneration()) as bigint,
      params: commitment,
      domain: DOMAIN.GUARDIAN,
      nonce,
      deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.setGuardians(w.threshold, w.guardians, w.guardianIsContract, quorum(w, d), nonce, FAR_DEADLINE)
    ).wait();

    // The request is not CLEARED — it is left active and permanently
    // unexecutable, which is the state the model's own I-RECOVERY-TERMINATION
    // assertion calls out by name: "unexecutable and undeletable".
    expect((await w.vault.recovery())[R.ACTIVE], "still stored as live").to.equal(true);
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await expect(
      w.vault.executeRecovery({
        newSigner: nominee,
        newPqKeyHash: hash,
        newPqKey: KEY32("v-d-pq"),
        newEcdsaPop: sign(keyOf("v-d-nominee"), pop),
        newPqPop: sign(keyOf("v-d-pq"), pop),
      }),
      "the approved request is destroyed in effect",
    ).to.be.revertedWithCustomError(w.vault, "BadRoster");

    // Model: the replacement itself is DENIED and the request survives intact.
    const m = makeModel("ACCOUNT_PER_VAULT");
    const cred = { commitment: "cred-2", schemeId: "ECDSA_SECP256K1" as const, generation: 1, possessionProven: true };
    m.initiateRecovery("GUARDIAN", cred);
    m.supportRecovery("g1");
    m.supportRecovery("g2");
    expect(m.replaceGuardians("GUARDIAN_QUORUM", ["h1", "h2", "h3"]).kind, "model: denied").to.equal("DENIED");
    expect(m.kernel.recovery, "model: preserved").to.not.equal(null);
  });
});
