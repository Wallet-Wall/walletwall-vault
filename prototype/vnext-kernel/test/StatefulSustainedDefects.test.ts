/**
 * EXPERIMENTAL PROTOTYPE — THE COMPOSITION DEFECT LEDGER, EXECUTED.
 *
 * Defects found by the stateful campaign and reproduced FIRSTHAND against the
 * compiled kernel. `stateful/defects.ts` carries the full analysis, the
 * contradicted published claim, the root cause, and a minimal fix sketch.
 *
 * THESE TESTS ASSERT THE DEFECTIVE BEHAVIOUR ON PURPOSE.
 * ------------------------------------------------------
 * That is the point. Each is written so that IF A FIX LANDS IT FAILS, which is
 * what forces the fixer to update this file, `stateful/defects.ts` and
 * AUTHORITY.md together. A defect that can be quietly fixed while a security
 * table still says it is unreachable is how a stale table is born; a defect that
 * is quietly SUPPRESSED is worse. Neither happens here.
 *
 * THE MECHANISM HAS NOW FIRED ONCE, WHICH IS WHY SD-1 READS DIFFERENTLY.
 * ---------------------------------------------------------------------
 * SD-1 was remediated by `I-FLOOR-SHAPE-IMMUTABLE`, its reproduction went red
 * exactly as designed, and it is INVERTED IN PLACE rather than deleted: the same
 * sequence, step for step, with the verdict moved. Deleting it would have
 * erased the evidence that the interlock worked. Its ledger entry moved to
 * `REMEDIATED_DEFECTS`, which records the head it was SUSTAINED at, and the
 * residual it left is carried as SD-4 in its own right.
 *
 * NONE OF THESE IS AN UNAUTHORIZED ASSET OR CONTROL ESCALATION. All are DENIAL /
 * LIVENESS or state-incoherence outcomes. No declared cut for asset control,
 * credential replacement, verifier replacement, guardian transition or migration
 * is reduced by any of them. That bound is asserted below, not merely in prose.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  pqHash,
  pqKeyBytes,
  recoverParams,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";
import { REMEDIATED_DEFECTS, SUSTAINED_DEFECTS } from "../stateful/defects.js";

const DAY = 24 * 60 * 60;

/** Signs and submits a setVerifier with an arbitrary floor, as the credential holder. */
async function setVerifierAs(
  w: World,
  verifier: string,
  floor: Floor,
  credKey: ethers.SigningKey,
  pqKey: ethers.SigningKey | null,
): Promise<void> {
  const current = await w.vault.securityFloor();
  const requirePqNow = current[0] as boolean;
  const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await w.vault.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: 1n,
    actionType: ACTION.SET_VERIFIER,
    authorityGeneration: credGen,
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.setVerifier(
      verifier,
      [floor.requirePq, floor.pqParamLevel, floor.pqPublicKeyLength, floor.pqSignatureLength],
      nonce,
      FAR_DEADLINE,
      sign(credKey, d),
      requirePqNow && pqKey ? sign(pqKey, d) : "0x",
      requirePqNow && pqKey ? pqKeyBytes(pqKey) : "0x",
    )
  ).wait();
}

/**
 * SD-4 is SUSTAINED but is NOT reproduced in this file, and that is deliberate
 * rather than an omission: it is the declared residual of the SD-1 remediation,
 * it needs a genesis shape `deployWorld` could not previously build, and it is
 * only meaningful beside the fix that produced it. Its reproduction — including
 * the quorum's escape — lives in test/Sd1RecoveryFloorBinding.test.ts, which is
 * what its ledger entry's `reproducedBy` names and what the receipt publishes.
 */
describe("vNext kernel — COMPOSITION DEFECT LEDGER (SD-1, SD-3, SD-6, SD-7, SD-9b/c/d/e remediated; SD-2 and SD-10 reproduced here, SD-4 / SD-5 / SD-8 next door)", function () {
  this.timeout(600_000);

  it("the ledger is complete and every entry is classified as denial or incoherence, never escalation", function () {
    // IDENTITY, NOT ARITHMETIC. A receipt can carry the right counts and the
    // wrong defects, so both sets are asserted by id; an entry that arrives or
    // leaves has to move these lists deliberately (Lane W2P).
    const SUSTAINED_IDS = [
      "SD-2-containment-window-is-tumbling",
      "SD-4-ecdsa-only-shape-declaration-is-uncounted",
      "SD-5-permanent-shape-capture-on-the-declaring-edge",
      "SD-8-genesis-exhibit-cannot-prove-well-formedness",
      "SD-10-approved-request-stranded-by-guardian-rotation",
    ];
    expect([...SUSTAINED_DEFECTS.map((d) => d.id)].sort(), "the sustained set, by id").to.deep.equal(
      [...SUSTAINED_IDS].sort(),
    );
    expect(SUSTAINED_DEFECTS.length).to.equal(5);
    for (const d of SUSTAINED_DEFECTS) {
      expect(d.classification, d.id).to.be.oneOf(["LIVENESS_DENIAL", "STATE_INCOHERENCE"]);
      expect(d.contradicts.length, d.id + " must name the published claim it falsifies").to.be.greaterThan(40);
      expect(d.rootCause.length, d.id + " must name the source construct").to.be.greaterThan(40);
      expect(d.minimalFixSketch.length, d.id + " must carry a minimal fix sketch").to.be.greaterThan(30);
    }
    // SD-1 and SD-3 are no longer here; they are in REMEDIATED_DEFECTS. A fix
    // that merely DELETED a ledger entry would leave a repository in which the
    // inverted reproduction has no explanation, so each entry MOVED rather than
    // vanished, and each still names the head it was sustained at.
    //
    // SD-4 is deliberately NOT in that list. A fix for it was built, measured
    // and then removed — refusing a ONE-SHOT transition hands the opposing
    // principal a veto over a capability it cannot itself exercise — so it stays
    // SUSTAINED, and it now carries a CAMPAIGN PROPERTY it never had, which means
    // the "still reproducing" assertion covers it for the first time.
    const REMEDIATED_IDS = [
      "SD-1-floor-length-poisoning",
      "SD-3-setverifier-skips-genesis-satisfiability",
      "SD-6-unattested-commitment-install-on-an-ecdsa-only-floor",
      "SD-7-genesis-admits-an-unsatisfiable-floor",
      "SD-9b-expired-request-retains-blocking-effect",
      "SD-9c-guardian-quorum-cancellation-absent",
      "SD-9d-live-request-overwrite",
      "SD-9e-expiry-equality-boundary",
    ];
    for (const closed of REMEDIATED_IDS) {
      expect(SUSTAINED_DEFECTS.map((d) => d.id), closed + " must not be listed as sustained any more").to.not.include(
        closed,
      );
      expect(REMEDIATED_DEFECTS.map((d) => d.id), closed + " must be recorded as remediated").to.include(closed);
    }
    expect([...REMEDIATED_DEFECTS.map((r) => r.id)].sort(), "the remediated set, by id").to.deep.equal(
      [...REMEDIATED_IDS].sort(),
    );
    expect(REMEDIATED_DEFECTS.length).to.equal(8);
    // A defect is sustained or remediated, never both, and never twice.
    const everyId = [...SUSTAINED_DEFECTS.map((d) => d.id), ...REMEDIATED_DEFECTS.map((r) => r.id)];
    expect(new Set(everyId).size, "ids are unique across both arrays").to.equal(everyId.length);
    // SD-9a is a REMEDIATION HAZARD / SPECIFICATION GAP, not a present defect;
    // it must not be smuggled into either array so that a receipt can count it.
    expect(everyId.some((id) => id.toLowerCase().includes("sd-9a")), "SD-9a is not a defect entry").to.equal(false);
    // Lane W2's four closures name their exact source identities.
    const W1_RECORD = "4b9127269602d8eab3700d96dda4d5cfcf2e0d55";
    const W2_COMMIT_A = "c182db1099d92ff5830ae71116613c739b034bd9";
    for (const id of REMEDIATED_IDS.filter((x) => x.startsWith("SD-9"))) {
      const r = REMEDIATED_DEFECTS.find((x) => x.id === id)!;
      expect(r.sustainedAt, id + " was first recorded by Lane W1").to.equal(W1_RECORD);
      expect(r.remediatedOn.startsWith(W2_COMMIT_A), id + " names Lane W2's Commit A as its source").to.equal(true);
      expect(r.invertedReproduction, id + " must point at the W2 lifecycle suite").to.include(
        "W2RecoveryLifecycle.test.ts",
      );
    }
    // SD-10 is present, has no campaign oracle, and is reproduced in THIS file.
    const sd10 = SUSTAINED_DEFECTS.find((d) => d.id === "SD-10-approved-request-stranded-by-guardian-rotation")!;
    expect(sd10.property, "SD-10 has no campaign property; its reproduction is deterministic").to.equal(null);
    expect(sd10.reproducedBy ?? "", "SD-10 names this file").to.include("StatefulSustainedDefects.test.ts");
    // SD-4 stays sustained on its campaign property, and its entry carries the
    // canonical disposition rather than the refuted general claims.
    const sd4 = SUSTAINED_DEFECTS.find((d) => d.id === "SD-4-ecdsa-only-shape-declaration-is-uncounted")!;
    expect(sd4.property).to.equal("G-DECLARATION-SUBORDINATE-TO-RECOVERY");
    const sd4Text = Object.values(sd4).join(" ");
    expect(sd4Text, "a refuted claim must not be republished").to.not.include("No fifth family is known");
    expect(sd4Text, "a refuted claim must not be republished").to.not.include("liveness cost is INHERENT");
    expect(sd4Text).to.include("SD4_DEDICATED_REMEDIATION = NOT_REQUIRED");
    expect(sd4Text).to.include("G_PRIME_INCREMENTAL_VALUE = NONE_ESTABLISHED");
    for (const r of REMEDIATED_DEFECTS) {
      expect(r.sustainedAt, r.id + " must name the head it was sustained at").to.match(/^[0-9a-f]{40}$/);
      expect(r.invariant.length, r.id + " must state the invariant that closed it").to.be.greaterThan(60);
      expect(
        r.rejectedAlternatives.length,
        r.id + " must record the designs rejected — a fix with no rejected alternatives was not chosen",
      ).to.be.greaterThan(60);
    }
    // The residual is a first-class sustained defect, not a footnote.
    const residuals = REMEDIATED_DEFECTS.map((r) => r.residual).filter((x): x is string => x !== null);
    for (const id of residuals) {
      expect(SUSTAINED_DEFECTS.map((d) => d.id), "a declared residual must be carried as a sustained defect").to.include(
        id,
      );
    }
  });

  // =====================================================================
  /**
   * REMEDIATED — and kept here, running, rather than deleted.
   *
   * This is the SAME sequence that sustained SD-1 at ec5adce9, step for step:
   * the same honest quorum, the same approved recovery, the same single-field
   * length change. Only the VERDICT has moved. Steps 1 and 2 still assert what
   * they always did; step 3 now asserts that the poisoning transition is
   * REFUSED, and step 4 — which is the point — asserts that the recovery the
   * attack existed to veto actually EXECUTES.
   *
   * Asserting the execution, not merely the absence of a revert, is deliberate:
   * `_requireIncomingPossession` reverts `BadSignature` from three different
   * branches, so a revert-selector assertion could not distinguish a fixed
   * kernel from a broken one.
   */
  it("SD-1 — REMEDIATED: the floor-length poisoning that vetoed recovery is now refused, and the recovery executes", async function () {
    const w = await deployWorld({ label: "sd1", verifier: "honest" });

    // 1. An HONEST guardian quorum (k = 2 distinct principals) approves a recovery.
    const gGen = (await w.vault.guardianGeneration()) as bigint;
    const gNonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const newCred = w.spareCred[0]!;
    const newPq = w.sparePq[0]!;
    const rd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.RECOVER, authorityGeneration: gGen,
      params: recoverParams(addrOf(newCred), pqHash(newPq), w.verifiers.honest),
      domain: DOMAIN.GUARDIAN, nonce: gNonce, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(newCred), pqHash(newPq), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, rd), sign(w.gKeys[1]!, rd)],
      }, gNonce, FAR_DEADLINE)
    ).wait();
    expect((await w.vault.recovery())[7], "recovery must be active").to.equal(true);
    expect(Number((await w.vault.recovery())[6]), "challenge budget untouched").to.equal(0);

    // 2. The COMPROMISED credential (2 roots — the declared asset cut, so it has
    //    gained nothing it did not already have) attempts to change ONLY the
    //    signature LENGTH. requirePq stays true and pqParamLevel does not
    //    decrease, so the two ORIGINAL clauses of _requireNoDowngrade permit it.
    //    I-FLOOR-SHAPE-IMMUTABLE is the third clause, and it does not.
    const before = await w.vault.securityFloor();
    expect(Number(before[3]), "the honest floor declares a 65-byte signature").to.equal(65);
    await expect(
      setVerifierAs(
        w, w.verifiers.honest,
        { requirePq: true, pqParamLevel: Number(before[1]), pqPublicKeyLength: 32, pqSignatureLength: 64 },
        w.credKey, w.pqKey,
      ),
      "REMEDIATED: the poisoning transition is refused at the write",
    ).to.be.revertedWithCustomError(w.vault, "Downgrade");
    const after = await w.vault.securityFloor();
    expect(Number(after[3]), "REMEDIATED: the recorded shape did not move").to.equal(65);
    expect(Number(after[2]), "REMEDIATED: neither did the key shape").to.equal(Number(before[2]));

    // 3. AND THE POINT. The recovery this attack existed to veto now completes.
    //    Asserted as an OBSERVED INSTALL, because _requireIncomingPossession
    //    reverts BadSignature from three branches and the absence of one
    //    particular revert would prove nothing.
    await networkHelpers.time.increase(7 * DAY + 1);
    const pop = (await w.vault.recoveryPossessionDigest()) as string;
    await (
      await w.vault.executeRecovery({
        newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey: pqKeyBytes(newPq),
        newEcdsaPop: sign(newCred, pop), newPqPop: sign(newPq, pop),
      })
    ).wait();
    expect(await w.vault.ecdsaSigner(), "REMEDIATED: the guardian-approved credential is installed")
      .to.equal(addrOf(newCred));
    expect(await w.vault.pqPublicKeyHash(), "REMEDIATED: and so is its PQ commitment").to.equal(pqHash(newPq));

    // 4. The challenge budget was never needed, because there was never a veto.
    //    At ec5adce9 this same assertion read "challengesUsed is STILL 0" and was
    //    the PROOF OF THE DEFECT: the counter never engaged while the veto ran
    //    unbounded. Here it means the opposite — nothing was ever vetoed.
    const rec = await w.vault.recovery();
    expect(rec[7], "the request is consumed, not stranded").to.equal(false);
    expect(Number(rec[6]), "no challenge was consumed").to.equal(0);

    // 5. AND THE BOUND ON THE CLAIM: no guardian was compromised, and the
    //    guardian roster is untouched, so no authority CUT moved.
    expect(await w.vault.guardianCommitment()).to.equal(
      ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["uint64", "address[]", "bool[]"], [w.threshold, w.guardians, w.guardianIsContract],
        ),
      ),
    );
    expect(Number(await w.vault.guardianThreshold()), "the guardian cut k is unchanged").to.equal(2);
  });

  // =====================================================================
  it("SD-2 — the containment budget window is TUMBLING: k guardians hold 9 CONTIGUOUS contained days from a declared 6", async function () {
    const w = await deployWorld({ label: "sd2", verifier: "honest" });
    const now = async (): Promise<number> => Number((await ethers.provider.getBlock("latest"))!.timestamp);
    const contain = async (): Promise<boolean> => {
      const gGen = (await w.vault.guardianGeneration()) as bigint;
      const n = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
        actionType: ACTION.RECOVER, authorityGeneration: gGen, params: ethers.id("CONTAIN"),
        domain: DOMAIN.GUARDIAN, nonce: n, deadline: FAR_DEADLINE,
      });
      try {
        await (
          await w.vault.enterContainment({
            members: w.guardians, isContract: w.guardianIsContract,
            attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
          }, n, FAR_DEADLINE)
        ).wait();
        return true;
      } catch { return false; }
    };
    const advanceTo = async (t: number): Promise<void> => {
      const d = t - (await now());
      if (d > 0) await networkHelpers.time.increase(d);
    };

    // THE STRADDLE. Two containments at the END of an epoch, two more immediately
    // after the rollover. Each epoch's own accounting stays within CONTAINMENT_BUDGET;
    // the DENIAL is contiguous across the boundary.
    expect(await contain(), "containment #1").to.equal(true);
    const W = Number(await w.vault.containmentWindowStart());

    await advanceTo(W + 27 * DAY);
    expect(await contain(), "containment #2 at +27d, still inside the first epoch").to.equal(true);
    expect(Number(await w.vault.containmentUsedInWindow()), "epoch 1 is now at the full budget").to.equal(6 * DAY);
    const contiguousFrom = Number(await w.vault.containedUntil()) - 3 * DAY;

    const containedUntilEpoch1 = Number(await w.vault.containedUntil());
    await advanceTo(W + 30 * DAY);
    const enteredAt3 = (await now()) + 1;
    expect(await contain(), "containment #3 — the rollover resets the ORIGIN to now").to.equal(true);
    expect(
      enteredAt3 <= containedUntilEpoch1 + 1,
      "the third containment must begin with NO GAP, or the denial is not contiguous",
    ).to.equal(true);
    expect(
      Number(await w.vault.containmentWindowStart()) >= W + 30 * DAY,
      "the origin JUMPED to now rather than sliding — this is a TUMBLING epoch",
    ).to.equal(true);
    expect(Number(await w.vault.containmentUsedInWindow()), "and the budget reset to zero, then took 3d").to.equal(3 * DAY);

    await advanceTo(W + 33 * DAY);
    expect(await contain(), "containment #4").to.equal(true);
    const contiguousTo = Number(await w.vault.containedUntil());

    const contiguousDays = (contiguousTo - contiguousFrom) / DAY;
    console.log("      measured contiguous denial: " + contiguousDays.toFixed(4) + " days (declared budget 6.00)");
    expect(
      contiguousDays > 6,
      "SUSTAINED: contiguous denial (" + contiguousDays.toFixed(4) + "d) exceeds the declared 6-day budget",
    ).to.equal(true);
    expect(Math.round(contiguousDays), "the straddle yields 3 x CONTAINMENT_MAX contiguous").to.equal(9);

    // THE BOUND ON THE CLAIM: containment withdraws SPENDING and never RECOVERY,
    // so the remedy stays reachable throughout — this is denial, not capture.
    const gGen = (await w.vault.guardianGeneration()) as bigint;
    const n = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
    const rd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.RECOVER, authorityGeneration: gGen,
      params: recoverParams(addrOf(w.spareCred[0]!), pqHash(w.sparePq[0]!), w.verifiers.honest),
      domain: DOMAIN.GUARDIAN, nonce: n, deadline: FAR_DEADLINE,
    });
    await (
      await w.vault.initiateRecovery(addrOf(w.spareCred[0]!), pqHash(w.sparePq[0]!), w.verifiers.honest, {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, rd), sign(w.gKeys[1]!, rd)],
      }, n, FAR_DEADLINE)
    ).wait();
    expect((await w.vault.recovery())[7], "recovery remains OPEN while contained").to.equal(true);
  });

  // =====================================================================
  /**
   * REMEDIATED, and inverted in place rather than deleted.
   *
   * This is the SAME sequence that sustained SD-3 at ec5adce9 — an ECDSA-only
   * genesis, one root, the same arming call — with only the VERDICT moved. The
   * genesis positive control is kept because it is what made the defect legible:
   * `initialize` always refused this state, and the transition simply did not.
   * `I-DECLARATION-EXHIBITED` is what closed the gap between them.
   *
   * The full remediation evidence, including the NON-ZERO form the ledger's own
   * fix sketch would have missed, lives in Sd34AuthenticationSatisfiability and
   * Sd34DeclarationInvariants.
   */
  it("SD-3 — REMEDIATED: the transition now refuses exactly what genesis always refused", async function () {
    const w = await deployWorld({ label: "sd3", verifier: "honest", ecdsaOnlyFloor: true });
    expect(await w.vault.pqPublicKeyHash(), "no PQ key is committed").to.equal(ethers.ZeroHash);
    expect((await w.vault.securityFloor())[0], "and no PQ conjunct is demanded").to.equal(false);

    // GENESIS REFUSES THIS EXACT COMBINATION — unchanged, and still the control
    // that proves the kernel knows the state is invalid.
    const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
    await expect(
      factory.deployVault(ethers.id("sd3-genesis-control"), {
        signer: addrOf(w.credKey), pqKeyHash: ethers.ZeroHash, verifier: w.verifiers.honest,
        threshold: 2, guardians: w.guardians, guardianIsContract: w.guardianIsContract,
        floor: { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
      }, "0x"),
      "initialize must refuse requirePq with a zero key commitment",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    // AND NOW SO DOES THE TRANSITION. At ec5adce9 this SUCCEEDED at one root and
    // left every credential path dead on a conjunct with no preimage.
    await expect(
      setVerifierAs(
        w, w.verifiers.honest,
        { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
        w.credKey, null,
      ),
      "REMEDIATED: nothing hashes to a zero commitment, so the declaration cannot be witnessed",
    ).to.be.revertedWithCustomError(w.vault, "BadSignature");

    expect((await w.vault.securityFloor())[0], "the conjunct was never armed").to.equal(false);
    expect(await w.vault.pqPublicKeyHash(), "and the commitment is untouched").to.equal(ethers.ZeroHash);

    // POSITIVE CONTROL — the vault is not merely refusing everything: it still
    // spends under its ECDSA-only floor, exactly as before.
    const sNonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
    const credGen = (await w.vault.credentialGeneration()) as bigint;
    const amount = ethers.parseEther("1");
    const sd = digestOf({
      chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
      actionType: ACTION.SPEND, authorityGeneration: credGen,
      params: spendParams(w.recipient, amount),
      domain: DOMAIN.SPEND, nonce: sNonce, deadline: FAR_DEADLINE,
    });
    const balBefore = await ethers.provider.getBalance(w.recipient);
    await (
      await w.vault.execute(w.recipient, amount, sNonce, FAR_DEADLINE, sign(w.credKey, sd), "0x", "0x")
    ).wait();
    expect(await ethers.provider.getBalance(w.recipient), "the vault still works").to.equal(balBefore + amount);
  });

  // =====================================================================
  /**
   * SD-10 — SUSTAINED. Recorded by Lane W1 (4b912726, SD9_RECOVERY_LIFECYCLE_DEFECTS.md),
   * measured there on the pre-W2 kernel (Sd4LaneV "D"), and RE-MEASURED HERE on
   * the W2 kernel, because W2 changed the defect's BLAST RADIUS without touching
   * `setGuardians`: a request stranded by a generation bump is still stored
   * `active` and, since W2, still EFFECTIVELY LIVE — so it now blocks a fresh
   * initiation (BadState) and migration (NoRecovery) until the NEW quorum cancels
   * it or it expires. This test asserts the defective behaviour on purpose, and
   * then the exit at k as the bound on the claim, so a fix cannot land silently
   * while the ledger still calls the request stranded.
   */
  it("SD-10 — SUSTAINED: a guardian-set replacement STRANDS an approved request, which stays stored active and (since W2) blocks re-initiation until the NEW quorum cancels it", async function () {
    const w = await deployWorld({ label: "sd10", verifier: "honest" });
    const guardianAuth = async (actionType: string, params: string) => {
      const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: 1n,
        actionType, authorityGeneration: (await w.vault.guardianGeneration()) as bigint,
        params, domain: DOMAIN.GUARDIAN, nonce, deadline: FAR_DEADLINE,
      });
      const proof = {
        members: w.guardians, isContract: w.guardianIsContract,
        attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
      };
      return { nonce, proof };
    };
    const initiate = async (cred: ethers.SigningKey, pq: ethers.SigningKey) => {
      const a = await guardianAuth(ACTION.RECOVER, recoverParams(addrOf(cred), pqHash(pq), w.verifiers.honest));
      return w.vault.initiateRecovery(addrOf(cred), pqHash(pq), w.verifiers.honest, a.proof, a.nonce, FAR_DEADLINE);
    };
    const change = async (cred: ethers.SigningKey, pq: ethers.SigningKey) => {
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      return {
        newSigner: addrOf(cred), newPqKeyHash: pqHash(pq), newPqKey: pqKeyBytes(pq),
        newEcdsaPop: sign(cred, pop), newPqPop: sign(pq, pop),
      };
    };

    // 1. An HONEST quorum (k = 2 distinct principals) approves a recovery.
    const cred1 = w.spareCred[0]!;
    const pq1 = w.sparePq[0]!;
    await (await initiate(cred1, pq1)).wait();
    const boundGeneration = (await w.vault.recovery())[5] as bigint;
    expect((await w.vault.recovery())[7], "approved and live").to.equal(true);

    // 2. The SAME quorum re-commits the IDENTICAL roster. `setGuardians` consults
    //    nothing about `recovery`: it is admitted while the request is live, and
    //    the generation moves. The reference model DENIES this exact move
    //    (I-APPROVED-REQUEST-PRESERVATION); the kernel does not.
    const commitment = (await w.vault.rosterCommitment(w.threshold, w.guardians, w.guardianIsContract)) as string;
    const g = await guardianAuth(ACTION.SET_GUARDIANS, commitment);
    await (
      await w.vault.setGuardians(w.threshold, w.guardians, w.guardianIsContract, g.proof, g.nonce, FAR_DEADLINE)
    ).wait();
    expect((await w.vault.guardianGeneration()) as bigint, "the generation bumped").to.equal(boundGeneration + 1n);

    // 3. SUSTAINED: at maturity the approved request is unexecutable — the
    //    generation binding that correctly kills a STALE constituency's authority
    //    (stateful mutant M16) kills the request this SAME constituency approved —
    //    and it is still stored active with no challenge consumed.
    await networkHelpers.time.increase(7 * DAY + 1);
    await expect(
      w.vault.executeRecovery(await change(cred1, pq1)),
      "SUSTAINED (SD-10): the approved request is destroyed in effect",
    ).to.be.revertedWithCustomError(w.vault, "BadRoster");
    const stranded = await w.vault.recovery();
    expect(stranded[7], "SUSTAINED: still stored active").to.equal(true);
    expect(Number(stranded[6]), "SUSTAINED: no challenge was consumed — no principal ended it").to.equal(0);

    // 4. W2 BLAST RADIUS (recorded, not remediated): the stranded request is still
    //    effectively live, so a fresh initiation is refused as an overwrite.
    await expect(
      initiate(w.spareCred[1]!, w.sparePq[1]!),
      "W2: a stranded request blocks re-initiation until it is cleared",
    ).to.be.revertedWithCustomError(w.vault, "BadState");

    // 5. THE BOUND ON THE CLAIM: escapable at k, and by no smaller principal. The
    //    NEW quorum's explicit exit (K-9 mechanism B, digest bound to the CURRENT
    //    generation) clears it, and a fresh request then completes.
    const c = await guardianAuth(ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
    await (await w.vault.cancelRecoveryByQuorum(c.proof, c.nonce, FAR_DEADLINE)).wait();
    expect((await w.vault.recovery())[7], "cleared by the new quorum").to.equal(false);
    const cred2 = w.spareCred[1]!;
    const pq2 = w.sparePq[1]!;
    await (await initiate(cred2, pq2)).wait();
    await networkHelpers.time.increase(7 * DAY + 1);
    await (await w.vault.executeRecovery(await change(cred2, pq2))).wait();
    expect(await w.vault.ecdsaSigner(), "the re-proposed recovery installs").to.equal(addrOf(cred2));
  });

  // =====================================================================
  it("prints the sustained-defect ledger", function () {
    console.log("\n  REMEDIATED COMPOSITION DEFECTS");
    for (const r of REMEDIATED_DEFECTS) {
      console.log("\n  " + r.id);
      console.log("    DEFECT_SUSTAINED_AT   " + r.sustainedAt);
      console.log("    DEFECT_REMEDIATED_ON  " + r.remediatedOn);
      console.log("    invariant   : " + r.invariant.slice(0, 150) + "...");
      console.log("    residual    : " + (r.residual ?? "none"));
    }
    console.log("\n  SUSTAINED COMPOSITION DEFECTS (still open)");
    for (const d of SUSTAINED_DEFECTS) {
      console.log("\n  " + d.id + "  [" + d.classification + "]  roots: " + d.rootsRequired.split("—")[0]!.trim());
      console.log("    " + d.title);
      console.log("    contradicts : " + d.contradicts.slice(0, 150) + "...");
      console.log("    minimal fix : " + d.minimalFixSketch.slice(0, 130) + "...");
    }
    console.log("");
  });
});
