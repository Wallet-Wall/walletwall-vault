/**
 * EXPERIMENTAL PROTOTYPE — LANE SD-10: APPROVED-REQUEST PRESERVATION ACROSS A
 * GUARDIAN-SET REPLACEMENT, ON THE REAL ARTIFACT.
 *
 * SOURCE AUTHORITY, quoted rather than paraphrased
 * (docs/Vault_vNext_Architecture.md:951):
 *
 *   I-APPROVED-REQUEST-PRESERVATION. Once a request reaches quorum, a
 *   guardian-set replacement cannot clear it.
 *
 * read with :948 I-RECOVERY-TERMINATION ("every quorum-approved request leaves
 * the system by execution, cancellation, or expiry — and expiry requires no
 * principal to act") and :945 I-RECOVERY-NONVETO ("no principal holds an
 * unbounded veto over an otherwise-valid recovery").
 *
 * THE FROZEN TARGET (Lane SD10-D1, decision PRESERVE APPROVED REQUEST):
 *
 *   an already quorum-approved recovery remains EXECUTABLE across guardian-set
 *   replacement until execution, explicit cancellation, credential challenge,
 *   or expiry.
 *
 *   FRESH guardian authority after rotation = the CURRENT roster only.
 *   OLD guardian approval = a preserved PRE-COMMITTED EFFECT, not fresh
 *   authority. The old roster keeps NO membership and NO seat.
 *
 * WHAT THIS IS NOT. Preservation is not unconditional execution. Every other
 * gate on `executeRecovery` stands unchanged — maturity, the half-open expiry
 * window, the active flag, and above all `_requireIncomingPossession` against
 * the INCOMING verifier. Section F below is the standing proof of that.
 *
 * WRITTEN RED FIRST. Against the exact base a42f5c7e the primary property (A1)
 * fails with `BadRoster`, thrown by the one statement this lane removes:
 * `executeRecovery`'s `r.boundGuardianGeneration != guardianGeneration`. The
 * tests that pin behaviour the correction must PRESERVE — the old roster's
 * total loss of fresh authority, the current quorum's cancellation, the
 * challenge budget, the request clocks — pass on both kernels and are
 * regression guards, not RED.
 *
 * MINED-INSTANT DISCIPLINE (Lane W1, inherited). Every boundary probe asserts
 * the block timestamp the transaction ACTUALLY executed at, and carries an
 * explicit gasLimit so a reverting probe is still MINED rather than refused at
 * gas estimation.
 *
 * NOTHING HERE ASKS THE KERNEL WHAT TO SIGN. Every digest is mirrored from
 * `stateful/world.ts` / `sd4-harness.ts`, so a kernel that binds the wrong
 * fields cannot make this harness agree with it.
 */
import { expect } from "chai";
import { ethers, networkHelpers } from "./connection.js";
import { R, abi } from "./sd4-harness.js";
import {
  ACTION,
  DOMAIN,
  FAR_DEADLINE,
  addrOf,
  deployWorld,
  digestOf,
  keyOf,
  sign,
  type World,
} from "../stateful/world.js";

const KERNEL_GEN = 1n;

// ---------------------------------------------------------------------------
// Rosters. The world's own `quorum()` helper is pinned to the GENESIS roster,
// which is precisely the roster this lane needs to rotate AWAY from, so the
// suite carries its own explicit-roster equivalents.
// ---------------------------------------------------------------------------

interface Roster {
  readonly keys: ethers.SigningKey[];
  readonly members: string[];
  readonly isContract: boolean[];
}

/** A replacement roster derived from `tag`, in the STRICTLY ASCENDING order the kernel demands. */
const mkRoster = (tag: string): Roster => {
  const keys = [0, 1, 2]
    .map((i) => keyOf(`sd10-${tag}-g${i}`))
    .sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));
  return { keys, members: keys.map(addrOf), isContract: [false, false, false] };
};

/** The genesis roster, as a Roster. */
const genesisRoster = (w: World): Roster => ({
  keys: w.gKeys,
  members: w.guardians,
  isContract: w.guardianIsContract,
});

/** A 2-of-3 quorum proof signed by an EXPLICIT roster's seats 0 and 1. */
const quorumOf = (r: Roster, digest: string) => ({
  members: r.members,
  isContract: r.isContract,
  attestingIndices: [0, 1],
  attestations: [sign(r.keys[0]!, digest), sign(r.keys[1]!, digest)],
});

/** A guardian-domain digest at the vault's CURRENT generation and nonce. */
async function gDigest(w: World, v: ethers.Contract, action: string, params: string) {
  const nonce = (await v.nonces(DOMAIN.GUARDIAN)) as bigint;
  const gGen = (await v.guardianGeneration()) as bigint;
  return {
    nonce,
    digest: digestOf({
      chainId: w.chainId,
      vault: w.vaultAddress,
      kernelGeneration: KERNEL_GEN,
      actionType: action,
      authorityGeneration: gGen,
      params,
      domain: DOMAIN.GUARDIAN,
      nonce,
      deadline: FAR_DEADLINE,
    }),
  };
}

type Overrides = { gasLimit?: number };
const MINED: Overrides = { gasLimit: 2_000_000 };

/**
 * REPLACE the roster in force (`from`) with a genuinely different one (`to`).
 * This is the transition the whole lane turns on: it bumps `guardianGeneration`
 * and leaves the OLD roster holding no seat at all.
 */
async function replaceRoster(w: World, v: ethers.Contract, from: Roster, to: Roster, overrides: Overrides = {}) {
  const commitment = (await v.rosterCommitment(w.threshold, to.members, to.isContract)) as string;
  const { digest, nonce } = await gDigest(w, v, ACTION.SET_GUARDIANS, commitment);
  return v.setGuardians(w.threshold, to.members, to.isContract, quorumOf(from, digest), nonce, FAR_DEADLINE, overrides);
}

// ---------------------------------------------------------------------------
// Credentials, proposals, execution — mirrors of the W2 suite's helpers.
// ---------------------------------------------------------------------------

interface Cred {
  nominee: ethers.SigningKey;
  pqNominee: ethers.SigningKey;
  key32: string;
  hash: string;
}
const mkCred = (tag: string): Cred => {
  const nominee = keyOf(`sd10-${tag}-s`);
  const pqNominee = keyOf(`sd10-${tag}-p`);
  const key32 = abi.encode(["address"], [addrOf(pqNominee)]);
  return { nominee, pqNominee, key32, hash: ethers.keccak256(key32) };
};

/** `initiateRecovery` for `c`, signed by the roster CURRENTLY in force. */
async function propose(w: World, v: ethers.Contract, r: Roster, c: Cred, verifier?: string) {
  const ver = verifier ?? w.verifiers.honest;
  const params = ethers.keccak256(abi.encode(["address", "bytes32", "address"], [addrOf(c.nominee), c.hash, ver]));
  const { digest, nonce } = await gDigest(w, v, ACTION.RECOVER, params);
  return v.initiateRecovery(addrOf(c.nominee), c.hash, ver, quorumOf(r, digest), nonce, FAR_DEADLINE);
}

/** `executeRecovery` with GENUINE possession proofs over the live request. */
async function execute(v: ethers.Contract, c: Cred, overrides: Overrides = {}) {
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

/** The credential's BOUNDED challenge (`cancelRecovery`), mirrored from the W2 suite. */
async function challenge(w: World, v: ethers.Contract, credKey: ethers.SigningKey, overrides: Overrides = {}) {
  const nonce = (await v.nonces(DOMAIN.CREDENTIAL)) as bigint;
  const credGen = (await v.credentialGeneration()) as bigint;
  const d = digestOf({
    chainId: w.chainId,
    vault: w.vaultAddress,
    kernelGeneration: KERNEL_GEN,
    actionType: ACTION.RECOVER,
    authorityGeneration: credGen,
    params: ethers.id("CANCEL"),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return v.cancelRecovery(nonce, FAR_DEADLINE, sign(credKey, d), overrides);
}

/** The complete stored request, as the identity this lane claims is preserved. */
async function requestIdentity(v: ethers.Contract) {
  const r = await v.recovery();
  return {
    proposedSigner: String(r[R.SIGNER]),
    proposedPqKeyHash: String(r[R.PQ_KEY_HASH]),
    proposedVerifier: String(r[R.VERIFIER]),
    executableAt: r[R.EXECUTABLE_AT] as bigint,
    expiresAt: r[R.EXPIRES_AT] as bigint,
    boundGuardianGeneration: r[R.GUARDIAN_GEN] as bigint,
    challengesUsed: r[R.CHALLENGES] as bigint,
    active: r[R.ACTIVE] as boolean,
  };
}

const at = async (t: bigint) => networkHelpers.time.setNextBlockTimestamp(t);

describe("SD-10 — an approved recovery request survives a guardian-set replacement", () => {
  // =========================================================================
  // A. THE PRIMARY PROPERTY. Approve under G, replace the roster (G+1), mature,
  //    prove possession, execute. On the exact base this reverts BadRoster.
  // =========================================================================
  describe("A. preservation across one replacement", () => {
    it("A1 an approved R1 executes after the roster that approved it has been replaced, and it is the SAME R1", async function () {
      const w = await deployWorld({ label: "sd10-a1" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const g1 = mkRoster("a1-new");
      const c = mkCred("a1");

      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      const genAtApproval = (await v.guardianGeneration()) as bigint;
      expect(approved.active, "R1 approved and stored").to.equal(true);
      expect(approved.boundGuardianGeneration, "R1 is bound to the generation that approved it").to.equal(
        genAtApproval,
      );

      // THE REPLACEMENT. A genuinely different roster: no seat is shared.
      await (await replaceRoster(w, v, g0, g1)).wait();
      expect((await v.guardianGeneration()) as bigint, "generation advanced").to.equal(genAtApproval + 1n);
      for (const m of g1.members) expect(g0.members, "the new roster shares no seat").to.not.include(m);

      // I-APPROVED-REQUEST-PRESERVATION, field by field: the replacement
      // cleared NOTHING. `boundGuardianGeneration` stays pinned at G — it is
      // APPROVAL PROVENANCE, not a claim about who holds authority now.
      expect(await requestIdentity(v), "the replacement cleared nothing").to.deep.equal(approved);

      // Mature and execute. Possession is proven against the INCOMING verifier
      // exactly as before; nothing about the proof changes.
      await at(approved.executableAt);
      await (await execute(v, c)).wait();

      expect(await v.ecdsaSigner(), "R1's proposed signer is installed").to.equal(addrOf(c.nominee));
      expect(await v.pqPublicKeyHash(), "R1's PQ commitment is installed").to.equal(c.hash);
      expect(await v.pqVerifier(), "R1's proposed verifier is installed").to.equal(approved.proposedVerifier);
      expect((await requestIdentity(v)).active, "the request is consumed by execution").to.equal(false);
    });

    it("A2 the NEW roster gains no retroactive authorship: it never signed R1, and execution stays permissionless and pre-committed", async function () {
      const w = await deployWorld({ label: "sd10-a2" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const g1 = mkRoster("a2-new");
      const c = mkCred("a2");

      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, g1)).wait();

      // The ONLY guardian-domain acts the new roster has performed are none:
      // its arrival consumed the guardian nonce that the OLD roster signed for.
      // R1's approving digest was signed at generation G by g0's seats, and no
      // g1 seat ever attested to R1's params. Re-deriving that digest at the
      // CURRENT generation produces a value g0's stored approval does not match
      // — which is exactly why nothing here is retroactive authorship.
      const params = ethers.keccak256(
        abi.encode(["address", "bytes32", "address"], [approved.proposedSigner, approved.proposedPqKeyHash, approved.proposedVerifier]),
      );
      const freshDigest = (await gDigest(w, v, ACTION.RECOVER, params)).digest;
      const approvalDigest = digestOf({
        chainId: w.chainId,
        vault: w.vaultAddress,
        kernelGeneration: KERNEL_GEN,
        actionType: ACTION.RECOVER,
        authorityGeneration: approved.boundGuardianGeneration,
        params,
        domain: DOMAIN.GUARDIAN,
        nonce: 0n,
        deadline: FAR_DEADLINE,
      });
      expect(freshDigest, "a fresh approval of R1 today is a DIFFERENT digest").to.not.equal(approvalDigest);

      // PERMISSIONLESS AND PRE-COMMITTED: an outsider — no seat on either
      // roster, no credential — completes it, because execution carries no
      // discretion. It installs only what R1 already committed to.
      await at(approved.executableAt);
      const asOutsider = v.connect(w.outsider) as ethers.Contract;
      await (await execute(asOutsider, c)).wait();
      expect(await v.ecdsaSigner(), "the outsider installed R1's signer, not a choice of its own").to.equal(
        addrOf(c.nominee),
      );
    });
  });

  // =========================================================================
  // B. FRESH AUTHORITY IS THE CURRENT ROSTER'S, AND ONLY THE CURRENT ROSTER'S.
  //    The whole correction rests on this asymmetry: the OLD roster's approval
  //    survives as a pre-committed effect while the OLD roster keeps no seat.
  //    If any probe here ever passed, preservation would have become tenure.
  // =========================================================================
  describe("B. the replaced roster retains NO fresh authority", () => {
    it("B1 with R1 still live, the old roster can neither cancel it, replace the roster again, nor enter containment", async function () {
      const w = await deployWorld({ label: "sd10-b1" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const g1 = mkRoster("b1-new");
      const c = mkCred("b1");

      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, g1)).wait();

      // Each probe is signed by the OLD roster over the CURRENT generation —
      // the strongest form of the attack, since a stale-generation digest would
      // fail for the uninteresting reason. The old members are simply no longer
      // in the committed roster, so the proof fails canonicity.
      // Every probe names the error it must die of. `BadRoster` is the kernel's
      // answer to "you are not the roster", thrown by `_requireQuorum`'s
      // commitment check — which is the CORRECT meaning of that error, and the
      // meaning SD-10 abused when it also used it to mean "your already-approved
      // request is stale". Asserting the specific error is what makes each probe
      // a proof of an AUTHORITY refusal rather than of an incidental revert.
      const probes: { name: string; err: string; run: () => Promise<unknown> }[] = [
        {
          name: "cancelRecoveryByQuorum",
          err: "BadRoster",
          run: async () => {
            const { digest, nonce } = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
            return v.cancelRecoveryByQuorum(quorumOf(g0, digest), nonce, FAR_DEADLINE, MINED);
          },
        },
        {
          name: "setGuardians",
          err: "BadRoster",
          run: async () => replaceRoster(w, v, g0, mkRoster("b1-third"), MINED),
        },
        {
          name: "enterContainment",
          err: "BadRoster",
          run: async () => {
            const { digest, nonce } = await gDigest(w, v, ACTION.RECOVER, ethers.id("CONTAIN"));
            return v.enterContainment(quorumOf(g0, digest), nonce, FAR_DEADLINE, MINED);
          },
        },
      ];

      for (const p of probes) {
        await expect(p.run(), `old roster must hold no fresh ${p.name} authority`).to.be.revertedWithCustomError(
          v,
          p.err,
        );
      }

      // POSITIVE CONTROL. The probes above must fail because the OLD roster has
      // no authority — not because these calls are unreachable in this state.
      // The CURRENT roster performs one of them successfully, right here.
      const { digest, nonce } = await gDigest(w, v, ACTION.RECOVER, ethers.id("CONTAIN"));
      await (await v.enterContainment(quorumOf(g1, digest), nonce, FAR_DEADLINE)).wait();
      expect(await v.safeState(), "the CURRENT roster's containment succeeded").to.equal(1n);

      // And the preserved effect is untouched by all of it.
      expect(await requestIdentity(v), "R1 survived every old-roster attempt intact").to.deep.equal(approved);
    });

    it("B1b the old roster cannot create a FRESH recovery either — measured where the authority gate is actually reached", async function () {
      // `initiateRecovery` is deliberately NOT one of B1's probes. While R1 is
      // live, W2's overwrite refusal (`if (_recoveryIsLive()) revert BadState()`)
      // fires BEFORE `_requireQuorum` ever inspects the proof, so an old-roster
      // attempt there dies of the request's liveness rather than of the caller's
      // lack of authority. That probe would pass while proving nothing about
      // authority. Here the slot is cleared FIRST — by the current quorum, its
      // own exit — so the only obstacle left is who is signing.
      const w = await deployWorld({ label: "sd10-b1b" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const g1 = mkRoster("b1b-new");

      await (await propose(w, v, g0, mkCred("b1b"))).wait();
      await (await replaceRoster(w, v, g0, g1)).wait();
      const done = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
      await (await v.cancelRecoveryByQuorum(quorumOf(g1, done.digest), done.nonce, FAR_DEADLINE)).wait();
      expect((await requestIdentity(v)).active, "the slot is free").to.equal(false);

      const c2 = mkCred("b1b-fresh");
      const params = ethers.keccak256(
        abi.encode(["address", "bytes32", "address"], [addrOf(c2.nominee), c2.hash, w.verifiers.honest]),
      );
      const stale = await gDigest(w, v, ACTION.RECOVER, params);
      await expect(
        v.initiateRecovery(
          addrOf(c2.nominee),
          c2.hash,
          w.verifiers.honest,
          quorumOf(g0, stale.digest),
          stale.nonce,
          FAR_DEADLINE,
          MINED,
        ),
        "the replaced roster cannot propose a fresh recovery",
      ).to.be.revertedWithCustomError(v, "BadRoster");

      // POSITIVE CONTROL: the CURRENT roster proposes the identical request and
      // it is admitted, so the refusal above is about the signer, not the call.
      const fresh = await gDigest(w, v, ACTION.RECOVER, params);
      await (
        await v.initiateRecovery(
          addrOf(c2.nominee),
          c2.hash,
          w.verifiers.honest,
          quorumOf(g1, fresh.digest),
          fresh.nonce,
          FAR_DEADLINE,
        )
      ).wait();
      expect((await requestIdentity(v)).proposedSigner, "the current roster's fresh request stands").to.equal(
        addrOf(c2.nominee),
      );
    });

    it("B1c the old roster cannot bind a migration after rotation — measured with no live request in the way", async function () {
      // `bindMigration` is the other call whose authority gate a live request
      // hides: `if (_recoveryIsLive()) revert NoRecovery()` precedes the quorum
      // check, so with R1 standing an old-roster attempt dies of R1's liveness.
      // This world therefore never proposes one.
      const w = await deployWorld({ label: "sd10-b1c" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const g1 = mkRoster("b1c-new");
      await (await replaceRoster(w, v, g0, g1)).wait();

      const dest = { vault: w.destination, codeHash: ethers.id("sd10-dest"), generation: 2n };
      const bindDigest = async () => {
        const nonce = (await v.nonces(DOMAIN.MIGRATION)) as bigint;
        return {
          nonce,
          d: digestOf({
            chainId: w.chainId,
            vault: w.vaultAddress,
            kernelGeneration: KERNEL_GEN,
            actionType: ACTION.BIND_MIGRATION,
            authorityGeneration: (await v.guardianGeneration()) as bigint,
            params: ethers.keccak256(
              abi.encode(["address", "bytes32", "uint64"], [dest.vault, dest.codeHash, dest.generation]),
            ),
            domain: DOMAIN.MIGRATION,
            nonce,
            deadline: FAR_DEADLINE,
          }),
        };
      };

      const stale = await bindDigest();
      await expect(
        v.bindMigration(dest, quorumOf(g0, stale.d), stale.nonce, FAR_DEADLINE, sign(w.credKey, stale.d), MINED),
        "the replaced roster cannot bind a migration",
      ).to.be.revertedWithCustomError(v, "BadRoster");

      // POSITIVE CONTROL: identical call, current roster, admitted.
      const fresh = await bindDigest();
      await (
        await v.bindMigration(dest, quorumOf(g1, fresh.d), fresh.nonce, FAR_DEADLINE, sign(w.credKey, fresh.d))
      ).wait();
      expect((await v.migration())[0], "the current roster bound the migration").to.equal(dest.vault);
    });

    it("B2 the CURRENT quorum cancels the old-approved R1; the old quorum's fresh cancellation does not", async function () {
      const w = await deployWorld({ label: "sd10-b2" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const g1 = mkRoster("b2-new");
      const c = mkCred("b2");

      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, g1)).wait();

      // The OLD quorum, signing a FRESH cancellation at the current generation:
      // refused. Preservation is not symmetry — it does not hand the outgoing
      // roster a way back in.
      const stale = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
      await expect(
        v.cancelRecoveryByQuorum(quorumOf(g0, stale.digest), stale.nonce, FAR_DEADLINE, MINED),
        "the replaced roster holds no fresh cancellation authority",
      ).to.be.revertedWithCustomError(v, "BadRoster");
      expect((await requestIdentity(v)).active, "R1 still live after the refused stale cancel").to.equal(true);

      // The CURRENT quorum: succeeds. This is I-RECOVERY-TERMINATION's
      // cancellation exit, and it stays available to whoever holds authority NOW.
      const fresh = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
      await (await v.cancelRecoveryByQuorum(quorumOf(g1, fresh.digest), fresh.nonce, FAR_DEADLINE)).wait();
      const after = await requestIdentity(v);
      expect(after.active, "the current quorum terminated R1").to.equal(false);
      expect(after.challengesUsed, "a quorum cancellation refunds no challenge budget").to.equal(
        approved.challengesUsed,
      );
    });
  });

  // =========================================================================
  // C. THE CREDENTIAL'S BOUNDED CHALLENGE, unchanged by rotation. Preservation
  //    must not quietly widen the request's life: the credential's counted veto
  //    is one of I-RECOVERY-TERMINATION's exits and it still reaches R1.
  // =========================================================================
  describe("C. the credential challenge still terminates a preserved request, and stays bounded", () => {
    it("C1 after rotation the credential challenges R1: the count increments, authority clears, and no clock or budget is refunded", async function () {
      const w = await deployWorld({ label: "sd10-c1" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      await (await propose(w, v, g0, mkCred("c1"))).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, mkRoster("c1-new"))).wait();

      await (await challenge(w, v, w.credKey)).wait();

      const after = await requestIdentity(v);
      expect(after.challengesUsed, "the challenge is COUNTED").to.equal(approved.challengesUsed + 1n);
      expect(after.active, "request authority is cleared").to.equal(false);
      expect(after.executableAt, "no clock moved").to.equal(approved.executableAt);
      expect(after.expiresAt, "no clock moved").to.equal(approved.expiresAt);
      expect(after.boundGuardianGeneration, "approval provenance is untouched").to.equal(
        approved.boundGuardianGeneration,
      );
    });

    it("C2 the challenge budget is still bounded across rotations: the third challenge is refused", async function () {
      const w = await deployWorld({ label: "sd10-c2" });
      const v = w.vault;
      let roster = genesisRoster(w);

      // Spend the whole budget, rotating the roster between each episode so the
      // counter is measured across constituency changes rather than within one.
      for (let i = 0; i < 2; i++) {
        await (await propose(w, v, roster, mkCred(`c2-x${i}`))).wait();
        const next = mkRoster(`c2-r${i}`);
        await (await replaceRoster(w, v, roster, next)).wait();
        roster = next;
        await (await challenge(w, v, w.credKey)).wait();
      }
      expect((await requestIdentity(v)).challengesUsed, "budget exhausted").to.equal(2n);

      const finalCred = mkCred("c2-x2");
      await (await propose(w, v, roster, finalCred)).wait();
      const live = await requestIdentity(v);
      await (await replaceRoster(w, v, roster, mkRoster("c2-r2"))).wait();
      await expect(
        challenge(w, v, w.credKey, MINED),
        "I-VETO-BOUND still holds after rotation",
      ).to.be.revertedWithCustomError(v, "ChallengeExhausted");

      // POSITIVE CONTROL: the request the exhausted credential cannot challenge
      // is genuinely still there and still executable — the refusal above is the
      // budget, not a dead request.
      await at(live.executableAt);
      await (await execute(v, finalCred)).wait();
      expect(await v.ecdsaSigner(), "the preserved request executed").to.equal(addrOf(finalCred.nominee));
    });

    it("C3 a challenge is refused once R1 has expired, rotation or not: only an effectively-live request is a target", async function () {
      const w = await deployWorld({ label: "sd10-c3" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      await (await propose(w, v, g0, mkCred("c3"))).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, mkRoster("c3-new"))).wait();

      await at(approved.expiresAt);
      await expect(
        challenge(w, v, w.credKey, MINED),
        "an expired request is no challenge target",
      ).to.be.revertedWithCustomError(v, "NoRecovery");
      expect((await requestIdentity(v)).challengesUsed, "a refused challenge spends nothing").to.equal(
        approved.challengesUsed,
      );
    });
  });

  // =========================================================================
  // D. THE CLOCKS. The architecture's CLOCK RULE — no state transition may
  //    reset, extend, or suspend a clock — applies to `setGuardians` too. The
  //    half-open window [executableAt, expiresAt) is measured across a rotation
  //    at all three instants, each in its OWN world at a MINED timestamp.
  // =========================================================================
  describe("D. rotation moves no recovery clock, and the half-open window is unchanged", () => {
    const CASES = [
      { name: "expiresAt-1 — the last live instant: execution succeeds", delta: -1n, ok: true },
      { name: "expiresAt — already expired", delta: 0n, ok: false },
      { name: "expiresAt+1 — expired", delta: 1n, ok: false },
    ];

    for (const [i, k] of CASES.entries()) {
      it(`D${i + 1} after rotation, ${k.name}`, async function () {
        const w = await deployWorld({ label: `sd10-d${i}` });
        const v = w.vault;
        const g0 = genesisRoster(w);
        const c = mkCred(`d${i}`);
        await (await propose(w, v, g0, c)).wait();
        const approved = await requestIdentity(v);
        await (await replaceRoster(w, v, g0, mkRoster(`d${i}-new`))).wait();

        // The clocks the ROTATION left behind are the clocks the request was
        // born with. Asserted before the probe, so a probe that lands where it
        // should cannot be explained away by a moved window.
        const afterRotation = await requestIdentity(v);
        expect(afterRotation.executableAt, "executableAt untouched by rotation").to.equal(approved.executableAt);
        expect(afterRotation.expiresAt, "expiresAt untouched by rotation").to.equal(approved.expiresAt);

        // The preceding block sits strictly below the target, so the probe lands
        // ON it. Sent with an explicit gas limit so a REFUSED probe is still
        // MINED at the pinned instant and can prove where it executed — a probe
        // rejected at gas estimation never executes anywhere (Lane W1).
        const target = approved.expiresAt + k.delta;
        await networkHelpers.time.increaseTo(Number(target - 1n));
        await at(target);

        let error: string | null = null;
        try {
          await (await execute(v, c, MINED)).wait();
        } catch (e) {
          error = e instanceof Error ? e.message : String(e);
        }
        const landed = BigInt((await ethers.provider.getBlock("latest"))!.timestamp);
        expect(landed, "the probe was mined at the pinned instant").to.equal(target);

        if (k.ok) {
          expect(error, "execution succeeded at the last live instant").to.equal(null);
          expect(await v.ecdsaSigner(), "R1 installed").to.equal(addrOf(c.nominee));
        } else {
          expect(error ?? "", "execution refused as Expired — NOT as BadRoster").to.include("Expired");
          expect((await requestIdentity(v)).active, "the request is left standing, not consumed").to.equal(true);
        }
      });
    }
  });

  // =========================================================================
  // E. REPEATED ROTATIONS. Preservation is not a one-rotation grace period.
  // =========================================================================
  describe("E. R1 survives an arbitrary run of replacements", () => {
    it("E1 approve under G, rotate to G+1, G+2, G+3, then execute the SAME R1", async function () {
      const w = await deployWorld({ label: "sd10-e1" });
      const v = w.vault;
      let roster = genesisRoster(w);
      const c = mkCred("e1");

      await (await propose(w, v, roster, c)).wait();
      const approved = await requestIdentity(v);
      const g = approved.boundGuardianGeneration;

      for (let i = 1; i <= 3; i++) {
        const next = mkRoster(`e1-r${i}`);
        await (await replaceRoster(w, v, roster, next)).wait();
        roster = next;
        expect((await v.guardianGeneration()) as bigint, `generation is G+${i}`).to.equal(g + BigInt(i));
        expect(await requestIdentity(v), `R1 intact after rotation ${i}`).to.deep.equal(approved);
      }

      await at(approved.executableAt);
      await (await execute(v, c)).wait();
      expect(await v.ecdsaSigner(), "the same R1 executed three rosters later").to.equal(addrOf(c.nominee));
    });
  });

  // =========================================================================
  // F. PRESERVED_APPROVAL != UNCONDITIONAL_EXECUTION.
  //    `_requireIncomingPossession` is UNCHANGED by this lane and is still the
  //    thing standing between a preserved request and an installed credential.
  //    Every probe below runs AFTER a rotation — the state in which the removed
  //    check used to refuse everything indiscriminately, and so the state in
  //    which its removal could most easily have taken a real gate with it.
  // =========================================================================
  describe("F. incoming possession is still required after rotation", () => {
    it("F1 an unheld signer, a wrong PQ preimage, a wrong verifier proof and uncommitted material are each refused", async function () {
      const w = await deployWorld({ label: "sd10-f1" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const c = mkCred("f1");
      const impostor = mkCred("f1-impostor");

      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, mkRoster("f1-new"))).wait();
      await at(approved.executableAt);
      const pop = (await v.recoveryPossessionDigest()) as string;

      const honest = {
        newSigner: addrOf(c.nominee),
        newPqKeyHash: c.hash,
        newPqKey: c.key32,
        newEcdsaPop: sign(c.nominee, pop),
        newPqPop: sign(c.pqNominee, pop),
      };

      const probes: { name: string; change: Record<string, unknown> }[] = [
        {
          name: "the incoming ECDSA signer is not held (PoP signed by someone else)",
          change: { newEcdsaPop: sign(impostor.nominee, pop) },
        },
        { name: "the PQ preimage does not open R1's commitment", change: { newPqKey: impostor.key32 } },
        {
          name: "the incoming verifier's proof is not held (PQ PoP signed by someone else)",
          change: { newPqPop: sign(impostor.pqNominee, pop) },
        },
        {
          name: "the credential material was never committed by R1",
          change: { newSigner: addrOf(impostor.nominee), newPqKeyHash: impostor.hash },
        },
      ];

      for (const p of probes) {
        await expect(
          v.executeRecovery({ ...honest, ...p.change }, MINED),
          `preserved approval does not excuse possession: ${p.name}`,
        ).to.be.revertedWithCustomError(v, "BadSignature");
        expect((await requestIdentity(v)).active, "a refused execution consumes nothing").to.equal(true);
      }

      // POSITIVE CONTROL: the genuine holder, same state, same request.
      await (await v.executeRecovery(honest)).wait();
      expect(await v.ecdsaSigner(), "genuine possession still executes").to.equal(addrOf(c.nominee));
    });

    it("F2 a possession proof signed BEFORE the rotation is still the right proof after it", async function () {
      // `recoveryPossessionDigest()` binds `r.boundGuardianGeneration`, which
      // this lane deliberately leaves pinned at G. Had the correction re-bound
      // the request to the new generation instead — the family SD-10's own fix
      // sketch considered — this pre-signed proof would be refused. That is the
      // concrete reason the field is RETAINED, beyond observability.
      const w = await deployWorld({ label: "sd10-f2" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const c = mkCred("f2");

      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      const popBefore = (await v.recoveryPossessionDigest()) as string;
      const presigned = {
        newSigner: addrOf(c.nominee),
        newPqKeyHash: c.hash,
        newPqKey: c.key32,
        newEcdsaPop: sign(c.nominee, popBefore),
        newPqPop: sign(c.pqNominee, popBefore),
      };

      await (await replaceRoster(w, v, g0, mkRoster("f2-new"))).wait();
      expect((await v.recoveryPossessionDigest()) as string, "the possession digest did not move").to.equal(popBefore);

      await at(approved.executableAt);
      await (await v.executeRecovery(presigned)).wait();
      expect(await v.ecdsaSigner(), "the pre-signed proof executed after rotation").to.equal(addrOf(c.nominee));
    });
  });

  // =========================================================================
  // G. SAME-BLOCK ORDERING. On the base kernel the fate of an approved request
  //    depends on the ORDER two transactions happen to land in — a choice held
  //    by whoever builds the block, not by any principal the architecture
  //    names. Order-independence is the property that removes it.
  // =========================================================================
  describe("G. rotation raced against execution and against cancellation, in one block", () => {
    it("G1 setGuardians and executeRecovery in the same block: both succeed, in either order", async function () {
      this.timeout(600_000);
      for (const order of ["rotate-first", "execute-first"]) {
        const w = await deployWorld({ label: `sd10-g1-${order}` });
        const v = w.vault;
        const g0 = genesisRoster(w);
        const g1 = mkRoster(`g1-${order}`);
        const c = mkCred(`g1-${order}`);

        await (await propose(w, v, g0, c)).wait();
        const approved = await requestIdentity(v);
        await at(approved.executableAt);

        // Both payloads are built BEFORE either lands, so neither depends on the
        // other's effect — which is what makes this a genuine race rather than a
        // sequence.
        const commitment = (await v.rosterCommitment(w.threshold, g1.members, g1.isContract)) as string;
        const rot = await gDigest(w, v, ACTION.SET_GUARDIANS, commitment);
        const pop = (await v.recoveryPossessionDigest()) as string;
        const change = {
          newSigner: addrOf(c.nominee),
          newPqKeyHash: c.hash,
          newPqKey: c.key32,
          newEcdsaPop: sign(c.nominee, pop),
          newPqPop: sign(c.pqNominee, pop),
        };

        await ethers.provider.send("evm_setAutomine", [false]);
        const sendRotate = () =>
          v.setGuardians(w.threshold, g1.members, g1.isContract, quorumOf(g0, rot.digest), rot.nonce, FAR_DEADLINE, {
            gasLimit: 800_000,
          });
        const sendExec = () => v.executeRecovery(change, { gasLimit: 900_000 });
        const sent = await Promise.all(
          order === "rotate-first" ? [sendRotate(), sendExec()] : [sendExec(), sendRotate()],
        );
        await networkHelpers.mine();
        await ethers.provider.send("evm_setAutomine", [true]);

        const receipts = await Promise.all(sent.map((t) => ethers.provider.getTransactionReceipt(t.hash)));
        // The two acts touch different authority: rotation consumes a GUARDIAN
        // nonce, execution consumes none. Neither excludes the other, so the
        // block-builder's ordering choice decides nothing.
        expect(
          receipts.map((r) => r?.status),
          `${order}: both transactions succeed`,
        ).to.deep.equal([1, 1]);
        expect(await v.ecdsaSigner(), `${order}: R1 executed`).to.equal(addrOf(c.nominee));
        expect((await v.guardianGeneration()) as bigint, `${order}: the roster also rotated`).to.equal(
          approved.boundGuardianGeneration + 1n,
        );
      }
    });

    it("G2 setGuardians and the current quorum's cancellation in the same block: exactly one lands, never both", async function () {
      this.timeout(600_000);
      for (const order of ["rotate-first", "cancel-first"]) {
        const w = await deployWorld({ label: `sd10-g2-${order}` });
        const v = w.vault;
        const g0 = genesisRoster(w);
        const g1 = mkRoster(`g2-${order}`);

        await (await propose(w, v, g0, mkCred(`g2-${order}`))).wait();
        const commitment = (await v.rosterCommitment(w.threshold, g1.members, g1.isContract)) as string;
        const rot = await gDigest(w, v, ACTION.SET_GUARDIANS, commitment);
        const can = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));

        await ethers.provider.send("evm_setAutomine", [false]);
        const sendRotate = () =>
          v.setGuardians(w.threshold, g1.members, g1.isContract, quorumOf(g0, rot.digest), rot.nonce, FAR_DEADLINE, {
            gasLimit: 800_000,
          });
        const sendCancel = () =>
          v.cancelRecoveryByQuorum(quorumOf(g0, can.digest), can.nonce, FAR_DEADLINE, { gasLimit: 600_000 });
        const sent = await Promise.all(
          order === "rotate-first" ? [sendRotate(), sendCancel()] : [sendCancel(), sendRotate()],
        );
        await networkHelpers.mine();
        await ethers.provider.send("evm_setAutomine", [true]);

        const receipts = await Promise.all(sent.map((t) => ethers.provider.getTransactionReceipt(t.hash)));
        // Both are FRESH guardian acts, so both draw the same DOMAIN_GUARDIAN
        // nonce and the nonce serialises them. There is no reachable state in
        // which the roster both rotated and cancelled on one nonce.
        expect(
          receipts.filter((r) => r?.status === 1).length,
          `${order}: exactly one fresh guardian act lands`,
        ).to.equal(1);
        const rotated = ((await v.guardianGeneration()) as bigint) === 2n;
        const cancelled = !(await requestIdentity(v)).active;
        expect(rotated !== cancelled, `${order}: no contradictory authority state`).to.equal(true);
      }
    });
  });

  // =========================================================================
  // H. THE CHALLENGE EPOCH. `I-RECOVERY-CHALLENGE-EPOCH` says `challengesUsed`
  //    resets in exactly ONE place — the whole-struct delete in
  //    `executeRecovery`. A rotation is not that place, and preservation must
  //    not have quietly made it one.
  // =========================================================================
  describe("H. rotation neither resets, refunds, nor re-epochs the challenge budget", () => {
    it("H1 a partially consumed budget survives rotation; the preserved request still executes; only that execution resets it", async function () {
      const w = await deployWorld({ label: "sd10-h1" });
      const v = w.vault;
      const g0 = genesisRoster(w);

      // Spend ONE of two, then rotate.
      await (await propose(w, v, g0, mkCred("h1-a"))).wait();
      await (await challenge(w, v, w.credKey)).wait();
      expect((await requestIdentity(v)).challengesUsed, "one spent").to.equal(1n);

      const g1 = mkRoster("h1-new");
      await (await replaceRoster(w, v, g0, g1)).wait();
      expect((await requestIdentity(v)).challengesUsed, "rotation refunds nothing").to.equal(1n);

      // A fresh request under the NEW roster carries the spent budget forward.
      const c = mkCred("h1-b");
      await (await propose(w, v, g1, c)).wait();
      const approved = await requestIdentity(v);
      expect(approved.challengesUsed, "the new episode inherits the spent budget").to.equal(1n);

      await (await replaceRoster(w, v, g1, mkRoster("h1-newer"))).wait();
      expect((await requestIdentity(v)).challengesUsed, "a second rotation still refunds nothing").to.equal(1n);

      await at(approved.executableAt);
      await (await execute(v, c)).wait();
      expect((await requestIdentity(v)).challengesUsed, "the ONE reset boundary is a successful recovery").to.equal(0n);
    });

    it("H2 a budget EXHAUSTED before rotation stays exhausted after it, and the preserved request still executes", async function () {
      const w = await deployWorld({ label: "sd10-h2" });
      const v = w.vault;
      const g0 = genesisRoster(w);

      for (let i = 0; i < 2; i++) {
        await (await propose(w, v, g0, mkCred(`h2-x${i}`))).wait();
        await (await challenge(w, v, w.credKey)).wait();
      }
      expect((await requestIdentity(v)).challengesUsed, "exhausted").to.equal(2n);

      const c = mkCred("h2-final");
      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, mkRoster("h2-new"))).wait();

      expect((await requestIdentity(v)).challengesUsed, "rotation is not a new epoch").to.equal(2n);
      await expect(
        challenge(w, v, w.credKey, MINED),
        "rotation grants the credential no fresh challenge",
      ).to.be.revertedWithCustomError(v, "ChallengeExhausted");

      await at(approved.executableAt);
      await (await execute(v, c)).wait();
      expect(await v.ecdsaSigner(), "the preserved request executed").to.equal(addrOf(c.nominee));
      expect((await requestIdentity(v)).challengesUsed, "and THAT is the reset").to.equal(0n);
    });
  });

  // =========================================================================
  // I. THE ADVERSARIAL CASES THE DECISION HAS TO SURVIVE.
  //    Preservation gives an OUTGOING quorum's decision a life beyond its
  //    tenure, so the honest question is: what can a MALICIOUS outgoing quorum
  //    do with that, and what recourse does the incoming one have?
  // =========================================================================
  describe("I. hand-over, containment and the verifier escape", () => {
    it("I1 a MALICIOUS quorum approves R1 and rotates to an honest roster: the honest roster's recourse is cancellation, available across the whole live window", async function () {
      // The scenario preservation is most often challenged on. It is bounded by
      // the architecture's own accepted condition: guardian-majority compromise
      // is unrecoverable (§2.2), and the cut is k either way — the SAME quorum
      // could have executed R1 without rotating at all. What preservation must
      // NOT do is leave the incoming honest roster with no move.
      const w = await deployWorld({ label: "sd10-i1" });
      const v = w.vault;
      const malicious = genesisRoster(w);
      const honest = mkRoster("i1-honest");
      const evil = mkCred("i1-evil");

      await (await propose(w, v, malicious, evil)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, malicious, honest)).wait();

      // The honest roster inherits a live request it did not approve. Its
      // recourse is K-9 mechanism B under the CURRENT generation, and it is
      // available at the LAST live instant before maturity, not merely early.
      await networkHelpers.time.increaseTo(Number(approved.executableAt - 2n));
      await at(approved.executableAt - 1n);
      const { digest, nonce } = await gDigest(w, v, ACTION.RECOVER, ethers.id("QUORUM_CANCEL_RECOVERY"));
      await (await v.cancelRecoveryByQuorum(quorumOf(honest, digest), nonce, FAR_DEADLINE)).wait();

      expect((await requestIdentity(v)).active, "the honest roster terminated the inherited request").to.equal(false);
      expect(await v.ecdsaSigner(), "the malicious nominee was never installed").to.not.equal(addrOf(evil.nominee));

      // And the terminated request stays terminated: execution afterwards finds
      // no live request at all.
      await at(approved.executableAt);
      await expect(execute(v, evil, MINED), "nothing left to execute").to.be.revertedWithCustomError(v, "NoRecovery");
    });

    it("I2 containment does not veto a preserved request: I-RECOVERY-NONVETO holds across rotation", async function () {
      // `_requireRecoveryOpen` refuses only MIGRATION_ONLY and RETIRED, so a
      // CONTAINED vault still executes recovery. If preservation had quietly
      // made recovery contingent on the safe state, this is where it would show.
      const w = await deployWorld({ label: "sd10-i2" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const g1 = mkRoster("i2-new");
      const c = mkCred("i2");

      await (await propose(w, v, g0, c)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, g1)).wait();

      // CONTAINMENT_MAX is 3 days and RECOVERY_DELAY is 7, so containment
      // entered at t0 would have SELF-EXPIRED long before maturity and this test
      // would prove nothing. Enter it one day out, so the vault is still
      // EFFECTIVELY contained at the instant recovery executes.
      await networkHelpers.time.increaseTo(Number(approved.executableAt - 86_400n));
      const cont = await gDigest(w, v, ACTION.RECOVER, ethers.id("CONTAIN"));
      await (await v.enterContainment(quorumOf(g1, cont.digest), cont.nonce, FAR_DEADLINE)).wait();

      await at(approved.executableAt);
      await (await execute(v, c)).wait();
      // Read the DERIVED state, not the stored byte: containment self-expires on
      // wall clock, so the stored enum can claim CONTAINED when the kernel is
      // already treating the vault as NORMAL.
      expect(await v.effectiveSafeState(), "the vault was genuinely contained when recovery executed").to.equal(1n);
      expect(await v.ecdsaSigner(), "recovery completed while contained, after a rotation").to.equal(
        addrOf(c.nominee),
      );
    });

    it("I3 the verifier escape survives rotation: R1's REPLACEMENT verifier is what possession is proven against, not the vault's dead live one", async function () {
      // THE CASE THAT MATTERS MOST FOR LIVENESS. A vault whose installed
      // verifier is dead escapes through a recovery that carries a replacement.
      // On the base kernel, a rotation during that escape destroyed it and the
      // quorum had to start over; the escape and the rotation are exactly the
      // two things an operator is likely to be doing at the same time.
      // The vault's INSTALLED verifier reverts on every call — the condition the
      // verifier escape exists for. A world deployed this way is what the
      // `byzantine-verifier` campaign profile already uses.
      const w = await deployWorld({ label: "sd10-i3", verifier: "reverting" });
      const v = w.vault;
      const g0 = genesisRoster(w);
      const c = mkCred("i3");
      expect(await v.pqVerifier(), "the live verifier is the dead one").to.equal(w.verifiers.reverting);

      // R1 proposes the HONEST verifier as the replacement.
      await (await propose(w, v, g0, c, w.verifiers.honest)).wait();
      const approved = await requestIdentity(v);
      expect(approved.proposedVerifier, "R1 carries a replacement verifier").to.equal(w.verifiers.honest);

      await (await replaceRoster(w, v, g0, mkRoster("i3-new"))).wait();
      expect((await requestIdentity(v)).proposedVerifier, "the replacement verifier survived the rotation").to.equal(
        approved.proposedVerifier,
      );

      await at(approved.executableAt);
      await (await execute(v, c)).wait();
      expect(await v.pqVerifier(), "the escape completed: the replacement verifier is installed").to.equal(
        w.verifiers.honest,
      );
      expect(await v.ecdsaSigner()).to.equal(addrOf(c.nominee));
    });

    it("I4 a recovery proposing the CURRENTLY INSTALLED material still behaves like any other request across a rotation", async function () {
      // A same-material recovery is a legitimate no-op-shaped request (it is how
      // a quorum re-affirms a credential), and it is the case where a lazy
      // implementation might short-circuit. It gets no special treatment here.
      const w = await deployWorld({ label: "sd10-i4" });
      const v = w.vault;
      const g0 = genesisRoster(w);

      const installedSigner = (await v.ecdsaSigner()) as string;
      const installedHash = (await v.pqPublicKeyHash()) as string;
      const same: Cred = {
        nominee: w.credKey,
        pqNominee: w.pqKey,
        key32: abi.encode(["address"], [addrOf(w.pqKey)]),
        hash: installedHash,
      };
      expect(addrOf(same.nominee), "the world's credential is the installed one").to.equal(installedSigner);

      await (await propose(w, v, g0, same)).wait();
      const approved = await requestIdentity(v);
      await (await replaceRoster(w, v, g0, mkRoster("i4-new"))).wait();
      expect(await requestIdentity(v), "a same-material request is preserved like any other").to.deep.equal(approved);

      const genBefore = (await v.credentialGeneration()) as bigint;
      await at(approved.executableAt);
      await (await execute(v, same)).wait();
      expect(await v.ecdsaSigner(), "the same signer is re-installed").to.equal(installedSigner);
      expect(
        (await v.credentialGeneration()) as bigint,
        "and it is a REAL install: the credential generation advances",
      ).to.equal(genBefore + 1n);
    });
  });
});
