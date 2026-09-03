/**
 * EXPERIMENTAL PROTOTYPE — THE `requirePq` false -> true EDGE, BEFORE AND AFTER.
 *
 * SD-3 and SD-4 were recorded separately, but they are ONE TRANSITION: the
 * single moment in a vault's life at which the PQ authentication shape is
 * declared. They differ only in which committed authentication commitment the
 * declaration breaks:
 *
 *   SD-3  breaks `pqPublicKeyHash`            — the SPENDING commitment
 *   SD-4  breaks `recovery.proposedPqKeyHash` — an APPROVED RECOVERY's commitment
 *
 * They are nonetheless INDEPENDENT. The two commitments are different variables
 * chosen by different principals, and only the first is exhibitable by the
 * principal making the transition — which is why the prior lane's hypothesis
 * that closing SD-4 "necessarily intersects" SD-3 is REFUTED below rather than
 * inherited. Two clauses were needed, and each is discriminated by its own tests
 * in `Sd34DeclarationInvariants.test.ts`.
 *
 * WHY THE EDGE IS THE ONLY MOMENT. `securityFloor` has exactly two writers,
 * `initialize` and `setVerifier`; `initialize` validates satisfiability at
 * genesis; `requirePq` is monotone; and since `I-FLOOR-SHAPE-IMMUTABLE` the two
 * structural length fields freeze the instant `requirePq` holds. So the shape
 * moves at most once, here, and never again.
 *
 * THIS FILE IS THE EVIDENCE LEDGER FOR THAT EDGE. The sequences below are the
 * ones that SUSTAINED SD-3 and SD-4 at `ec5adce9`, kept verbatim with their
 * verdicts moved — deleting them would erase the proof that the interlock in
 * `stateful/defects.ts` worked. Alongside them are the facts about the edge that
 * NO ledger entry recorded and that remain true after the fix; those are now
 * SD-5 and SD-6, and they are declared rather than absorbed.
 *
 * TWO LEDGER CLAIMS WERE TESTED AND BOTH WERE WRONG:
 *   1. SD-3's title said "PERMANENTLY bricking spending at cut 1". Its own
 *      `notAnEscalationBecause` said "escapable at k", and that field was right.
 *   2. SD-3's `minimalFixSketch` proposed a ZERO-HASH check only. A NON-ZERO
 *      commitment reaches the identical dead state by declaring a shape no
 *      preimage of it has, so the recorded sketch would have shipped a fix that
 *      left the defect open.
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
  pqHash,
  pqKeyBytes,
  recoverParams,
  setVerifierParams,
  sign,
  spendParams,
  type Floor,
  type World,
} from "../stateful/world.js";

const KERNEL_GEN = 1n;

async function liveFloor(w: World): Promise<Floor> {
  const f = await w.vault.securityFloor();
  return {
    requirePq: f[0] as boolean,
    pqParamLevel: Number(f[1]),
    pqPublicKeyLength: Number(f[2]),
    pqSignatureLength: Number(f[3]),
  };
}

/**
 * `setVerifier` as the credential principal.
 *
 * On a vault whose CURRENT floor has `requirePq == false`, `_authorise` returns
 * before the PQ leg, so this is a ONE-ROOT call: no PQ signature is supplied and
 * none is consulted. The `pqKey` argument is nonetheless meaningful there — it
 * is `I-DECLARATION-EXHIBITED`'s satisfiability witness, a PUBLIC value that
 * grants authority to nobody — and it defaults to the vault's committed key so
 * the honest path is the default and every attack has to opt out explicitly.
 */
async function setVerifierTx(
  w: World,
  verifier: string,
  floor: Floor,
  opts: { cred?: ethers.SigningKey; pqSig?: string; pqKey?: string } = {},
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
    params: setVerifierParams(verifier, floor),
    domain: DOMAIN.CREDENTIAL,
    nonce,
    deadline: FAR_DEADLINE,
  });
  return w.vault.setVerifier(
    verifier,
    floorTuple(floor),
    nonce,
    FAR_DEADLINE,
    sign(cred, d),
    opts.pqSig ?? (current.requirePq ? sign(w.pqKey, d) : "0x"),
    opts.pqKey ?? pqKeyBytes(w.pqKey),
  );
}

async function initiate(w: World, i: number, verifier: string, pqKeyHash: string): Promise<ethers.SigningKey> {
  const cred = w.spareCred[i]!;
  const gGen = (await w.vault.guardianGeneration()) as bigint;
  const nonce = (await w.vault.nonces(DOMAIN.GUARDIAN)) as bigint;
  const d = digestOf({
    chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
    actionType: ACTION.RECOVER, authorityGeneration: gGen,
    params: recoverParams(addrOf(cred), pqKeyHash, verifier),
    domain: DOMAIN.GUARDIAN, nonce, deadline: FAR_DEADLINE,
  });
  await (
    await w.vault.initiateRecovery(addrOf(cred), pqKeyHash, verifier, {
      members: w.guardians, isContract: w.guardianIsContract,
      attestingIndices: [0, 1], attestations: [sign(w.gKeys[0]!, d), sign(w.gKeys[1]!, d)],
    }, nonce, FAR_DEADLINE)
  ).wait();
  return cred;
}

const keyOfLength = (n: number, fill: number): string => ethers.hexlify(new Uint8Array(n).fill(fill));
const RECOVERY = { CHALLENGES: 6, ACTIVE: 7 } as const;

describe("vNext kernel — the requirePq false -> true edge (SD-3 remediated; SD-4 / SD-5 / SD-6 / SD-7 sustained)", function () {
  this.timeout(600_000);

  // =====================================================================
  // SD-3 — REMEDIATED
  // =====================================================================
  describe("SD-3 — REMEDIATED: a declaration must be satisfiable by the committed material", function () {
    it("SD-3 FORM 1 — the sustained sequence, verdict moved: arming against a ZERO commitment is now REFUSED", async function () {
      const w = await deployWorld({ label: "sd3-cut", verifier: "honest", ecdsaOnlyFloor: true });
      expect(await w.vault.pqPublicKeyHash(), "born with no PQ commitment").to.equal(ethers.ZeroHash);
      expect((await liveFloor(w)).requirePq).to.equal(false);

      // At ec5adce9 this call SUCCEEDED at one root, and every credential action
      // was dead afterwards because `keccak256(pqKey) == 0` has no preimage.
      await expect(
        setVerifierTx(
          w, w.verifiers.honest,
          { requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 },
        ),
        "REMEDIATED: nothing hashes to the zero commitment, so the declaration cannot be witnessed",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq, "the floor never moved").to.equal(false);
    });

    it("SD-3 FORM 1' — the state is now UNREACHABLE, which is what makes the old escape moot", async function () {
      // The recorded severity dispute is settled by construction rather than by
      // argument: the ledger title said "permanently bricking" and its own
      // `notAnEscalationBecause` said "escapable at k". The field was right —
      // and the state it described can no longer be entered at all.
      const w = await deployWorld({ label: "sd3-sev", verifier: "honest", ecdsaOnlyFloor: true });
      for (const shape of [32, 1, 65_535]) {
        await expect(
          setVerifierTx(w, w.verifiers.honest, {
            requirePq: true, pqParamLevel: 1, pqPublicKeyLength: shape, pqSignatureLength: 65,
          }),
          "no declared shape can be witnessed against a zero commitment",
        ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      }
      expect(await w.vault.pqPublicKeyHash()).to.equal(ethers.ZeroHash);
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });

    it("SD-3 FORM 2 — the form the ledger's OWN fix sketch would have missed is refused too", async function () {
      // `minimalFixSketch` proposed `if (floor.requirePq && pqPublicKeyHash == 0)
      // revert`, which closes the zero case only. The harm was never "the hash is
      // zero" — it was "the declared requirements are unsatisfiable by the
      // committed material", which a NON-ZERO commitment reaches just as well.
      const w = await deployWorld({
        label: "sd3-gen", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      expect(await w.vault.pqPublicKeyHash(), "a perfectly good NON-ZERO commitment").to.not.equal(ethers.ZeroHash);
      await expect(
        setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 33, pqSignatureLength: 65,
        }, { pqKey: keyOfLength(33, 1) }),
        "REMEDIATED: a 33-byte witness does not hash to a 32-byte key's commitment",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");
      expect((await liveFloor(w)).requirePq).to.equal(false);
    });
  });

  // =====================================================================
  // SD-4 — REMEDIATED
  // =====================================================================
  describe("SD-4 — SUSTAINED: the declaration still front-runs an approved remedy", function () {
    it("SD-4 — the sustained sequence, verdict moved: the declaration is REFUSED and the recovery then executes", async function () {
      const w = await deployWorld({
        label: "sd4-cut", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // An honest k = 2 quorum approves a recovery to a 48-byte PQ key. Nothing
      // about the proposal is malformed; the quorum picks hash and verifier.
      const proposedKey = keyOfLength(48, 0xab);
      const proposedHash = ethers.keccak256(proposedKey);
      const newCred = await initiate(w, 0, w.verifiers.alwaysTrue, proposedHash);
      expect((await w.vault.recovery())[RECOVERY.ACTIVE]).to.equal(true);
      // SUSTAINED: one root declares a 32-byte shape — satisfiable for the
      // vault's OWN committed key, so `I-DECLARATION-EXHIBITED` is satisfied on
      // BOTH conjuncts — and fatal for the quorum's 48-byte proposal.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq, "SUSTAINED: the declaration succeeded").to.equal(true);

      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await expect(
        w.vault.executeRecovery({
          newSigner: addrOf(newCred), newPqKeyHash: proposedHash, newPqKey: proposedKey,
          newEcdsaPop: sign(newCred, pop), newPqPop: keyOfLength(65, 1),
        }),
        "SUSTAINED (SD-4): the approved recovery is unexecutable",
      ).to.be.revertedWithCustomError(w.vault, "BadSignature");

      // THE POINT: the destruction is UNACCOUNTED. `challengesUsed` — the only
      // mechanism AUTHORITY.md cites for bounding a credential-held veto — never
      // engages, and the request is left stranded ACTIVE.
      const rec = await w.vault.recovery();
      expect(rec[RECOVERY.ACTIVE], "the request is still active and still dead").to.equal(true);
      expect(Number(rec[RECOVERY.CHALLENGES]), "SUSTAINED: challengesUsed is STILL 0").to.equal(0);
    });

    it("SD-4 — the EXHIBIT provably cannot close this, which is why it is still open", async function () {
      // The prior lane hypothesised that exhibiting the committed key closes SD-4.
      // It does not, and this is the proof: the declared key length MATCHES the
      // incumbent exactly, so BOTH exhibit conjuncts pass and the declaration
      // still succeeds — while the quorum's 48-byte proposal dies. SD-3 concerns
      // `pqPublicKeyHash`; SD-4 concerns `recovery.proposedPqKeyHash`. Different
      // variables, chosen by different principals.
      const w = await deployWorld({
        label: "sd4-indep", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await initiate(w, 0, w.verifiers.alwaysTrue, ethers.keccak256(keyOfLength(48, 0xcd)));
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq, "the witness is valid, so the declaration proceeds").to.equal(true);
    });
  });

  // =====================================================================
  // SD-5 / SD-6 — SUSTAINED, and reproduced here rather than argued
  // =====================================================================
  describe("SD-5 — SUSTAINED: the declaration is one-shot and IRREVERSIBLE", function () {
    it("a vacuous shape, once declared, can never be changed by any principal — a quorum included", async function () {
      const w = await deployWorld({
        label: "sd5-perm", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // `_requireSaneFloor` bounds only 0 and MAX_PQ_LENGTH, and any pqParamLevel
      // INCREASE is admitted, so maximal advertised strength on a one-byte factor
      // is a legal declaration. The exhibit constrains the KEY length to the
      // committed key's, so the attacker uses the honest 32-byte shape here and
      // takes its vacuity in `pqSignatureLength`, which no commitment binds.
      await (
        await setVerifierTx(w, w.verifiers.alwaysTrue, {
          requirePq: true, pqParamLevel: 65535, pqPublicKeyLength: 32, pqSignatureLength: 1,
        })
      ).wait();
      const f = await liveFloor(w);
      expect(f.pqParamLevel, "advertises maximal strength...").to.equal(65535);
      expect(f.pqSignatureLength, "...backed by a one-byte signature").to.equal(1);

      // A guardian quorum recovers the vault completely — and inherits the shape.
      const newPq = w.sparePq[0]!;
      const newCred = await initiate(w, 0, w.verifiers.alwaysTrue, pqHash(newPq));
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await (
        await w.vault.executeRecovery({
          newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey: pqKeyBytes(newPq),
          newEcdsaPop: sign(newCred, pop), newPqPop: keyOfLength(1, 0x02),
        })
      ).wait();
      expect(await w.vault.ecdsaSigner(), "the quorum owns the vault now").to.equal(addrOf(newCred));
      expect((await liveFloor(w)).pqSignatureLength, "and the shape survived the remedy").to.equal(1);

      // The RECOVERED credential — full authority, installed by k guardians —
      // still cannot restore a real signature shape.
      const cur = await liveFloor(w);
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const target = { ...cur, pqSignatureLength: 65 };
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SET_VERIFIER, authorityGeneration: gen,
        params: setVerifierParams(w.verifiers.honest, target),
        domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
      });
      await expect(
        w.vault.setVerifier(
          w.verifiers.honest, floorTuple(target), nonce, FAR_DEADLINE,
          sign(newCred, d), keyOfLength(1, 0x03), pqKeyBytes(newPq),
        ),
        "SUSTAINED (SD-5): the shape is permanent, against every principal at every cut",
      ).to.be.revertedWithCustomError(w.vault, "Downgrade");
    });

    it("the cut on an ECDSA-only vault is ONE, which AUTHORITY.md's asset-control row does not caveat", async function () {
      const w = await deployWorld({
        label: "sd5-cut1", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      // No PQ SIGNATURE at all. The witness is a public value, so supplying it
      // proves nothing about a second factor: the cut is 1 before and after.
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65,
        }, { pqSig: "0x" })
      ).wait();
      expect((await liveFloor(w)).requirePq, "one root moved the security floor").to.equal(true);
    });
  });

  describe("SD-7 — SUSTAINED: the GENESIS twin, which neither clause reaches", function () {
    it("a vault can still be BORN with a floor its own committed key cannot satisfy, and the shape is permanent", async function () {
      // `initialize`'s only material check is a ZERO-ness test, and
      // `_requireIncomingPossession` has exactly two call sites — neither of them
      // `initialize` — so there is no genesis possession proof of any kind. Both
      // new clauses live in `setVerifier` and never run here.
      const w = await deployWorld({ label: "sd7-genesis", verifier: "honest" });
      const factory = await ethers.getContractAt("VaultKernelPrototype", w.vaultAddress, w.deployer);
      const fac = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
      const salt = ethers.id("sd7-genesis-twin");
      const genesis = {
        signer: addrOf(w.credKey),
        // A 48-byte key committed against a floor that declares 32.
        pqKeyHash: ethers.keccak256(keyOfLength(48, 0x5a)),
        verifier: w.verifiers.honest,
        threshold: w.threshold,
        guardians: w.guardians,
        guardianIsContract: w.guardianIsContract,
        floor: floorTuple({ requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 }),
      };
      const predicted: string = await fac.predictVault(salt, genesis);
      await (await fac.deployVault(salt, genesis)).wait();
      const twin = await ethers.getContractAt("VaultKernelPrototype", predicted, w.deployer);

      // SUSTAINED (SD-7): born unspendable. `_authorise` demands a 32-byte key
      // hashing to a 48-byte key's commitment — a second-preimage problem.
      const nonce = (await twin.nonces(DOMAIN.SPEND)) as bigint;
      const gen = (await twin.credentialGeneration()) as bigint;
      const sd = digestOf({
        chainId: w.chainId, vault: predicted, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SPEND, authorityGeneration: gen,
        params: spendParams(w.recipient, ethers.parseEther("1")),
        domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
      });
      await expect(
        twin.execute(w.recipient, ethers.parseEther("1"), nonce, FAR_DEADLINE,
          sign(w.credKey, sd), sign(w.pqKey, sd), keyOfLength(32, 0x5a)),
        "SUSTAINED (SD-7): the vault is born unable to authorise",
      ).to.be.revertedWithCustomError(factory, "BadSignature");

      // And the shape is already frozen, because `requirePq` holds from birth.
      expect(Number((await twin.securityFloor())[2])).to.equal(32);
    });
  });

  describe("SD-6 — SUSTAINED: an unattested commitment install while requirePq is false", function () {
    it("rotateCredential installs an arbitrary pqPublicKeyHash with NO possession proof of any kind", async function () {
      // `_requireIncomingPossession` returns at `if (!floor.requirePq) return;`
      // BEFORE the keccak cross-check, so the incoming commitment is accepted
      // unattested. It is dormant while requirePq is false — and the declaring
      // edge is what makes it live, which is why the exhibit's strength against a
      // determined adversary is bounded by this defect and not by its own logic.
      const w = await deployWorld({
        label: "sd6-unattested", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      const nCred = w.spareCred[2]!;
      const fabricated = ethers.keccak256(keyOfLength(7, 0x77)); // a key nobody holds
      const nonce = (await w.vault.nonces(DOMAIN.CREDENTIAL)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const d = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.ROTATE, authorityGeneration: gen,
        params: ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(["address", "bytes32"], [addrOf(nCred), fabricated]),
        ),
        domain: DOMAIN.CREDENTIAL, nonce, deadline: FAR_DEADLINE,
      });
      const pop = (await w.vault.credentialPossessionDigest(addrOf(nCred), fabricated)) as string;
      await (
        await w.vault.rotateCredential(
          {
            newSigner: addrOf(nCred), newPqKeyHash: fabricated,
            newPqKey: "0x", newEcdsaPop: sign(nCred, pop), newPqPop: "0x",
          },
          nonce, FAR_DEADLINE, sign(w.credKey, d), "0x", "0x",
        )
      ).wait();
      expect(await w.vault.pqPublicKeyHash(), "SUSTAINED (SD-6): an unattested commitment is installed")
        .to.equal(fabricated);
    });
  });

  // =====================================================================
  // POSITIVE CONTROLS — so a blanket revert can never be mistaken for a fix
  // =====================================================================
  describe("POSITIVE CONTROLS", function () {
    it("a legitimate declaration, witnessed by the committed key, works and the vault still spends", async function () {
      const w = await deployWorld({
        label: "sd34-pc1", verifier: "honest", ecdsaOnlyFloor: true, commitPqKeyOnEcdsaOnlyFloor: true,
      });
      await (
        await setVerifierTx(w, w.verifiers.honest, {
          requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 32, pqSignatureLength: 65,
        })
      ).wait();
      expect((await liveFloor(w)).requirePq).to.equal(true);

      const nonce = (await w.vault.nonces(DOMAIN.SPEND)) as bigint;
      const gen = (await w.vault.credentialGeneration()) as bigint;
      const sd = digestOf({
        chainId: w.chainId, vault: w.vaultAddress, kernelGeneration: KERNEL_GEN,
        actionType: ACTION.SPEND, authorityGeneration: gen,
        params: spendParams(w.recipient, ethers.parseEther("1")),
        domain: DOMAIN.SPEND, nonce, deadline: FAR_DEADLINE,
      });
      const before = await ethers.provider.getBalance(w.recipient);
      await (
        await w.vault.execute(w.recipient, ethers.parseEther("1"), nonce, FAR_DEADLINE,
          sign(w.credKey, sd), sign(w.pqKey, sd), pqKeyBytes(w.pqKey))
      ).wait();
      expect(await ethers.provider.getBalance(w.recipient), "the armed vault is genuinely usable")
        .to.equal(before + ethers.parseEther("1"));
    });

    it("a PQ-ENABLED genesis is unaffected: the edge does not exist there, and recovery still executes", async function () {
      const w = await deployWorld({ label: "sd34-pc2", verifier: "honest" });
      expect((await liveFloor(w)).requirePq, "born requiring PQ").to.equal(true);
      const newPq = w.sparePq[0]!;
      const newCred = await initiate(w, 0, w.verifiers.honest, pqHash(newPq));
      await networkHelpers.time.increase(7 * DAY + 1);
      const pop = (await w.vault.recoveryPossessionDigest()) as string;
      await (
        await w.vault.executeRecovery({
          newSigner: addrOf(newCred), newPqKeyHash: pqHash(newPq), newPqKey: pqKeyBytes(newPq),
          newEcdsaPop: sign(newCred, pop), newPqPop: sign(newPq, pop),
        })
      ).wait();
      expect(await w.vault.ecdsaSigner()).to.equal(addrOf(newCred));
    });

    it("genesis still refuses the unsatisfiable configuration it always refused", async function () {
      const w = await deployWorld({ label: "sd34-pc3", verifier: "honest" });
      const factory = await ethers.getContractAt("VaultKernelFactoryPrototype", w.factoryAddress, w.deployer);
      await expect(
        factory.deployVault(ethers.id("sd34-pc3-bad"), {
          signer: addrOf(w.credKey),
          pqKeyHash: ethers.ZeroHash,
          verifier: w.verifiers.honest,
          threshold: w.threshold,
          guardians: w.guardians,
          guardianIsContract: w.guardianIsContract,
          floor: floorTuple({ requirePq: true, pqParamLevel: 1, pqPublicKeyLength: 32, pqSignatureLength: 65 }),
        }),
      ).to.revert(ethers);
    });
  });
});
