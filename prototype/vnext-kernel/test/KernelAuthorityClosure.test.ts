/**
 * EXPERIMENTAL PROTOTYPE — INDEPENDENT AUTHORITY-CLOSURE SUITE (M-K28..M-K37).
 *
 * WHY THIS FILE IS SEPARATE, AND WHY IT DUPLICATES ITS HELPERS
 * -----------------------------------------------------------
 * An independent review of the compiled kernel alleged authority gaps that
 * contradicted the prototype's published minimum-cut claims. Every one was
 * REPRODUCED against the real kernel before being fixed. This suite is the
 * permanent regression record, and it deliberately shares no helper code with
 * `KernelPrototype.test.ts`: a shared helper bug could make both suites agree
 * while both are wrong. The duplication buys independence.
 *
 * THE STANDARD THESE TESTS ARE HELD TO
 * ------------------------------------
 * A closure attack is NOT disproven by "the dangerous setter reverted". It is
 * disproven by showing the CATASTROPHIC END STATE is unreachable:
 *
 *     initial compromise -> intermediate transition -> ASSET MOVEMENT
 *
 * so every attack below carries through to the asset check, and every one is
 * paired with a POSITIVE CONTROL so a refusal can never be mistaken for a kill
 * that setup produced.
 *
 * THE SECOND FACTOR HERE IS HONEST. `EcdsaBackedVerifier` demands a real
 * signature from a real independent keypair, so no result below can be
 * dismissed as "the mock was weak".
 */
import { expect } from "chai";
import { ethers } from "./connection.js";

const ZERO = "0x0000000000000000000000000000000000000000";
const DAY = 24 * 60 * 60;
const abi = ethers.AbiCoder.defaultAbiCoder();

const ACTION = {
  SPEND: ethers.id("SPEND"),
  ROTATE: ethers.id("ROTATE_CREDENTIAL"),
  SET_VERIFIER: ethers.id("SET_VERIFIER"),
  SET_POLICY: ethers.id("SET_POLICY"),
  SET_GUARDIANS: ethers.id("SET_GUARDIANS"),
  RECOVER: ethers.id("RECOVER"),
} as const;
const DOMAIN = { SPEND: 0, CREDENTIAL: 1, GUARDIAN: 2, MIGRATION: 3 } as const;

/** The honest second factor's declared shape: a 32-byte key, a 65-byte sig. */
const FLOOR = { requirePq: true, pqParamLevel: 3, pqPublicKeyLength: 32, pqSignatureLength: 65 };
const FLOOR_TUPLE = [FLOOR.requirePq, FLOOR.pqParamLevel, FLOOR.pqPublicKeyLength, FLOOR.pqSignatureLength];

interface Parts {
  chainId: bigint;
  vault: string;
  kernelGeneration: bigint;
  actionType: string;
  authorityGeneration: bigint;
  params: string;
  domain: number;
  nonce: bigint;
  deadline: bigint;
}

function digestOf(p: Parts): string {
  const ds = ethers.keccak256(
    abi.encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        ethers.id("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        ethers.id("WalletWallVaultKernel"),
        ethers.id("0-prototype"),
        p.chainId,
        p.vault,
      ],
    ),
  );
  const sh = ethers.keccak256(
    abi.encode(
      ["bytes32", "uint64", "uint64", "bytes32", "uint8", "uint256", "uint64"],
      [p.actionType, p.kernelGeneration, p.authorityGeneration, p.params, p.domain, p.nonce, p.deadline],
    ),
  );
  return ethers.keccak256(ethers.concat(["0x1901", ds, sh]));
}

const sign = (k: ethers.SigningKey, d: string) => ethers.Signature.from(k.sign(d)).serialized;
const keyOf = (l: string) => new ethers.SigningKey(ethers.id(l));
const addrOf = (k: ethers.SigningKey) => ethers.computeAddress(k.publicKey);
/** The honest verifier's "public key": the second keypair's address, 32 bytes. */
const pqKeyBytes = (k: ethers.SigningKey) => abi.encode(["address"], [addrOf(k)]);
const pqHash = (k: ethers.SigningKey) => ethers.keccak256(pqKeyBytes(k));
/** Rosters must be STRICTLY ASCENDING — that is the distinctness rule itself. */
const ascending = (a: string[]) => [...a].sort((x, y) => (BigInt(x) < BigInt(y) ? -1 : 1));

interface Genesis {
  signer: string;
  pqKeyHash: string;
  verifier: string;
  threshold: number;
  guardians: string[];
  guardianIsContract: boolean[];
  floor: typeof FLOOR;
}

describe("vNext kernel — INDEPENDENT AUTHORITY-CLOSURE REVIEW (M-K28..M-K37)", function () {
  type Fx = Awaited<ReturnType<typeof deploy>>;

  /**
   * A vault under an HONEST second factor. The attacker in these tests holds
   * `ownerKey` ONLY — the exact "one root compromised" scenario the published
   * `min(2, k)` claim says must be survivable.
   */
  async function deploy() {
    const [deployer, attacker, recipient] = await ethers.getSigners();
    const chainId = (await ethers.provider.getNetwork()).chainId;

    const ownerKey = keyOf("closure-owner");
    const pqKey = keyOf("closure-pq");
    const gKeys = [1, 2, 3].map((i) => keyOf(`closure-guardian-${i}`));
    const sortedKeys = [...gKeys].sort((a, b) => (BigInt(addrOf(a)) < BigInt(addrOf(b)) ? -1 : 1));

    const V = await ethers.getContractFactory("EcdsaBackedVerifier", deployer);
    const verifier = await V.deploy();
    await verifier.waitForDeployment();
    const Impl = await ethers.getContractFactory("VaultKernelPrototype", deployer);
    const impl = await Impl.deploy();
    await impl.waitForDeployment();
    const F = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
    const factory = await F.deploy(await impl.getAddress(), 1);
    await factory.waitForDeployment();

    const genesis: Genesis = {
      signer: addrOf(ownerKey),
      pqKeyHash: pqHash(pqKey),
      verifier: await verifier.getAddress(),
      threshold: 2,
      guardians: sortedKeys.map(addrOf),
      guardianIsContract: [false, false, false],
      floor: FLOOR,
    };

    const salt = ethers.id("closure-vault");
    const predicted = await factory.predictVault(salt, genesis);
    await (await factory.deployVault(salt, genesis, pqKeyBytes(pqKey))).wait();
    const vault = await ethers.getContractAt("VaultKernelPrototype", predicted, deployer);
    await deployer.sendTransaction({ to: predicted, value: ethers.parseEther("10") });

    return {
      deployer,
      attacker,
      recipient,
      chainId,
      ownerKey,
      pqKey,
      sortedKeys,
      genesis,
      verifier,
      impl,
      factory,
      vault,
      vaultAddress: predicted,
      salt,
    };
  }

  function parts(f: Fx, over: Partial<Parts>): Parts {
    return {
      chainId: f.chainId,
      vault: f.vaultAddress,
      kernelGeneration: 1n,
      actionType: ACTION.SPEND,
      authorityGeneration: 1n,
      params: ethers.ZeroHash,
      domain: DOMAIN.SPEND,
      nonce: 0n,
      deadline: BigInt(2 ** 40),
      ...over,
    };
  }

  const spendParams = (to: string, a: bigint) => ethers.keccak256(abi.encode(["address", "uint256"], [to, a]));

  async function spend(f: Fx, ec: ethers.SigningKey, pq: ethers.SigningKey, nonce: bigint, credGen: bigint) {
    const to = f.recipient.address;
    const amount = ethers.parseEther("1");
    const d = digestOf(parts(f, { params: spendParams(to, amount), nonce, authorityGeneration: credGen }));
    return f.vault.execute(to, amount, nonce, BigInt(2 ** 40), sign(ec, d), sign(pq, d), pqKeyBytes(pq));
  }

  function quorum(f: Fx, digest: string, indices: number[]) {
    return {
      members: f.genesis.guardians,
      isContract: f.genesis.guardianIsContract,
      attestingIndices: indices,
      attestations: indices.map((i) => sign(f.sortedKeys[i], digest)),
    };
  }

  /** A complete incoming credential with both possession proofs. */
  function change(ec: ethers.SigningKey, pq: ethers.SigningKey, pop: string) {
    return {
      newSigner: addrOf(ec),
      newPqKeyHash: pqHash(pq),
      newPqKey: pqKeyBytes(pq),
      newEcdsaPop: sign(ec, pop),
      newPqPop: sign(pq, pop),
    };
  }

  async function rig() {
    const [deployer, attacker] = await ethers.getSigners();
    const Impl = await ethers.getContractFactory("VaultKernelPrototype", deployer);
    const impl = await Impl.deploy();
    await impl.waitForDeployment();
    const F = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
    const factory = await F.deploy(await impl.getAddress(), 1);
    await factory.waitForDeployment();
    const V = await ethers.getContractFactory("EcdsaBackedVerifier", deployer);
    const v = await V.deploy();
    await v.waitForDeployment();
    return { deployer, attacker, impl, factory, verifier: await v.getAddress() };
  }

  // =====================================================================
  describe("FINDING A — does HYBRID survive an ECDSA-only compromise?", function () {
    it("POSITIVE CONTROL — the honest second factor really is required", async function () {
      const f = await deploy();
      await (await spend(f, f.ownerKey, f.pqKey, 0n, 1n)).wait();
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(to, amount), nonce: 1n }));
      await expect(
        f.vault.execute(
          to,
          amount,
          1,
          BigInt(2 ** 40),
          sign(f.ownerKey, d),
          sign(keyOf("wrong"), d),
          pqKeyBytes(f.pqKey),
        ),
      ).to.be.revertedWithCustomError(f.vault, "VerifierDenied");
    });

    it("M-K28 — an ECDSA-ONLY attacker cannot rotate the credential, so cannot spend", async function () {
      const f = await deploy();
      const aE = keyOf("A1-attacker-ecdsa");
      const aP = keyOf("A1-attacker-pq");
      const rotD = digestOf(
        parts(f, {
          actionType: ACTION.ROTATE,
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(aE), pqHash(aP)])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      const pop = await f.vault.credentialPossessionDigest(addrOf(aE), pqHash(aP));

      // THE ATTACK: ONE root. The attacker holds the ECDSA key and must forge
      // the PQ conjunct, which the honest verifier refuses.
      await expect(
        f.vault.rotateCredential(
          change(aE, aP, pop),
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, rotD),
          sign(aP, rotD),
          pqKeyBytes(f.pqKey),
        ),
      ).to.be.revertedWithCustomError(f.vault, "VerifierDenied");

      // CATASTROPHIC END STATE unreachable: credential intact, assets intact.
      expect(await f.vault.ecdsaSigner()).to.equal(addrOf(f.ownerKey));
      expect(await ethers.provider.getBalance(f.vaultAddress)).to.equal(ethers.parseEther("10"));

      // CONTROL — the holder of BOTH factors rotates, and the new credential
      // spends. So the refusal above is the missing factor, not a broken path.
      await (
        await f.vault.rotateCredential(
          change(aE, aP, pop),
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, rotD),
          sign(f.pqKey, rotD),
          pqKeyBytes(f.pqKey),
        )
      ).wait();
      expect(await f.vault.ecdsaSigner()).to.equal(addrOf(aE));
      await (await spend(f, aE, aP, 0n, 2n)).wait();
    });

    it("M-K29 — an ECDSA-ONLY attacker cannot install an always-true verifier, so cannot spend", async function () {
      const f = await deploy();
      const Evil = await ethers.getContractFactory("ConfigurableVerifier", f.deployer);
      const evil = await Evil.deploy(0); // ALWAYS_TRUE
      await evil.waitForDeployment();
      const evilAddr = await evil.getAddress();

      // The floor is NOT lowered, so the no-downgrade rule has nothing to object
      // to. The downgrade would be in WHICH verifier answers.
      const svD = digestOf(
        parts(f, {
          actionType: ACTION.SET_VERIFIER,
          params: ethers.keccak256(
            abi.encode(["address", "tuple(bool,uint16,uint32,uint32)"], [evilAddr, FLOOR_TUPLE]),
          ),
          domain: DOMAIN.CREDENTIAL,
        }),
      );

      await expect(
        f.vault.setVerifier(
          evilAddr,
          FLOOR,
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, svD),
          sign(keyOf("forged"), svD),
          pqKeyBytes(f.pqKey),
        ),
      ).to.be.revertedWithCustomError(f.vault, "VerifierDenied");
      expect(await f.vault.pqVerifier()).to.equal(await f.verifier.getAddress());

      // CATASTROPHIC END STATE unreachable: with the honest verifier still in
      // place the attacker cannot spend, even supplying the PUBLIC pq key.
      const to = f.recipient.address;
      const amount = ethers.parseEther("1");
      const d = digestOf(parts(f, { params: spendParams(to, amount) }));
      await expect(
        f.vault.execute(
          to,
          amount,
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, d),
          sign(keyOf("forged2"), d),
          pqKeyBytes(f.pqKey),
        ),
      ).to.be.revertedWithCustomError(f.vault, "VerifierDenied");
      expect(await ethers.provider.getBalance(f.vaultAddress)).to.equal(ethers.parseEther("10"));

      // CONTROL — the legitimate HYBRID holder CAN replace the verifier.
      await (
        await f.vault.setVerifier(
          evilAddr,
          FLOOR,
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, svD),
          sign(f.pqKey, svD),
          pqKeyBytes(f.pqKey),
        )
      ).wait();
      expect(await f.vault.pqVerifier()).to.equal(evilAddr);
    });

    it("VERIFIER LIVENESS — a permanently dead verifier is escapable by guardian recovery", async function () {
      const f = await deploy();
      const Dead = await ethers.getContractFactory("ConfigurableVerifier", f.deployer);
      const dead = await Dead.deploy(2); // REVERTS forever
      await dead.waitForDeployment();
      const svD = digestOf(
        parts(f, {
          actionType: ACTION.SET_VERIFIER,
          params: ethers.keccak256(
            abi.encode(["address", "tuple(bool,uint16,uint32,uint32)"], [await dead.getAddress(), FLOOR_TUPLE]),
          ),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.setVerifier(
          await dead.getAddress(),
          FLOOR,
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, svD),
          sign(f.pqKey, svD),
          pqKeyBytes(f.pqKey),
        )
      ).wait();

      // Spending is DENIED — accepted, declared, inside the envelope. And the
      // credential path can no longer replace the verifier either, because
      // `setVerifier` is HYBRID and the PQ leg is dead. That is exactly why the
      // escape must live with the GUARDIANS rather than with one factor.
      let denied = false;
      try {
        await (await spend(f, f.ownerKey, f.pqKey, 0n, 1n)).wait();
      } catch {
        denied = true;
      }
      expect(denied).to.equal(true);

      const Good = await ethers.getContractFactory("EcdsaBackedVerifier", f.deployer);
      const good = await Good.deploy();
      await good.waitForDeployment();
      const nE = keyOf("recovered-ecdsa");
      const nP = keyOf("recovered-pq");
      const recD = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [addrOf(nE), pqHash(nP), await good.getAddress()]),
          ),
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await (
        await f.vault.initiateRecovery(
          addrOf(nE),
          pqHash(nP),
          await good.getAddress(),
          quorum(f, recD, [0, 1]),
          0,
          BigInt(2 ** 40),
        )
      ).wait();
      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await f.vault.executeRecovery(change(nE, nP, await f.vault.recoveryPossessionDigest()))).wait();

      // LIVENESS RESTORED on the replacement verifier.
      expect(await f.vault.pqVerifier()).to.equal(await good.getAddress());
      await (await spend(f, nE, nP, 0n, 2n)).wait();
    });
  });

  // =====================================================================
  describe("FINDING B — does quorum count PRINCIPALS or INDICES?", function () {
    it("M-K30 — the same EOA at two roster indices cannot reach quorum", async function () {
      const r = await rig();
      const A = keyOf("dupe-A");
      const B = keyOf("dupe-B");
      const g: Genesis = {
        signer: addrOf(keyOf("dupe-owner")),
        pqKeyHash: pqHash(keyOf("dupe-pq")),
        verifier: r.verifier,
        threshold: 2,
        guardians: [addrOf(A), addrOf(A), addrOf(B)],
        guardianIsContract: [false, false, false],
        floor: FLOOR,
      };
      // THE FIX IS AT ADMISSION: a duplicate roster is not representable, so a
      // vault whose quorum one principal could meet cannot be created at all.
      await expect(r.factory.deployVault(ethers.id("dupe"), g, pqKeyBytes(keyOf("dupe-pq")))).to.be.revertedWithCustomError(r.impl, "NotOrdered");

      // CONTROL: the same principals, DISTINCT and ascending, deploy fine.
      await (
        await r.factory.deployVault(ethers.id("dupe"), {
          ...g,
          guardians: ascending([addrOf(A), addrOf(B), r.deployer.address]),
        }, pqKeyBytes(keyOf("dupe-pq")))
      ).wait();
    });

    it("M-K31 — the same ERC-1271 guardian at two indices cannot reach quorum", async function () {
      const r = await rig();
      const G = await (await ethers.getContractFactory("GoodContractGuardian", r.deployer)).deploy();
      await G.waitForDeployment();
      const g1 = await G.getAddress();
      const g: Genesis = {
        signer: addrOf(keyOf("d1271-owner")),
        pqKeyHash: pqHash(keyOf("d1271-pq")),
        verifier: r.verifier,
        threshold: 2,
        guardians: [g1, g1, r.deployer.address],
        guardianIsContract: [true, true, false],
        floor: FLOOR,
      };
      await expect(r.factory.deployVault(ethers.id("d1271"), g, pqKeyBytes(keyOf("d1271-pq")))).to.be.revertedWithCustomError(r.impl, "NotOrdered");
    });

    it("M-K32 — the SAME address cannot hold two seats under different auth modes", async function () {
      const r = await rig();
      const G = await (await ethers.getContractFactory("GoodContractGuardian", r.deployer)).deploy();
      await G.waitForDeployment();
      const dual = await G.getAddress();
      // One PRINCIPAL wearing two hats: an EOA seat and an ERC-1271 seat. A
      // principal is an ADDRESS, not an (address, mode) pair.
      const g: Genesis = {
        signer: addrOf(keyOf("dual-owner")),
        pqKeyHash: pqHash(keyOf("dual-pq")),
        verifier: r.verifier,
        threshold: 2,
        guardians: [dual, dual, r.deployer.address],
        guardianIsContract: [false, true, false],
        floor: FLOOR,
      };
      await expect(r.factory.deployVault(ethers.id("dual"), g, pqKeyBytes(keyOf("dual-pq")))).to.be.revertedWithCustomError(r.impl, "NotOrdered");
    });

    it("a guardian TRANSITION to a duplicate roster is refused too", async function () {
      const f = await deploy();
      const A = keyOf("trans-A");
      const dup = [addrOf(A), addrOf(A)];
      const newCommitment = ethers.keccak256(abi.encode(["uint64", "address[]", "bool[]"], [2n, dup, [false, false]]));
      const sgD = digestOf(
        parts(f, { actionType: ACTION.SET_GUARDIANS, params: newCommitment, domain: DOMAIN.GUARDIAN }),
      );
      await expect(
        f.vault.setGuardians(2, dup, [false, false], quorum(f, sgD, [0, 1]), 0, BigInt(2 ** 40)),
      ).to.be.revertedWithCustomError(f.vault, "NotOrdered");
      expect(await f.vault.guardianGeneration()).to.equal(1n);
    });

    it("POSITIVE CONTROL — distinct principals reach quorum normally", async function () {
      const f = await deploy();
      const nE = keyOf("distinct-new");
      const nP = keyOf("distinct-new-pq");
      const recD = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [addrOf(nE), pqHash(nP), await f.verifier.getAddress()]),
          ),
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await (
        await f.vault.initiateRecovery(
          addrOf(nE),
          pqHash(nP),
          await f.verifier.getAddress(),
          quorum(f, recD, [0, 1]),
          0,
          BigInt(2 ** 40),
        )
      ).wait();
      expect((await f.vault.recovery()).active).to.equal(true);
    });
  });

  // =====================================================================
  describe("FINDING C — can the counterfactual vault identity be salt-squatted?", function () {
    it("M-K33 — an attacker cannot occupy the identity the user predicted", async function () {
      const r = await rig();
      const salt = ethers.id("user-chosen-salt");
      const userEcdsa = keyOf("victim-owner");
      const userGenesis: Genesis = {
        signer: addrOf(userEcdsa),
        pqKeyHash: pqHash(keyOf("victim-pq")),
        verifier: r.verifier,
        threshold: 2,
        guardians: ascending([addrOf(keyOf("vg1")), addrOf(keyOf("vg2")), addrOf(keyOf("vg3"))]),
        guardianIsContract: [false, false, false],
        floor: FLOOR,
      };
      const predicted = await r.factory.predictVault(salt, userGenesis);

      // The attacker front-runs with the SAME salt and THEIR OWN authority.
      const attackerGenesis: Genesis = {
        ...userGenesis,
        signer: r.attacker.address,
        guardians: ascending([r.attacker.address, addrOf(keyOf("ag2"))]),
        guardianIsContract: [false, false],
        threshold: 1,
      };
      expect(await r.factory.predictVault(salt, attackerGenesis)).to.not.equal(predicted);
      // `attackerGenesis` spreads the user's config, so it carries the USER's
      // commitment — and the attacker CAN exhibit it, because a PQ public key is
      // public. That is exactly right: `I-COMMITMENT-EXHIBITED-AT-ADMISSION` is
      // a satisfiability witness, not an authority gate, and must not be
      // mistaken for one. What defeats the squat is
      // `I-COUNTERFACTUAL-IDENTITY-BINDING`, which is unchanged.
      await (
        await r.factory.connect(r.attacker).deployVault(salt, attackerGenesis, pqKeyBytes(keyOf("victim-pq")))
      ).wait();

      // I-COUNTERFACTUAL-IDENTITY-BINDING: the user's address is untouched.
      expect(await ethers.provider.getCode(predicted)).to.equal("0x");

      // And the user can still instantiate their intended configuration there.
      await (await r.factory.deployVault(salt, userGenesis, pqKeyBytes(keyOf("victim-pq")))).wait();
      const got = await ethers.getContractAt("VaultKernelPrototype", predicted, r.deployer);
      expect(await got.ecdsaSigner()).to.equal(addrOf(userEcdsa));
      expect(await got.guardianThreshold()).to.equal(2n);
    });

    it("an IDENTICAL authorised configuration submitted by a stranger is harmless", async function () {
      const r = await rig();
      const salt = ethers.id("shared-salt");
      const ownerKey = keyOf("harmless-owner");
      const genesis: Genesis = {
        signer: addrOf(ownerKey),
        pqKeyHash: pqHash(keyOf("harmless-pq")),
        verifier: r.verifier,
        threshold: 2,
        guardians: ascending([addrOf(keyOf("hg1")), addrOf(keyOf("hg2"))]),
        guardianIsContract: [false, false],
        floor: FLOOR,
      };
      const predicted = await r.factory.predictVault(salt, genesis);

      // Permissionless execution of an ALREADY-AUTHORISED intent is not a
      // takeover: the result is the state the user asked for, at the address the
      // user predicted. Distinguishing the two is the point of the finding.
      await (await r.factory.connect(r.attacker).deployVault(salt, genesis, pqKeyBytes(keyOf("harmless-pq")))).wait();
      const got = await ethers.getContractAt("VaultKernelPrototype", predicted, r.deployer);
      expect(await got.ecdsaSigner()).to.equal(addrOf(ownerKey));
      expect(await got.guardianThreshold()).to.equal(2n);
    });
  });

  // =====================================================================
  describe("FINDING D — is incoming credential possession proven?", function () {
    it("M-K34 — rotation to an UNPOSSESSED ECDSA signer is refused", async function () {
      const f = await deploy();
      const stranded = "0x000000000000000000000000000000000000dEaD";
      const nP = keyOf("m34-pq");
      const rotD = digestOf(
        parts(f, {
          actionType: ACTION.ROTATE,
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [stranded, pqHash(nP)])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      const pop = await f.vault.credentialPossessionDigest(stranded, pqHash(nP));
      // Fully authorised by BOTH outgoing factors. The only missing thing is
      // possession of the INCOMING one.
      await expect(
        f.vault.rotateCredential(
          {
            newSigner: stranded,
            newPqKeyHash: pqHash(nP),
            newPqKey: pqKeyBytes(nP),
            newEcdsaPop: sign(keyOf("not-dead"), pop),
            newPqPop: sign(nP, pop),
          },
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, rotD),
          sign(f.pqKey, rotD),
          pqKeyBytes(f.pqKey),
        ),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");

      // POST-TRANSITION LIVENESS: the vault is NOT stranded.
      expect(await f.vault.ecdsaSigner()).to.equal(addrOf(f.ownerKey));
      await (await spend(f, f.ownerKey, f.pqKey, 0n, 1n)).wait();
    });

    it("M-K34b — rotation WITH possession succeeds and the new credential spends", async function () {
      const f = await deploy();
      const nE = keyOf("m34b-ecdsa");
      const nP = keyOf("m34b-pq");
      const rotD = digestOf(
        parts(f, {
          actionType: ACTION.ROTATE,
          params: ethers.keccak256(abi.encode(["address", "bytes32"], [addrOf(nE), pqHash(nP)])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      const pop = await f.vault.credentialPossessionDigest(addrOf(nE), pqHash(nP));
      await (
        await f.vault.rotateCredential(
          change(nE, nP, pop),
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, rotD),
          sign(f.pqKey, rotD),
          pqKeyBytes(f.pqKey),
        )
      ).wait();
      await (await spend(f, nE, nP, 0n, 2n)).wait();
    });

    it("M-K35 — recovery to an UNPOSSESSED PQ commitment cannot complete", async function () {
      const f = await deploy();
      const nE = keyOf("m35-ecdsa");
      const bogus = ethers.id("nobody-holds-this");
      const recD = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [addrOf(nE), bogus, await f.verifier.getAddress()]),
          ),
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await (
        await f.vault.initiateRecovery(
          addrOf(nE),
          bogus,
          await f.verifier.getAddress(),
          quorum(f, recD, [0, 1]),
          0,
          BigInt(2 ** 40),
        )
      ).wait();
      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      const pop = await f.vault.recoveryPossessionDigest();
      await expect(
        f.vault.executeRecovery({
          newSigner: addrOf(nE),
          newPqKeyHash: bogus,
          newPqKey: pqKeyBytes(keyOf("guess")),
          newEcdsaPop: sign(nE, pop),
          newPqPop: sign(keyOf("guess"), pop),
        }),
      ).to.be.revertedWithCustomError(f.vault, "BadSignature");

      // The vault is NOT left spend-impossible.
      expect(await f.vault.ecdsaSigner()).to.equal(addrOf(f.ownerKey));
      await (await spend(f, f.ownerKey, f.pqKey, 0n, 1n)).wait();
    });

    it("M-K36 — a possessed recovery completes and the recovered credential spends", async function () {
      const f = await deploy();
      const nE = keyOf("m36-ecdsa");
      const nP = keyOf("m36-pq");
      const recD = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [addrOf(nE), pqHash(nP), await f.verifier.getAddress()]),
          ),
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await (
        await f.vault.initiateRecovery(
          addrOf(nE),
          pqHash(nP),
          await f.verifier.getAddress(),
          quorum(f, recD, [0, 1]),
          0,
          BigInt(2 ** 40),
        )
      ).wait();
      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await f.vault.executeRecovery(change(nE, nP, await f.vault.recoveryPossessionDigest()))).wait();
      await (await spend(f, nE, nP, 0n, 2n)).wait();
    });

    it("the PoP digest is NOT movable by the outgoing credential (#178 lesson)", async function () {
      const f = await deploy();
      const nE = keyOf("veto-probe");
      const nP = keyOf("veto-probe-pq");
      const recD = digestOf(
        parts(f, {
          actionType: ACTION.RECOVER,
          params: ethers.keccak256(
            abi.encode(["address", "bytes32", "address"], [addrOf(nE), pqHash(nP), await f.verifier.getAddress()]),
          ),
          domain: DOMAIN.GUARDIAN,
        }),
      );
      await (
        await f.vault.initiateRecovery(
          addrOf(nE),
          pqHash(nP),
          await f.verifier.getAddress(),
          quorum(f, recD, [0, 1]),
          0,
          BigInt(2 ** 40),
        )
      ).wait();
      const armed = await f.vault.recoveryPossessionDigest();

      // The outgoing credential spends, consuming its own nonce. If the PoP
      // digest moved, every spend would invalidate a pre-signed possession
      // proof — handing the compromised credential a repeatable veto.
      await (await spend(f, f.ownerKey, f.pqKey, 0n, 1n)).wait();
      expect(await f.vault.recoveryPossessionDigest()).to.equal(armed);

      await ethers.provider.send("evm_increaseTime", [8 * DAY]);
      await ethers.provider.send("evm_mine", []);
      await (await f.vault.executeRecovery(change(nE, nP, armed))).wait();
      expect(await f.vault.ecdsaSigner()).to.equal(addrOf(nE));
    });
  });

  // =====================================================================
  describe("FINDING E — the implementation-custody claim, corrected", function () {
    it("the implementation CAN receive value but holds NO authority", async function () {
      const f = await deploy();
      const implAddr = await f.impl.getAddress();

      // THE CORRECTED CLAIM. Unsolicited value CAN arrive — any claim of
      // physically impossible custody would be false, since an ERC-20 can be
      // transferred to any address regardless of its code.
      await f.deployer.sendTransaction({ to: implAddr, value: ethers.parseEther("1") });
      expect(await ethers.provider.getBalance(implAddr)).to.equal(ethers.parseEther("1"));

      // What IS true, and is the claim that matters: it holds no authority and
      // can never be initialised into holding any.
      const inst = await ethers.getContractAt("VaultKernelPrototype", implAddr, f.attacker);
      expect(await inst.ecdsaSigner()).to.equal(ZERO);
      await expect(inst.initialize(f.genesis, pqKeyBytes(f.pqKey))).to.be.revertedWithCustomError(inst, "AlreadyInitialized");

      // No spend is authorisable, and the reason is condition (3) of #179
      // §4.3a: the stored credential is address(0), while `ECDSA.recover`
      // either reverts or returns a REAL address — so the comparison can never
      // succeed. That is a stronger guarantee than a state gate, which is why
      // the refusal is `BadSignature` and not `BadState`.
      const d = digestOf(parts(f, { vault: implAddr, params: spendParams(f.recipient.address, 1n) }));
      await expect(
        inst.execute(f.recipient.address, 1, 0, BigInt(2 ** 40), sign(f.ownerKey, d), "0x", "0x"),
      ).to.be.revertedWithCustomError(inst, "BadSignature");
      // The value that arrived is therefore unreachable by ANY caller: it is
      // stuck, not stealable. The corrected claim is "cannot exercise vault
      // authority", never "cannot receive or hold assets".
      expect(await ethers.provider.getBalance(implAddr)).to.equal(ethers.parseEther("1"));
    });
  });

  // =====================================================================
  describe("FINDING F — can the policy plane represent stateful policy?", function () {
    it("M-K37 — a CUMULATIVE limit is now enforceable at the plane boundary", async function () {
      const f = await deploy();
      const P = await ethers.getContractFactory("StatefulPolicy", f.deployer);
      const policy = await P.deploy(ethers.parseEther("1.5"));
      await policy.waitForDeployment();

      const spD = digestOf(
        parts(f, {
          actionType: ACTION.SET_POLICY,
          params: ethers.keccak256(abi.encode(["address"], [await policy.getAddress()])),
          domain: DOMAIN.CREDENTIAL,
        }),
      );
      await (
        await f.vault.setPolicy(
          await policy.getAddress(),
          0,
          BigInt(2 ** 40),
          sign(f.ownerKey, spD),
          sign(f.pqKey, spD),
          pqKeyBytes(f.pqKey),
        )
      ).wait();

      // POSITIVE CONTROL: the first spend is admitted and RECORDED.
      await (await spend(f, f.ownerKey, f.pqKey, 0n, 1n)).wait();
      expect(await policy.spent()).to.equal(ethers.parseEther("1"));

      // The second would exceed the cumulative cap and is DENIED — the thing a
      // view-only boundary could not do.
      await expect(spend(f, f.ownerKey, f.pqKey, 1n, 1n)).to.be.revertedWithCustomError(f.vault, "PolicyDenied");
      expect(await ethers.provider.getBalance(f.vaultAddress)).to.equal(ethers.parseEther("9"));
    });
  });

  // =====================================================================
  describe("GENESIS VALIDATION and OBSERVABILITY", function () {
    it("malformed genesis states are refused", async function () {
      const r = await rig();
      const base: Genesis = {
        signer: addrOf(keyOf("gv-owner")),
        pqKeyHash: pqHash(keyOf("gv-pq")),
        verifier: r.verifier,
        threshold: 2,
        guardians: ascending([addrOf(keyOf("gv1")), addrOf(keyOf("gv2")), addrOf(keyOf("gv3"))]),
        guardianIsContract: [false, false, false],
        floor: FLOOR,
      };
      // CONTROL: the base configuration deploys.
      await (await r.factory.deployVault(ethers.id("gv-ok"), base, pqKeyBytes(keyOf("gv-pq")))).wait();

      const cases: [string, Genesis, string][] = [
        ["zero signer", { ...base, signer: ZERO }, "ZeroAddress"],
        ["zero verifier", { ...base, verifier: ZERO }, "ZeroAddress"],
        ["verifier with no code", { ...base, verifier: r.deployer.address }, "ZeroAddress"],
        ["threshold zero", { ...base, threshold: 0 }, "BadRoster"],
        ["threshold exceeds roster", { ...base, threshold: 4 }, "BadRoster"],
        [
          "zero guardian address",
          { ...base, guardians: [ZERO, ...base.guardians], guardianIsContract: [false, false, false, false] },
          "NotOrdered",
        ],
        ["mandatory PQ with no committed key", { ...base, pqKeyHash: ethers.ZeroHash }, "BadSignature"],
        [
          "mandatory PQ with zero-length shapes",
          { ...base, floor: { ...FLOOR, pqSignatureLength: 0 } },
          "BadSignature",
        ],
      ];
      for (const [name, g, err] of cases) {
        await expect(r.factory.deployVault(ethers.id("gv-" + name), g, pqKeyBytes(keyOf("gv-pq"))), name).to.be.revertedWithCustomError(
          r.impl,
          err,
        );
      }
    });

    it("a factory cannot be bound to a codeless implementation or generation zero", async function () {
      const [deployer] = await ethers.getSigners();
      const F = await ethers.getContractFactory("VaultKernelFactoryPrototype", deployer);
      await expect(F.deploy(deployer.address, 1)).to.be.revertedWithCustomError(F, "NoCode");
      await expect(F.deploy(ZERO, 1)).to.be.revertedWithCustomError(F, "ZeroAddress");
      const Impl = await ethers.getContractFactory("VaultKernelPrototype", deployer);
      const impl = await Impl.deploy();
      await impl.waitForDeployment();
      await expect(F.deploy(await impl.getAddress(), 0)).to.be.revertedWithCustomError(F, "ZeroGeneration");
    });

    it("effectiveSafeState() reports what the kernel ENFORCES, not a stale enum", async function () {
      const f = await deploy();
      const cD = digestOf(
        parts(f, { actionType: ACTION.RECOVER, params: ethers.id("CONTAIN"), domain: DOMAIN.GUARDIAN }),
      );
      await (await f.vault.enterContainment(quorum(f, cD, [0, 1]), 0, BigInt(2 ** 40))).wait();
      expect(await f.vault.safeState()).to.equal(1); // CONTAINED
      expect(await f.vault.effectiveSafeState()).to.equal(1);

      await ethers.provider.send("evm_increaseTime", [4 * DAY]);
      await ethers.provider.send("evm_mine", []);

      // The STORED enum is now STALE — containment expired on wall clock with no
      // transaction. An observatory publishing the stored value would publish a
      // claim the kernel does not hold.
      expect(await f.vault.safeState()).to.equal(1);
      expect(await f.vault.effectiveSafeState()).to.equal(0);
      await (await spend(f, f.ownerKey, f.pqKey, 0n, 1n)).wait();
    });
  });
});
